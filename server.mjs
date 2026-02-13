import express from "express";
import path from "path";
import fs from "fs";
import crypto from "crypto";
import { fileURLToPath } from "url";
import helmet from "helmet";
import morgan from "morgan";
import rateLimit from "express-rate-limit";
import multer from "multer";
import { execFile } from "child_process";
import { promisify } from "util";
import archiver from "archiver";
import unzipper from "unzipper";

const execFileAsync = promisify(execFile);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT || 3000);
const IS_PROD = process.env.NODE_ENV === "production";

/** ============= Carpetas temporales ============= */
const TMP_DIR = path.join(__dirname, "tmp");
const UPLOAD_DIR = path.join(TMP_DIR, "uploads");
const OUT_DIR = path.join(TMP_DIR, "out");

for (const dir of [TMP_DIR, UPLOAD_DIR, OUT_DIR]) {
  fs.mkdirSync(dir, { recursive: true });
}

/** ============= Seguridad base (OWASP) ============= */
app.set("trust proxy", 1);
app.disable("x-powered-by");

// HTTPS redirect (solo prod y si viene por proxy)
app.use((req, res, next) => {
  const proto = req.get("x-forwarded-proto");
  if (IS_PROD && proto && proto !== "https") {
    return res.redirect(301, `https://${req.get("host")}${req.originalUrl}`);
  }
  next();
});

// Helmet + CSP conservadora (no rompe tu app)
app.use(
  helmet({
    crossOriginResourcePolicy: false,
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        "default-src": ["'self'"],
        "script-src": ["'self'"],
        "style-src": ["'self'", "'unsafe-inline'"], // por si usas styles inline
        "img-src": ["'self'", "data:"],
        "connect-src": ["'self'"],
        "frame-ancestors": ["'none'"],
      },
    },
    referrerPolicy: { policy: "no-referrer" },
  })
);

app.use(morgan(IS_PROD ? "combined" : "dev"));

/** Rate limit global */
app.use(
  rateLimit({
    windowMs: 60 * 1000,
    limit: 60,
    standardHeaders: "draft-7",
    legacyHeaders: false,
  })
);

/** Rate limit estricto para compresión */
const compressLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 12,
  standardHeaders: "draft-7",
  legacyHeaders: false,
});

/** (Opcional) Token para evitar abuso público */
const API_TOKEN = process.env.API_TOKEN || "";
app.use("/api", (req, res, next) => {
  if (!API_TOKEN) return next();
  const token = req.get("x-api-token");
  if (token !== API_TOKEN) return res.status(401).json({ error: "No autorizado" });
  next();
});

/** Servir frontend */
app.use(express.static(path.join(__dirname, "public"), { maxAge: "1h" }));

/** ============= Utils ============= */
function safeUnlink(p) {
  try {
    fs.unlinkSync(p);
  } catch {}
}

function bytesToHuman(bytes) {
  const units = ["B", "KB", "MB", "GB"];
  let i = 0;
  let val = bytes;
  while (val >= 1024 && i < units.length - 1) {
    val /= 1024;
    i++;
  }
  return `${val.toFixed(i === 0 ? 0 : 2)} ${units[i]}`;
}

function sanitizeFilename(name) {
  return name.replace(/[^\w.\-]+/g, "_").slice(0, 140);
}

/** Runner seguro: execFile + timeout + captura */
async function run(cmd, args, { timeoutMs = 90_000 } = {}) {
  try {
    const { stdout, stderr } = await execFileAsync(cmd, args, {
      timeout: timeoutMs,
      windowsHide: true,
      maxBuffer: 10 * 1024 * 1024,
    });
    return { stdout: String(stdout || ""), stderr: String(stderr || "") };
  } catch (e) {
    const out = e?.stdout ? String(e.stdout) : "";
    const err = e?.stderr ? String(e.stderr) : "";
    const timedOut = Boolean(e?.killed) || e?.code === "ETIMEDOUT";
    const meta = timedOut ? `TIMEOUT ${timeoutMs}ms` : `code=${e?.code ?? "?"}`;
    const detail = (err || out || "").trim();
    throw new Error(`${cmd} falló (${meta}). ${detail}`.trim());
  }
}

/** ============= Upload seguro (multer) ============= */
const MAX_FILE_SIZE = Number(process.env.MAX_FILE_SIZE || 50) * 1024 * 1024; // MB
const allowedExt = new Set([".pdf", ".docx"]);

const upload = multer({
  dest: UPLOAD_DIR,
  limits: { fileSize: MAX_FILE_SIZE, files: 1 },
  fileFilter: (_req, file, cb) => {
    const ext = path.extname(file.originalname || "").toLowerCase();
    if (!allowedExt.has(ext)) return cb(new Error("Solo se soporta PDF y DOCX."));
    cb(null, true);
  },
});

/** Magic bytes (no confía en extensión) */
async function verifyMagic(inputPath, ext) {
  const fd = await fs.promises.open(inputPath, "r");
  try {
    const buf = Buffer.alloc(4);
    await fd.read(buf, 0, 4, 0);

    if (ext === ".pdf" && buf.toString("utf8") !== "%PDF") {
      throw new Error("El archivo no parece un PDF válido.");
    }
    if (ext === ".docx" && (buf[0] !== 0x50 || buf[1] !== 0x4b)) {
      throw new Error("El archivo no parece un DOCX válido.");
    }
  } finally {
    await fd.close();
  }
}

/** ============= Concurrencia limitada (anti DoS) ============= */
const MAX_CONCURRENT_COMPRESS = Number(process.env.MAX_CONCURRENT_COMPRESS || 1);
let currentCompress = 0;

/** ============= PDF: QPDF (lossless) ============= */
const QPDF_WIN_DEFAULT = "C:\\Program Files\\qpdf 12.2.0\\bin\\qpdf.exe";
const QPDF_BIN =
  process.env.QPDF_PATH || (process.platform === "win32" ? QPDF_WIN_DEFAULT : "qpdf");

async function compressPdfLossless(inputPath, outputPath) {
  await run(
    QPDF_BIN,
    [
      "--object-streams=generate",
      "--stream-data=compress",
      "--compression-level=9",
      inputPath,
      outputPath,
    ],
    { timeoutMs: 120_000 }
  );
}

/** ============= PDF: Ghostscript (lossy controlado) ============= */
const GS_BIN =
  process.env.GS_PATH || (process.platform === "win32" ? "gswin64c.exe" : "gs");

const PDF_LEVELS = {
  min: { engine: "qpdf" },
  medium: { engine: "gs", preset: "/ebook", dpi: 150, timeoutMs: 300_000 },
  high: { engine: "gs", preset: "/screen", dpi: 96, timeoutMs: 300_000 },
};

async function compressPdfWithGhostscript(inputPath, outputPath, preset, dpi, timeoutMs) {
  await run(
    GS_BIN,
    [
      "-sDEVICE=pdfwrite",
      "-dCompatibilityLevel=1.4",
      `-dPDFSETTINGS=${preset}`,
      "-dNOPAUSE",
      "-dBATCH",
      "-dSAFER",
      "-dDetectDuplicateImages=true",
      "-dCompressFonts=true",
      "-dSubsetFonts=true",

      // Downsample real (para bajar MB de verdad)
      "-dDownsampleColorImages=true",
      "-dDownsampleGrayImages=true",
      "-dDownsampleMonoImages=true",
      "-dColorImageDownsampleType=/Bicubic",
      "-dGrayImageDownsampleType=/Bicubic",
      "-dMonoImageDownsampleType=/Subsample",
      `-dColorImageResolution=${dpi}`,
      `-dGrayImageResolution=${dpi}`,
      "-dMonoImageResolution=300",

      // Si el PDF tiene problemas, mejor que lo diga
      "-dPDFSTOPONERROR",

      `-sOutputFile=${outputPath}`,
      inputPath,
    ],
    { timeoutMs }
  );
}

/** ============= DOCX: recompress ZIP + anti zip-bomb ============= */
const MAX_DOCX_ENTRIES = Number(process.env.MAX_DOCX_ENTRIES || 5000);
const MAX_DOCX_UNCOMPRESSED = Number(process.env.MAX_DOCX_UNCOMPRESSED || 300) * 1024 * 1024;

function isSuspiciousZipPath(p) {
  return p.startsWith("/") || p.startsWith("\\") || p.includes("..") || p.includes(":");
}

async function recompressDocxLossless(inputPath, outputPath) {
  const dir = await unzipper.Open.file(inputPath);

  if (dir.files.length > MAX_DOCX_ENTRIES) {
    throw new Error("DOCX sospechoso (demasiados archivos internos).");
  }

  let total = 0;
  for (const f of dir.files) {
    if (isSuspiciousZipPath(f.path)) {
      throw new Error("DOCX sospechoso (rutas internas inválidas).");
    }
    total += Number(f.uncompressedSize || 0);
    if (total > MAX_DOCX_UNCOMPRESSED) {
      throw new Error("DOCX sospechoso (tamaño descomprimido excesivo).");
    }
  }

  await new Promise((resolve, reject) => {
    const outStream = fs.createWriteStream(outputPath);
    const archive = archiver("zip", { zlib: { level: 9 } });

    outStream.on("close", resolve);
    outStream.on("error", reject);
    archive.on("error", reject);

    archive.pipe(outStream);

    for (const entry of dir.files) {
      if (entry.type === "Directory") {
        const name = entry.path.endsWith("/") ? entry.path : entry.path + "/";
        archive.append("", { name });
      } else {
        archive.append(entry.stream(), { name: entry.path });
      }
    }

    archive.finalize();
  });
}

/** ============= API ============= */
app.get("/api/health", (_req, res) => res.json({ ok: true }));

app.post("/api/compress", compressLimiter, upload.single("file"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No se recibió archivo." });

  const originalName = req.file.originalname || "archivo";
  const ext = path.extname(originalName).toLowerCase();

  if (!allowedExt.has(ext)) {
    safeUnlink(req.file.path);
    return res.status(415).json({ error: "Solo se soporta PDF y DOCX." });
  }

  if (currentCompress >= MAX_CONCURRENT_COMPRESS) {
    safeUnlink(req.file.path);
    return res.status(503).json({ error: "Servidor ocupado. Intenta nuevamente." });
  }

  currentCompress++;

  const inputPath = req.file.path;

  const levelRaw = String(req.body?.level || "min").toLowerCase();
  const level = PDF_LEVELS[levelRaw] ? levelRaw : "min";

  const outBase = sanitizeFilename(`${path.basename(originalName, ext)}.compressed${ext}`);
  const outputPath = path.join(OUT_DIR, `${Date.now()}-${crypto.randomUUID()}-${outBase}`);

  let cleaned = false;
  const cleanupOnce = () => {
    if (cleaned) return;
    cleaned = true;
    safeUnlink(inputPath);
    safeUnlink(outputPath);
    currentCompress = Math.max(0, currentCompress - 1);
  };

  try {
    await verifyMagic(inputPath, ext);

    const before = fs.statSync(inputPath).size;

    // PDF
    if (ext === ".pdf") {
      const cfg = PDF_LEVELS[level];

      if (cfg.engine === "qpdf") {
        await compressPdfLossless(inputPath, outputPath);
        res.setHeader("X-Engine", "qpdf");
      } else {
        try {
          await compressPdfWithGhostscript(
            inputPath,
            outputPath,
            cfg.preset,
            cfg.dpi,
            cfg.timeoutMs
          );
          res.setHeader("X-Engine", "ghostscript");
        } catch (e) {
          // fallback seguro
          console.error("[GS ERROR]", e.message);
          safeUnlink(outputPath);
          await compressPdfLossless(inputPath, outputPath);
          res.setHeader("X-Engine", "qpdf-fallback");
          res.setHeader("X-Warn", String(e.message).slice(0, 200));
        }
      }
    }

    // DOCX
    if (ext === ".docx") {
      await recompressDocxLossless(inputPath, outputPath);
      res.setHeader("X-Engine", "docx-zip");
    }

    const after = fs.statSync(outputPath).size;
    const saved = before - after;

    res.setHeader("Cache-Control", "no-store");

    // Métricas
    res.setHeader("X-Original-Bytes", String(before));
    res.setHeader("X-Compressed-Bytes", String(after));
    res.setHeader("X-Saved-Bytes", String(saved));
    res.setHeader("X-Original-Human", bytesToHuman(before));
    res.setHeader("X-Compressed-Human", bytesToHuman(after));

    // Descarga
    res.setHeader("Content-Disposition", `attachment; filename="${outBase}"`);
    res.setHeader(
      "Content-Type",
      ext === ".pdf"
        ? "application/pdf"
        : "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    );

    const read = fs.createReadStream(outputPath);
    read.pipe(res);

    res.on("finish", cleanupOnce);
    res.on("close", cleanupOnce);
  } catch (e) {
    console.error("[COMPRESS ERROR]", e.message);
    cleanupOnce();

    // Mensaje seguro al cliente
    const safeMsg = IS_PROD
      ? "No se pudo procesar el archivo. Intenta con otro o más tarde."
      : `No se pudo procesar el archivo. Detalle: ${e.message}`;

    return res.status(500).json({ error: safeMsg });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`✅ App corriendo en puerto ${PORT}`);
});
