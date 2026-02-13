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
const PORT = process.env.PORT || 3000;

const TMP_DIR = path.join(__dirname, "tmp");
const UPLOAD_DIR = path.join(TMP_DIR, "uploads");
const OUT_DIR = path.join(TMP_DIR, "out");

for (const dir of [TMP_DIR, UPLOAD_DIR, OUT_DIR]) {
  fs.mkdirSync(dir, { recursive: true });
}

/** =========================
 * Seguridad base / proxy
 * ========================= */
app.set("trust proxy", 1); // Render/Reverse proxy
app.disable("x-powered-by");

// HTTPS redirect (solo prod)
app.use((req, res, next) => {
  const proto = req.get("x-forwarded-proto");
  if (process.env.NODE_ENV === "production" && proto && proto !== "https") {
    return res.redirect(301, `https://${req.get("host")}${req.originalUrl}`);
  }
  next();
});

// Headers + logs
app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(morgan(process.env.NODE_ENV === "production" ? "combined" : "dev"));

/** Rate limit global */
app.use(
  rateLimit({
    windowMs: 60 * 1000,
    limit: 60,
    standardHeaders: "draft-7",
    legacyHeaders: false,
  })
);

/** Rate limit más estricto para compresión */
const compressLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 12,
  standardHeaders: "draft-7",
  legacyHeaders: false,
});

/** =========================
 * Opcional: Token de acceso
 * ========================= */
const API_TOKEN = process.env.API_TOKEN || "";
app.use("/api", (req, res, next) => {
  if (!API_TOKEN) return next();
  const token = req.get("x-api-token");
  if (token !== API_TOKEN) return res.status(401).json({ error: "No autorizado" });
  next();
});

/** =========================
 * Servir frontend (sin caché en DEV)
 * ========================= */
app.use(
  express.static(path.join(__dirname, "public"), {
    maxAge: process.env.NODE_ENV === "production" ? "1h" : 0,
    etag: process.env.NODE_ENV === "production",
  })
);

/** =========================
 * Upload seguro (multer)
 * ========================= */
const MAX_FILE_SIZE = Number(process.env.MAX_FILE_SIZE || 200) * 1024 * 1024;
const allowedExt = new Set([".pdf", ".docx"]);

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

const upload = multer({
  dest: UPLOAD_DIR,
  limits: { fileSize: MAX_FILE_SIZE, files: 1 },
  fileFilter: (_req, file, cb) => {
    const ext = path.extname(file.originalname || "").toLowerCase();
    if (!allowedExt.has(ext)) return cb(new Error("Solo se soporta PDF y DOCX."));
    cb(null, true);
  },
});

/** =========================
 * Runner seguro: execFile + timeout
 * ========================= */
async function run(cmd, args, { timeoutMs = 90_000 } = {}) {
  try {
    await execFileAsync(cmd, args, {
      timeout: timeoutMs,
      windowsHide: true,
      maxBuffer: 1024 * 1024,
    });
  } catch (e) {
    if (e?.code === "ENOENT") {
      throw new Error(`No se encontró el ejecutable: ${cmd}. Configura la ruta o instala la herramienta.`);
    }
    const stderr = e?.stderr ? String(e.stderr) : "";
    throw new Error(`${cmd} falló. ${stderr}`.trim());
  }
}

/** =========================
 * QPDF (PDF lossless)
 * ========================= */
const QPDF_WIN_DEFAULT = "C:\\Program Files\\qpdf 12.2.0\\bin\\qpdf.exe";
const QPDF_BIN = process.env.QPDF_PATH || (process.platform === "win32" ? QPDF_WIN_DEFAULT : "qpdf");

if (process.platform === "win32" && !fs.existsSync(QPDF_BIN)) {
  console.warn("⚠️ No se encontró QPDF en:", QPDF_BIN);
  console.warn("👉 Configura QPDF_PATH o agrega QPDF al PATH.");
} else {
  console.log("QPDF_BIN =>", QPDF_BIN);
}

async function compressPdfLossless(inputPath, outputPath) {
  await run(
    QPDF_BIN,
    ["--object-streams=generate", "--stream-data=compress", "--compression-level=9", inputPath, outputPath],
    { timeoutMs: 90_000 }
  );
}

/** =========================
 * Ghostscript (PDF con pérdida controlada)
 * ========================= */
const GS_BIN = process.env.GS_PATH || (process.platform === "win32" ? "gswin64c.exe" : "gs");

// perfil más agresivo (más parecido a iLovePDF)
const GS_PROFILE = {
  medium: { preset: "/ebook", color: 150, gray: 150, mono: 300 },
  high: { preset: "/screen", color: 96, gray: 96, mono: 200 },
};

async function compressPdfWithGhostscript(inputPath, outputPath, level) {
  const cfg = GS_PROFILE[level];
  if (!cfg) throw new Error("Nivel inválido para Ghostscript.");

  await run(
    GS_BIN,
    [
      "-sDEVICE=pdfwrite",
      "-dCompatibilityLevel=1.4",
      `-dPDFSETTINGS=${cfg.preset}`,
      "-dNOPAUSE",
      "-dBATCH",
      "-dQUIET",
      "-dSAFER",
      "-dDetectDuplicateImages=true",
      "-dCompressFonts=true",
      "-dSubsetFonts=true",

      // Downsample explícito
      "-dDownsampleColorImages=true",
      "-dDownsampleGrayImages=true",
      "-dDownsampleMonoImages=true",
      "-dColorImageDownsampleType=/Bicubic",
      "-dGrayImageDownsampleType=/Bicubic",
      "-dMonoImageDownsampleType=/Bicubic",
      `-dColorImageResolution=${cfg.color}`,
      `-dGrayImageResolution=${cfg.gray}`,
      `-dMonoImageResolution=${cfg.mono}`,

      `-sOutputFile=${outputPath}`,
      inputPath,
    ],
    { timeoutMs: 180_000 }
  );
}

async function compressPdfByLevel(inputPath, outputPath, level, tempFiles) {
  if (level === "min") {
    await compressPdfLossless(inputPath, outputPath);
    return;
  }

  // Ghostscript -> (opcional) qpdf para “limpiar” y optimizar un poco más
  const gsTmp = path.join(OUT_DIR, `${Date.now()}-${crypto.randomUUID()}-gs.pdf`);
  tempFiles.push(gsTmp);

  await compressPdfWithGhostscript(inputPath, gsTmp, level);
  await compressPdfLossless(gsTmp, outputPath);
}

/** =========================
 * DOCX lossless + anti zip-bomb
 * ========================= */
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
    if (isSuspiciousZipPath(f.path)) throw new Error("DOCX sospechoso (rutas internas inválidas).");
    total += Number(f.uncompressedSize || 0);
    if (total > MAX_DOCX_UNCOMPRESSED) throw new Error("DOCX sospechoso (tamaño descomprimido excesivo).");
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

/** =========================
 * Validación por magic bytes
 * ========================= */
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

/** =========================
 * Concurrencia limitada
 * ========================= */
const MAX_CONCURRENT_COMPRESS = Number(process.env.MAX_CONCURRENT_COMPRESS || 2);
let currentCompress = 0;

app.get("/api/health", (_req, res) => res.json({ ok: true }));

app.post("/api/compress", compressLimiter, upload.single("file"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No se recibió archivo." });

  const originalName = req.file.originalname || "archivo";
  const ext = path.extname(originalName).toLowerCase();

  if (!allowedExt.has(ext)) {
    safeUnlink(req.file.path);
    return res.status(415).json({ error: "Solo se soporta PDF y DOCX." });
  }

  // Nivel (min | medium | high) - viene en multipart (multer lo coloca en req.body)
  const requested = String(req.body?.level || "min").toLowerCase();
  const level = ["min", "medium", "high"].includes(requested) ? requested : "min";

  // Debug útil para confirmar
  if (process.env.NODE_ENV !== "production") {
    console.log("Nivel recibido:", req.body?.level, "-> nivel usado:", level);
  }

  if (currentCompress >= MAX_CONCURRENT_COMPRESS) {
    safeUnlink(req.file.path);
    return res.status(503).json({ error: "Servidor ocupado. Intenta nuevamente en unos segundos." });
  }

  currentCompress++;

  const inputPath = req.file.path;
  const safeName = sanitizeFilename(`${path.basename(originalName, ext)}.compressed${ext}`);
  const outputPath = path.join(OUT_DIR, `${Date.now()}-${crypto.randomUUID()}-${safeName}`);

  const tempFiles = []; // temporales extra (ghostscript)
  let cleaned = false;

  const cleanupOnce = () => {
    if (cleaned) return;
    cleaned = true;
    safeUnlink(inputPath);
    safeUnlink(outputPath);
    for (const p of tempFiles) safeUnlink(p);
    currentCompress = Math.max(0, currentCompress - 1);
  };

  try {
    await verifyMagic(inputPath, ext);

    const before = fs.statSync(inputPath).size;

    if (ext === ".pdf") {
      await compressPdfByLevel(inputPath, outputPath, level, tempFiles);
    } else {
      await recompressDocxLossless(inputPath, outputPath);
    }

    const after = fs.statSync(outputPath).size;
    const saved = before - after;

    res.setHeader("Cache-Control", "no-store");

    // Métricas + debug
    res.setHeader("X-Original-Bytes", String(before));
    res.setHeader("X-Compressed-Bytes", String(after));
    res.setHeader("X-Saved-Bytes", String(saved));
    res.setHeader("X-Original-Human", bytesToHuman(before));
    res.setHeader("X-Compressed-Human", bytesToHuman(after));
    res.setHeader("X-Level", level);
    res.setHeader("X-Engine", ext === ".pdf" ? (level === "min" ? "qpdf" : "ghostscript+qpdf") : "docx-zip");

    res.setHeader("Content-Disposition", `attachment; filename="${safeName}"`);
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
    cleanupOnce();
    const msg =
      ext === ".pdf"
        ? `Error al comprimir PDF (${level}). Detalle: ${e.message}`
        : `Error al comprimir DOCX. Detalle: ${e.message}`;
    return res.status(500).json({ error: msg });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`✅ App corriendo en http://localhost:${PORT}`);
});
