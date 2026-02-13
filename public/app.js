// public/app.js

const drop = document.getElementById("drop");
const fileInput = document.getElementById("file");
const btnCompress = document.getElementById("btnCompress");
const btnReset = document.getElementById("btnReset");

const fileName = document.getElementById("fileName");
const fileSize = document.getElementById("fileSize");

const progressBar = document.getElementById("progressBar");
const progressText = document.getElementById("progressText");

const result = document.getElementById("result");
const errorBox = document.getElementById("error");

const origHuman = document.getElementById("origHuman");
const compHuman = document.getElementById("compHuman");
const savedHuman = document.getElementById("savedHuman");
const download = document.getElementById("download");

let selectedFile = null;
let objectUrl = null;

function human(bytes) {
  const units = ["B", "KB", "MB", "GB"];
  let i = 0;
  let v = bytes;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(i === 0 ? 0 : 2)} ${units[i]}`;
}

function resetUI() {
  selectedFile = null;
  fileInput.value = "";
  fileName.textContent = "—";
  fileSize.textContent = "—";
  btnCompress.disabled = true;
  btnReset.disabled = true;

  progressBar.style.width = "0%";
  progressText.textContent = "0%";

  result.hidden = true;
  errorBox.hidden = true;
  errorBox.textContent = "";

  if (objectUrl) {
    URL.revokeObjectURL(objectUrl);
    objectUrl = null;
  }
  download.removeAttribute("href");
  download.removeAttribute("download");
}

function setFile(file) {
  selectedFile = file;

  fileName.textContent = file.name;
  fileSize.textContent = human(file.size);

  btnCompress.disabled = false;
  btnReset.disabled = false;

  result.hidden = true;
  errorBox.hidden = true;
  errorBox.textContent = "";
}

drop.addEventListener("dragover", (e) => {
  e.preventDefault();
  drop.classList.add("dragover");
});

drop.addEventListener("dragleave", () => {
  drop.classList.remove("dragover");
});

drop.addEventListener("drop", (e) => {
  e.preventDefault();
  drop.classList.remove("dragover");

  const file = e.dataTransfer.files?.[0];
  if (!file) return;

  const ok = /\.(pdf|docx)$/i.test(file.name);
  if (!ok) {
    errorBox.hidden = false;
    errorBox.textContent = "Solo se soporta .pdf y .docx";
    return;
  }
  setFile(file);
});

fileInput.addEventListener("change", () => {
  const file = fileInput.files?.[0];
  if (!file) return;
  setFile(file);
});

btnReset.addEventListener("click", resetUI);

function getSelectedLevel() {
  const rawLevel = (document.querySelector('input[name="level"]:checked')?.value || "min").toLowerCase();

  // Mapeo para soportar values en español o inglés
  const levelMap = {
    min: "min",
    minima: "min",
    mínimo: "min",
    minimo: "min",

    medium: "medium",
    media: "medium",

    high: "high",
    alta: "high",
  };

  const normalized = levelMap[rawLevel] || "min";
  return { rawLevel, normalized };
}

btnCompress.addEventListener("click", async () => {
  if (!selectedFile) return;

  btnCompress.disabled = true;
  errorBox.hidden = true;
  errorBox.textContent = "";
  result.hidden = true;

  progressBar.style.width = "0%";
  progressText.textContent = "0%";

  const form = new FormData();
  form.append("file", selectedFile);

  // Nivel de compresión
  const { rawLevel, normalized } = getSelectedLevel();
  form.append("level", normalized);

  // Debug útil
  console.log("Level seleccionado:", rawLevel, "-> enviado al backend:", normalized);

  // Usamos XHR para tener progreso real de subida
  const xhr = new XMLHttpRequest();
  xhr.open("POST", "/api/compress", true);
  xhr.responseType = "blob";

  xhr.upload.onprogress = (e) => {
    if (!e.lengthComputable) return;
    const pct = Math.round((e.loaded / e.total) * 100);
    progressBar.style.width = `${pct}%`;
    progressText.textContent = `${pct}%`;
  };

  xhr.onload = () => {
    btnCompress.disabled = false;

    if (xhr.status >= 200 && xhr.status < 300) {
      const origB = Number(xhr.getResponseHeader("X-Original-Bytes") || "0");
      const compB = Number(xhr.getResponseHeader("X-Compressed-Bytes") || "0");
      const savedB = Number(xhr.getResponseHeader("X-Saved-Bytes") || "0");

      origHuman.textContent = xhr.getResponseHeader("X-Original-Human") || human(origB);
      compHuman.textContent = xhr.getResponseHeader("X-Compressed-Human") || human(compB);
      savedHuman.textContent = human(savedB);

      // Debug del backend
      console.log("X-Level:", xhr.getResponseHeader("X-Level"));
      console.log("X-Engine:", xhr.getResponseHeader("X-Engine"));

      const disposition = xhr.getResponseHeader("Content-Disposition") || "";
      const match = disposition.match(/filename="(.+?)"/i);
      const outName = match?.[1] || "archivo.compressed";

      if (objectUrl) URL.revokeObjectURL(objectUrl);
      objectUrl = URL.createObjectURL(xhr.response);

      download.href = objectUrl;
      download.download = outName;

      result.hidden = false;
      progressBar.style.width = "100%";
      progressText.textContent = "100%";
      return;
    }

    // Si el backend devuelve JSON de error, aquí no lo parseamos directo porque responseType=blob
    const reader = new FileReader();
    reader.onload = () => {
      errorBox.hidden = false;
      errorBox.textContent = reader.result?.toString() || "Error desconocido.";
    };
    reader.readAsText(xhr.response);
  };

  xhr.onerror = () => {
    btnCompress.disabled = false;
    errorBox.hidden = false;
    errorBox.textContent = "Error de red. Revisa tu conexión o el servidor.";
  };

  xhr.send(form);
});

// Inicial
resetUI();
