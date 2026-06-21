/* =====================================================================
   SISTEM PAKAR FUZZY LOGIC — PENILAIAN KEAMANAN PASSWORD
   Metode: Mamdani (Fuzzifikasi -> Inferensi min-max -> Defuzzifikasi Centroid)
   ===================================================================== */

/* ---------------------------------------------------------------------
   1. FUNGSI KEANGGOTAAN (MEMBERSHIP FUNCTIONS)
   --------------------------------------------------------------------- */

// Segitiga: 0 di a, puncak 1 di b, 0 lagi di c
function triangular(x, a, b, c) {
  if (x <= a || x >= c) return 0;
  if (x === b) return 1;
  if (x < b) return (x - a) / (b - a);
  return (c - x) / (c - b);
}

// Bahu kiri: penuh (1) di bawah b, turun dari b ke c, 0 di atas c
// dipakai untuk kategori "rendah/pendek/sedikit" yang terbuka ke kiri
function shoulderLeft(x, b, c) {
  if (x <= b) return 1;
  if (x >= c) return 0;
  return (c - x) / (c - b);
}

// Bahu kanan: 0 di bawah b, naik dari b ke c, penuh (1) di atas c
// dipakai untuk kategori "tinggi/panjang/banyak" yang terbuka ke kanan
function shoulderRight(x, b, c) {
  if (x <= b) return 0;
  if (x >= c) return 1;
  return (x - b) / (c - b);
}

/* ---------------------------------------------------------------------
   2. FUZZIFIKASI VARIABEL INPUT
   --------------------------------------------------------------------- */

// Variabel 1: Panjang Password (karakter)
function fuzzifyLength(len) {
  return {
    Pendek: shoulderLeft(len, 4, 8),
    Sedang: triangular(len, 6, 10, 14),
    Panjang: shoulderRight(len, 12, 16),
  };
}

// Variabel 2: Variasi Jenis Karakter (0-4: lowercase, UPPERCASE, angka, simbol)
function fuzzifyVariety(v) {
  return {
    Rendah: shoulderLeft(v, 1, 2),
    Sedang: triangular(v, 1, 2, 3),
    Tinggi: shoulderRight(v, 2, 3),
  };
}

// Variabel 3: Skor Pola Umum / Predictability (0-10, makin tinggi makin mudah ditebak)
function fuzzifyPattern(p) {
  return {
    TidakAda: shoulderLeft(p, 1, 3),
    Sedikit: triangular(p, 1, 4, 7),
    Banyak: shoulderRight(p, 5, 8),
  };
}

// Variabel output: Tingkat Keamanan (skor 0-100)
function fuzzifyOutput(score, term) {
  switch (term) {
    case "Lemah": return shoulderLeft(score, 25, 45);
    case "Sedang": return triangular(score, 30, 50, 70);
    case "Kuat": return triangular(score, 55, 70, 85);
    case "SangatKuat": return shoulderRight(score, 75, 90);
  }
}

/* ---------------------------------------------------------------------
   3. EKSTRAKSI FITUR DARI STRING PASSWORD
   --------------------------------------------------------------------- */

function getLength(password) {
  return password.length;
}

function getCharVariety(password) {
  let types = 0;
  if (/[a-z]/.test(password)) types++;
  if (/[A-Z]/.test(password)) types++;
  if (/[0-9]/.test(password)) types++;
  if (/[^a-zA-Z0-9]/.test(password)) types++;
  return types;
}

// Daftar kata/pola yang umum dipakai (boleh diperluas)
const COMMON_PASSWORDS = [
  "password", "123456", "12345678", "qwerty", "letmein", "admin",
  "welcome", "monkey", "dragon", "iloveyou", "123123", "abc123",
  "111111", "sayang", "rahasia", "indonesia",
];

function getPatternScore(password) {
  let score = 0;
  const lower = password.toLowerCase();

  // 1. cocok dengan kata/pola umum
  if (COMMON_PASSWORDS.some((w) => lower.includes(w))) score += 4;

  // 2. karakter berurutan, mis. "abcd", "1234"
  let seqCount = 0;
  for (let i = 0; i < password.length - 2; i++) {
    const a = password.charCodeAt(i);
    const b = password.charCodeAt(i + 1);
    const c = password.charCodeAt(i + 2);
    if (b - a === 1 && c - b === 1) seqCount++;
  }
  score += Math.min(seqCount, 3);

  // 3. karakter berulang, mis. "aaa", "111"
  let repCount = 0;
  for (let i = 0; i < password.length - 2; i++) {
    if (password[i] === password[i + 1] && password[i + 1] === password[i + 2]) repCount++;
  }
  score += Math.min(repCount, 3);

  return Math.min(score, 10);
}

/* ---------------------------------------------------------------------
   4. BASIS ATURAN (RULE BASE) — 27 aturan, mencakup semua kombinasi
      3 variabel input x 3 himpunan = hasil keputusan pakar
   --------------------------------------------------------------------- */

const RULES = [
  ["Pendek", "Rendah", "TidakAda", "Lemah"],
  ["Pendek", "Rendah", "Sedikit", "Lemah"],
  ["Pendek", "Rendah", "Banyak", "Lemah"],
  ["Pendek", "Sedang", "TidakAda", "Lemah"],
  ["Pendek", "Sedang", "Sedikit", "Lemah"],
  ["Pendek", "Sedang", "Banyak", "Lemah"],
  ["Pendek", "Tinggi", "TidakAda", "Sedang"],
  ["Pendek", "Tinggi", "Sedikit", "Lemah"],
  ["Pendek", "Tinggi", "Banyak", "Lemah"],

  ["Sedang", "Rendah", "TidakAda", "Lemah"],
  ["Sedang", "Rendah", "Sedikit", "Lemah"],
  ["Sedang", "Rendah", "Banyak", "Lemah"],
  ["Sedang", "Sedang", "TidakAda", "Sedang"],
  ["Sedang", "Sedang", "Sedikit", "Sedang"],
  ["Sedang", "Sedang", "Banyak", "Lemah"],
  ["Sedang", "Tinggi", "TidakAda", "Kuat"],
  ["Sedang", "Tinggi", "Sedikit", "Sedang"],
  ["Sedang", "Tinggi", "Banyak", "Sedang"],

  ["Panjang", "Rendah", "TidakAda", "Sedang"],
  ["Panjang", "Rendah", "Sedikit", "Lemah"],
  ["Panjang", "Rendah", "Banyak", "Lemah"],
  ["Panjang", "Sedang", "TidakAda", "Kuat"],
  ["Panjang", "Sedang", "Sedikit", "Sedang"],
  ["Panjang", "Sedang", "Banyak", "Sedang"],
  ["Panjang", "Tinggi", "TidakAda", "SangatKuat"],
  ["Panjang", "Tinggi", "Sedikit", "Kuat"],
  ["Panjang", "Tinggi", "Banyak", "Sedang"],
];

/* ---------------------------------------------------------------------
   5. INFERENSI (MAMDANI, operator AND = min) & AGREGASI (max)
   --------------------------------------------------------------------- */

function evaluateRules(lengthDeg, varietyDeg, patternDeg) {
  return RULES.map(([lt, vt, pt, out]) => ({
    length: lt, variety: vt, pattern: pt, output: out,
    alpha: Math.min(lengthDeg[lt], varietyDeg[vt], patternDeg[pt]),
  })).filter((r) => r.alpha > 0);
}

/* ---------------------------------------------------------------------
   6. DEFUZZIFIKASI — metode CENTROID (titik berat)
   --------------------------------------------------------------------- */

function defuzzify(activatedRules) {
  let numerator = 0;
  let denominator = 0;
  for (let x = 0; x <= 100; x++) {
    let aggregated = 0;
    for (const rule of activatedRules) {
      const clipped = Math.min(rule.alpha, fuzzifyOutput(x, rule.output));
      aggregated = Math.max(aggregated, clipped);
    }
    numerator += x * aggregated;
    denominator += aggregated;
  }
  return denominator === 0 ? 0 : numerator / denominator;
}

function getLabel(score) {
  if (score < 35) return "Lemah";
  if (score < 60) return "Sedang";
  if (score < 80) return "Kuat";
  return "Sangat Kuat";
}

/* ---------------------------------------------------------------------
   7. FUNGSI UTAMA — dipanggil oleh UI
   --------------------------------------------------------------------- */

function analyzePassword(password) {
  const length = getLength(password);
  const variety = getCharVariety(password);
  const pattern = getPatternScore(password);

  const lengthDeg = fuzzifyLength(length);
  const varietyDeg = fuzzifyVariety(variety);
  const patternDeg = fuzzifyPattern(pattern);

  const activated = evaluateRules(lengthDeg, varietyDeg, patternDeg);
  const score = defuzzify(activated);

  return {
    length, variety, pattern,
    lengthDeg, varietyDeg, patternDeg,
    score: Math.round(score),
    label: getLabel(score),
  };
}

function getSuggestions(password, result) {
  const tips = [];
  if (result.length < 12) tips.push("Tambah panjang password, idealnya minimal 12-16 karakter.");
  if (result.variety < 3) tips.push("Kombinasikan huruf besar, huruf kecil, angka, dan simbol.");
  if (result.pattern >= 4) tips.push("Hindari kata umum, urutan karakter (abcd/1234), atau karakter berulang.");
  if (tips.length === 0) tips.push("Password ini sudah memenuhi karakteristik password yang kuat.");
  return tips;
}

/* =====================================================================
   8. INTEGRASI UI — menghubungkan engine di atas dengan index.html
   ===================================================================== */

document.addEventListener("DOMContentLoaded", () => {
  const input = document.getElementById("password-input");
  const toggleBtn = document.getElementById("toggle-visibility");
  const scoreValue = document.getElementById("score-value");
  const scoreLabel = document.getElementById("score-label");
  const scoreBarFill = document.getElementById("score-bar-fill");
  const readout = document.getElementById("readout");
  const suggestionsList = document.getElementById("suggestions-list");
  const resultPanel = document.getElementById("result-panel");
  const emptyState = document.getElementById("empty-state");

  const LABEL_CLASS = {
    "Lemah": "state-lemah",
    "Sedang": "state-sedang",
    "Kuat": "state-kuat",
    "Sangat Kuat": "state-sangatkuat",
  };

  const VARIABLES = [
    { key: "lengthDeg", title: "Panjang Password", terms: ["Pendek", "Sedang", "Panjang"], raw: (r) => `${r.length} karakter` },
    { key: "varietyDeg", title: "Variasi Karakter", terms: ["Rendah", "Sedang", "Tinggi"], raw: (r) => `${r.variety} dari 4 jenis` },
    { key: "patternDeg", title: "Pola Umum / Predictability", terms: ["TidakAda", "Sedikit", "Banyak"], raw: (r) => `skor ${r.pattern} / 10` },
  ];

  const TERM_LABEL = {
    Pendek: "Pendek", Sedang: "Sedang", Panjang: "Panjang",
    Rendah: "Rendah", Tinggi: "Tinggi",
    TidakAda: "Tidak Ada", Sedikit: "Sedikit", Banyak: "Banyak",
  };

  function renderReadout(result) {
    readout.innerHTML = "";
    VARIABLES.forEach((v) => {
      const row = document.createElement("div");
      row.className = "readout-row";

      const head = document.createElement("div");
      head.className = "readout-head";
      head.innerHTML = `<span class="readout-title">${v.title}</span><span class="readout-raw">${v.raw(result)}</span>`;
      row.appendChild(head);

      const bars = document.createElement("div");
      bars.className = "readout-bars";
      v.terms.forEach((term) => {
        const degree = result[v.key][term];
        const pct = Math.round(degree * 100);
        const bar = document.createElement("div");
        bar.className = "readout-bar";
        bar.innerHTML = `
          <span class="readout-bar-label">${TERM_LABEL[term]}</span>
          <div class="readout-bar-track">
            <div class="readout-bar-fill" style="width:${pct}%"></div>
          </div>
          <span class="readout-bar-pct">${pct}%</span>
        `;
        bars.appendChild(bar);
      });
      row.appendChild(bars);
      readout.appendChild(row);
    });
  }

  function renderSuggestions(password, result) {
    suggestionsList.innerHTML = "";
    getSuggestions(password, result).forEach((tip) => {
      const li = document.createElement("li");
      li.textContent = tip;
      suggestionsList.appendChild(li);
    });
  }

  function render() {
    const password = input.value;

    if (password.length === 0) {
      resultPanel.classList.add("is-empty");
      emptyState.style.display = "block";
      return;
    }
    resultPanel.classList.remove("is-empty");
    emptyState.style.display = "none";

    const result = analyzePassword(password);

    scoreValue.textContent = result.score;
    scoreLabel.textContent = result.label;
    scoreBarFill.style.width = `${result.score}%`;

    Object.values(LABEL_CLASS).forEach((c) => resultPanel.classList.remove(c));
    resultPanel.classList.add(LABEL_CLASS[result.label]);

    renderReadout(result);
    renderSuggestions(password, result);
  }

  input.addEventListener("input", render);

  toggleBtn.addEventListener("click", () => {
    const isPassword = input.type === "password";
    input.type = isPassword ? "text" : "password";
    toggleBtn.textContent = isPassword ? "Sembunyikan" : "Tampilkan";
    toggleBtn.setAttribute("aria-pressed", String(isPassword));
  });

  render();
});