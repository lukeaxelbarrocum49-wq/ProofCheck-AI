"use strict";

const STORAGE_KEY = "proofcheck_ai_history_v1";
const MAX_HISTORY = 200;

const $ = (selector) => document.querySelector(selector);

let history = loadHistory();
let selectedImage = null;
let ocrBusy = false;
let toastTimer;

function loadHistory() {
  try {
    const data = JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]");
    return Array.isArray(data) ? data.filter(x =>
      x && typeof x.id === "string" &&
      typeof x.type === "string" &&
      typeof x.risk === "string"
    ) : [];
  } catch {
    return [];
  }
}

function saveHistory() {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(history.slice(0, MAX_HISTORY)));
    return true;
  } catch {
    showToast("Unable to save. Browser storage may be full or disabled.");
    return false;
  }
}

function escapeHTML(value) {
  return String(value).replace(/[&<>"']/g, char => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;",
    '"': "&quot;", "'": "&#39;"
  })[char]);
}

function showToast(message) {
  const toast = $("#toast");
  toast.textContent = message;
  toast.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove("show"), 2800);
}

function riskLabel(score) {
  if (score >= 60) return "High risk";
  if (score >= 30) return "Medium risk";
  return "Lower risk";
}

function riskClass(score) {
  if (score >= 60) return "risk-high";
  if (score >= 30) return "risk-medium";
  return "risk-low";
}

function classify(score) {
  if (score >= 60) return "high";
  if (score >= 30) return "medium";
  return "low";
}

function makeId() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 9);
}

function analyzeText(text) {
  const content = text.trim();
  const lower = content.toLowerCase();
  const findings = [];
  let score = 0;

  if (!content) {
    return {
      score: 0,
      findings: ["Enter some text before running an analysis."]
    };
  }

  const checks = [
    {
      pattern: /\b(urgent|immediately|act now|final warning|within \d+ hours?|expires today)\b/i,
      points: 18,
      message: "Urgent or pressure-based language"
    },
    {
      pattern: /\b(password|passcode|one[- ]time code|otp|verification code|pin number)\b/i,
      points: 20,
      message: "Requests or references to sensitive login codes"
    },
    {
      pattern: /\b(click here|tap here|verify your account|confirm your account|login to|log in to|sign in to)\b/i,
      points: 16,
      message: "Message encourages clicking or signing in"
    },
    {
      pattern: /\b(account (?:will be|has been) (?:blocked|suspended|locked|closed)|account suspension)\b/i,
      points: 22,
      message: "Threat of account suspension or closure"
    },
    {
      pattern: /\b(prize|winner|won|claim your reward|free gift|you have been selected|lottery)\b/i,
      points: 15,
      message: "Unexpected prize or reward language"
    },
    {
      pattern: /\b(send|transfer|pay|deposit|wire)\b.{0,45}\b(money|cash|fee|payment|crypto|cryptocurrency|gift card)\b/i,
      points: 22,
      message: "Potential payment or money-transfer request"
    },
    {
      pattern: /\b(gift card|bitcoin|crypto wallet|recovery phrase|seed phrase)\b/i,
      points: 24,
      message: "Payment or account-recovery method often abused by scammers"
    },
    {
      pattern: /\b(bank account|credit card|debit card|social security|national id|government id)\b/i,
      points: 12,
      message: "Sensitive personal or financial information is mentioned"
    },
    {
      pattern: /\b(keep (?:this|it) secret|don't tell anyone|do not tell anyone|act discreetly)\b/i,
      points: 18,
      message: "Secrecy or isolation language"
    },
    {
      pattern: /\b(refund|delivery failed|parcel held|customs fee|missed delivery)\b/i,
      points: 10,
      message: "Delivery or refund theme that may be used in phishing"
    }
  ];

  for (const check of checks) {
    if (check.pattern.test(content)) {
      findings.push(check.message);
      score += check.points;
    }
  }

  const urls = content.match(/\b(?:https?:\/\/|www\.)[^\s<>"']+/gi) || [];

  if (urls.length) {
    findings.push("Contains one or more links. Check each destination carefully.");
    score += 8;

    for (const rawUrl of urls) {
      const cleaned = rawUrl.replace(/[),.!?;]+$/, "");
      try {
        const parsed = new URL(
          cleaned.startsWith("www.") ? "https://" + cleaned : cleaned
        );

        if (parsed.protocol !== "https:") {
          findings.push("A link uses an unencrypted HTTP connection.");
          score += 12;
        }

        if (parsed.username || parsed.password) {
          findings.push("A link contains unusual embedded login information.");
          score += 20;
        }

        if (parsed.hostname.startsWith("xn--") ||
            parsed.hostname.split(".").some(part => part.startsWith("xn--"))) {
          findings.push("A link uses internationalized domain encoding; verify the domain carefully.");
          score += 12;
        }
      } catch {
        findings.push("A link could not be parsed normally.");
        score += 8;
      }
    }
  }

  if (/\b\d{4,8}\b/.test(content) &&
      /\b(code|otp|pin|password|verify|verification)\b/i.test(content)) {
    findings.push("A numeric code appears alongside authentication language.");
    score += 10;
  }

  score = Math.min(100, score);

  if (!findings.length) {
    findings.push("No common warning patterns were detected by these basic checks.");
  }

  return { score, findings };
}

function analyzeUrlValue(rawValue) {
  const value = rawValue.trim();

  if (!value) {
    return { error: "Please enter a URL." };
  }

  if (/[\s<>"'`\\]/.test(value)) {
    return { error: "The URL contains spaces or characters that are not accepted here. Check your input." };
  }

  if (/^(javascript|data|file|vbscript):/i.test(value)) {
    return {
      score: 100,
      findings: ["This is not a normal web address.", "The URL uses a potentially dangerous or local-only scheme."],
      host: value.split(":")[0],
      displayUrl: value
    };
  }

  let parsed;
  try {
    const normalized = /^[a-z][a-z\d+.-]*:/i.test(value)
      ? value
      : "https://" + value;

    parsed = new URL(normalized);
  } catch {
    return { error: "This does not look like a valid URL. Check the spelling and format." };
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    return { error: "Only HTTP and HTTPS website addresses can be checked." };
  }

  if (!parsed.hostname || !parsed.hostname.includes(".")) {
    return { error: "Enter a full website address, such as example.com." };
  }

  const findings = [];
  let score = 0;
  const host = parsed.hostname.toLowerCase();
  const full = parsed.href.toLowerCase();

  if (parsed.protocol === "http:") {
    findings.push("Uses HTTP rather than HTTPS; traffic may not be encrypted.");
    score += 18;
  } else {
    findings.push("Uses HTTPS, but encryption alone does not prove a website is trustworthy.");
  }

  if (parsed.username || parsed.password) {
    findings.push("Contains user information before the hostname, which can disguise the real destination.");
    score += 25;
  }

  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) {
    findings.push("Uses an IPv4 address instead of a conventional domain name.");
    score += 20;
  }

  if (host.includes("xn--") || host.split(".").some(part => part.startsWith("xn--"))) {
    findings.push("Uses internationalized domain encoding; look out for look-alike characters.");
    score += 18;
  }

  if (host.split(".").length >= 5) {
    findings.push("Has an unusually long chain of subdomains.");
    score += 10;
  }

  const suspiciousTerms = [
    "login", "verify", "secure", "account", "update",
    "password", "wallet", "claim", "prize", "gift",
    "confirm", "billing", "payment"
  ];

  const foundTerms = suspiciousTerms.filter(term =>
    (host + parsed.pathname).includes(term)
  );

  if (foundTerms.length >= 2) {
    findings.push("Contains multiple security-, account-, or reward-related terms in its address.");
    score += 14;
  } else if (foundTerms.length === 1) {
    findings.push("Contains a security-, account-, or reward-related term; this alone is not proof of fraud.");
    score += 5;
  }

  if (host.length > 45) {
    findings.push("The hostname is unusually long.");
    score += 8;
  }

  if (/%[0-9a-f]{2}/i.test(parsed.pathname) && /%40|%2f|%5c/i.test(parsed.pathname)) {
    findings.push("The path contains encoded special characters; inspect the destination carefully.");
    score += 8;
  }

  if (!findings.length) {
    findings.push("No common suspicious URL patterns were detected.");
  }

  return {
    score: Math.min(100, score),
    findings,
    host,
    displayUrl: parsed.href
  };
}

function saveAnalysis(type, original, result) {
  const item = {
    id: makeId(),
    type,
    original: String(original).slice(0, 12000),
    score: result.score,
    risk: classify(result.score),
    findings: result.findings.slice(0, 30),
    date: new Date().toISOString()
  };

  history.unshift(item);
  history = history.slice(0, MAX_HISTORY);
  saveHistory();
  updateDashboard();
  return item;
}

function renderResult(target, type, original, result) {
  if (result.error) {
    target.innerHTML = `
      <div class="result-card">
        <h3>Unable to analyze</h3>
        <p>${escapeHTML(result.error)}</p>
      </div>`;
    return;
  }

  saveAnalysis(type, original, result);

  const findingsHTML = result.findings.map(item =>
    `<li>${escapeHTML(item)}</li>`
  ).join("");

  target.innerHTML = `
    <div class="result-card">
      <div class="result-top">
        <div>
          <h3>${escapeHTML(riskLabel(result.score))}</h3>
          <p>Category: ${escapeHTML(type)}</p>
        </div>
        <span class="risk-pill ${riskClass(result.score)}">${escapeHTML(riskLabel(result.score))}</span>
      </div>
      <div class="score-row">
        <div class="score-track">
          <div class="score-fill" style="width:${result.score}%"></div>
        </div>
        <span class="score-value">${result.score}/100</span>
      </div>
      <h4>Findings</h4>
      <ul class="finding-list">${findingsHTML}</ul>
      <div class="safe-note">
        This score is a heuristic warning indicator, not a verified probability of fraud.
        A low score does not mean the content is safe.
      </div>
      <div class="button-row">
        <button class="secondary-btn" data-copy-result="${escapeHTML(
          type + "\n" + riskLabel(result.score) + " (" + result.score + "/100)\n" +
          result.findings.join("\n")
        )}">Copy results</button>
      </div>
    </div>`;

  updateDashboard();
  renderHistory();
}

function analyzeMessage() {
  const text = $("#messageInput").value;
  if (!text.trim()) {
    showToast("Please enter a message first.");
    $("#messageInput").focus();
    return;
  }

  renderResult($("#messageResult"), "Message", text, analyzeText(text));
}

function analyzeUrl() {
  const text = $("#urlInput").value;
  const result = analyzeUrlValue(text);
  renderResult($("#urlResult"), "URL", text, result);
}

function analyzeOcrText() {
  const text = $("#ocrText").value;
  if (!text.trim()) {
    showToast("Extract or paste some text first.");
    return;
  }

  renderResult($("#ocrResult"), "Screenshot text", text, analyzeText(text));
}

function formatDate(dateString) {
  const date = new Date(dateString);
  if (Number.isNaN(date.getTime())) return "Unknown date";
  return date.toLocaleString();
}

function updateDashboard() {
  $("#statTotal").textContent = history.length;
  $("#statHigh").textContent = history.filter(item => item.risk === "high").length;
  $("#statMessages").textContent = history.filter(item => item.type === "Message" || item.type === "Screenshot text").length;
  $("#statUrls").textContent = history.filter(item => item.type === "URL").length;

  const recent = history.slice(0, 5);

  if (!recent.length) {
    $("#recentActivity").innerHTML = '<div class="empty-state">No analyses yet. Try one of the tools above.</div>';
    return;
  }

  $("#recentActivity").innerHTML = recent.map(item => `
    <div class="activity-row">
      <div>
        <strong>${escapeHTML(item.type)} · ${escapeHTML(riskLabel(item.score))}</strong>
        <small>${escapeHTML(formatDate(item.date))}</small>
      </div>
      <span class="risk-pill ${riskClass(item.score)}">${item.score}/100</span>
    </div>
  `).join("");
}

function renderHistory() {
  const container = $("#historyList");

  if (!history.length) {
    container.innerHTML = '<div class="empty-state">Your saved analyses will appear here.</div>';
    return;
  }

  container.innerHTML = history.map(item => `
    <article class="history-item">
      <div>
        <strong>${escapeHTML(item.type)} · ${escapeHTML(riskLabel(item.score))}</strong>
        <small>${escapeHTML(formatDate(item.date))}</small>
      </div>
      <button class="secondary-btn" data-delete-history="${escapeHTML(item.id)}">Delete</button>
      <div class="history-detail">
        <p>${escapeHTML(item.original.slice(0, 280))}${item.original.length > 280 ? "…" : ""}</p>
        <span class="risk-pill ${riskClass(item.score)}">${item.score}/100</span>
        <ul class="finding-list">${item.findings.map(f => `<li>${escapeHTML(f)}</li>`).join("")}</ul>
      </div>
    </article>
  `).join("");
}

function exportCSV() {
  if (!history.length) {
    showToast("There is no history to export.");
    return;
  }

  const columns = ["Date", "Type", "Risk", "Score", "Original text", "Findings"];

  const csvCell = value => '"' + String(value ?? "").replace(/"/g, '""') + '"';

  const rows = history.map(item => [
    item.date,
    item.type,
    item.risk,
    item.score,
    item.original,
    item.findings.join(" | ")
  ]);

  const csv = "\uFEFF" + [columns, ...rows].map(row =>
    row.map(csvCell).join(",")
  ).join("\r\n");

  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");

  link.href = url;
  link.download = "proofcheck-history.csv";
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);

  showToast("History export started.");
}

function showPage(pageId) {
  const page = document.getElementById(pageId);
  if (!page || !page.classList.contains("page")) return;

  document.querySelectorAll(".page").forEach(el => el.classList.remove("active"));
  page.classList.add("active");

  document.querySelectorAll(".nav-link").forEach(button => {
    button.classList.toggle("active", button.dataset.page === pageId);
  });

  $("#navigation").classList.remove("open");

  if (pageId === "history") renderHistory();
  if (pageId === "dashboard") updateDashboard();

  window.scrollTo({ top: 0, behavior: "smooth" });
}

function clearImage() {
  selectedImage = null;
  $("#imageInput").value = "";
  $("#imagePreview").src = "";
  $("#imagePreview").classList.add("hidden");
  $("#ocrText").value = "";
  $("#ocrStatus").textContent = "OCR requires an internet connection to load its text-recognition library.";
  $("#ocrProgress").classList.add("hidden");
  $("#ocrProgressBar").style.width = "0%";
  $("#ocrResult").innerHTML = "";
}

async function extractAndAnalyze() {
  if (ocrBusy) return;

  if (!selectedImage) {
    showToast("Please choose an image first.");
    return;
  }

  if (!window.Tesseract || typeof window.Tesseract.recognize !== "function") {
    showToast("OCR library did not load. Check your internet connection and reload the page.");
    $("#ocrStatus").textContent = "OCR library unavailable. You can still paste text below and analyze it.";
    return;
  }

  ocrBusy = true;
  $("#extractText").disabled = true;
  $("#extractText").textContent = "Processing…";
  $("#ocrProgress").classList.remove("hidden");
  $("#ocrStatus").textContent = "Recognizing text in your image…";

  try {
    const result = await window.Tesseract.recognize(
      selectedImage,
      "eng",
      {
        logger: message => {
          if (typeof message.progress === "number") {
            const percent = Math.round(message.progress * 100);
            $("#ocrProgressBar").style.width = percent + "%";
            $("#ocrStatus").textContent =
              "OCR processing: " + percent + "%";
          }
        }
      }
    );

    const text = result.data && result.data.text
      ? result.data.text.trim()
      : "";

    $("#ocrText").value = text;
    $("#ocrProgressBar").style.width = "100%";

    if (!text) {
      $("#ocrStatus").textContent = "No readable text found. Try a clearer screenshot.";
      showToast("No readable text found.");
      return;
    }

    $("#ocrStatus").textContent = "Text extraction completed.";
    renderResult($("#ocrResult"), "Screenshot text", text, analyzeText(text));
    showToast("Screenshot text extracted and analyzed.");
  } catch (error) {
    console.error("OCR error:", error);
    $("#ocrStatus").textContent = "Text extraction failed. Check your internet connection or try another image.";
    showToast("OCR failed. You can paste text manually.");
  } finally {
    ocrBusy = false;
    $("#extractText").disabled = false;
    $("#extractText").textContent = "Extract and analyze text";
  }
}

/* Navigation */
document.querySelectorAll("[data-page]").forEach(button => {
  button.addEventListener("click", event => {
    event.preventDefault();
    showPage(button.dataset.page);
  });
});

document.querySelectorAll("[data-go]").forEach(button => {
  button.addEventListener("click", () => showPage(button.dataset.go));
});

$("#menuToggle").addEventListener("click", () => {
  $("#navigation").classList.toggle("open");
});

/* Message analyzer */
$("#analyzeMessage").addEventListener("click", analyzeMessage);
$("#clearMessage").addEventListener("click", () => {
  $("#messageInput").value = "";
  $("#messageResult").innerHTML = "";
  $("#messageCount").textContent = "0 characters";
});

$("#messageInput").addEventListener("input", () => {
  $("#messageCount").textContent =
    $("#messageInput").value.length + " characters";
});

/* URL checker */
$("#analyzeUrl").addEventListener("click", analyzeUrl);
$("#urlInput").addEventListener("keydown", event => {
  if (event.key === "Enter") analyzeUrl();
});

/* Screenshot OCR */
$("#imageInput").addEventListener("change", event => {
  const file = event.target.files && event.target.files[0];
  if (!file) return;

  const allowedTypes = ["image/jpeg", "image/png", "image/webp"];

  if (!allowedTypes.includes(file.type)) {
    showToast("Choose a JPG, PNG, or WEBP image.");
    event.target.value = "";
    return;
  }

  if (file.size > 10 * 1024 * 1024) {
    showToast("Please choose an image smaller than 10 MB.");
    event.target.value = "";
    return;
  }

  if (selectedImage && selectedImage.startsWith("blob:")) {
    URL.revokeObjectURL(selectedImage);
  }

  selectedImage = URL.createObjectURL(file);
  $("#imagePreview").src = selectedImage;
  $("#imagePreview").classList.remove("hidden");
  $("#ocrText").value = "";
  $("#ocrResult").innerHTML = "";
  $("#ocrStatus").textContent = "Image selected. Press the button to extract text.";
});

$("#extractText").addEventListener("click", extractAndAnalyze);
$("#clearImage").addEventListener("click", clearImage);
$("#analyzeOcrText").addEventListener("click", analyzeOcrText);

/* History and export */
$("#exportHistory").addEventListener("click", exportCSV);

$("#clearHistory").addEventListener("click", () => {
  if (!history.length) {
    showToast("History is already empty.");
    return;
  }

  if (!confirm("Delete all saved analysis history on this device?")) return;

  history = [];
  saveHistory();
  renderHistory();
  updateDashboard();
  showToast("History cleared.");
});

/* Handle dynamically created buttons safely */
document.addEventListener("click", async event => {
  const copyButton = event.target.closest("[data-copy-result]");

  if (copyButton) {
    const text = copyButton.getAttribute("data-copy-result") || "";

    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
      } else {
        const area = document.createElement("textarea");
        area.value = text;
        area.style.position = "fixed";
        area.style.opacity = "0";
        document.body.appendChild(area);
        area.select();
        const copied = document.execCommand("copy");
        area.remove();

        if (!copied) throw new Error("Copy failed");
      }

      showToast("Results copied.");
    } catch {
      showToast("Copy failed. Please select and copy the results manually.");
    }
    return;
  }
  const deleteButton = event.target.closest("[data-delete-history]");

  if (deleteButton) {
    const id = deleteButton.getAttribute("data-delete-history");
    history = history.filter(item => item.id !== id);
    saveHistory();
    renderHistory();
    updateDashboard();
    showToast("Analysis deleted.");
  }
});

/* Initial screen */
updateDashboard();
renderHistory();
showPage("dashboard");
