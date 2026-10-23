let sessionId = null;
let polling = null;

const qrImg = document.getElementById("qr-img");
const qrCaption = document.getElementById("qr-caption");
const walletLink = document.getElementById("wallet-link");
const portalStatus = document.getElementById("portal-status");
const resetBtn = document.getElementById("portal-reset-btn");
const pendingPanel = document.getElementById("portal-pending");
const resultPanel = document.getElementById("portal-result");
const againBtn = document.getElementById("portal-again-btn");

async function startSession() {
  if (polling) clearInterval(polling);
  resultPanel.hidden = true;
  pendingPanel.hidden = false;
  resetBtn.hidden = true;
  qrCaption.textContent = "Generating session…";
  portalStatus.innerHTML = `<p class="hint">Waiting for a proof from your phone…</p>`;

  const res = await fetch("/api/portal/session/new", { method: "POST" }).then((r) => r.json());
  sessionId = res.session_id;
  qrImg.src = `/api/portal/qr/${sessionId}`;
  walletLink.href = res.wallet_url;
  qrCaption.textContent = `Session ${sessionId} — ${res.wallet_url}`;

  polling = setInterval(pollStatus, 1000);
}

async function pollStatus() {
  if (!sessionId) return;
  const status = await fetch(`/api/portal/session/${sessionId}/status`).then((r) => r.json());

  if (status.status === "pending" || status.status === "unknown") return;

  clearInterval(polling);
  renderResult(status);
}

function renderResult(status) {
  pendingPanel.hidden = true;
  resultPanel.hidden = false;

  const titleEl = document.getElementById("result-title");
  const tagEl = document.getElementById("result-tag");
  const verdictEl = document.getElementById("verdict-big");
  const mathEl = document.getElementById("result-math");
  const yEl = document.getElementById("field-y");

  if (status.status === "verified") {
    titleEl.textContent = "✅ Trading account opened";
    tagEl.textContent = "a fresh, live Schnorr proof checked out";
    verdictEl.textContent = "KYC_Verified: TRUE";
    verdictEl.className = "verdict-big verdict-ok";
  } else {
    titleEl.textContent = "⚠️ Verification failed";
    tagEl.textContent = "the presented proof did not check out";
    verdictEl.textContent = "INVALID PROOF";
    verdictEl.className = "verdict-big verdict-fail";
  }

  const short = (hex) => (hex ? hex.slice(0, 22) + "…" : "—");
  mathEl.innerHTML = `
    <p class="stat-line">commitment (t) received: <code>${short(status.t)}</code></p>
    <p class="stat-line">challenge (c) this server issued: <code>${short(status.c)}</code></p>
    <p class="stat-line">response (s) received: <code>${short(status.s)}</code></p>
    <p class="${status.status === "verified" ? "result-safe" : "hint"}">g^s mod p ${status.status === "verified" ? "==" : "!="} t · y^c mod p</p>
  `;
  yEl.textContent = short(status.y);

  resetBtn.hidden = false;
}

resetBtn.addEventListener("click", startSession);
againBtn.addEventListener("click", startSession);

startSession();
