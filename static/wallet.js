/* ---------------------------------------------------------------------------
 * KYC wallet (phone side). Same honest-scope idea as biometric.js: the PAN
 * card photo is read and hashed entirely in this tab — SHA-256(image bytes)
 * mod q becomes a secret x, exactly the way a face frame becomes one on the
 * biometric page. The image itself never touches fetch(). Only y = g^x
 * (at registration) and then a fresh (t, c, s) Schnorr proof per approval
 * ever cross the network.
 * ------------------------------------------------------------------------- */

const sessionId = new URLSearchParams(location.search).get("session");
const username = "kyc:" + (sessionId || "no-session");

const walletSession = document.getElementById("wallet-session");
const panFile = document.getElementById("pan-file");
const panUploadLabel = document.getElementById("pan-upload-label");
const panPreview = document.getElementById("pan-preview");
const panHashRow = document.getElementById("pan-hash-row");
const panHashEl = document.getElementById("pan-hash");
const panUploadNote = document.getElementById("pan-upload-note");
const proveBtn = document.getElementById("prove-btn");
const proveMath = document.getElementById("prove-math");
const interceptBox = document.getElementById("wallet-intercept");

let panX = null; // secret derived from the PAN photo — stays in this tab's memory only

if (sessionId) {
  walletSession.textContent = `Presenting KYC proof to trading platform session: ${sessionId}`;
} else {
  walletSession.textContent = "⚠️ No trading platform session in this URL — open this page by scanning a platform's QR code.";
}

// The PAN image never crosses the network. This handler reads it, hashes
// it, shows a local preview + the hash, and discards the file object —
// there is no upload call anywhere in this file.
panFile.addEventListener("change", async () => {
  const file = panFile.files[0];
  if (!file) return;

  const objectUrl = URL.createObjectURL(file);
  panPreview.src = objectUrl;
  panPreview.hidden = false;
  panUploadLabel.innerHTML = `📎 ${file.name}`;

  const buf = await file.arrayBuffer();
  const hex = await zkpSha256HexBytes(buf);
  panX = BigInt("0x" + hex) % ZKP_Q;

  panHashEl.textContent = "0x" + hex.slice(0, 32) + "…";
  panHashRow.hidden = false;
  panUploadNote.hidden = false;

  proveBtn.disabled = !sessionId;
  proveBtn.textContent = "✅ Approve & present KYC proof";
  proveMath.innerHTML = `<p class="hint">Ready. Tap approve to register your commitment and run a live Schnorr proof.</p>`;
});

proveBtn.addEventListener("click", async () => {
  if (panX === null || !sessionId) return;
  proveBtn.disabled = true;
  proveMath.innerHTML = `<p class="cracking">registering commitment…</p>`;

  const y = zkpModPow(ZKP_G, panX, ZKP_P);

  await fetch("/api/zkp/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, y: y.toString(16) }),
  }).then((r) => r.json());

  proveMath.innerHTML = `
    <p class="stat-line">1. PAN photo (never transmitted) → SHA-256 → secret <code>x = ${zkpShort(panX)}</code> (stays on this phone)</p>
    <p class="stat-line">2. y = g^x mod p → <code>${zkpShort(y)}</code> — registered with the platform</p>
    <p class="cracking">running live proof…</p>
  `;

  const result = await zkpProve(panX, "/api/zkp/login/commit", { username }, "/api/zkp/login/respond");

  if (result.error) {
    proveMath.innerHTML += `<p class="hint">${result.error}</p>`;
    proveBtn.disabled = false;
    return;
  }

  interceptBox.hidden = false;
  document.getElementById("w-t").textContent = zkpShort(result.t);
  document.getElementById("w-c").textContent = zkpShort(result.c);
  document.getElementById("w-s").textContent = zkpShort(result.s);

  const verdictEl = document.getElementById("w-verdict");
  if (result.valid) {
    verdictEl.textContent = "✓ proof sent — the platform now knows you hold a PAN photo, nothing else";
    verdictEl.className = "intercept-verdict ok";
    proveMath.innerHTML += `<p class="result-safe">g^s mod p == t · y^c mod p ✓ — check the platform's screen, it should update now.</p>`;
    proveBtn.textContent = "✅ Proof sent — you can close this tab";
  } else {
    verdictEl.textContent = "✗ proof failed";
    verdictEl.className = "intercept-verdict fail";
    proveBtn.disabled = false;
  }
});
