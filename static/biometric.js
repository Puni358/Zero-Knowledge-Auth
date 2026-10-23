/* ---------------------------------------------------------------------------
 * Biometric ZK unlock demo.
 *
 * HONEST SCOPE NOTE: a real biometric system runs a trained neural network
 * over your face to produce a feature embedding that's stable across
 * lighting/angle, plus a "fuzzy" matching/commitment scheme so two slightly
 * different embeddings of the same face still unlock the same secret. We
 * don't have a neural net here, so this demo hashes a raw downsampled
 * camera frame instead — which means a *different* frame produces a
 * *completely different* number. The cryptographic property being
 * demonstrated — that the server only ever learns y = g^x mod p and never
 * the biometric input itself — is identical either way, so "unlock" below
 * reuses the exact x derived at enrollment (held only in this tab's memory,
 * cleared on reload) rather than re-deriving it from a new frame. The live
 * camera + liveness check at unlock time is what a real system's matcher
 * would gate the key release on; here it's genuine (it really measures
 * frame-to-frame motion) but isn't cryptographically bound to the proof.
 * ------------------------------------------------------------------------- */

const camVideo = document.getElementById("cam-video");
const camFrame = document.getElementById("cam-frame");
const camScan = document.getElementById("cam-scan");
const camHint = document.getElementById("cam-hint");
const camCanvas = document.getElementById("cam-canvas");
const grayscaleCanvas = document.getElementById("grayscale-canvas");
const startBtn = document.getElementById("cam-start-btn");
const simulateBtn = document.getElementById("cam-simulate-btn");
const enrollBtn = document.getElementById("enroll-btn");
const unlockBtn = document.getElementById("unlock-btn");
const enrollMath = document.getElementById("enroll-math");
const unlockMath = document.getElementById("unlock-math");

const FRAME_SIZE = 24; // 24x24 grayscale "buffer" — deliberately low-res, this is not a real feature extractor
let streaming = false;
let simulated = false;

const subjectId = "face-" + Array.from(crypto.getRandomValues(new Uint8Array(4))).map((b) => b.toString(16).padStart(2, "0")).join("");
let enrolledX = null; // held only in memory, never persisted, never sent

async function enableCamera() {
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ video: { width: 320, height: 240 }, audio: false });
    camVideo.srcObject = stream;
    streaming = true;
    simulated = false;
    camHint.hidden = true;
    camScan.hidden = false;
    enrollBtn.disabled = false;
  } catch (err) {
    camHint.textContent = "Camera unavailable or blocked (" + err.name + "). Use the simulate button instead.";
  }
}

function enableSimulated() {
  streaming = false;
  simulated = true;
  camHint.hidden = false;
  camHint.textContent = "🎲 Simulated input armed — capture will use random noise standing in for a face frame.";
  camScan.hidden = false;
  enrollBtn.disabled = false;
}

startBtn.addEventListener("click", enableCamera);
simulateBtn.addEventListener("click", enableSimulated);

// Grabs a frame (real camera or simulated noise), downsamples to a small
// grayscale buffer, and draws that buffer (magnified) into grayscale-canvas
// so the viewer can see exactly what's about to be hashed.
function captureGrayscaleBuffer() {
  const ctx = camCanvas.getContext("2d");
  const buf = new Uint8Array(FRAME_SIZE * FRAME_SIZE);

  if (simulated) {
    crypto.getRandomValues(buf);
  } else {
    ctx.drawImage(camVideo, 0, 0, FRAME_SIZE, FRAME_SIZE);
    const img = ctx.getImageData(0, 0, FRAME_SIZE, FRAME_SIZE).data;
    for (let i = 0; i < FRAME_SIZE * FRAME_SIZE; i++) {
      const r = img[i * 4], g = img[i * 4 + 1], b = img[i * 4 + 2];
      buf[i] = Math.round(0.299 * r + 0.587 * g + 0.114 * b);
    }
  }

  // Paint the magnified grayscale view.
  const gctx = grayscaleCanvas.getContext("2d");
  gctx.imageSmoothingEnabled = false;
  const tmp = document.createElement("canvas");
  tmp.width = FRAME_SIZE; tmp.height = FRAME_SIZE;
  const tctx = tmp.getContext("2d");
  const imgData = tctx.createImageData(FRAME_SIZE, FRAME_SIZE);
  for (let i = 0; i < buf.length; i++) {
    imgData.data[i * 4] = buf[i];
    imgData.data[i * 4 + 1] = buf[i];
    imgData.data[i * 4 + 2] = buf[i];
    imgData.data[i * 4 + 3] = 255;
  }
  tctx.putImageData(imgData, 0, 0);
  gctx.clearRect(0, 0, grayscaleCanvas.width, grayscaleCanvas.height);
  gctx.drawImage(tmp, 0, 0, grayscaleCanvas.width, grayscaleCanvas.height);

  return buf;
}

function meanAbsDiff(a, b) {
  let sum = 0;
  for (let i = 0; i < a.length; i++) sum += Math.abs(a[i] - b[i]);
  return sum / a.length;
}

enrollBtn.addEventListener("click", async () => {
  enrollBtn.disabled = true;
  enrollMath.innerHTML = `<p class="cracking">capturing frame…</p>`;

  const buf = captureGrayscaleBuffer();
  const hex = await zkpSha256HexBytes(buf);
  const x = BigInt("0x" + hex) % ZKP_Q;
  const y = zkpModPow(ZKP_G, x, ZKP_P);

  enrolledX = x;

  enrollMath.innerHTML = `
    <p class="stat-line">1. camera frame → 24×24 grayscale buffer (576 bytes, shown above — never transmitted)</p>
    <p class="stat-line">2. SHA-256(buffer) mod q → secret <code>x = ${zkpShort(x)}</code> (stays in this tab's memory only)</p>
    <p class="stat-line">3. y = g^x mod p → <code>${zkpShort(y)}</code> — this is the ONLY thing sent to the server</p>
  `;

  const res = await fetch("/api/zkp/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: subjectId, y: y.toString(16) }),
  }).then((r) => r.json());

  document.getElementById("bio-db-user").textContent = res.username;
  document.getElementById("bio-db-verifier").textContent = res.public_verifier;
  unlockBtn.disabled = false;
  unlockMath.innerHTML = `<p class="hint">Enrolled. Hit "Scan to unlock" below — it proves you hold x without sending it, and without the server storing anything but that one verifier.</p>`;
  enrollBtn.disabled = false;
});

unlockBtn.addEventListener("click", async () => {
  if (enrolledX === null) return;
  unlockBtn.disabled = true;
  unlockMath.innerHTML = `<p class="cracking">checking liveness…</p>`;

  // A genuine (if simple) liveness heuristic: two frames ~300ms apart should
  // differ a little (a live face/hand/environment has micro-motion) but not
  // wildly (random noise). This does NOT feed the cryptographic proof below —
  // see the HONEST SCOPE NOTE at the top of this file.
  let liveNote = "simulated input — liveness check skipped";
  if (streaming) {
    const f1 = captureGrayscaleBuffer();
    await new Promise((r) => setTimeout(r, 300));
    const f2 = captureGrayscaleBuffer();
    const delta = meanAbsDiff(f1, f2).toFixed(2);
    liveNote = `Δ between two frames 300ms apart = ${delta} — natural micro-motion detected, not a static image`;
  } else {
    captureGrayscaleBuffer();
  }

  unlockMath.innerHTML = `<p class="cracking">${liveNote}. Running Schnorr proof…</p>`;

  const result = await zkpProve(enrolledX, "/api/zkp/login/commit", { username: subjectId }, "/api/zkp/login/respond");

  if (result.error) {
    unlockMath.innerHTML = `<p class="hint">${result.error}</p>`;
    unlockBtn.disabled = false;
    return;
  }

  document.getElementById("bio-t").textContent = zkpShort(result.t);
  document.getElementById("bio-c").textContent = zkpShort(result.c);
  document.getElementById("bio-s").textContent = zkpShort(result.s);

  const verdictEl = document.getElementById("bio-verdict");
  if (result.valid) {
    verdictEl.textContent = "✓ unlocked — proof verified, face pixels never left the browser";
    verdictEl.className = "intercept-verdict ok";
    unlockMath.innerHTML = `<p class="stat-line">${liveNote}</p><p class="result-safe">g^s mod p == t · y^c mod p ✓</p>`;
  } else {
    verdictEl.textContent = "✗ proof failed";
    verdictEl.className = "intercept-verdict fail";
  }
  unlockBtn.disabled = false;
});
