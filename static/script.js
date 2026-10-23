async function postJSON(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  return res.json();
}

async function getJSON(url) {
  const res = await fetch(url);
  return res.json();
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/* ---------------- Eve: simulated Wi-Fi / MITM packet sniffer ----------------
   This does not actually sniff a network interface — it logs the exact JSON
   bytes each panel sends over the wire, at the moment they're sent, before
   any reply comes back. That's the honest point: if Eve genuinely sat on
   the Wi-Fi between browser and server, this is byte-for-byte what she'd see
   in the request body, nothing more, nothing less. */

let eveSniffing = false;
const eveToggle = document.getElementById("eve-toggle");
const eveLog = document.getElementById("eve-log");

function logPacket(panel, route, payload, danger) {
  if (!eveSniffing) return;
  const time = new Date().toLocaleTimeString([], { hour12: false });
  const row = document.createElement("div");
  row.className = "eve-packet" + (danger ? " eve-packet--danger" : " eve-packet--safe");
  row.innerHTML = `
    <div class="eve-packet-head">
      <span class="eve-time">${time}</span>
      <span class="eve-panel">${panel}</span>
      <span class="eve-route">${route}</span>
      <span class="eve-flag">${danger ? "🔓 USABLE SECRET" : "🔒 useless alone"}</span>
    </div>
    <pre class="eve-payload">${JSON.stringify(payload, null, 0)}</pre>
  `;
  eveLog.prepend(row);
}

eveToggle.addEventListener("click", () => {
  eveSniffing = !eveSniffing;
  if (eveSniffing) {
    eveToggle.textContent = "🔴 Eve is listening on the Wi-Fi — click to stop";
    eveToggle.classList.add("active");
    eveLog.innerHTML = `<p class="hint">Listening… use either login box above and watch what crosses the wire.</p>`;
  } else {
    eveToggle.textContent = "🕵️ Simulate a Wi-Fi / MITM interception (start Eve)";
    eveToggle.classList.remove("active");
  }
});

/* ---------------- Schnorr ZKP math ----------------
   P, G, Q, modPow, randBelow, sha256Hex etc. now live in zkp-core.js
   (loaded before this file) so every panel — password, biometric, age —
   shares one implementation. Thin aliases below keep this file's existing
   call sites unchanged. */

const P = ZKP_P, G = ZKP_G, Q = ZKP_Q;
const modPow = zkpModPow, randBelow = zkpRandBelow, short = zkpShort;
const deriveSecretX = (username, password) => zkpDeriveSecretX(username, password);

/* ---------------- Traditional panel ---------------- */

const tradForm = document.getElementById("trad-register");
const breachBtn = document.getElementById("breach-btn");
const breachLog = document.getElementById("breach-log");
let tradUsername = null;

tradForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(tradForm);
  const username = fd.get("username");
  const password = fd.get("password");

  // This IS the vulnerability, made visible: the server hashes server-side,
  // so the plaintext password has to travel over the network to get there.
  // Hashing protects the database at rest. It does nothing for the wire.
  logPacket("traditional", "POST /api/traditional/register", { username, password }, true);

  const data = await postJSON("/api/traditional/register", { username, password });
  tradUsername = data.username;
  document.getElementById("trad-db-user").textContent = data.username;
  document.getElementById("trad-db-hash").textContent = data.hash;
  breachBtn.disabled = false;
  breachLog.innerHTML = `<p class="hint">Account stored. Hit "Simulate GPU breach" to attack the hash above.</p>`;
});

breachBtn.addEventListener("click", async () => {
  if (!tradUsername) return;
  breachBtn.disabled = true;
  breachLog.innerHTML = `<p class="cracking">brute-forcing lowercase keyspace (1, 2, 3… chars) against the MD5 hash…</p>`;

  const started = await postJSON("/api/traditional/breach/start", { username: tradUsername });
  if (started.error) {
    breachLog.innerHTML = `<p class="hint">${started.error}</p>`;
    breachBtn.disabled = false;
    return;
  }

  let data;
  while (true) {
    await sleep(250);
    data = await getJSON(`/api/traditional/breach/status?username=${encodeURIComponent(tradUsername)}`);
    if (data.error) {
      breachLog.innerHTML = `<p class="hint">${data.error}</p>`;
      breachBtn.disabled = false;
      return;
    }
    breachLog.innerHTML = `<p class="cracking">trying ${data.current_length}-char lowercase combinations… ${data.attempts.toLocaleString()} guesses in ${data.elapsed_seconds}s</p>`;
    if (data.done) break;
  }

  if (data.found) {
    breachLog.innerHTML = `
      <p class="result-found">CRACKED → "${data.found}"</p>
      <p class="stat-line">${data.attempts.toLocaleString()} guesses · ${data.elapsed_seconds}s on one CPU core</p>
      <p class="stat-line">A single consumer GPU does this keyspace in well under a millisecond — and a full 8-character keyspace in hours, against this same unsalted hash.</p>
    `;
  } else {
    breachLog.innerHTML = `
      <p class="result-safe">Not found within ${data.time_budget_seconds}s (reached ${data.final_length}-char lowercase combinations)</p>
      <p class="stat-line">${data.attempts.toLocaleString()} guesses exhausted in ${data.elapsed_seconds}s — your password is outside what this laptop can search in a live demo window.</p>
      <p class="stat-line">That's not the hash protecting you — it's that this laptop only had ${data.time_budget_seconds} seconds. Scale the hardware, not the demo, and this bar moves a lot. The password still has to be typed into a form, hashed, and stored somewhere. The right panel removes that requirement entirely.</p>
    `;
  }
  breachBtn.disabled = false;
});

/* ---------------- ZKP panel ---------------- */

const zkpRegisterForm = document.getElementById("zkp-register");
const zkpLoginForm = document.getElementById("zkp-login");
const zkpLoginBtn = document.getElementById("zkp-login-btn");
let zkpUsername = null;

zkpRegisterForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(zkpRegisterForm);
  const username = fd.get("username");
  const password = fd.get("password");

  // x and password stay in this tab forever. Only the public verifier y
  // crosses the wire — and y alone can't be reversed back into x (that's
  // the discrete-log problem the whole scheme leans on).
  const x = await deriveSecretX(username, password);
  const y = modPow(G, x, P);

  logPacket("zkp", "POST /api/zkp/register", { username, y: short(y) }, false);

  const data = await postJSON("/api/zkp/register", { username, y: y.toString(16) });
  zkpUsername = data.username;
  document.getElementById("zkp-db-user").textContent = data.username;
  document.getElementById("zkp-db-verifier").textContent = data.public_verifier;
  zkpLoginBtn.disabled = false;
});

zkpLoginForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!zkpUsername) return;
  const fd = new FormData(zkpLoginForm);
  const username = zkpUsername;
  const password = fd.get("password");

  // Step 1: commit. x derived locally, r is a fresh one-time secret nonce,
  // t = g^r mod p is sent — it reveals nothing about r or x.
  const x = await deriveSecretX(username, password);
  const r = randBelow(Q - 1n) + 1n;
  const t = modPow(G, r, P);

  logPacket("zkp", "POST /api/zkp/login/commit", { username, t: short(t) }, false);
  const commit = await postJSON("/api/zkp/login/commit", { username, t: t.toString(16) });
  if (commit.error) {
    document.getElementById("zkp-verdict").textContent = commit.error;
    document.getElementById("zkp-verdict").className = "intercept-verdict fail";
    return;
  }
  const c = BigInt(commit.challenge_c); // server already sends it 0x-prefixed via hex()
  document.getElementById("zkp-challenge").textContent = short(c);

  // Step 2: respond. s mixes the one-time r with x and the server's fresh
  // random challenge c. Record it, replay it later — c will never repeat,
  // so the same (t, s) pair verifies against nothing next time.
  const s = (r + c * x) % Q;
  logPacket("zkp", "POST /api/zkp/login/respond", { s: short(s) }, false);
  const result = await postJSON("/api/zkp/login/respond", { s: s.toString(16) });
  document.getElementById("zkp-proof").textContent = short(s);

  const verdictEl = document.getElementById("zkp-verdict");
  if (result.valid) {
    verdictEl.textContent = "✓ proof verified — password never left the browser";
    verdictEl.className = "intercept-verdict ok";
  } else {
    verdictEl.textContent = "✗ proof failed — wrong password";
    verdictEl.className = "intercept-verdict fail";
  }
  zkpLoginForm.reset();
});
