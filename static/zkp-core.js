/* ---------------------------------------------------------------------------
 * Shared Schnorr zero-knowledge math, used by every panel on this site
 * (password-proof, biometric-proof, age-proof). Mirrors the server's group
 * (P, G, Q = (P-1)/2) defined in app.py. Nothing in this file ever talks to
 * the network — it only derives secrets and does modular arithmetic in the
 * browser so those secrets never have to leave it.
 * ------------------------------------------------------------------------- */

const ZKP_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFFn;
const ZKP_G = 2n;
const ZKP_Q = (ZKP_P - 1n) / 2n;

/* Pure-JS SHA-256 (FIPS 180-4) — deliberately NOT using crypto.subtle.digest.
 * SubtleCrypto only works in a "secure context" (https:, or the special-
 * cased http://localhost/127.0.0.1) — any other plain http:// origin,
 * including the LAN IP a phone needs to scan the KYC wallet's QR code at
 * all, leaves crypto.subtle undefined. crypto.getRandomValues has no such
 * restriction, so only hashing needed a fallback. Verified against known
 * SHA-256 test vectors (empty string, "abc", a 1000-byte input) before use. */
function zkpSha256Bytes(bytes) {
  const K = new Uint32Array([
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
  ]);
  let h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a,h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;

  const rotr = (x, n) => ((x >>> n) | (x << (32 - n))) >>> 0;

  const bitLen = bytes.length * 8;
  const padLen = (bytes.length + 1 + 8 + 63) & ~63;
  const msg = new Uint8Array(padLen);
  msg.set(bytes);
  msg[bytes.length] = 0x80;
  const dv = new DataView(msg.buffer);
  dv.setUint32(padLen - 4, bitLen >>> 0, false);
  dv.setUint32(padLen - 8, Math.floor(bitLen / 0x100000000), false);

  const w = new Uint32Array(64);
  for (let chunkStart = 0; chunkStart < padLen; chunkStart += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(chunkStart + i * 4, false);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >>> 3);
      const s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2] >>> 10);
      w[i] = (w[i-16] + s0 + w[i-7] + s1) >>> 0;
    }
    let a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
      const S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;
      h=g; g=f; f=e; e=(d+temp1)>>>0; d=c; c=b; b=a; a=(temp1+temp2)>>>0;
    }
    h0=(h0+a)>>>0; h1=(h1+b)>>>0; h2=(h2+c)>>>0; h3=(h3+d)>>>0;
    h4=(h4+e)>>>0; h5=(h5+f)>>>0; h6=(h6+g)>>>0; h7=(h7+h)>>>0;
  }

  const out = new Uint8Array(32);
  const outDv = new DataView(out.buffer);
  [h0,h1,h2,h3,h4,h5,h6,h7].forEach((h, i) => outDv.setUint32(i * 4, h, false));
  return out;
}

async function zkpSha256Hex(str) {
  return [...zkpSha256Bytes(new TextEncoder().encode(str))].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function zkpSha256HexBytes(bytes) {
  return [...zkpSha256Bytes(new Uint8Array(bytes))].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function zkpModPow(base, exp, mod) {
  base = ((base % mod) + mod) % mod;
  let result = 1n;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}

// Uniform random BigInt in [0, n-1] using the browser's CSPRNG.
function zkpRandBelow(n) {
  const bits = n.toString(2).length;
  const bytes = Math.ceil(bits / 8);
  const excess = BigInt(bytes * 8) - BigInt(bits);
  let r;
  do {
    const arr = new Uint8Array(bytes);
    crypto.getRandomValues(arr);
    r = 0n;
    for (const b of arr) r = (r << 8n) | BigInt(b);
    r >>= excess;
  } while (r >= n);
  return r;
}

function zkpShort(bigint) {
  const hex = bigint.toString(16);
  return "0x" + hex.slice(0, 20) + (hex.length > 20 ? "…" : "");
}

// Derives a secret exponent x (mod Q) from an arbitrary string — the same
// construction the password panel uses (SHA-256 of a salted string, reduced
// mod Q). Anything can go in: a password, a face-frame digest, a DOB claim.
async function zkpDeriveSecretX(...parts) {
  const hex = await zkpSha256Hex(parts.join("||"));
  return BigInt("0x" + hex) % ZKP_Q;
}

// One full "prove you hold secret x behind public commitment y" round,
// entirely client-side except the two network hops to fetch a fresh
// challenge and submit the response. Reuses whatever /commit + /respond
// route pair you point it at.
async function zkpProve(x, commitUrl, commitBody, respondUrl) {
  const r = zkpRandBelow(ZKP_Q - 1n) + 1n;
  const t = zkpModPow(ZKP_G, r, ZKP_P);

  const commit = await fetch(commitUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ...commitBody, t: t.toString(16) }),
  }).then((res) => res.json());

  if (commit.error) return { error: commit.error };

  const c = BigInt(commit.challenge_c);
  const s = (r + c * x) % ZKP_Q;

  const result = await fetch(respondUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ s: s.toString(16) }),
  }).then((res) => res.json());

  return { t, c, s, ...result };
}
