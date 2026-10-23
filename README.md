# Zero-Knowledge Auth — live demo suite

A localhost Flask app with four side-by-side demos for a hackathon judging
table, built to show *exactly* what a server needs to know about you — and
what it doesn't. Nothing here is a mockup: every proof, hash, and brute
force is computed live, in the open, in code any judge can read.

## Run it

```
pip install -r requirements.txt
python3 app.py
```

Open **http://127.0.0.1:5000** in a browser. The startup line also prints a
LAN address (e.g. `http://192.168.1.6:5000`) — use that one on a phone for
the KYC-gate demo. No internet connection is needed once the two packages
in `requirements.txt` are installed; everything runs fully offline at the
venue, phone included, as long as the phone and the laptop share a network
(same Wi-Fi, a hotspot from either device, or Bluetooth tethering).

## Project structure

```
app.py                  all server-side logic — every route, the brute
                         force, the Schnorr math, the QR/session wiring —
                         in one file, deliberately not obfuscated or split
                         up, so it's easy to read top to bottom
requirements.txt        Flask + qrcode, nothing else
templates/
  index.html             demo 1: password hash+breach vs. Schnorr ZKP
  biometric.html          demo 2: webcam face capture -> ZK unlock
  portal.html              demo 3: trading platform KYC gate (desktop side)
  wallet.html               demo 3: phone wallet (scanned via QR)
static/
  zkp-core.js            shared math: pure-JS SHA-256, modular exponentiation,
                         CSPRNG nonce generation, the generic Schnorr
                         commit/respond helper — used by every panel below
  script.js              demo 1 (password + breach + the "Eve" Wi-Fi sniffer)
  biometric.js            demo 2
  portal.js                demo 3 (desktop)
  wallet.js                 demo 3 (phone)
  style.css               one shared stylesheet, no external fonts/CDNs
```

## The four demos, and what's real vs. what's a toy

### 1. Password hash+breach vs. Schnorr ZKP (`/`)

- **Traditional panel**: a genuine, live, time-bounded MD5 brute force.
  It tries every 1-letter guess, then 2, then 3, 4, 5… (lowercase a–z)
  against the real stored hash, with a live counter, until it finds the
  password or hits an 8-second budget (`BREACH_TIME_BUDGET_SECONDS` in
  `app.py`). On an ordinary laptop core this reliably clears everything up
  to ~5 letters inside that window; 6+ letters will time out, and the UI
  says so honestly instead of hanging. That timeout *is* the point: ~12
  million real guesses in 8 seconds on one CPU core is the honest ceiling
  of a live laptop demo — a GPU rig closes most of that gap in seconds
  against the same unsalted hash.
- **ZKP panel**: a genuine Schnorr zero-knowledge identification protocol
  over a 1024-bit safe-prime group, computed client-side in the browser
  (`static/zkp-core.js`). The server only ever stores a public verifier
  `y = g^x mod p`; the password-derived secret `x` and the per-login
  random nonce `r` never leave the browser tab. Every login produces a
  fresh challenge and proof, so replaying an intercepted request fails.
- **🕵️ Eve is on the Wi-Fi**: logs the literal JSON bytes each button
  press sends over the network, live — the password panel's plaintext
  password shows up flagged red; the ZKP panel's `y`/`t`/`s` show up
  flagged "useless alone."

### 2. Biometric ZK unlock (`/biometric`)

A webcam frame is downsampled to a 24×24 grayscale buffer (shown on
screen, magnified, so you can see exactly what gets hashed), reduced to a
secret `x` via SHA-256, and proved with the same Schnorr protocol as demo
1. The server's "biometric record" is one number (`y`) — 0 image files, 0
feature vectors. **Honest scope note**: a real biometric system uses a
trained neural embedding plus fuzzy matching so two photos of the same
face produce compatible outputs; this demo hashes raw pixels instead, so
"unlock" reuses the `x` captured at enrollment (held only in that tab's
memory) rather than re-deriving it from a new frame. The cryptographic
property being shown — the server never learns the biometric input,
only `y = g^x` — is identical either way. A real two-frame liveness check
(genuine frame-to-frame motion measurement) runs at unlock time but isn't
cryptographically bound to the proof.

### 3. Trading-platform KYC gate (`/portal` + `/wallet`)

Desktop shows a QR code; a phone scans it, opens the wallet page, and
uploads a PAN card photo. That photo is hashed into a secret `x` **on the
phone** and is never uploaded anywhere — not to this server, not
transiently, not at all. The wallet then runs the exact same Schnorr
commit/challenge/response proof as demos 1 and 2, and the desktop portal
polls for the result and displays `KYC_Verified: TRUE` plus the live
`(t, c, s)` that crossed the wire. The portal's "database" never holds a
PAN number, a name, a date of birth, or an image — only `y`.
**Honest scope note**: this proves "a photo was uploaded and hashed," not
"this is a government-issued PAN card" — real KYC needs an OCR step plus
an NSDL/UTIITSL verification API this demo doesn't have credentials for.
The cross-device, zero-knowledge wire protocol is the real, working part.

Because the QR has to be reachable from an actual phone, the server binds
`0.0.0.0` and the QR encodes the machine's real LAN IP (auto-detected in
`app.py`, not `127.0.0.1`, which only ever resolves back to the laptop
itself). Because `crypto.subtle` (the browser's native SHA-256) only works
on `https://` or `localhost`, `static/zkp-core.js` ships its own pure-JS
SHA-256 (verified against known test vectors) so hashing still works on
the plain `http://192.168.x.x` origin a phone actually connects to.

## Suggested script for the table

1. Register the same password on both sides of demo 1. Turn on Eve, hit
   "Simulate GPU breach" on the left, then log in twice on the right —
   point at Eve's log: plaintext password vs. numbers useless alone.
2. Switch to the biometric demo. Enroll a face, then unlock — the "server
   database" panel visibly says 0 images, 0 vectors, the whole time.
3. Switch to the KYC gate. Scan the QR with an actual phone on the same
   Wi-Fi, upload any photo as a stand-in PAN card, approve. Watch the
   desktop screen update live with the Schnorr proof and `KYC_Verified:
   TRUE` — no PAN number, name, DOB, or image ever touched the server.
4. Close with: every panel on the left side of each demo has a secret
   that has to exist somewhere — typed, transmitted, hashed, stored. Every
   panel on the right never creates that secret-in-transit at all.
