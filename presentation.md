# Zero-Knowledge Authentication — 10-Minute Presentation Script + Q&A

**Team:** Speaker 1 (Opener), **Speaker 2** (Real-world proof), **Speaker 3** (Closer), **Lead** (main presenter, ~7 min, runs all demos).
**Total talk time:** ~10 minutes (≈1,350 spoken words at a normal pace) + Q&A.
**Stage notes** are in *[italics]*. Demo app: `python3 app.py` → http://127.0.0.1:5000 (phone on same Wi-Fi for the KYC demo).

| Block | Who | Time |
|---|---|---|
| 1. Hook | Speaker 1 | 0:00 – 1:00 |
| 2. The problem: breaches + why hashing/2FA aren't enough | Lead | 1:00 – 3:00 |
| 3. The idea: Zero-Knowledge in one example | Lead | 3:00 – 4:00 |
| 4. Who already uses it | Speaker 2 | 4:00 – 5:00 |
| 5. Live demos (password → face → KYC) | Lead | 5:00 – 8:30 |
| 6. Honest limits + what's next | Lead | 8:30 – 9:15 |
| 7. Close | Speaker 3 | 9:15 – 10:00 |

---

## 1. Hook — Speaker 1 (≈1 min)

*[Walk up. Do not start with "Hello, we are…". Start with the question.]*

"Raise your hand if you've ever been told: *'Your data may have been compromised.'*

*[Pause. Hands go up.]*

You're not unlucky. You're normal. In 2013, Yahoo lost data on **every one of its accounts — about three billion** — and the passwords were protected with MD5, a hash that's old and fast to crack. In 2012, LinkedIn lost passwords that later surfaced online as **117 million emails and passwords**. In 2024, here in India, a hacker leaked customer data from **Star Health** — names, medical details, even ID copies — through Telegram chatbots.

And here's the part nobody tells you: every one of those companies *had a login system that worked perfectly.* The login worked. The *design* was the problem — because to log you in, the server has to **know something about your secret.**

What if it didn't? What if a server could verify you… while learning **nothing**? That's what we built. Over to our lead."

---

## 2. The Problem — Lead (≈2 min)

"Let me make this concrete. Every normal login does this: you type your password, it travels to the server, the server hashes it and compares it with the database.

Two weaknesses. Both are in our demo, and you'll see them live.

**Weakness one: the database.** Companies store hashes, not plain passwords. Good. But a hacker who steals that database doesn't try to 'reverse' it. They copy it to their own machine and *guess* — billions of guesses per second on modern GPUs — until a guess hashes to the same value. Yahoo's MD5 and LinkedIn's SHA-1 are exactly the kind of fast hashes that fall to this. In the LinkedIn case, the people selling the data claimed they'd cracked about 90% of the passwords in 72 hours. Treat that number as *their claim*, not a verified fact — but it shows how the market sees weak hashes.

And a cracked password is worse than one lost account, because people reuse passwords.

**Weakness two: the moment of login.** Even with a perfect database, your raw password still travels to the server and sits in its memory. This week's news makes the point. **PHP2Shell** — two critical flaws in PHP itself, patched on **October 21** — can let an attacker run code on a vulnerable web server. If an attacker is running code on your login server, they can read what's in its memory — and in a normal system, that includes passwords as they arrive. *(Exploitation reports are still disputed — the PHP Foundation said it hadn't seen working exploits while Amazon and Cloudflare reported attempts — so I'm using it as an example of the risk, not claiming people are being hacked right now.)*

'But we have 2FA!' 2FA is great — but it protects the *user*, not the *server's database*, and attackers have learned to go around it. In **2022, Uber** was breached after an attacker spammed a contractor with approval prompts until they tapped 'accept'. **Cisco** was hit the same year with the same trick — MFA fatigue combined with phone-call phishing. Both attackers *already had the password.* 2FA is a second lock. We want to fix the first one."

---

## 3. The Idea — Lead (≈1 min)

"Zero-knowledge proof. Simplest example I know: you want to prove you know a secret door code, without telling me the code.

You walk into a ring-shaped cave with a door at the back. You go in one side — I can't see which. I shout 'come out the LEFT side!' If you know the code, you can always do it. If you were guessing, you'd be wrong half the time. We repeat it 20 times. If you pass 20 times, the chance you were bluffing is about one in a million — and **I never learned the code.**

That's the principle. In our app, it's a real protocol — **Schnorr's identification protocol**: 

1. Your browser turns the password into a secret number **x**, and registers only a public value **y = g^x mod p**. The server stores *only y*.
2. To log in: browser sends a fresh random commitment; server sends a random challenge; browser answers with a number that only someone who knows **x** can compute.
3. The server checks the math. **Password never sent. Never stored.** Every login uses new random numbers, so a replayed recording fails.

Same family of ideas as SRP, which is used by real password managers. We just chose to show the mechanism openly so you can inspect every number."

---

## 4. Who Already Uses This — Speaker 2 (≈1 min)

"This isn't a lab idea. The same family — password-authenticated protocols where the server never sees your password — is already in products you know. **1Password** and **Proton** use the Secure Remote Password protocol, and Apple's HomeKit pairing uses it too. And **Zcash** uses zero-knowledge proofs called zk-SNARKs, so the network can confirm a transaction is valid without seeing the sender, receiver, or amount.

In India there's even an open-source project called **Anon Aadhaar**, built by Ethereum's Privacy & Scaling Explorations team. It reads the government's digital signature on your Aadhaar QR code and proves things like 'I'm over 18' — without revealing your name or number. Its own docs say it's experimental, not production-ready — but the direction is clear. The question isn't *whether* this works. It's why most websites still aren't using it."

---

## 5. Live Demo — Lead (≈3.5 min)

*[Have the app open. Two browser windows: `/`, `/biometric`, `/portal`. Phone ready.]*

### Demo 1 — Password vs. ZKP (≈1.5 min)

"Left side: traditional. Right side: zero-knowledge. I'll register the *same* password on both. *[Register a short lowercase password, e.g. 5 letters.]*

Now I switch on **Eve** — a simulated person on the Wi-Fi who logs the actual bytes each button sends. *[Toggle Eve.]*

Left, I hit 'Simulate GPU breach'. This is a real, live brute force against the stored MD5 hash — you can see the guess counter. *[Wait for it to crack.]* Cracked. That's the database leak scenario. This is a laptop core, capped at 8 seconds. A GPU does it far faster against the same unsalted hash.

Now I log in on both sides. *[Point at Eve's log.]* Left: the **plaintext password** shows up in red. Right: three numbers — y, t, s — and a note that they're useless alone. A new login produces different numbers every time."

### Demo 2 — Biometric (≈1 min)

"Why this matters most: you can reset a password. You can't reset your face. *[Open `/biometric`.]* I enroll my face. The page shows the tiny 24×24 grayscale picture that gets hashed on-device. Now look at the server panel: **0 images, 0 feature vectors.** Just one number. I unlock — same proof as before."

### Demo 3 — KYC Gate (≈1 min)

"Trading platforms hold PAN cards, DOBs, addresses — a goldmine. *[Open `/portal`, scan QR with phone.]* My phone uploads a photo; it's hashed **on the phone** and never sent anywhere. The phone runs the proof; the desktop shows `KYC_Verified: TRUE` and the live proof values. The platform's database holds a PAN number? No. A name? No. An image? No. Just `y`."

---

## 6. Honest Limits + What's Next — Lead (≈45 sec)

"Judges, we want to be straight about what is a demo and what isn't.

- The biometric demo hashes raw pixels. A real system uses a neural-network face embedding with fuzzy matching, because no two photos are pixel-identical. What we proved is the cryptographic property: the server only ever sees `y`.
- The KYC demo proves 'a photo was hashed and proven' — not 'this is a genuine PAN card.' Real KYC needs OCR and the official verification APIs.
- And ZKP is not magic. If an attacker takes over the server, they can't steal passwords from the database — but they could tamper with the login page code that your browser downloads. Zero-knowledge protects the *data at rest*; it needs to be paired with things like signed code and passkeys.

Next: replace our toy biometric with a real embedding, plug in verifiable credentials like Anon Aadhaar for 'over 18', and package it as a drop-in widget so small websites can use it without hiring a cryptographer."

---

## 7. Close — Speaker 3 (≈45 sec)

"Let's go back to where we started. Yahoo. LinkedIn. Star Health. Different companies, same flaw: *the server held something that was worth stealing.*

We took a different approach: **don't give the server anything worth stealing.** On the left side of every demo, there's a secret that has to exist somewhere — typed, transmitted, stored. On the right side, that secret never leaves your device.

You can't leak what you never had. Thank you — we'd love your questions."

---

# Q&A Bank

*Suggested owner in brackets. If someone else is asked, hand to the owner: "Our lead can take that." Speaker 2 and 3 should memorize only the ones marked for them.*

### Basics

**Q1. Isn't hashing already enough? Stolen hashes are useless.** *[Lead]*
Not useless — they're attackable offline. Attackers guess billions of passwords per second against a stolen hash and see which match. Fast hashes like MD5 and SHA-1 (Yahoo, LinkedIn) fall quickly; even bcrypt/Argon2 only slow this down. Also, hashing doesn't help while the raw password is in transit and in server memory at login. ZKP removes the password from the wire completely.

**Q2. Doesn't 2FA already solve this?** *[Lead or Speaker 2]*
2FA is a good second lock, and we'd keep it. But it protects the *user* after a password is stolen; it doesn't change what the server stores. And attackers bypass it: Uber and Cisco (2022) were hit with MFA-fatigue, and phishing proxies relay codes in real time. Fixing the first lock means a breach gives the attacker nothing to start those attacks with.

**Q3. What's the difference between your project and SRP / Passkeys? What's the innovation?** *[Lead]*
Honest answer: we don't claim to invent new cryptography — Schnorr's protocol is from 1989 and SRP is well established. Passkeys are a strong solution too. Our contribution is applying it to the data that truly can't be rotated — **biometrics and identity documents** — and showing it end to end, across devices (phone wallet ↔ desktop portal), with every number visible. The roadmap is packaging it as a simple drop-in for small sites.

**Q4. Is this real zero-knowledge or a simulation?** *[Lead]*
It's the real Schnorr identification protocol over a 1024-bit safe-prime group, computed in the browser. Honest note: it's an *interactive* proof with a server-chosen challenge; production systems often use a non-interactive variant (Fiat–Shamir) or a larger/elliptic-curve group. Nothing in the demo is mocked — the brute force and the proofs are computed live.

### Security hardness

**Q5. If the hacker steals `y`, can't they just brute-force the password from it?** *[Lead — likely the sharpest question]*
Yes, in principle — this is a real limitation. `y` is derived from the password, so a weak password could be guessed offline and checked against `y`, much like a hash. ZKP doesn't fix weak passwords. Our demo's derivation uses a fast hash, so a production version should use a slow key-derivation function (Argon2/scrypt) with a salt, or an aPAKE such as OPAQUE, which is designed to resist this. What ZKP *does* eliminate: the password in transit, in server memory, and in logs. We'd rather say this ourselves than have you find it.

**Q6. PHP2Shell — would your system have been safe?** *[Lead]*
Partially, and we won't oversell it. PHP2Shell is a remote-code-execution flaw in PHP, patched Oct 21. A server with ZKP stores no passwords or biometrics, so there's nothing to dump from the database, and nothing to skim from login requests. But an attacker running code on the server could also change the login page's JavaScript to capture passwords from *future* users. So: it limits the damage of a breach, it doesn't replace patching. (Also, exploitation reports are disputed — we're using it as an example of the risk.)

**Q7. What stops replay attacks?** *[Lead]*
Each login uses a fresh random nonce from the client and a fresh random challenge from the server. A recorded proof is only valid for that challenge, so replaying it fails — you can see the proof values change in Eve's log on every login.

**Q8. What if the user's phone is stolen?** *[Speaker 3 or Lead]*
The secret is released only after local verification (biometric/PIN) on the device, and in a real deployment the key lives in the phone's secure hardware. Like any credential, there should be a revocation and re-registration path — replace `y` on the server and the old key is dead. That's far better than a leaked face, which can never be revoked.

### Biometrics

**Q9. How can you match a face without storing it? Your demo just hashes pixels.** *[Lead]*
Correct, and it's stated in our README. A real system extracts a face embedding with a neural network, tolerates small differences with fuzzy extractors, and releases the key only on a local match. The demo shows the part that matters for privacy: the server's record is one number, with 0 images and 0 vectors.

**Q10. What about spoofing with a photo or deepfake?** *[Lead]*
Our demo has a basic two-frame motion check, but we're upfront that it isn't cryptographically bound to the proof. Production needs hardware-backed liveness (depth sensors, secure enclave). That's the same mechanism phones use for Face ID.

### India / identity

**Q11. How is this relevant to India?** *[Speaker 2 or Lead]*
India has had major identity-data incidents: Star Health (2024) with medical data and ID copies reportedly leaked via Telegram bots, and in 2023 a seller on a hacker forum claimed to have 815 million Indian records, including Aadhaar details, after which the government investigated (the source was reportedly linked to ICMR COVID records but never publicly settled). Those claims come from sellers and reporters, not all confirmed. The pattern is the same: centralized stores of documents. Proving "over 18" or "KYC done" without handing over the document removes the honeypot. Anon Aadhaar is an open-source experiment in exactly this direction.

**Q12. Will this pass real KYC rules (RBI/SEBI)?** *[Lead]*
No — and our demo says so. It proves a document was presented without storing it; real KYC needs government verification and regulator-approved flows. The idea is for a regulated verifier to check the document once, issue a signed credential, and let the user prove facts from it without re-uploading the document everywhere.

### Practical

**Q13. Why not just use passkeys / WebAuthn?** *[Lead]*
Passkeys are excellent — they also keep secrets on-device and use public-key proofs, and we'd recommend them for login. Our project overlaps in principle but extends to proving *attributes* (age, KYC) and biometric-style secrets, which passkeys don't do on their own.

**Q14. Performance? 1024-bit math in the browser sounds slow.** *[Lead]*
Modular exponentiation at 1024 bits is fast enough that the demo feels instant on a laptop (measure it on your machine before claiming a number). Production would use elliptic curves — much faster and smaller.

**Q15. Is 1024-bit secure?** *[Lead]*
It's a demo parameter chosen so judges can follow the numbers. 1024-bit discrete-log groups are below current recommendations; real deployments use 2048-bit or larger groups, or elliptic curves like Curve25519.

**Q16. What was the hardest part?** *[Speaker 2 or 3 — personalise with your own story]*
Make the demo honest: running real math in the browser, including our own SHA-256 because the browser's built-in one doesn't work on plain `http://192.168.x.x` addresses a phone connects to — and keeping the demo cleanly separated from the claims.

---

# Fact Check & Sources

Every external claim in the script was checked against reporting on **24 Oct 2026**. Wording is deliberately cautious where sources disagree.

| Claim in script | Status | Source / note |
|---|---|---|
| Yahoo 2013 breach affected all ~3 billion accounts; passwords hashed with MD5 | Confirmed (Verizon/Yahoo disclosure, Oct 2017) | TechCrunch, Help Net Security, Sophos |
| LinkedIn 2012 breach; 117M emails+passwords surfaced in 2016; unsalted SHA-1 | Confirmed that 117M emails+passwords were posted online and LinkedIn confirmed the data; unsalted SHA-1 widely reported (LinkedIn said it had hashed and salted for several years, so not every record is clearly unsalted) | TechCrunch, The Register, Sophos |
| "90% cracked in 72 hours" | **Seller's claim**, not independently verified — script says so | Motherboard via The Register |
| Star Health 2024 leak via Telegram chatbots | Confirmed reporting (Reuters, Sept 2024); company disputes some details; data included medical/ID info | BOOM, Moneylife, Deccan Herald |
| 815M Indian records offered for sale (Oct 2023), linked to ICMR | Seller claim + Resecurity sample check; ICMR link **unconfirmed** — script says so | Moneylife, BOOM, BW Healthcare |
| Uber 2022 breach via MFA fatigue (LAPSUS$-linked) | Confirmed (Uber's own statement) | Uber / multiple reports |
| Cisco 2022 breach via MFA fatigue + vishing (Yanluowang) | Confirmed (Cisco Talos) | Cisco Talos; details vary by source |
| PHP2Shell: 2 critical RCE flaws (CVE-2026-109618/-109619), patched Oct 21, 2026 | Confirmed. **It is RCE, not a login bypass.** Exploitation status is disputed | The Hacker News, watchTowr, Qualys, Cloudflare, CNBC |
| 1Password/Proton/Apple HomeKit use SRP | Widely documented; 1Password also adds a Secret Key | Vendor security docs |
| Zcash uses zk-SNARKs | Confirmed | Zcash docs |
| Anon Aadhaar (PSE) proves Aadhaar QR-signed facts via zk-SNARK; experimental | Confirmed; project docs say not production-ready | PSE docs |

**Corrections to the earlier Q&A draft (docx):**
1. It said PHP2Shell lets attackers "bypass login screens" and that a ZKP server would hold "absolutely nothing" after a breach. Reporting describes **remote code execution**; and a compromised server could tamper with login-page code, so the script now says "limits the damage", not "nothing".
2. It said "Apple and 1Password have used this for years" for SRP — fine for 1Password/HomeKit; Apple's usage is narrower than implied, so the script avoids claiming broad Apple login use.
3. The docx called our protocol SRP; our app implements **Schnorr identification**, and the script says so.
4. Added honest limits (Q5, Q9, Q10, Q12, Q15) so judges don't find them first.
