"""
ZK Authentication Demo — Traditional (hash+breach) vs Zero-Knowledge Proof
Built for a hackathon poster demo. Runs entirely on localhost, no external
network calls, no real user data of any kind.

HONEST SCOPE NOTE (read this before you present):
  The "Simulate GPU breach" button runs a REAL, time-bounded brute-force
  search against the stored unsalted MD5 hash: it tries every 1-letter
  lowercase combination, then every 2-letter, then 3, 4, 5... climbing the
  keyspace live, and gives up after BREACH_TIME_BUDGET_SECONDS of wall-clock
  time on one CPU core. It will only find the traditional-panel password if
  the search reaches it inside that budget. If a judge sets a longer/stronger
  password, the search will exhaust its time budget and report "not found" —
  and THAT is the point to make out loud: "This is a laptop doing a few
  hundred thousand guesses in 8 seconds. A GPU rig does billions per second
  against the exact same unsalted MD5 hash. The fix isn't a longer password,
  it's not having a password to steal at all — which is what the ZKP side
  demonstrates."
  Do NOT claim this can crack arbitrary passwords in general. It's bounded
  by design, live, in front of the audience.
"""

import hashlib
import io
import os
import random
import secrets
import socket
import string
import threading
import time
from itertools import product

import qrcode
import qrcode.image.svg
from flask import Flask, Response, jsonify, render_template, request, session

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# ---------------------------------------------------------------------------
# In-memory "databases" (reset on restart — nothing is written to disk)
# ---------------------------------------------------------------------------
traditional_db = {}   # username -> md5 hash
zkp_db = {}           # username -> {"y": verifier, "p": prime, "g": generator, "q": order}

# A real (small, demo-sized) safe prime for the Schnorr ZKP group.
# p is prime, q = (p-1)/2 is also prime (safe prime), g generates the
# order-q subgroup. These are fixed constants chosen for the demo — real
# deployments use standardized 2048+ bit groups.
P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
G = 2
Q = (P - 1) // 2  # subgroup order used for exponent arithmetic


# ---------------------------------------------------------------------------
# Traditional panel: MD5 hash storage + live, time-bounded brute force
# ---------------------------------------------------------------------------
BRUTE_FORCE_ALPHABET = string.ascii_lowercase
BREACH_TIME_BUDGET_SECONDS = 8  # wall-clock budget for the live demo search

# username -> job state dict. Each job runs in its own background thread so
# /status can be polled repeatedly while it's in flight.
breach_jobs = {}
breach_jobs_lock = threading.Lock()


@app.route("/api/traditional/register", methods=["POST"])
def traditional_register():
    data = request.get_json(force=True)
    username = (data.get("username") or "demo").strip()[:32]
    password = data.get("password") or ""
    digest = hashlib.md5(password.encode()).hexdigest()
    traditional_db[username] = digest
    return jsonify({"username": username, "hash": digest})


def _run_breach(username, target_hash):
    """Background worker: climb 1, 2, 3, 4, 5... char lowercase guesses
    against target_hash, updating breach_jobs[username] live, until the
    password is found or the time budget runs out."""
    job = breach_jobs[username]
    start = time.time()
    attempts = 0
    found = None
    length = 1
    timed_out = False

    while True:
        job["current_length"] = length
        for combo in product(BRUTE_FORCE_ALPHABET, repeat=length):
            elapsed = time.time() - start
            if elapsed > BREACH_TIME_BUDGET_SECONDS:
                timed_out = True
                break
            attempts += 1
            guess = "".join(combo)
            if hashlib.md5(guess.encode()).hexdigest() == target_hash:
                found = guess
                break
            # Publish progress periodically rather than on every guess so the
            # lock isn't contended on every single MD5 call.
            if attempts % 200 == 0:
                with breach_jobs_lock:
                    job["attempts"] = attempts
                    job["elapsed_seconds"] = round(elapsed, 2)

        with breach_jobs_lock:
            job["attempts"] = attempts
            job["elapsed_seconds"] = round(time.time() - start, 2)

        if found is not None or timed_out:
            break
        length += 1

    with breach_jobs_lock:
        job["attempts"] = attempts
        job["elapsed_seconds"] = round(time.time() - start, 3)
        job["final_length"] = length
        job["found"] = found
        job["timed_out"] = timed_out
        job["done"] = True


@app.route("/api/traditional/breach/start", methods=["POST"])
def traditional_breach_start():
    data = request.get_json(force=True)
    username = (data.get("username") or "demo").strip()[:32]
    target_hash = traditional_db.get(username)
    if not target_hash:
        return jsonify({"error": "no stored user — register first"}), 400

    with breach_jobs_lock:
        existing = breach_jobs.get(username)
        if existing and not existing.get("done"):
            return jsonify({"error": "breach already running for this user"}), 409
        breach_jobs[username] = {
            "attempts": 0,
            "current_length": 1,
            "elapsed_seconds": 0.0,
            "found": None,
            "timed_out": False,
            "done": False,
            "time_budget_seconds": BREACH_TIME_BUDGET_SECONDS,
        }

    thread = threading.Thread(target=_run_breach, args=(username, target_hash), daemon=True)
    thread.start()

    return jsonify({"status": "started", "time_budget_seconds": BREACH_TIME_BUDGET_SECONDS})


@app.route("/api/traditional/breach/status", methods=["GET"])
def traditional_breach_status():
    username = (request.args.get("username") or "demo").strip()[:32]
    with breach_jobs_lock:
        job = breach_jobs.get(username)
        if not job:
            return jsonify({"error": "no breach running — call /start first"}), 404
        return jsonify(dict(job))


# ---------------------------------------------------------------------------
# ZKP panel: real Schnorr identification protocol (interactive, 3-move)
#
# Every value below is computed in the browser (see static/script.js) and
# only ever crosses the wire as the already-public pieces of the protocol:
# y (verifier), t (commitment), c (challenge), s (response). The secret x
# (derived from username+password) and the one-time nonce r are generated
# client-side and never serialized into a request — this route layer never
# even sees a password.
# ---------------------------------------------------------------------------
@app.route("/api/zkp/register", methods=["POST"])
def zkp_register():
    data = request.get_json(force=True)
    username = (data.get("username") or "demo").strip()[:32]
    y_hex = data.get("y") or "0"
    y = int(y_hex, 16) % P   # public verifier, computed client-side as g^x mod p

    zkp_db[username] = {"y": y}
    return jsonify({"username": username, "public_verifier": hex(y)[:24] + "…"})


@app.route("/api/zkp/login/commit", methods=["POST"])
def zkp_login_commit():
    """Step 1 (client -> server): prover sends commitment t = g^r mod p,
    computed client-side from a fresh one-time secret r. Server replies with
    a fresh random challenge c — never reused, so nothing recorded here can
    be replayed against a future login."""
    data = request.get_json(force=True)
    username = (data.get("username") or "demo").strip()[:32]
    t_hex = data.get("t") or "0"
    t = int(t_hex, 16) % P

    if username not in zkp_db:
        return jsonify({"error": "no stored user — register first"}), 400

    challenge = secrets.randbelow(Q - 1) + 1

    # Stash this login attempt's commitment + challenge server-side so the
    # next call (/respond) can verify against them. No secret ever lands here.
    session["zkp_t"] = t
    session["zkp_challenge"] = challenge
    session["zkp_user"] = username

    return jsonify({"challenge_c": hex(challenge)})


@app.route("/api/zkp/login/respond", methods=["POST"])
def zkp_login_respond():
    """Step 2-3: prover sends s = (r + c*x) mod q, computed entirely
    client-side. Server verifies g^s == t * y^c (mod p) using only public
    values — it never learns x, r, or the password, and s is worthless for
    any future login since the next challenge c will be different."""
    data = request.get_json(force=True)
    s_hex = data.get("s") or "0"
    s = int(s_hex, 16) % Q

    t = session.get("zkp_t")
    c = session.get("zkp_challenge")
    username = session.get("zkp_user")
    if t is None or username not in zkp_db:
        return jsonify({"error": "no login in progress — call commit first"}), 400

    y = zkp_db[username]["y"]

    # Verify: g^s should equal t * y^c  (mod p)
    lhs = pow(G, s, P)
    rhs = (t * pow(y, c, P)) % P
    valid = lhs == rhs

    # The KYC trading-portal wallet proves under username "kyc:<session_id>"
    # so the portal (a different device/browser, polling by session_id) can
    # pick up the same verdict and the exact (t, c, s) that were just
    # checked — the server is simply relaying what it already computed
    # above, not learning anything new about the PAN image.
    if username.startswith("kyc:"):
        session_id = username[len("kyc:"):]
        if session_id in portal_sessions:
            portal_sessions[session_id] = {
                "status": "verified" if valid else "invalid",
                "y": hex(y),
                "t": hex(t),
                "c": hex(c),
                "s": hex(s),
            }

    return jsonify({"valid": valid})


# ---------------------------------------------------------------------------
# Trading platform KYC gate: QR-scan + phone wallet, proved with the SAME
# Schnorr protocol as the password and biometric panels above — no separate
# scheme, no claims form. You scan a QR on your phone, upload your PAN card
# photo there, and the phone proves it holds *a* PAN image (hashed into a
# secret x, exactly like the biometric demo) without that image, or any
# number derived identifiably from it, ever reaching this server. Only
# y = g^x (at registration) and then a fresh (t, c, s) triple per login ever
# cross the network — literally the same three values the biometric and
# password panels show you.
#
# Cross-device wiring: the wallet (phone) registers + proves under the
# username f"kyc:{session_id}" using the existing generic /api/zkp/* routes
# below. zkp_login_respond, when it sees that prefix, mirrors its own
# verdict and the (t, c, s) it just checked into portal_sessions so the
# portal (a different device/browser, polling by session_id) can show it.
#
# HONEST SCOPE NOTE: this proves "a photo was uploaded and hashed," not
# "this is a government-issued PAN card" — real KYC needs an OCR + NSDL/
# UTIITSL verification API this demo doesn't have credentials for. The
# selective-disclosure property (server learns nothing about the image) is
# the real, working part.
# ---------------------------------------------------------------------------

# session_id -> {"status": "pending"|"verified"|"invalid", "y"/"t"/"c"/"s": hex|None}
portal_sessions = {}


def _lan_ip() -> str:
    """Best-effort LAN IP so a QR code scanned by a phone on the same
    Wi-Fi/hotspot/Bluetooth-tethered network actually resolves back to this
    machine — 127.0.0.1 in the QR would only ever work on this laptop."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))  # no packet actually sent; just picks the outbound interface
        return s.getsockname()[0]
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "127.0.0.1"
    finally:
        s.close()


SERVER_PORT = 5000
LAN_IP = _lan_ip()


def _wallet_url(session_id: str) -> str:
    return f"http://{LAN_IP}:{SERVER_PORT}/wallet?session={session_id}"


@app.route("/api/portal/session/new", methods=["POST"])
def portal_session_new():
    session_id = secrets.token_urlsafe(8)
    portal_sessions[session_id] = {"status": "pending"}
    return jsonify({"session_id": session_id, "wallet_url": _wallet_url(session_id)})


@app.route("/api/portal/qr/<session_id>")
def portal_qr(session_id):
    img = qrcode.make(_wallet_url(session_id), image_factory=qrcode.image.svg.SvgPathImage)
    buf = io.BytesIO()
    img.save(buf)
    return Response(buf.getvalue(), mimetype="image/svg+xml")


@app.route("/api/portal/session/<session_id>/status")
def portal_session_status(session_id):
    return jsonify(portal_sessions.get(session_id, {"status": "unknown"}))


@app.route("/biometric")
def biometric_page():
    return render_template("biometric.html")


@app.route("/portal")
def portal_page():
    return render_template("portal.html")


@app.route("/wallet")
def wallet_page():
    return render_template("wallet.html")


@app.route("/")
def index():
    return render_template("index.html")


if __name__ == "__main__":
    print(f"\n  ZK Auth Demo running →  http://127.0.0.1:{SERVER_PORT}")
    print(f"  On your phone's Wi-Fi/hotspot/Bluetooth-tethered network →  http://{LAN_IP}:{SERVER_PORT}\n")
    # 0.0.0.0, not 127.0.0.1: the KYC wallet demo needs a phone on the same
    # network to reach this server to scan the QR code at all.
    app.run(host="0.0.0.0", port=SERVER_PORT, debug=False, threaded=True)
