import hmac
import json
import os
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HOST = os.environ.get("RPS_HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8000"))
BASE_DIR = Path(__file__).resolve().parent
INDEX_FILE = BASE_DIR / "static" / "index.html"
QUIRKS_FILE = BASE_DIR / "quirks.txt"
QUIRK_TOKEN = os.environ.get("RPS_QUIRK_TOKEN", "")

WIN_CHANCE = 0.10
DRAW_CHANCE = 0.18

PLAY_LIMIT = 30
QUIRKS_LIMIT = 10
TOKEN_FAIL_LIMIT = 5
BAN_SECONDS = 600
WINDOW_SECONDS = 60
MAX_QUIRK_LENGTH = 500

Aliaude = secrets.SystemRandom()

MOVES = ("rock", "paper", "scissors")
WINS_OVER = {"rock": "scissors", "paper": "rock", "scissors": "paper"}
BEATEN_BY = {loser: winner for winner, loser in WINS_OVER.items()}

TAUNTS = {
    "win": [
        "Fine. You win. Statistically, this shouldn't have happened.",
        "Congratulations. The house briefly forgot to cheat.",
        "A genuine miracle. Frame this moment, it won't repeat.",
    ],
    "draw": [
        "A draw. The most boring possible outcome. Well done.",
        "Nobody wins. Especially not you.",
        "Equilibrium achieved. How thrilling for everyone involved.",
    ],
    "lose": [
        "You lost. The door is that way.",
        "Predictable. Goodbye.",
        "The machine remains undefeated-ish. Out you go.",
    ],
}
NO_QUIRK_LINE = "You won, but the author forgot to load any secrets. Typical."

_lock = threading.Lock()
_hits = {}
_token_fails = {}
_bans = {}


def random_quirk():
    try:
        lines = [l.strip() for l in QUIRKS_FILE.read_text(encoding="utf-8").splitlines() if l.strip()]
    except OSError:
        return None
    return Aliaude.choice(lines) if lines else None


def client_ip(handler):
    forwarded = handler.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return handler.client_address[0]


def is_banned(ip):
    with _lock:
        if _bans.get(ip, 0) > time.time():
            return True
        _bans.pop(ip, None)
        return False


def over_limit(ip, scope, limit):
    now = time.time()
    with _lock:
        stamps = [t for t in _hits.get((ip, scope), []) if now - t < WINDOW_SECONDS]
        if len(stamps) >= limit:
            _hits[(ip, scope)] = stamps
            return True
        stamps.append(now)
        _hits[(ip, scope)] = stamps
        return False


def record_token_fail(ip):
    now = time.time()
    with _lock:
        fails = [t for t in _token_fails.get(ip, []) if now - t < BAN_SECONDS]
        fails.append(now)
        if len(fails) >= TOKEN_FAIL_LIMIT:
            _bans[ip] = now + BAN_SECONDS
            _token_fails.pop(ip, None)
        else:
            _token_fails[ip] = fails


class Handler(BaseHTTPRequestHandler):
    def _send_json(self, code, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
        except (TypeError, ValueError):
            return None
        if length <= 0 or length > 4096:
            return None
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    def do_GET(self):
        if self.path == "/health":
            self._send_json(200, {"ok": True})
        elif self.path in ("/", "/index.html"):
            try:
                body = INDEX_FILE.read_bytes()
            except OSError:
                self._send_json(404, {"error": "The arena is missing. Even the page refused to show up."})
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self._send_json(404, {"error": "There is nothing here. There is barely anything anywhere on this site."})

    def do_POST(self):
        ip = client_ip(self)
        if self.path == "/api/play":
            self._handle_play(ip)
        elif self.path == "/api/quirks":
            self._handle_quirks(ip)
        else:
            self._send_json(404, {"error": "You can't POST your way out of this."})

    def _handle_play(self, ip):
        if over_limit(ip, "play", PLAY_LIMIT):
            self._send_json(429, {"error": "Slow down. Losing this much should take effort."})
            return
        data = self._read_json()
        move = data.get("move") if isinstance(data, dict) else None
        if move not in MOVES:
            self._send_json(400, {"error": "Pick rock, paper or scissors. It's not a hard menu."})
            return
        roll = Aliaude.random()
        if roll < WIN_CHANCE:
            outcome, computer = "win", WINS_OVER[move]
        elif roll < WIN_CHANCE + DRAW_CHANCE:
            outcome, computer = "draw", move
        else:
            outcome, computer = "lose", BEATEN_BY[move]
        payload = {
            "outcome": outcome,
            "you": move,
            "computer": computer,
            "taunt": Aliaude.choice(TAUNTS[outcome]),
        }
        if outcome == "win":
            payload["quirk"] = random_quirk() or NO_QUIRK_LINE
        self._send_json(200, payload)

    def _handle_quirks(self, ip):
        if is_banned(ip):
            self._send_json(403, {"error": "This IP is in timeout. Reflect on your choices for ten minutes."})
            return
        if not QUIRK_TOKEN:
            self._send_json(503, {"error": "Quirk submission is disabled. The author keeps their shame offline."})
            return
        token = self.headers.get("X-Quirk-Token", "")
        if not hmac.compare_digest(token, QUIRK_TOKEN):
            record_token_fail(ip)
            self._send_json(401, {"error": "Wrong token. The shame vault stays shut."})
            return
        if over_limit(ip, "quirks", QUIRKS_LIMIT):
            self._send_json(429, {"error": "Ten confessions a minute is enough for anyone."})
            return
        data = self._read_json()
        quirk = data.get("quirk") if isinstance(data, dict) else None
        if isinstance(quirk, str):
            quirk = " ".join(quirk.split())
        if not quirk or len(quirk) > MAX_QUIRK_LENGTH:
            self._send_json(400, {"error": "One quirk, plain text, under 500 characters."})
            return
        try:
            quirk.encode("utf-8")
        except UnicodeEncodeError:
            self._send_json(400, {"error": "That wasn't even valid text. The vault rejects gibberish."})
            return
        with _lock:
            with QUIRKS_FILE.open("a", encoding="utf-8") as f:
                f.write(quirk + "\n")
        self._send_json(200, {"ok": True})


def main():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"rps-tyranny listening on http://{HOST}:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
