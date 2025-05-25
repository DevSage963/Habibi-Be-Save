from flask import Flask, render_template, request
import hashlib
import string
import random
import datetime
import hashlib
import requests

app = Flask(__name__)


# Für Passwort Check: einfache Bewertung
def password_score(pw):
    length = len(pw)
    has_upper = any(c.isupper() for c in pw)
    has_lower = any(c.islower() for c in pw)
    has_digit = any(c.isdigit() for c in pw)
    has_special = any(c in string.punctuation for c in pw)

    score = 0
    if length >= 8:
        score += 3
    elif length >= 5:
        score += 1

    score += has_upper + has_lower + has_digit + has_special
    if score > 10:
        score = 10

    return score, length, has_upper, has_lower, has_digit, has_special


# Knackzeit Beispiel (grobe Abschätzung)
def crack_time_seconds(pw):
    charset_size = 0
    if any(c.islower() for c in pw):
        charset_size += 26
    if any(c.isupper() for c in pw):
        charset_size += 26
    if any(c.isdigit() for c in pw):
        charset_size += 10
    if any(c in string.punctuation for c in pw):
        charset_size += len(string.punctuation)

    length = len(pw)
    if charset_size == 0 or length == 0:
        return 0

    # Bruteforce 1 Milliarde Versuche/Sekunde als Beispiel
    attempts_per_sec = 10 ** 9
    combinations = charset_size ** length
    seconds = combinations / attempts_per_sec
    return seconds


def format_time(seconds):
    if seconds == 0:
        return "Unbekannt"
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, sec = divmod(rem, 60)
    parts = []
    if days > 0:
        parts.append(f"{int(days)} Tage")
    if hours > 0:
        parts.append(f"{int(hours)} Stunden")
    if minutes > 0:
        parts.append(f"{int(minutes)} Minuten")
    if sec > 0:
        parts.append(f"{int(sec)} Sekunden")
    return ", ".join(parts)


# Passwort Generator
def generate_password(length, uppercase, lowercase, digits, special):
    charset = ""
    if uppercase:
        charset += string.ascii_uppercase
    if lowercase:
        charset += string.ascii_lowercase
    if digits:
        charset += string.digits
    if special:
        charset += string.punctuation

    if not charset:
        return ""

    return ''.join(random.choice(charset) for _ in range(length))


# Hash Algorithmen
HASH_ALGOS = ["md5", "sha1", "sha256", "sha512"]

# Datenleck Beispiel (Dummy-Daten)
DATA_LEAKS = {
    "HaveIBeenPwned": 42,
    "RockYou": 1234,
    "Adobe2013": 5,
    "LinkedIn2012": 78
}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/check", methods=["GET", "POST"])
def check():
    password = None
    score = 0
    length = 0
    has_upper = has_lower = has_digit = has_special = False
    crack_time_readable = ""
    if request.method == "POST":
        password = request.form.get("password", "")
        score, length, has_upper, has_lower, has_digit, has_special = password_score(password)
        seconds = crack_time_seconds(password)
        crack_time_readable = format_time(seconds)
    return render_template("check_password.html", password=password, score=score, length=length,
                           has_upper=has_upper, has_lower=has_lower, has_digit=has_digit,
                           has_special=has_special, crack_time_readable=crack_time_readable)


@app.route("/generate", methods=["GET", "POST"])
def generate():
    password = None
    length = 16
    uppercase = lowercase = digits = special = True
    if request.method == "POST":
        length = int(request.form.get("length", 16))
        uppercase = bool(request.form.get("uppercase"))
        lowercase = bool(request.form.get("lowercase"))
        digits = bool(request.form.get("digits"))
        special = bool(request.form.get("special"))
        password = generate_password(length, uppercase, lowercase, digits, special)
    return render_template("generate_password.html", password=password, length=length,
                           uppercase=uppercase, lowercase=lowercase, digits=digits, special=special)


@app.route("/hash", methods=["GET", "POST"])
def hash_tool():
    hashed = None
    text = ""
    selected_algo = "sha256"
    if request.method == "POST":
        text = request.form.get("text", "")
        selected_algo = request.form.get("algorithm", "sha256")
        if selected_algo in HASH_ALGOS:
            h = hashlib.new(selected_algo)
            h.update(text.encode("utf-8"))
            hashed = h.hexdigest()
    return render_template("hash_password.html", hashed=hashed, text=text, algorithms=HASH_ALGOS,
                           selected_algo=selected_algo)


@app.route("/leak", methods=["GET", "POST"])
def leak():
    leak_checked = False
    leak_found = False
    leak_count = 0
    password = ""

    if request.method == "POST":
        leak_checked = True
        password = request.form.get("password", "").strip()

        # SHA-1 Hash des Passworts erstellen
        sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix = sha1_hash[:5]

        try:
            # API-Anfrage an HaveIBeenPwned
            response = requests.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                headers={'User-Agent': 'Habibi-Be-Save Security Check'}
            )

            if response.status_code == 200:
                # Überprüfe alle Hashes aus der Antwort
                for line in response.text.splitlines():
                    suffix, count = line.split(":")
                    if prefix + suffix == sha1_hash:
                        leak_count = int(count)
                        leak_found = True
                        break

        except requests.exceptions.RequestException:
            pass  # Fehlerbehandlung hier einfügen

    return render_template("leak.html",
                           leak_checked=leak_checked,
                           leak_found=leak_found,
                           leak_count=leak_count,
                           password=password)

if __name__ == "__main__":
    app.run(debug=True)
