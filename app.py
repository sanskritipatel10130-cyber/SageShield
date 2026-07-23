from flask import Flask, request, jsonify
from flask_cors import CORS
from html import escape
import re

app = Flask("phishing_detector")
CORS(app)  # <--- THIS IS WHAT ALLOWS CHROME EXTENSIONS TO CONNECT

def check_email(emailtext):
    suspicious_words = [
        "urgent",
        "verify",
        "password",
        "suspended",
        "click here",
        "bank account",
        "act now",
        "winner",
        "gift card",
        "immediately"
    ]

    email_lower = emailtext.lower()
    found_words = []

    for word in suspicious_words:
        if word in email_lower:
            found_words.append(word)

    score = 15 + (len(found_words) * 15)

    if "http://" in email_lower or "https://" in email_lower:
        score = score + 20
        found_words.append("a link")

    if score > 95:
        score = 95

    return score, found_words

def highlight_email(emailtext, found_words):
    safe_email = escape(emailtext)

    for word in found_words:
        if word != "a link":
            safe_word = re.escape(word)

            safe_email = re.sub(
                safe_word,
                lambda match: "<mark>" + match.group(0) + "</mark>",
                safe_email,
                flags=re.IGNORECASE
            )

    safe_email = re.sub(
        r"https?://[^\s<]+",
        lambda match: "<mark>" + match.group(0) + "</mark>",
        safe_email
    )

    return safe_email

def show_result(score, found_words, emailtext):
    hearts = round(score / 20)

    if hearts < 1:
        hearts = 1

    if hearts > 5:
        hearts = 5

    heartline = "♥" * hearts + "♡" * (5 - hearts)

    if score >= 50:
        verdict = "Likely phishing"
        message = "This email contains warning signs often used in phishing attempts."
    else:
        verdict = "Likely legitimate"
        message = "This email has few common phishing warning signs."

    reasons = ""

    if found_words:
        for word in found_words:
            reasons = reasons + "<li>Suspicious signal found: " + word + "</li>"
    else:
        reasons = "<li>No common phishing words or suspicious links were found.</li>"

    highlighted_email = highlight_email(emailtext, found_words)

    return f"""
    <body style="background:#fff7f9; font-family:Trebuchet MS, Arial, sans-serif; text-align:center; padding:60px 20px; color:#58705b;">
      <div style="background:white; max-width:600px; margin:auto; padding:40px; border-radius:24px; border:3px solid #b7cdb8; box-shadow:0 8px 18px #f0d9df;">
        <h1 style="color:#86a889;">Email Safety Result</h1>

        <p style="font-size:26px; color:#eaa1b4;">{heartline}</p>

        <h2>{verdict}</h2>
        <p>{message}</p>

        <p><b>Confidence score: {score}%</b></p>

        <div style="background:#f1f7ef; border-radius:16px; padding:20px; text-align:left; margin-top:25px;">
          <h3>Why was it rated this way?</h3>
          <ul>{reasons}</ul>
        </div>

        <div style="background:#fff7f9; border-radius:16px; padding:20px; text-align:left; margin-top:20px;">
          <h3>Highlighted email</h3>
          <p style="white-space:pre-wrap; line-height:1.6;">{highlighted_email}</p>
        </div>

        <br>

        <a href="/" style="background:#f3b6c5; color:white; text-decoration:none; padding:13px 26px; border-radius:20px; font-weight:bold;">
          Check another email
        </a>
      </div>
    </body>
    """

@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        emailtext = request.form.get("emailText", "").strip()
        file = request.files.get("emailFile")

        if file and file.filename:
            emailtext = file.read().decode("utf-8", errors="ignore")

        if emailtext:
            score, found_words = check_email(emailtext)
            return show_result(score, found_words, emailtext)

        return "Please upload a text file or paste an email first."

    return open("templates/index.html").read()


# --- NEW ROUTE ADDED FOR CHROME EXTENSION ---
@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    data = request.get_json() or {}
    emailtext = data.get("emailText", "").strip()

    if not emailtext:
        return jsonify({"error": "Please provide email text."}), 400

    score, found_words = check_email(emailtext)

    hearts = round(score / 20)
    if hearts < 1:
        hearts = 1
    if hearts > 5:
        hearts = 5
    heartline = "♥" * hearts + "♡" * (5 - hearts)

    if score >= 50:
        verdict = "Likely phishing"
        message = "This email contains warning signs often used in phishing attempts."
    else:
        verdict = "Likely legitimate"
        message = "This email has few common phishing warning signs."

    highlighted = highlight_email(emailtext, found_words)

    return jsonify({
        "score": score,
        "heartline": heartline,
        "verdict": verdict,
        "message": message,
        "found_words": found_words,
        "highlighted_email": highlighted
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
