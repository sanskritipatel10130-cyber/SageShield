from flask import Flask, request, jsonify
from flask_cors import CORS
from html import escape
import re

# 1. INITIALIZE APP FIRST
app = Flask("phishing_detector")
CORS(app)  # Allows Chrome Extension connections

def check_email(emailtext):
    # Normalize whitespaces and newlines into single spaces to avoid regex breaking
    clean_email = re.sub(r'\s+', ' ', emailtext).strip().lower()

    suspicious_words = [
        # Urgency & Typos
        "urgent", "immediately", "immediatly", "act now", "final warning", 
        "last chance", "time sensitive", "response required", "required action",
        "take action", "within 24 hours", "within 48 hours", "important notice",
        "attention", "limited time", "expires today", "deadline",

        # Verification & Auth
        "verify", "verification", "confirm", "confirmation", "confirm your account",
        "verify your account", "verify your identity", "authenticate", "validation",
        "login", "log in", "sign in", "password", "reset password", "security alert",
        "account suspended", "account locked", "unusual activity", "unauthorized access",
        "one-time password", "otp", "2fa", "mfa",

        # Actions & Links
        "click here", "click below", "follow this link", "download attachment",
        "open attachment", "attached file", "attached invoice", "attached document",

        # Financial & High Risk (Single keywords + Full phrases)
        "give me", "credit card", "credit", "card", "debit card", "debit", "cvv", 
        "bank account", "bank", "banking", "routing number", "account number", 
        "payment", "payment failed", "update payment", "billing", "invoice", "refund", 
        "tax refund", "wire transfer", "direct deposit", "financial information",

        # Scam Personas & Keywords (Catch individual root words too)
        "nigerian prince", "nigerian", "prince", "foreign prince", "royal family", 
        "inheritance", "widow inheritance", "foreign inheritance", "winner", 
        "you have won", "congratulations", "claim your prize", "prize", "lottery", 
        "jackpot", "cash reward", "unclaimed funds", "beneficiary", "business proposal", 

        # Crypto & Gift Cards
        "bitcoin", "crypto", "cryptocurrency", "ethereum", "wallet", "seed phrase",
        "gift card", "apple gift card", "amazon gift card",

        # Impersonation & Security
        "paypal", "amazon", "microsoft", "apple", "google", "netflix", "irs",
        "social security", "ssn", "delivery failed", "tracking number", "fedex",
        "ups", "usps", "dhl", "virus detected", "your computer is infected",
        "technical support",

        # Generic Suspicious Phrases
        "dear customer", "dear valued customer", "kindly", "please kindly",
        "your mailbox is full", "avoid suspension", "avoid legal action",
        "work from home", "romance scam", "sugar daddy", "western union", "moneygram"
    ]

    found_words = []

    # Use regex word boundaries on normalized text
    for word in suspicious_words:
        pattern = r"\b" + re.escape(word) + r"\b"
        if re.search(pattern, clean_email):
            found_words.append(word)

    # Base score calculation
    score = 15 + (len(found_words) * 15)

    # High-Risk Combination Checks
    has_scam_identity = any(w in found_words for w in ["nigerian prince", "nigerian", "prince", "foreign prince", "royal family", "inheritance"])
    has_urgency = any(w in found_words for w in ["urgent", "immediately", "immediatly", "act now", "take action"])
    has_finance = any(w in found_words for w in ["credit card", "credit", "card", "bank account", "bank", "ssn", "give me", "debit"])

    # High-risk combinations trigger major score boosts
    if has_scam_identity:
        score += 45
    if has_urgency and has_finance:
        score += 35
    if has_finance and "give me" in found_words:
        score += 30

    if "http://" in clean_email or "https://" in clean_email:
        score += 20
        found_words.append("a link")

    # Keep score bounded between 0 and 95%
    score = min(max(score, 0), 95)
    
    # Deduplicate matching results for clean output
    unique_words = list(set(found_words))

    print("Found signals:", unique_words)
    return score, unique_words

def highlight_email(emailtext, found_words):
    safe_email = escape(emailtext)

    # Sort keywords by length so longer phrases get highlighted first
    for word in sorted(set(found_words), key=len, reverse=True):
        if word != "a link":
            safe_email = re.sub(
                r"\b" + re.escape(word) + r"\b",
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
    hearts = min(max(hearts, 1), 5)
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
            reasons += f"<li>Suspicious signal found: {word}</li>"
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

# 2. DEFINE ROUTES AFTER 'app' INITIALIZATION
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

# 3. ROUTE FOR CHROME EXTENSION
@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    data = request.get_json() or {}
    emailtext = data.get("emailText", "").strip()

    if not emailtext:
        return jsonify({"error": "Please provide email text."}), 400

    score, found_words = check_email(emailtext)

    hearts = round(score / 20)
    hearts = min(max(hearts, 1), 5)
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
