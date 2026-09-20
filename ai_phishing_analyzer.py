#!/usr/bin/env python3
"""
AI-Enhanced Phishing Email Analyzer - COMPLETE (single file)
============================================================
Everything in one runnable script:

  1. Deterministic analyzer  -> scores any .eml/.txt email out of 100
  2. AI explanation layer    -> sends the findings to a LOCAL Ollama model
                                (llama3.2) which writes a Tier-1 SOC analyst
                                explanation. No cloud AI, works offline.

RUN IT:
    python ai_phishing_analyzer.py samples\\phishing_sample.eml
    python ai_phishing_analyzer.py samples\\phishing_sample.eml --json
    python ai_phishing_analyzer.py samples\\phishing_sample.eml --no-ai
    python ai_phishing_analyzer.py samples\\phishing_sample.eml --model llama3.2:3b

REQUIREMENTS:
    Python 3 only (no pip installs - standard library only).
    For the AI explanation: install Ollama (ollama.com) and run
        ollama pull llama3.2
    The analyzer works WITHOUT Ollama too (it just skips the AI part).
"""

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime
from difflib import SequenceMatcher
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse

# ============================================================================
# CONFIGURATION
# ============================================================================

OLLAMA_BASE_URL = "http://127.0.0.1:11434"
OLLAMA_GENERATE_URL = f"{OLLAMA_BASE_URL}/api/generate"
OLLAMA_TAGS_URL = f"{OLLAMA_BASE_URL}/api/tags"
DEFAULT_MODEL = "llama3.2"

# Category weights (must sum to 100)
WEIGHTS = {
    "Authentication": 30,
    "Domain Reputation": 20,
    "URL Analysis": 20,
    "Content/NLP": 20,
    "Structural": 10,
}

TRUSTED_BRANDS = [
    "paypal", "apple", "google", "microsoft", "amazon", "netflix",
    "facebook", "instagram", "whatsapp", "linkedin", "twitter", "x",
    "chase", "wellsfargo", "citibank", "hsbc", "icici", "hdfcbank",
    "sbi", "axisbank", "dhl", "fedex", "ups", "usps",
]

BAD_TLDS = [".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".icu", ".rest"]

SHORTENERS = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "buff.ly",
              "rebrand.ly", "cutt.ly", "shorturl.at", "ow.ly"]

URGENCY_PHRASES = [
    "urgent", "immediately", "within 24 hours", "within 48 hours", "act now",
    "final notice", "last warning", "account suspended", "account locked",
    "verify your account", "confirm your identity", "unusual activity",
    "unauthorized access", "suspend", "limited time", "expires today",
    "failure to", "legal action", "prosecuted", "arrest warrant",
    "update your payment", "payment declined", "won a prize", "you have won",
    "claim your", "click here to verify",
]

CREDENTIAL_BAIT = ["login", "log-in", "signin", "sign-in", "verify", "confirm",
                   "update", "secure", "account", "password", "wallet"]

RISKY_ATTACHMENTS = [".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".jar",
                     ".ps1", ".msi", ".zip", ".rar", ".iso", ".html"]

# ============================================================================
# PART 1 - DETERMINISTIC ANALYZER
# ============================================================================

def _domain_of(address):
    """Extract domain from an email address like 'Name <user@domain.com>'."""
    if not address:
        return ""
    m = re.search(r"@([A-Za-z0-9.-]+)", address)
    return m.group(1).lower() if m else ""


def _extract_links(text):
    """Pull every http/https link out of a text body."""
    return re.findall(r'https?://[^\s<>"\')\]]+', text or "")


def _host_of(url):
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _is_ip(host):
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host or ""))


def _looks_like_brand(domain):
    """Fuzzy-match a domain against trusted brands -> (brand, similarity)."""
    core = domain
    for tld in BAD_TLDS + [".com", ".net", ".org", ".in", ".co", ".info", ".online", ".site", ".click"]:
        if core.endswith(tld):
            core = core[: -len(tld)]
    core = core.split(".")[-1]  # last subdomain label is the brand-ish part
    best, score = None, 0.0
    for brand in TRUSTED_BRANDS:
        s = SequenceMatcher(None, core, brand).ratio()
        if s > score:
            best, score = brand, s
    if best and score >= 0.80:
        return best, round(score, 2)
    return None, 0.0


def analyze(path):
    """Run all 5 checks on an email file. Returns a result dict."""
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    subject = str(msg.get("Subject", ""))
    from_raw = str(msg.get("From", ""))
    reply_to = str(msg.get("Reply-To", ""))
    auth_results = str(msg.get("Authentication-Results", ""))

    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body += part.get_content()
    else:
        try:
            body = msg.get_content()
        except Exception:
            body = ""

    from_domain = _domain_of(from_raw)
    text = f"{subject}\n{body}"

    indicators = []   # master list of everything found
    groups = {}       # category -> points earned

    def add(category, name, reason, points, severity, evidence_text=""):
        indicators.append({
            "name": name, "category": category, "severity": severity,
            "points": points, "reason": reason, "evidence": evidence_text,
        })
        groups[category] = min(WEIGHTS[category], groups.get(category, 0) + points)

    # ---- Check 1: Authentication (SPF / DKIM / DMARC) -------------------
    for mech, pts in (("spf", 15), ("dkim", 10), ("dmarc", 10)):
        m = re.search(rf"\b{mech}\s*=\s*(\w+)", auth_results, re.I)
        if m and m.group(1).lower() in ("fail", "softfail"):
            add("Authentication", f"{mech.upper()} Fail",
                f"{mech.upper()} failed - sender not authorized by the domain's DNS records",
                pts, "high", f"{mech}={m.group(1).lower()}")

    # ---- Check 2: Domain Reputation -------------------------------------
    domains = [from_domain] + [_host_of(u) for u in _extract_links(text)]
    seen_domains = set()
    for d in domains:
        if not d or d in seen_domains:
            continue
        seen_domains.add(d)
        if _is_ip(d):
            add("Domain Reputation", "IP-as-Domain",
                "Raw IP address used instead of a domain name", 8, "medium", d)
            continue
        brand, sim = _looks_like_brand(d)
        if brand:
            add("Domain Reputation", "Typosquat / Lookalike",
                f"'{d}' closely mimics the brand '{brand}' ({int(sim*100)}% similar)",
                13, "high", d)
        if any(d.endswith(t) for t in BAD_TLDS):
            add("Domain Reputation", "High-Abuse TLD",
                f"'{d}' uses a cheap, abuse-friendly TLD often used by scammers",
                7, "medium", d)

    # ---- Check 3: URL Analysis ------------------------------------------
    for url in _extract_links(text):
        host = _host_of(url)
        if not host:
            continue
        if any(s in host for s in SHORTENERS):
            add("URL Analysis", "URL Shortener",
                f"Shortened URL '{url}' hides the real destination",
                8, "medium", url)
        if _is_ip(host):
            add("URL Analysis", "IP in URL", f"URL points to raw IP '{host}'",
                8, "high", url)
        if "@" in url:
            add("URL Analysis", "@ Trick in URL",
                "'@' in URL redirects the click to the part AFTER the @ symbol",
                10, "high", url)
        if host.count(".") >= 3 and not _is_ip(host):
            add("URL Analysis", "Deep Subdomains",
                f"'{host}' chains 3+ subdomains - a classic hiding technique",
                5, "low", host)
        low = url.lower()
        if any(w in low for w in CREDENTIAL_BAIT) and brand_hint(low):
            add("URL Analysis", "Credential-Bait Path",
                f"Link '{url}' asks for account/login action while impersonating a brand",
                5, "high", url)

    # ---- Check 4: Content / NLP -----------------------------------------
    hits = [p for p in URGENCY_PHRASES if p in text.lower()]
    if hits:
        add("Content/NLP", "Urgency / Pressure Language",
            f"{len(hits)} urgency phrase(s) found - panic is a manipulation tactic",
            min(10, 4 + 2 * len(hits)), "high", "; ".join(hits[:5]))
    money = re.findall(r"[$€£]\s?\d[\d,]*(?:\.\d{2})?", text)
    if money:
        add("Content/NLP", "Financial Lure",
            f"Money amount(s) {', '.join(money[:3])} used to trigger panic/ greed",
            5, "medium", ", ".join(money[:3]))
    words = re.findall(r"\b[A-Z]{4,}\b", text)
    if len(words) >= 3:
        add("Content/NLP", "Excessive Capitalization",
            f"{len(words)} ALL-CAPS words - shouting to create panic",
            4, "low", " ".join(words[:5]))
    if re.search(r"\bDear\s+(Customer|User|Member|Client)\b", text, re.I):
        add("Content/NLP", "Generic Greeting",
            "'Dear Customer/User' - mass-mailed, not personally addressed",
            3, "low", "Dear Customer/User/Member")

    # ---- Check 5: Structural --------------------------------------------
    display = re.sub(r"<[^>]+>", "", from_raw).strip().strip('"')
    if display and from_domain:
        display_brands = [b for b in TRUSTED_BRANDS if b in display.lower()]
        if display_brands and display_brands[0] not in from_domain:
            add("Structural", "Display-Name Spoofing",
                f"Display name says '{display}' but domain is '{from_domain}'",
                6, "high", from_raw)
    if reply_to and _domain_of(reply_to) and _domain_of(reply_to) != from_domain:
        add("Structural", "Reply-To Mismatch",
            f"Replies go to '{_domain_of(reply_to)}' instead of the sender domain",
            4, "medium", reply_to)
    for part in msg.walk():
        fn = (part.get_filename() or "").lower()
        if fn and any(fn.endswith(e) for e in RISKY_ATTACHMENTS):
            add("Structural", "Risky Attachment",
                f"Attachment '{fn}' can carry malware", 8, "high", fn)

    score = sum(groups.values())
    if score <= 14:
        level = "CLEAN"
    elif score <= 34:
        level = "LOW"
    elif score <= 59:
        level = "MEDIUM"
    else:
        level = "HIGH RISK"

    urls = [{"url": u, "host": _host_of(u)} for u in _extract_links(text)]
    summary = f"{level}: score {score}/100, {len(indicators)} indicator(s) across {len(groups)} categories."

    return {
        "file": path,
        "analyzed_at": datetime.now().isoformat(timespec="seconds"),
        "subject": subject,
        "sender": {"sender": display_name(from_raw), "email": from_raw, "domain": from_domain},
        "risk_score": score,
        "risk_level": level,
        "category_scores": groups,
        "category_max": WEIGHTS,
        "urls": urls,
        "indicators": indicators,
        "summary": summary,
    }


def brand_hint(text):
    return any(b in text for b in TRUSTED_BRANDS)


def display_name(raw):
    return re.sub(r"<[^>]+>", "", raw or "").strip().strip('"')


# ============================================================================
# PART 2 - AI EXPLANATION LAYER (local Ollama - no cloud, no pip installs)
# ============================================================================

def get_installed_models(timeout=3):
    """Return locally installed Ollama model names, or [] if unreachable."""
    try:
        req = urllib.request.Request(OLLAMA_TAGS_URL, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        return [m.get("name") for m in payload.get("models", []) if m.get("name")]
    except Exception:
        return []


def ollama_available(timeout=3):
    return bool(get_installed_models(timeout=timeout))


def build_analyst_prompt(result):
    """
    Build a constrained prompt from the deterministic analysis.
    The model is told NOT to invent evidence and NOT to override the score.
    """
    evidence = [{
        "name": i.get("name"), "category": i.get("category"),
        "severity": i.get("severity"), "points": i.get("points"),
        "reason": i.get("reason"), "evidence": i.get("evidence"),
    } for i in result.get("indicators", [])]

    sender = result.get("sender", {})

    return f"""
You are a Tier-1 SOC analyst assistant.

Your job is to explain an existing deterministic phishing-email
analysis to a cybersecurity analyst.

IMPORTANT RULES:
- Do not invent indicators.
- Do not invent URLs, domains, headers, or sender information.
- Do not claim that the message is definitely malicious.
- Do not change or override the deterministic risk score.
- Clearly distinguish observed evidence from analyst recommendations.
- Keep the explanation concise and professional.
- Use only the supplied analysis data.

DETERMINISTIC ANALYSIS
Risk score: {result.get("risk_score", 0)}/100
Risk level: {result.get("risk_level", "Unknown")}

SENDER
Displayed sender: {sender.get("sender", "")}
Sender email: {sender.get("email", "")}
Sender domain: {sender.get("domain", "")}

URLS
{json.dumps(result.get("urls", []), indent=2)}

DETECTED INDICATORS
{json.dumps(evidence, indent=2)}

EXISTING SUMMARY
{result.get("summary", "")}

Provide the following sections:

1. ANALYST SUMMARY
Explain in 2-4 sentences why the message received its current risk level.

2. KEY RED FLAGS
List the most important observed indicators and briefly explain their significance.

3. INVESTIGATION PRIORITIES
Give 3-5 concrete checks a SOC analyst should perform next.

4. USER ACTION
State what the recipient should avoid doing until verification is complete.

5. CONFIDENCE AND LIMITATIONS
Explain that this is a rule-based analysis and that the LLM is only
providing an explanation. Mention important missing controls such as
SPF/DKIM/DMARC validation, live URL reputation, attachment analysis,
or sandboxing where appropriate.

Do not use markdown tables.
"""


def explain_with_ollama(result, model=DEFAULT_MODEL, timeout=90, verbose=True):
    """
    Ask the local Ollama model to explain the analysis.
    Returns the explanation text, or None if anything fails.
    """
    prompt = build_analyst_prompt(result)
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.2},
    }
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        OLLAMA_GENERATE_URL, data=body,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8")).get("response", "").strip()
    except urllib.error.HTTPError as e:
        if verbose:
            print(f"\n[AI] Ollama HTTP error {e.code}: {e.reason} (model '{model}' not found? Run: ollama pull {model})")
    except Exception as e:
        if verbose:
            print(f"\n[AI] Ollama unavailable ({type(e).__name__}). Deterministic report above is still valid.")
    return None


# ============================================================================
# PART 3 - REPORTING
# ============================================================================

def print_report(result, ai_text=None):
    bar_len = 10
    line = "=" * 66
    print(line)
    print("  AI-ENHANCED PHISHING EMAIL ANALYZER  |  SOC Triage Report")
    print(line)
    print(f"  File      : {result['file']}")
    print(f"  From      : {result['sender']['email']}")
    print(f"  Subject   : {result['subject']}")
    print()
    print("  RISK BREAKDOWN")
    for cat, maxpts in WEIGHTS.items():
        pts = result["category_scores"].get(cat, 0)
        filled = round(pts / maxpts * bar_len) if maxpts else 0
        print(f"  {cat:<20} [{ '#' * filled}{'-' * (bar_len - filled)}] {pts:>2} / {maxpts} pts")
    print()
    if result["indicators"]:
        print("  EVIDENCE")
        for i in result["indicators"]:
            tag = "HIGH" if i["severity"] == "high" else ("MED " if i["severity"] == "medium" else "LOW ")
            print(f"  [{tag}] {i['name']}: {i['reason']} (+{i['points']})")
            if i.get("evidence"):
                print(f"         evidence: {i['evidence']}")
        print()
    print(f"  TOTAL RISK SCORE : {result['risk_score']} / 100")
    verdict = {"CLEAN": "CLEAN - no significant phishing indicators detected.",
               "LOW": "LOW RISK - minor indicators present, monitor.",
               "MEDIUM": "MEDIUM RISK - suspicious, verify before acting.",
               "HIGH RISK": "HIGH RISK - likely phishing. Quarantine & report."}
    print(f"  VERDICT          : {verdict[result['risk_level']]}")
    if ai_text:
        print()
        print("=" * 66)
        print("  AI SOC ANALYST EXPLANATION (local Ollama - advisory only)")
        print("=" * 66)
        print(ai_text)


# ============================================================================
# PART 4 - CLI ENTRY POINT
# ============================================================================

def main():
    ap = argparse.ArgumentParser(
        description="AI-Enhanced Phishing Email Analyzer (deterministic + local Ollama AI)")
    ap.add_argument("email_file", help="Path to a .eml or .txt email file")
    ap.add_argument("--json", action="store_true", help="Also save a JSON report next to the email")
    ap.add_argument("--no-ai", action="store_true", help="Skip the Ollama AI explanation")
    ap.add_argument("--model", default=DEFAULT_MODEL, help=f"Ollama model (default: {DEFAULT_MODEL})")
    args = ap.parse_args()

    try:
        result = analyze(args.email_file)
    except FileNotFoundError:
        print(f"ERROR: file not found: {args.email_file}")
        sys.exit(1)

    ai_text = None
    if not args.no_ai:
        models = get_installed_models()
        if models:
            if args.model not in models and f"{args.model}:latest" not in models:
                print(f"[AI] Model '{args.model}' not installed (you have: {', '.join(models)}). Using: {models[0]}")
                args.model = models[0]
            ai_text = explain_with_ollama(result, model=args.model)
        else:
            print("\n[AI] Ollama not running or not installed - skipping AI explanation.")
            print("[AI] To enable: install Ollama, then run:  ollama pull llama3.2")

    print_report(result, ai_text)

    if args.json:
        out = re.sub(r"\.(eml|txt)$", "", args.email_file, flags=re.I) + "_report.json"
        with open(out, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
        print(f"\n  JSON report saved: {out}")


if __name__ == "__main__":
    main()
