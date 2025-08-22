import tkinter as tk
from tkinter import messagebox, ttk
from urllib.parse import urlparse
import ipaddress
import re

# -----------------------------
# Heuristic phishing checks
# -----------------------------
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "billing",
    "signin", "webscr", "password", "reset", "confirm"
]

SUSPICIOUS_TLDS = [
    # Not "bad" by themselves, but commonly abused in spam/phishing.
    "xyz", "top", "gq", "tk", "ml", "ga", "cf", "zip", "cam", "work", "support"
]

URL_LENGTH_WARN = 75
URL_LENGTH_HIGH = 120

def normalize_url(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        return raw
    # Add scheme if missing to help the parser
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        raw = "http://" + raw
    return raw

def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

def count_subdomains(host: str) -> int:
    # Simple split; no external libs needed
    if not host:
        return 0
    parts = host.split(".")
    return max(0, len(parts) - 2)  # everything before domain + TLD

def get_tld(host: str) -> str:
    # Very rough TLD grab (last label)
    if not host or "." not in host:
        return ""
    return host.rsplit(".", 1)[-1].lower()

def suspicious_score(url: str):
    reasons = []
    score = 0

    parsed = urlparse(url)
    host = parsed.hostname or ""
    scheme = parsed.scheme.lower()
    path = parsed.path or ""
    query = parsed.query or ""
    port = parsed.port

    # 1) Very long URLs
    if len(url) > URL_LENGTH_HIGH:
        score += 2
        reasons.append(f"Very long URL ({len(url)} chars).")
    elif len(url) > URL_LENGTH_WARN:
        score += 1
        reasons.append(f"Long URL ({len(url)} chars).")

    # 2) HTTP instead of HTTPS
    if scheme == "http":
        score += 2
        reasons.append("Uses HTTP (not HTTPS).")

    # 3) '@' in URL
    if "@" in url:
        score += 3
        reasons.append("Contains '@' (may hide real destination).")

    # 4) IP address as hostname
    if host and is_ip(host):
        score += 3
        reasons.append("IP address used as hostname.")

    # 5) Many subdomains (e.g., a.b.c.d.example.com)
    subs = count_subdomains(host)
    if subs >= 3:
        score += 2
        reasons.append(f"Many subdomains ({subs}).")
    elif subs == 2:
        score += 1
        reasons.append(f"Multiple subdomains ({subs}).")

    # 6) Hyphenated domains
    hyphens = host.count("-")
    if hyphens >= 4:
        score += 2
        reasons.append(f"Many hyphens in domain ({hyphens}).")
    elif hyphens >= 2:
        score += 1
        reasons.append(f"Hyphens in domain ({hyphens}).")

    # 7) Punycode (IDN) — often used to mimic brands (not always bad)
    if "xn--" in host:
        score += 2
        reasons.append("Punycode/IDN detected in domain (xn--).")

    # 8) Suspicious TLDs (not inherently malicious, but a small signal)
    tld = get_tld(host)
    if tld in SUSPICIOUS_TLDS:
        score += 1
        reasons.append(f"TLD '.{tld}' is commonly abused.")

    # 9) Suspicious keywords in path/query
    lowered = (path + "?" + query).lower()
    hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in lowered]
    if hits:
        score += min(2, len(hits))  # cap contribution
        reasons.append(f"Suspicious keywords found: {', '.join(sorted(set(hits)))}.")

    # 10) Encoded characters / heavy query usage
    if "%" in url and len(re.findall(r"%[0-9A-Fa-f]{2}", url)) >= 3:
        score += 1
        reasons.append("Multiple encoded characters in URL.")
    if query.count("&") + query.count("=") >= 6:
        score += 1
        reasons.append("Very complex query parameters.")

    # 11) Non-standard port
    if port and port not in (80, 443):
        score += 1
        reasons.append(f"Non-standard port used (: {port}).")

    # Final verdict thresholds
    if score >= 7:
        verdict = "⚠️ Likely PHISHING"
        level = "high"
    elif score >= 4:
        verdict = "🟡 Suspicious"
        level = "medium"
    else:
        verdict = "✅ Likely Safe"
        level = "low"

    return verdict, level, score, reasons


# -----------------------------
# GUI
# -----------------------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Simple Phishing URL Checker")
        self.geometry("680x420")
        self.minsize(640, 400)

        # Title
        title = tk.Label(self, text="Phishing URL Checker", font=("Segoe UI", 16, "bold"))
        title.pack(pady=(14, 6))

        # URL input
        row = tk.Frame(self)
        row.pack(fill="x", padx=16)

        tk.Label(row, text="Paste URL:", font=("Segoe UI", 11)).pack(side="left")
        self.url_var = tk.StringVar()
        self.entry = tk.Entry(row, textvariable=self.url_var, font=("Segoe UI", 11))
        self.entry.pack(side="left", fill="x", expand=True, padx=8)
        self.entry.focus_set()

        # Buttons
        btns = tk.Frame(self)
        btns.pack(fill="x", padx=16, pady=8)

        self.check_btn = ttk.Button(btns, text="Check URL", command=self.on_check)
        self.check_btn.pack(side="left")

        self.clear_btn = ttk.Button(btns, text="Clear", command=self.on_clear)
        self.clear_btn.pack(side="left", padx=8)

        # Verdict badge
        self.verdict_label = tk.Label(self, text="Verdict will appear here", font=("Segoe UI", 13, "bold"),
                                      bd=1, relief="solid", padx=10, pady=6)
        self.verdict_label.pack(fill="x", padx=16, pady=(4, 8))

        # Details box
        tk.Label(self, text="Why this verdict:", font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=16)
        self.details = tk.Text(self, height=10, font=("Consolas", 10), wrap="word")
        self.details.pack(fill="both", expand=True, padx=16, pady=(4, 12))
        self.details.configure(state="disabled")

        # Footer hint
        hint = tk.Label(self, text="Tip: This is a simple heuristic checker. It may be wrong. "
                                   "Don’t enter passwords into sites you’re unsure about.",
                        font=("Segoe UI", 9), fg="#666")
        hint.pack(pady=(0, 10))

        # ttk theme (nice buttons)
        try:
            self.style = ttk.Style(self)
            if "vista" in self.style.theme_names():
                self.style.theme_use("vista")
        except Exception:
            pass

    def color_for_level(self, level: str):
        if level == "high":
            return "#ffefef", "#a40000"  # light red bg, dark red text
        if level == "medium":
            return "#fff8e5", "#8a5a00"  # light yellow bg, brown text
        return "#eaffea", "#0f6a00"     # light green bg, green text

    def on_check(self):
        raw = self.url_var.get().strip()
        if not raw:
            messagebox.showinfo("No URL", "Please paste a URL to check.")
            return

        url = normalize_url(raw)
        verdict, level, score, reasons = suspicious_score(url)

        bg, fg = self.color_for_level(level)
        self.verdict_label.config(text=f"{verdict}  (Score: {score})", bg=bg, fg=fg)

        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("end", f"Checked URL: {url}\n\n")
        if reasons:
            for i, r in enumerate(reasons, 1):
                self.details.insert("end", f"{i}. {r}\n")
        else:
            self.details.insert("end", "No obvious red flags found based on simple checks.\n")
        self.details.configure(state="disabled")

    def on_clear(self):
        self.url_var.set("")
        self.verdict_label.config(text="Verdict will appear here", bg=self.cget("bg"), fg="black")
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.configure(state="disabled")


if __name__ == "__main__":
    App().mainloop()

