from flask import Flask, render_template, request, jsonify
import subprocess, re
from pathlib import Path
import joblib

app = Flask(__name__)
MODEL_PATH = Path("model/wifi_risk_model.joblib")
model = joblib.load(MODEL_PATH) if MODEL_PATH.exists() else None
FEATURES = ["open_network", "weak_security", "hidden_ssid", "low_signal", "suspicious_name"]

def scan_wifi_windows():
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True, text=True, encoding="utf-8", errors="ignore", timeout=10
        )
        output = result.stdout
        networks, current = [], None

        for raw in output.splitlines():
            line = raw.strip()
            m = re.match(r"^SSID\s+\d+\s*:\s*(.*)$", line, re.I)
            if m:
                current = {
                    "ssid": m.group(1).strip() or "(Hidden Network)",
                    "auth": "Unknown", "encryption": "Unknown",
                    "signal": 0, "channel": "Unknown"
                }
                networks.append(current)
                continue
            if current is None:
                continue
            m = re.match(r"^Authentication\s*:\s*(.*)$", line, re.I)
            if m: current["auth"] = m.group(1).strip(); continue
            m = re.match(r"^Encryption\s*:\s*(.*)$", line, re.I)
            if m: current["encryption"] = m.group(1).strip(); continue
            m = re.match(r"^Signal\s*:\s*(\d+)%", line, re.I)
            if m: current["signal"] = int(m.group(1)); continue
            m = re.match(r"^Channel\s*:\s*(\d+)", line, re.I)
            if m: current["channel"] = int(m.group(1)); continue

        unique = {}
        for n in networks:
            unique.setdefault(n["ssid"], n)
        return list(unique.values()), None
    except Exception as e:
        return [], str(e)

def make_features(n):
    ssid = n.get("ssid", "")
    auth = n.get("auth", "").lower()
    enc = n.get("encryption", "").lower()
    signal = int(n.get("signal", 0) or 0)

    open_network = int("open" in auth or auth in ("", "unknown"))
    weak_security = int(open_network or "wep" in auth or "wep" in enc or "none" in enc)
    hidden_ssid = int(ssid == "(Hidden Network)" or not ssid.strip())
    low_signal = int(signal < 30)
    words = ["free", "freewifi", "free wi-fi", "guest", "public", "airport", "hotel", "cafe", "coffee"]
    suspicious_name = int(open_network and any(w in ssid.lower() for w in words))
    return {
        "open_network": open_network, "weak_security": weak_security,
        "hidden_ssid": hidden_ssid, "low_signal": low_signal,
        "suspicious_name": suspicious_name
    }

def analyze(n):
    f = make_features(n)
    X = [[f[k] for k in FEATURES]]

    if model:
        risk = str(model.predict(X)[0])
        confidence = round(float(max(model.predict_proba(X)[0])) * 100, 1)
    else:
        score = 4*f["open_network"] + 3*f["weak_security"] + f["hidden_ssid"] + f["low_signal"] + 2*f["suspicious_name"]
        risk = "High Risk" if score >= 6 else ("Medium Risk" if score >= 3 else "Low Risk")
        confidence = None

    reasons = []
    if f["open_network"]: reasons.append("Open authentication detected.")
    if f["weak_security"]: reasons.append("Weak or absent encryption detected.")
    if f["hidden_ssid"]: reasons.append("SSID is hidden or unavailable.")
    if f["low_signal"]: reasons.append("Signal strength is low.")
    if f["suspicious_name"]: reasons.append("Network name needs extra verification.")
    if not reasons: reasons.append("No obvious high-risk indicator was detected from available scan data.")

    rec = {
        "Low Risk": "Use normal caution and avoid sharing sensitive information on unfamiliar networks.",
        "Medium Risk": "Verify the network with the venue and avoid sensitive transactions if possible.",
        "High Risk": "Avoid connecting if possible; prefer a trusted network or mobile hotspot."
    }[risk]

    return {**n, "risk": risk, "confidence": confidence, "reasons": reasons, "recommendation": rec}

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/api/scan")
def scan():
    nets, error = scan_wifi_windows()
    if error and not nets:
        return jsonify({"success": False, "error": error}), 500
    return jsonify({"success": True, "networks": [analyze(n) for n in nets]})

@app.route("/api/analyze", methods=["POST"])
def demo():
    data = request.get_json(silent=True) or {}
    n = {
        "ssid": data.get("ssid", "Cafe_Free_WiFi"),
        "auth": data.get("auth", "Open"),
        "encryption": data.get("encryption", "None"),
        "signal": int(data.get("signal", 78)),
        "channel": data.get("channel", "6")
    }
    return jsonify({"success": True, "result": analyze(n)})

if __name__ == "__main__":
    app.run(debug=True)
