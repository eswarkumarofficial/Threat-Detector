from flask import Flask, request, jsonify, render_template
from werkzeug.utils import secure_filename
import requests
import socket
import re
import time
import dns.resolver  # pip install dnspython

app = Flask(__name__)

# API Keys (replace with your own)
IPINFO_TOKEN = 'API'
ABUSEIPDB_KEY = 'API'
VT_KEY = 'API'

def is_ip(address):
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", address) is not None

def resolve_domain(domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        return answers[0].to_text()
    except Exception as e:
        print(f"[DNS ERROR] Could not resolve {domain}: {e}")
        return None

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/lookup", methods=["POST"])
def lookup():
    data = request.json
    query = data.get("query")

    results = {
        "query": query,
        "ip": None,
        "domain": None,
        "is_malicious": False,
        "ipinfo": {},
        "abuseipdb": {},
        "virustotal": [],
        "summary": {
            "malicious": 0,
            "clean": 0,
            "suspicious": 0,
            "undetected": 0
        }
    }

    try:
        if is_ip(query):
            ip = query
            domain = None
        else:
            ip = resolve_domain(query)
            domain = query
            if not ip:
                return jsonify({"error": f"Could not resolve domain: {query}"}), 400

        results["ip"] = ip
        results["domain"] = domain

        # IPInfo
        ipinfo_url = f"https://ipinfo.io/{ip}?token={IPINFO_TOKEN}"
        ipinfo_resp = requests.get(ipinfo_url)
        results["ipinfo"] = ipinfo_resp.json()

        # AbuseIPDB
        headers_abuse = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
        abuse_url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        abuse_resp = requests.get(abuse_url, headers=headers_abuse)
        abuse_data = abuse_resp.json().get("data", {})
        results["abuseipdb"] = abuse_data

        if abuse_data.get("abuseConfidenceScore", 0) >= 50:
            results["summary"]["malicious"] += 1
            results["is_malicious"] = True
        else:
            results["summary"]["clean"] += 1

        # VirusTotal
        headers_vt = {"x-apikey": VT_KEY}
        vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}" if is_ip(query) else f"https://www.virustotal.com/api/v3/domains/{query}"
        vt_resp = requests.get(vt_url, headers=headers_vt)
        vt_data = vt_resp.json()

        analysis_results = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_results", {})
        filtered_results = []

        for engine_name, details in analysis_results.items():
            category = details.get("category", "undetected")
            result = details.get("result")
            filtered_results.append({
                "engine_name": engine_name,
                "category": category,
                "result": result
            })

            if category == "malicious":
                results["summary"]["malicious"] += 1
            elif category == "undetected":
                results["summary"]["undetected"] += 1
            elif category == "suspicious":
                results["summary"]["suspicious"] += 1
            else:
                results["summary"]["clean"] += 1

        results["virustotal"] = filtered_results

        if results["summary"]["malicious"] > 0:
            results["is_malicious"] = True

    except Exception as e:
        results["error"] = str(e)

    return jsonify(results)

@app.route("/scan-file", methods=["POST"])
def scan_file():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    try:
        files = {"file": (secure_filename(file.filename), file.stream)}
        headers = {"x-apikey": VT_KEY}
        upload_url = "https://www.virustotal.com/api/v3/files"
        upload_resp = requests.post(upload_url, files=files, headers=headers)
        upload_data = upload_resp.json()

        data_id = upload_data.get("data", {}).get("id")
        if not data_id:
            return jsonify({"error": "Failed to upload file"}), 500

        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{data_id}"
        time.sleep(15)
        analysis_resp = requests.get(analysis_url, headers=headers)
        analysis_data = analysis_resp.json()

        stats = analysis_data.get("data", {}).get("attributes", {}).get("stats", {})
        malicious_count = stats.get("malicious", 0)
        sha256 = analysis_data.get("meta", {}).get("file_info", {}).get("sha256", "unknown")

        return jsonify({
            "sha256": sha256,
            "malicious_count": malicious_count,
            "malicious": malicious_count > 0
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)
