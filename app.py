from flask import Flask, request, render_template
import csv
import requests
from datetime import datetime

def is_reachable(url):
    try:
        response = requests.get(url, timeout=5)
        return response.status_code < 400
    except requests.RequestException:
        return False
    
app = Flask(__name__)

def is_phishing(url):
    suspicious_keywords = ['login', 'secure', 'update', 'verify', 'bank']
    return any(keyword in url.lower() for keyword in suspicious_keywords)

def log_report(url, result):
    print(f"Logging: {url} => {result}")  # Debug
    with open('phishing_reports.csv', mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([datetime.now(), url, result])

@app.route('/')
def index():
    return render_template('index.html')
def check_with_virustotal(url):
    headers = {
        "x-apikey": "047673d4aa55dfb43497a72b4f70d126fc38b9bac2a4abaeace83275ea370699"
    }

    data = {'url': url}
    scan_response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=data)
    
    if scan_response.status_code != 200:
        return "Error: Unable to submit URL to VirusTotal."

    scan_id = scan_response.json()['data']['id']
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
    analysis_response = requests.get(analysis_url, headers=headers)

    if analysis_response.status_code != 200:
        return "Error: Unable to get analysis from VirusTotal."

    result_data = analysis_response.json()
    stats = result_data['data']['attributes']['stats']
    
    print("VirusTotal Scan Stats:", stats)

    if stats['malicious'] > 0 or stats['suspicious'] > 0:
        return "Phishing"
    else:
        return "Safe"

@app.route("/check", methods=["POST"])
def check():
    url = request.form['url']

    # OPTIONAL: Show warning if unreachable (but continue)
    if not is_reachable(url):
        print("⚠️ URL is unreachable, but continuing to scan with VirusTotal...")

    virustotal_result = check_with_virustotal(url)

# Use both: VirusTotal + your keyword check
    if virustotal_result == "Phishing" or is_phishing(url):
        result = "Phishing"
    else:
        result = "Safe"

    log_report(url, result)
    return render_template('index.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)




def log_report(url, result):
    print(f"Logging: {url} => {result}")  # 👈 This will show in terminal
    with open('phishing_reports.csv', mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([datetime.now(), url, result])
def get_phishtank_urls():
    # PhishTank API URL for JSON feed (no key needed for public data, but limited)
    url = "https://data.phishtank.com/data/online-valid.json"

    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        urls = [entry['url'] for entry in data['urls']]
        return urls
    else:
        print("Failed to fetch data:", response.status_code)
        return []

if __name__ == "__main__":
    phishing_urls = get_phishtank_urls()
    print("Sample phishing URLs:")
    for url in phishing_urls[:5]:
        print(url)
