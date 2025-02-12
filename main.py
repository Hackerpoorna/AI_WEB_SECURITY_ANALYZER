from flask import Flask, request, render_template, flash, redirect, url_for
import os
import subprocess
import requests
import socket

app = Flask(__name__)
app.secret_key = "secure_key"

# Ensure reports directory exists
if not os.path.exists("reports"):
    os.makedirs("reports")

def detect_framework(url):
    """Detects the framework used by the target website."""
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers

        if 'X-Powered-By' in headers:
            return headers['X-Powered-By']
        elif 'wordpress' in response.text.lower():
            return "WordPress"
        elif 'django' in response.text.lower():
            return "Django"
        elif 'laravel' in response.text.lower():
            return "Laravel"
        else:
            return "Unknown Framework"
    except Exception as e:
        return f"Error detecting framework: {str(e)}"

def get_ip_address(url):
    """Resolves the IP address of the target domain."""
    try:
        domain = url.replace('http://', '').replace('https://', '').split('/')[0]
        return socket.gethostbyname(domain)
    except Exception as e:
        return f"Error resolving IP: {str(e)}"

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form.get('url')
    if not url:
        flash("Invalid URL!", "danger")
        return redirect(url_for('home'))

    sanitized_url = url.replace('http://', '').replace('https://', '').replace('/', '_')
    target_domain = url.replace('http://', '').replace('https://', '').split('/')[0]
    report_path = f"reports/{sanitized_url}_report.txt"

    try:
        ip_address = get_ip_address(url)
        nmap_result = subprocess.getoutput(f"nmap -A {target_domain}")
        sqlmap_result = subprocess.getoutput(f"sqlmap -u {url} --batch --level=2 --risk=2")
        framework = detect_framework(url)

        with open(report_path, 'w') as report:
            report.write(f"=== Target Information ===\nIP Address: {ip_address}\n")
            report.write(f"\n=== NMAP SCAN RESULTS ===\n{nmap_result}\n")
            report.write(f"\n=== SQLMAP SCAN RESULTS ===\n{sqlmap_result}\n")
            report.write(f"\n=== FRAMEWORK DETECTION ===\nDetected Framework: {framework}\n")

        flash("Scan Complete! Report Ready.", "success")
        return render_template('result.html', framework=framework, nmap=nmap_result, sqlmap=sqlmap_result, ip_address=ip_address)
    except Exception as e:
        flash(f"An error occurred: {str(e)}", "danger")
        return redirect(url_for('home'))

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')
