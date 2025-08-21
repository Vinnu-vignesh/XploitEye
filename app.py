import subprocess
import requests
from flask import Flask, request, render_template, Response, session, redirect, url_for, send_file
from urllib.parse import urljoin
from fpdf import FPDF
from datetime import datetime
import mysql.connector 
from mysql.connector import Error

import os

app = Flask(__name__)
app.secret_key = "!@#secret123/"


# Define the function to get the database connection
import mysql.connector

def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="exploit",
        password="!@#Mysql123/",
        database="weblock"
    )


# PDF generation function
def generate_pdf_report(username, target_url, scan_results, filename="scan_report.pdf"):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "ExploitEye - Scan Report", ln=True, align="C")

    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 10, f"User: {username}", ln=True)
    pdf.cell(0, 10, f"Target URL: {target_url}", ln=True)
    pdf.cell(0, 10, f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
    pdf.ln(10)

    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Vulnerabilities Detected:", ln=True)
    pdf.ln(5)

    if not scan_results:
        pdf.set_font("Arial", "", 12)
        pdf.multi_cell(0, 10, "No vulnerabilities detected. The target appears secure.")
    else:
        for idx, result in enumerate(scan_results, 1):
            pdf.set_font("Arial", "B", 12)
            pdf.cell(0, 10, f"{idx}. {result['vuln']}", ln=True)
            pdf.set_font("Arial", "", 11)
            pdf.multi_cell(0, 8, f"- Description: {result['description']}")
            pdf.multi_cell(0, 8, f"- Mitigation: {result['mitigation']}")
            pdf.ln(5)

    pdf.output(filename)
    return filename



@app.route("/scan", methods=["POST"])
def scan():
    if "username" not in session:  # Check if the user is logged in
        return redirect(url_for("login"))  # Redirect to login page if not logged in

    url = request.form.get("url")
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    username = session["username"]  # Retrieve the logged-in user's username
    scan_results = []


    # Nmap
    try:
        nmap_output = subprocess.check_output(["nmap", "-sS", "-A", url.split("//")[-1]], universal_newlines=True)
        scan_results.insert(0, {
            "vuln": "Nmap Scan Result",
            "description": nmap_output,
            "mitigation": "Review open ports and disable unnecessary services."
        })

    except Exception as e:
        nmap_output = f"Nmap failed: {str(e)}"

    # SQLi
    try:
        payloads = ["'", "' OR 1=1 --"]
        for payload in payloads:
            test_url = f"{url}?id={payload}"
            response = requests.get(test_url, timeout=5)
            if any(x in response.text.lower() for x in ["sql syntax", "mysql", "syntax error"]):
                scan_results.append({
                    "vuln": "SQL Injection",
                    "description": f"Potential SQL Injection detected using payload: {payload}",
                    "mitigation": "Use parameterized queries to prevent SQL Injection."
                })
                break
    except Exception as e:
        scan_results.append({
            "vuln": "SQL Injection Test Error",
            "description": str(e),
            "mitigation": "Ensure the server is reachable and parameters are correct."
        })

    # XSS
    try:
        xss_payloads = ["<script>alert(1)</script>"]
        for payload in xss_payloads:
            test_url = f"{url}?q={payload}"
            response = requests.get(test_url, timeout=5)
            if payload in response.text:
                scan_results.append({
                    "vuln": "Reflected XSS",
                    "description": f"Reflected XSS detected with payload: {payload}",
                    "mitigation": "Sanitize input and set Content-Security-Policy headers."
                })
                break
    except Exception as e:
        scan_results.append({
            "vuln": "XSS Test Error",
            "description": str(e),
            "mitigation": "Ensure input fields are accessible and test safely."
        })

    # Security headers
    try:
        r = requests.get(url, timeout=5)
        headers = r.headers
        required_headers = {
            "Content-Security-Policy": "Helps mitigate XSS and data injection.",
            "X-Frame-Options": "Prevents clickjacking.",
            "X-Content-Type-Options": "Prevents MIME-type sniffing.",
            "Strict-Transport-Security": "Forces secure HTTPS connections."
        }
        for header, reason in required_headers.items():
            if header not in headers:
                scan_results.append({
                    "vuln": f"Missing Security Header: {header}",
                    "description": f"{header} is missing. {reason}",
                    "mitigation": f"Add the {header} header to all responses."
                })
    except Exception as e:
        scan_results.append({
            "vuln": "Security Headers Check Error",
            "description": str(e),
            "mitigation": "Ensure target is accessible and returns headers."
        })

    # Directory brute force
    try:
        dirs = ["admin", "login", "test"]
        for d in dirs:
            full_url = urljoin(url, d)
            r = requests.get(full_url)
            if r.status_code == 200:
                scan_results.append({
                    "vuln": "Exposed Directory",
                    "description": f"Accessible directory found: {full_url}",
                    "mitigation": "Restrict access using authentication or remove unnecessary folders."
                })
    except Exception as e:
        scan_results.append({
            "vuln": "Directory Brute Force Error",
            "description": str(e),
            "mitigation": "Ensure network connection and valid URL structure."
        })

    # Generate and send PDF report
    if not os.path.exists("reports"):
        os.makedirs("reports")
    filename = f"reports/{username}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    generate_pdf_report(username, url, scan_results, filename)

    return send_file(filename, as_attachment=True)

@app.route("/login", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        conn = get_db_connection()
        if conn is None:
            return "Database connection failed"

        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s", (username, password))
        user = cursor.fetchone()
        conn.close()

        if user:
            session["username"] = username
            return redirect(url_for("home"))
        else:
            return render_template("login.html", error="Invalid credentials.")
    return render_template("login.html")



@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        first_name = request.form.get("first_name")
        last_name = request.form.get("last_name")
        email = request.form.get("email")
        phone = request.form.get("phone")
        dob = request.form.get("birth_date")
        gender = request.form.get("gender")
        username = request.form.get("username")
        password = request.form.get("password")

        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if the username exists
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if user:
            conn.close()
            return render_template("login.html", error="Username already exists.")

        # Insert new user into the database
        cursor.execute("""
            INSERT INTO users (first_name, last_name, email, phone, birth_date, gender, username, password)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (first_name, last_name, email, phone, dob, gender, username, password))

        conn.commit()
        conn.close()
        return redirect(url_for("login"))

    return render_template("signup.html")

@app.route("/")
def home():
    return render_template("test1.html")

@app.route("/aboutUs")
def aboutUs():
    return render_template("aboutUs.html")

@app.route("/help")
def Help():
    return render_template("help.html")

@app.route("/services")
def Services():
    return render_template("/services.html")

@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        # You can access submitted data like this:
        name = request.form.get("name")
        email = request.form.get("email")
        message = request.form.get("message")

        # For now, just print it (or you can save it to MongoDB)
        print(f"Message from {name} ({email}): {message}")
        return render_template("contact.html", success=True)

    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=True)
