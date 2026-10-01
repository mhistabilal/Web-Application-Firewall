import re
import os
import sqlite3
import requests
from datetime import datetime
from flask import Flask, request, Response, render_template, redirect, url_for, session, flash

app = Flask(__name__)
app.secret_key = 'abu_zaria_cybersecurity_secret_key'  # Required to secure admin login sessions

# Replace your current BACKEND_URL line with this:
if os.environ.get('KUBERNETES_SERVICE_HOST') or os.path.exists('/.dockerenv'):
    # Running inside Docker environment
    BACKEND_URL = "http://127.0.0.1:5001"
else:
    # Running locally inside PyCharm workspace
    BACKEND_URL = "http://127.0.0.1:5001"
DB_PATH = "waf_logs.db"

# ---------------------------------------------------------
# CORE SECURITY LAYER: FIVE SIGNATURE REGEX MATRICES
# ---------------------------------------------------------
SIGNATURES = {
    "SQL Injection (SQLi)": r"(?i)(\b(SELECT|UNION|INSERT|UPDATE|DELETE|DROP|OR)\b|'|--|#)",
    "Cross-Site Scripting (XSS)": r"(?i)(<script.*?>|javascript:|onerror=|onload=)",
    "Path Traversal": r"(\.\.\/|\.\.\\)",
    "Remote Command Injection": r"(;|\||&&)\s*(whoami|cat|dir|ls|sh|bash|cmd)",
    "Automated Vulnerability Scanner": r"(?i)(sqlmap|nmap|nikto|dirbuster|acunetix)"
}


def init_database():
    """Initializes the structural SQLite relational table for persisting security events."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS waf_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT,
            timestamp TEXT,
            attack_type TEXT,
            payload TEXT
        )
    """)
    conn.commit()
    conn.close()


def log_incident(ip, attack_type, payload):
    """Writes flagged exploitation context into the auditing log database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO waf_logs (ip_address, timestamp, attack_type, payload) VALUES (?, ?, ?, ?)",
        (ip, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), attack_type, payload)
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------
# INTERCEPTION ROUTE (CATCHES ALL TRAFFIC FOR PORT 5000)
# ---------------------------------------------------------
@app.before_request
def inspect_traffic():
    """Intercepts and screens every incoming HTTP transaction prior to routing."""
    # Exclude administrative UI routes from being run through backend proxy logic
    if request.path in ['/waf-admin', '/login', '/logout', '/waf-admin/clear']:
        return None

    client_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')

    # Consolidate all user inputs (Query parameters, post body, headers) for inspection
    search_payloads = []
    if request.args:
        search_payloads.extend(request.args.values())
    if request.form:
        search_payloads.extend(request.form.values())

    # Check User-Agent header against malicious scanner footprint matrix
    for attack_name, regex in SIGNATURES.items():
        if re.search(regex, user_agent):
            log_incident(client_ip, "Automated Vulnerability Scanner", f"User-Agent: {user_agent}")
            return Response("<h1>403 Forbidden</h1><p>Access Denied: Malicious Automated Footprint Identified.</p>",
                            status=403)

    # Check incoming query parameter string content arrays
    for payload in search_payloads:
        for attack_name, regex in SIGNATURES.items():
            if re.search(regex, payload):
                log_incident(client_ip, attack_name, payload)
                return Response(
                    f"<h1>403 Forbidden</h1><p>Access Denied: Security Threat Flagged: [{attack_name}].</p>",
                    status=403)

    # REVERSE PROXY FORWARDING MECHANISM FOR AUTHORIZED CLEAN TRAFFIC
    try:
        # Re-build original connection request parameters pointing to downstream network node
        backend_response = requests.request(
            method=request.method,
            url=f"{BACKEND_URL}{request.full_path}",
            headers={key: value for key, value in request.headers if key != 'Host'},
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False
        )

        # Duplicate response structures back to client browser
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(name, value) for name, value in backend_response.raw.headers.items() if
                   name.lower() not in excluded_headers]

        return Response(backend_response.content, backend_response.status_code, headers)
    except requests.exceptions.ConnectionError:
        return Response(
            "<h1>502 Bad Gateway</h1><p>WAF Error: Unable to communicate with isolated target application.</p>",
            status=502)


# ---------------------------------------------------------
# ADMINISTRATIVE DASHBOARD AND AUTHENTICATION LOGIC
# ---------------------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Secures administrative access endpoints via credentials verification."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Explicit Hardcoded Safeguards for Administrative Panels
        if username == 'admin' and password == 'Kinger':
            session['authenticated'] = True
            return redirect('/waf-admin')
        else:
            flash("Invalid Administrative Credentials. Access Blocked.")
            return redirect('/login')

    # Inline rendering of simple Login UI
    return """
    <!DOCTYPE html>
    <html>
    <head><title>WAF Security Portal Login</title>
    <style>
        body { font-family: Arial, sans-serif; background: #0f2027; color: white; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .login-box { background: #203a43; padding: 40px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.5); text-align: center; width: 320px; }
        input[type="text"], input[type="password"] { width: 100%; padding: 10px; margin: 15px 0; border: none; border-radius: 4px; box-sizing: border-box;}
        input[type="submit"] { background: #17b978; color: white; border: none; padding: 12px; width: 100%; border-radius: 4px; font-size: 16px; cursor: pointer; }
        input[type="submit"]:hover { background: #11999e; }
    </style></head>
    <body>
        <div class="login-box">
            <h2>WAF Administrative Portal</h2>
            <form method="POST">
                <input type="text" name="username" placeholder="Admin Username" required>
                <input type="password" name="password" placeholder="Secret Key" required>
                <input type="submit" value="Authenticate Gateway">
            </form>
        </div>
    </body>
    </html>
    """


@app.route('/waf-admin')
def admin_dashboard():
    """Fetches audit database tables to construct real-time security dashboards."""
    if not session.get('authenticated'):
        return redirect('/login')

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM waf_logs ORDER BY id DESC")
    logs = cursor.fetchall()
    conn.close()

    return render_template('admin.html', logs=logs)


@app.route('/waf-admin/clear', methods=['POST'])
def clear_logs():
    """Triggers total purging sequence across the incident audit database layer."""
    if not session.get('authenticated'):
        return Response("Unauthorized operational command string.", status=401)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM waf_logs")  # Execute the clear mechanism
    conn.commit()
    conn.close()
    return redirect('/waf-admin')


@app.route('/logout')
def logout():
    """Destroys administrative configuration tokens from current browser storage."""
    session.clear()
    return redirect('/login')


if __name__ == '__main__':
    init_database()
    app.run(host='0.0.0.0', port=5000, debug=True)