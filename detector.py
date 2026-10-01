import re
import sqlite3
from datetime import datetime


class WAFEngine:
    def __init__(self):
        self.db_path = "waf_logs.db"
        self.init_db()

        # Highly expanded regex signature rules covering OWASP vulnerabilities
        self.rules = {
            "SQL_Injection": re.compile(
                r"UNION\s+(ALL\s+)?SELECT|SELECT.*FROM|' OR '1'='1'|--|/\*|\b(OR|AND)\b.*\s*=\s*\d+|WAITFOR\s+DELAY|SLEEP\(\d+\)",
                re.IGNORECASE
            ),
            "XSS": re.compile(
                r"<script.*?>|javascript:|onerror\s*=|alert\(|confirm\(|prompt\(|<img\s+src.*=|<svg/onload=",
                re.IGNORECASE
            ),
            "Path_Traversal": re.compile(
                r"\.\./\.\.|/etc/passwd|windows/win.ini|/bin/sh|/bin/bash",
                re.IGNORECASE
            ),
            "Command_Injection": re.compile(
                r";\s*whoami|;\s*id|\|\s*ping|&&\s*curl|;\s*uname|\bcat\s+/etc",
                re.IGNORECASE
            )
        }

        # Blacklisted automated security scanners and tools
        self.bad_user_agents = re.compile(
            r"sqlmap|nmap|nikto|dirbuster|gobuster|w3af|hydra",
            re.IGNORECASE
        )

    def init_db(self):
        """Creates the log table if it doesn't exist yet."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attack_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                ip_address TEXT,
                attack_type TEXT,
                payload TEXT,
                request_method TEXT,
                target_path TEXT
            )
        ''')
        conn.commit()
        conn.close()

    def log_attack(self, ip, attack_type, payload, method, path):
        """Saves a blocked attack attempt to the database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO attack_logs (timestamp, ip_address, attack_type, payload, request_method, target_path)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ip, attack_type, payload, method, path))
        conn.commit()
        conn.close()

    def inspect_string(self, data: str):
        """Checks a single string against security signatures."""
        if not data:
            return None
        for attack_type, pattern in self.rules.items():
            if pattern.search(data):
                return attack_type
        return None

    def is_malicious(self, request_data) -> tuple:
        """Scans URL params, headers, and request bodies."""
        client_ip = request_data.remote_addr
        method = request_data.method
        path = request_data.path

        # 1. Scan HTTP Request Headers: Inspect User-Agent for hacking tools
        user_agent = request_data.headers.get('User-Agent', '')
        if self.bad_user_agents.search(user_agent):
            self.log_attack(client_ip, "Malicious_Bot", user_agent[:100], method, path)
            return True, f"Automated scanning tool detected in User-Agent"

        # 2. Scan URL Query Parameters (?id=1)
        for key, val in request_data.args.items():
            match = self.inspect_string(val)
            if match:
                self.log_attack(client_ip, match, f"{key}={val}", method, path)
                return True, f"Malicious {match} in query parameter '{key}'"

        # 3. Scan Form Data or JSON Body
        body = request_data.get_data(as_text=True)
        if body:
            match = self.inspect_string(body)
            if match:
                self.log_attack(client_ip, match, body[:255], method, path)
                return True, f"Malicious {match} found in request body"

        return False, "Clean"