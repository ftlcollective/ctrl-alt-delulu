import sqlite3
import os
import subprocess

# Hardcoded secret (should be flagged)
API_KEY = "sk-live-51H8x2eZvKYlo2CJ9x7aBcDeFgHiJkLmNoPqRsT"

def get_user(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # SQL Injection vulnerability
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()

def run_backup(filename):
    # Command injection vulnerability
    os.system("tar -czf backup.tar.gz " + filename)

def render_page(user_input):
    # Reflected XSS-ish pattern for a template
    html = "<div>" + user_input + "</div>"
    return html
