"""DELIBERATELY VULNERABLE: only used to prove the CI scanners work. Never merge."""
import subprocess

PASSWORD = "admin123"


def find_user(conn, name):
    return conn.execute(f"SELECT * FROM users WHERE name = '{name}'").fetchall()


def ping(host):
    return subprocess.run(f"ping -c 1 {host}", shell=True)
