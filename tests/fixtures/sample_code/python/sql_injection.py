"""Sample SQL injection vulnerability for testing."""
import sqlite3


def get_user_vulnerable(username: str):
    """VULNERABLE: SQL injection via string formatting."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # This is vulnerable to SQL injection
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()


def delete_user_vulnerable(user_id: str):
    """VULNERABLE: SQL injection via string concatenation."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "DELETE FROM users WHERE id = " + user_id
    cursor.execute(query)
    conn.commit()
