"""Sample safe code for false positive testing."""
import sqlite3
from flask import Flask, request, render_template

app = Flask(__name__)


def get_user_safe(user_id: int):
    """SAFE: Parameterized query prevents SQL injection."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # This is safe - uses parameterized query
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    return cursor.fetchone()


@app.route("/search")
def search_safe():
    """SAFE: Uses proper escaping via template engine."""
    query = request.args.get("q", "")
    # This is safe - render_template auto-escapes
    return render_template("search.html", query=query)
