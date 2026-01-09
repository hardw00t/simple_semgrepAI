"""Sample XSS vulnerability for testing."""
from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route("/search")
def search_vulnerable():
    """VULNERABLE: XSS via template injection."""
    query = request.args.get("q", "")
    # This is vulnerable to XSS
    return render_template_string(f"<h1>Results for: {query}</h1>")


@app.route("/greet")
def greet_vulnerable():
    """VULNERABLE: XSS via direct HTML output."""
    name = request.args.get("name", "Guest")
    # This is vulnerable to XSS
    return f"<html><body><h1>Hello, {name}!</h1></body></html>"
