"""Flask application exposing phishing analysis with streaming output."""
from __future__ import annotations

from typing import Dict, Any

try:
    from flask import Flask, render_template, request, Response
except Exception:  # pragma: no cover - flask optional
    Flask = None  # type: ignore

from .agent import analyze_email_stream

if Flask:  # pragma: no cover - don't execute during tests
    app = Flask(__name__)

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.post("/analyze")
    def analyze():
        email: Dict[str, Any] = {
            "sender": request.form.get("sender", ""),
            "subject": request.form.get("subject", ""),
            "body": request.form.get("body", ""),
            "attachments": request.files.getlist("attachments"),
        }
        return Response(analyze_email_stream(email), mimetype="text/plain")

    if __name__ == "__main__":
        app.run(debug=True)
