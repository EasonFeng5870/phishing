import sys, pathlib
sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))

from backend.agent import analyze_email_stream


def test_analyze_stream_produces_final_line():
    email = {"sender": "user@example.com", "subject": "Test", "body": "Hello", "attachments": []}
    output = "".join(analyze_email_stream(email))
    assert "Final conclusion" in output
