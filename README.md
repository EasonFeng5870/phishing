# Phishing Analyzer

This prototype demonstrates a phishing detection workflow. A Flask backend exposes an analysis endpoint that streams detection steps to a simple HTML front end rendered with Jinja2 templates.

The backend defines several placeholder tools:

1. Sender blacklist lookup
2. Link inspection
3. Attachment scanning (including encryption checks)
4. QR code inspection
5. Semantic analysis of subject and body

If any tool flags the email, the final conclusion marks the message as phishing and can be extended to trigger a human-in-the-loop workflow.

## Development

```
# install dependencies (flask, langchain) if available
pip install -r requirements.txt

# run the development server
python -m backend.app
```

## Tests

```
pytest
```
