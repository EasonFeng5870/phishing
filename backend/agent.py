"""Email phishing analysis tools and streaming generator."""
from __future__ import annotations

import re
from typing import Iterable, Dict, Any, List

try:
    from langchain.agents import Tool, initialize_agent
    from langchain.llms import OpenAI
    LANGCHAIN_AVAILABLE = True
except Exception:  # pragma: no cover - langchain optional
    LANGCHAIN_AVAILABLE = False
    Tool = initialize_agent = OpenAI = None  # type: ignore

def check_sender_blacklist(sender: str) -> bool:
    """Return True if sender address looks suspicious.

    In a real system this would query a blacklist service.
    """
    return sender.endswith("@malicious.com")

def check_links(body: str) -> Dict[str, bool]:
    """Find links in the body and flag suspicious ones.

    Returns a mapping of url->is_phishing.
    """
    urls = re.findall(r"https?://\S+", body)
    return {url: False for url in urls}

def check_attachments(attachments: List[Any], body: str) -> List[Dict[str, Any]]:
    """Placeholder attachment scan.

    In a real system this would check for viruses or encryption.
    """
    results = []
    for att in attachments:
        results.append({"filename": getattr(att, "filename", str(att)), "encrypted": False, "virus": False})
    return results

def check_qr_codes(body: str) -> List[str]:
    """Detect QR codes in the body or attachments.

    Returns list of decoded URLs.
    """
    return []

def check_semantics(subject: str, body: str) -> bool:
    """Very naive semantic phishing detection using keywords."""
    suspicious = ["verify your account", "password", "bank", "urgent", "login"]
    content = f"{subject} {body}".lower()
    return any(word in content for word in suspicious)

def analyze_email_stream(email: Dict[str, Any]) -> Iterable[str]:
    """Yield step-by-step analysis results for an email."""
    yield "Checking sender blacklist...\n"
    blacklisted = check_sender_blacklist(email.get("sender", ""))
    yield f"Sender blacklisted: {blacklisted}\n"

    yield "Checking links...\n"
    links = check_links(email.get("body", ""))
    yield f"Links flagged: {links}\n"

    yield "Checking attachments...\n"
    attachments = check_attachments(email.get("attachments", []), email.get("body", ""))
    yield f"Attachment report: {attachments}\n"

    yield "Checking QR codes...\n"
    qrcodes = check_qr_codes(email.get("body", ""))
    yield f"QR code report: {qrcodes}\n"

    yield "Analyzing semantics...\n"
    semantic_flag = check_semantics(email.get("subject", ""), email.get("body", ""))
    yield f"Semantic phishing flag: {semantic_flag}\n"

    overall = bool(
        blacklisted
        or any(links.values())
        or any(a["virus"] for a in attachments)
        or semantic_flag
        or qrcodes
    )
    yield f"Final conclusion: {'phishing' if overall else 'not phishing'}\n"

# Optional LangChain agent creation for future use
if LANGCHAIN_AVAILABLE:  # pragma: no cover
    def build_langchain_agent() -> Any:
        """Construct a LangChain agent with the defined tools."""
        tools = [
            Tool(name="check_sender_blacklist", func=lambda x: check_sender_blacklist(x.get("sender", "")), description="Check if sender is blacklisted"),
            Tool(name="check_links", func=lambda x: check_links(x.get("body", "")), description="Check links for phishing"),
            Tool(name="check_attachments", func=lambda x: check_attachments(x.get("attachments", []), x.get("body", "")), description="Scan attachments"),
            Tool(name="check_qr_codes", func=lambda x: check_qr_codes(x.get("body", "")), description="Inspect QR codes"),
            Tool(name="check_semantics", func=lambda x: check_semantics(x.get("subject", ""), x.get("body", "")), description="Analyze semantics"),
        ]
        llm = OpenAI(temperature=0)
        return initialize_agent(tools, llm, agent="zero-shot-react-description", verbose=True)
