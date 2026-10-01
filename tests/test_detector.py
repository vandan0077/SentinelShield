from sentinelshield.detector import DetectionEngine

def categories(text):
    return {f.category for f in DetectionEngine().inspect(text)}

def test_benign():
    assert not categories("hello world")

def test_sqli():
    assert "SQL Injection" in categories("' OR '1'='1")

def test_xss():
    assert "Cross-Site Scripting" in categories("<script>alert(1)</script>")

def test_traversal():
    assert "Directory Traversal / LFI" in categories("../../etc/passwd")

def test_cmd():
    assert "Command Injection" in categories(";whoami")
