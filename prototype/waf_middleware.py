import re

# Простые сигнатуры для тестового rule-based слоя
RULES = {
    "sql_injection": re.compile(r"(?i)(union\s+select|select\s+.+\s+from|or\s+1=1)"),
    "xss": re.compile(r"(?i)<script>|onerror=|onload="),
    "path_traversal": re.compile(r"\.\./\.\./"),
}

def rule_based_check(request: str):
    """Возвращает (bool, reason): True, если запрос вредоносный."""
    for name, pattern in RULES.items():
        if pattern.search(request):
            return True, name
    return False, None


if __name__ == "__main__":
    samples = [
        "GET /index.php?id=1 HTTP/1.1",
        "GET /index.php?id=1 UNION SELECT username,password FROM users-- HTTP/1.1",
        "GET /search.php?q=<script>alert(1)</script> HTTP/1.1",
        "GET /download.php?file=../../etc/passwd HTTP/1.1",
    ]

    for req in samples:
        is_malicious, reason = rule_based_check(req)
        if is_malicious:
            print(f"[BLOCKED] ({reason}) → {req}")
        else:
            print(f"[ALLOWED] → {req}")
