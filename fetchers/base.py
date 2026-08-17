import bleach
from typing import Dict, Any, List
from datetime import datetime

class Severity:
    UNKNOWN = "UNKNOWN"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

SEVERITY_ORDER = {
    Severity.UNKNOWN: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4
}

def sanitize(html_text: str) -> str:
    if not html_text:
        return ""
    # Strip all tags as per bluemonday.StrictPolicy() equivalent in bleach
    return bleach.clean(html_text, tags=[], attributes={}, strip=True)

class BaseFetcher:
    def __init__(self, name: str, technology: str, min_severity: str = None):
        self.name = name
        self.technology = technology
        self.min_severity = min_severity

    def fetch(self) -> List[Dict[str, Any]]:
        raise NotImplementedError()

    def filter_severity(self, sev: str) -> bool:
        if not self.min_severity:
            return True
        return SEVERITY_ORDER.get(sev, 0) >= SEVERITY_ORDER.get(self.min_severity, 0)
