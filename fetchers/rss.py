import feedparser
import re
import requests
from typing import List, Dict, Any
from .base import BaseFetcher, Severity, sanitize

class RSSFetcher(BaseFetcher):
    def __init__(self, name: str, technology: str, url: str, min_severity: str = None):
        super().__init__(name, technology, min_severity)
        self.url = url

    def fetch(self) -> List[Dict[str, Any]]:
        headers = {'User-Agent': 'VulnWatch/1.0'}
        response = requests.get(self.url, headers=headers, timeout=30)
        response.raise_for_status()
        
        feed = feedparser.parse(response.content)
        findings = []
        
        for entry in feed.entries:
            finding = self._parse_entry(entry)
            if finding and self.filter_severity(finding['severity']):
                findings.append(finding)
                
        return findings

    def _parse_entry(self, entry: Any) -> Dict[str, Any]:
        title = entry.get("title", "")
        desc = entry.get("description", "")
        link = entry.get("link", "")
        
        # Try to extract CVE ID from title or description
        cve_id = self._extract_cve(title)
        if not cve_id:
            cve_id = self._extract_cve(desc)
            
        if not cve_id:
            # Fallback: use a hash or a slug of the link if no CVE is present
            # so we can at least track it, though CVE is preferred.
            if link:
                cve_id = link.split("/")[-1]
            else:
                return None
                
        severity = self._extract_severity(title, desc)
        
        return {
            'source': self.name,
            'technology': self.technology,
            'cve_id': cve_id,
            'severity': severity,
            'description': sanitize(desc),
            'url': link,
            'published': entry.get("published", ""),
            'affected_version': "",
            'fixed_version': ""
        }

    def _extract_cve(self, text: str) -> str:
        match = re.search(r'(CVE-\d{4}-\d{4,})', text, re.IGNORECASE)
        if match:
            return match.group(1).upper()
        return ""

    def _extract_severity(self, title: str, desc: str) -> str:
        combined = (title + " " + desc).lower()
        if "critical" in combined:
            return Severity.CRITICAL
        if "high" in combined:
            return Severity.HIGH
        if "medium" in combined:
            return Severity.MEDIUM
        if "low" in combined:
            return Severity.LOW
        return Severity.UNKNOWN
