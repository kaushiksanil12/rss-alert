import requests
from typing import List, Dict, Any
from .base import BaseFetcher, Severity, sanitize

class OSVFetcher(BaseFetcher):
    def __init__(self, name: str, technology: str, ecosystem: str, package: str, min_severity: str = None):
        super().__init__(name, technology, min_severity)
        self.ecosystem = ecosystem
        self.package = package
        self.base_url = "https://api.osv.dev/v1/query"

    def fetch(self) -> List[Dict[str, Any]]:
        payload = {
            "package": {
                "name": self.package,
                "ecosystem": self.ecosystem
            }
        }
        
        response = requests.post(self.base_url, json=payload, timeout=30)
        response.raise_for_status()
        data = response.json()
        
        vulns = data.get("vulns", [])
        
        # Sort vulnerabilities by published date (newest first)
        def get_pub_date(v):
            return v.get("published", "")
        vulns.sort(key=get_pub_date, reverse=True)
        
        findings = []
        for v in vulns:
            finding = self._parse_osv(v)
            if finding and self.filter_severity(finding['severity']):
                findings.append(finding)
                
        return findings

    def _parse_osv(self, v: Dict[str, Any]) -> Dict[str, Any]:
        cve_id = v.get("id")
        aliases = v.get("aliases", [])
        
        # Prefer CVE ID if available in aliases
        for alias in aliases:
            if alias.startswith("CVE-"):
                cve_id = alias
                break
                
        if not cve_id:
            return None

        # Severity
        severity = Severity.UNKNOWN
        for sev in v.get("severity", []):
            score_val = sev.get("score")
            parsed_sev = self._cvss_to_severity(score_val)
            if parsed_sev != Severity.UNKNOWN:
                severity = parsed_sev
                break
                
        # Database specific severity as fallback
        if severity == Severity.UNKNOWN and "database_specific" in v:
            db_sev = v["database_specific"].get("severity")
            if db_sev:
                severity = str(db_sev).upper()

        desc = sanitize(v.get("details", ""))
        
        url = ""
        refs = v.get("references", [])
        if refs:
            url = refs[0].get("url", "")
            
        affected, fixed = self._extract_versions(v.get("affected", []))

        return {
            'source': self.name,
            'technology': self.technology,
            'cve_id': cve_id,
            'severity': severity,
            'description': desc,
            'url': url,
            'published': v.get("published", ""),
            'affected_version': affected,
            'fixed_version': fixed
        }

    def _cvss_to_severity(self, score_val: Any) -> str:
        if not score_val:
            return Severity.UNKNOWN
        if isinstance(score_val, (int, float)):
            if score_val >= 9.0: return Severity.CRITICAL
            if score_val >= 7.0: return Severity.HIGH
            if score_val >= 4.0: return Severity.MEDIUM
            if score_val > 0: return Severity.LOW
        elif isinstance(score_val, str):
            try:
                val = float(score_val)
                return self._cvss_to_severity(val)
            except ValueError:
                pass
            upper_s = score_val.upper()
            if "CRITICAL" in upper_s: return Severity.CRITICAL
            if "HIGH" in upper_s: return Severity.HIGH
            if "MEDIUM" in upper_s: return Severity.MEDIUM
            if "LOW" in upper_s: return Severity.LOW
        return Severity.UNKNOWN

    def _extract_versions(self, affected_list: List[Dict[str, Any]]) -> (str, str):
        affected_ver, fixed_ver = "", ""
        for affected in affected_list:
            for rng in affected.get("ranges", []):
                for event in rng.get("events", []):
                    if "introduced" in event:
                        affected_ver = ">=" + event["introduced"]
                    if "fixed" in event:
                        fixed_ver = event["fixed"]
                        return affected_ver, fixed_ver
        return affected_ver, fixed_ver
