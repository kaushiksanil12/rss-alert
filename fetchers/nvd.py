import requests
import time
from typing import List, Dict, Any
from .base import BaseFetcher, Severity, sanitize, SEVERITY_ORDER

class NVDFetcher(BaseFetcher):
    def __init__(self, name: str, technology: str, keyword: str, min_severity: str = None, api_key: str = None):
        super().__init__(name, technology, min_severity)
        self.keyword = keyword
        self.api_key = api_key
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.results_per_page = 20
        self.sleep_time = 0.25 if api_key else 7.0

    def fetch(self) -> List[Dict[str, Any]]:
        # 1. Fetch exactly 1 item to get totalResults
        total_results = self._fetch_page(0, 1).get('totalResults', 0)
        if total_results == 0:
            return []

        # 2. Compute startIndex for the last page of up to 20 results (newest)
        start_index = max(0, total_results - self.results_per_page)
        
        time.sleep(self.sleep_time)

        # 3. Fetch actual newest results
        data = self._fetch_page(start_index, self.results_per_page)
        
        findings = []
        for item in data.get('vulnerabilities', []):
            cve = item.get('cve', {})
            finding = self._parse_cve(cve)
            if finding and self.filter_severity(finding['severity']):
                findings.append(finding)
                
        return findings

    def _fetch_page(self, start_index: int, results_per_page: int) -> Dict[str, Any]:
        params = {
            'keywordSearch': self.keyword,
            'resultsPerPage': results_per_page,
            'startIndex': start_index
        }
        headers = {'User-Agent': 'VulnWatch/1.0'}
        if self.api_key:
            headers['apiKey'] = self.api_key

        response = requests.get(self.base_url, params=params, headers=headers, timeout=45)
        response.raise_for_status()
        return response.json()

    def _parse_cve(self, cve: Dict[str, Any]) -> Dict[str, Any]:
        cve_id = cve.get('id')
        if not cve_id:
            return None

        # Extract severity
        severity = self._extract_severity(cve)
        
        # Extract description
        desc = ""
        for d in cve.get('descriptions', []):
            if d.get('lang') == 'en':
                desc = sanitize(d.get('value', ''))
                break
                
        # Extract URL
        url = ""
        refs = cve.get('references', [])
        if refs:
            url = refs[0].get('url', '')

        # Extract versions
        affected, fixed = self._extract_versions(cve.get('configurations', []))

        return {
            'source': self.name,
            'technology': self.technology,
            'cve_id': cve_id,
            'severity': severity,
            'description': desc,
            'url': url,
            'published': cve.get('published', ''),
            'affected_version': affected,
            'fixed_version': fixed
        }

    def _extract_severity(self, cve: Dict[str, Any]) -> str:
        metrics = cve.get('metrics', {})
        for key in ['cvssMetricV31', 'cvssMetricV30']:
            if key in metrics and metrics[key]:
                m = metrics[key][0].get('cvssData', {})
                sev = m.get('baseSeverity')
                if sev:
                    return sev.upper()
        if 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
            return metrics['cvssMetricV2'][0].get('baseSeverity', Severity.UNKNOWN).upper()
        return Severity.UNKNOWN

    def _extract_versions(self, configs: List[Dict[str, Any]]) -> (str, str):
        affected, fixed = "", ""
        for conf in configs:
            for node in conf.get('nodes', []):
                for match in node.get('cpeMatch', []):
                    if match.get('vulnerable'):
                        if match.get('versionEndExcluding'):
                            fixed = match.get('versionEndExcluding')
                        if match.get('versionStartIncluding'):
                            affected = ">=" + match.get('versionStartIncluding')
                        if affected or fixed:
                            return affected, fixed
        return affected, fixed
