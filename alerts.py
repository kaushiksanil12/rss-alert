import requests
from typing import List, Dict, Any
from datetime import datetime
from fetchers.base import SEVERITY_ORDER, Severity

class TeamsClient:
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    def is_configured(self) -> bool:
        return bool(self.webhook_url)

    def send_findings(self, findings: List[Dict[str, Any]]):
        if not findings or not self.is_configured():
            return

        card = self._build_message_card(findings)
        self._post(card)

    def send_meta_alert(self, source: str, consecutive_days: int):
        if not self.is_configured():
            return
            
        card = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "FF6B35",
            "summary": f"⚠️ Source '{source}' has failed for {consecutive_days} consecutive runs",
            "title": "⚠️ Vulnerability Source Failure Alert",
            "text": f"**Source `{source}`** has failed to fetch vulnerability data for **{consecutive_days} consecutive runs**. This may indicate a silent blind spot. Please investigate the source configuration and connectivity."
        }
        self._post(card)

    def _build_message_card(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        summary = f"🛡️ {len(findings)} new security finding(s) detected"
        theme_color = self._severity_theme_color(findings)

        sections = []
        for i, f in enumerate(findings):
            if i >= 20:
                break
                
            title = f"**{f['cve_id']}** — {f['technology']} (Source: {f['source']})"
            if f.get('url'):
                title = f"**[{f['cve_id']}]({f['url']})** — {f['technology']} (Source: {f['source']})"

            section = {
                "activityTitle": title,
                "activitySubtitle": f"Severity: **{f['severity']}** | Published: {f.get('published', 'unknown')}",
                "facts": self._build_facts(f),
                "markdown": True
            }
            if f.get('url'):
                section["potentialAction"] = [{
                    "@type": "OpenUri",
                    "name": "View Advisory",
                    "targets": [{"os": "default", "uri": f['url']}]
                }]
            sections.append(section)

        remaining = len(findings) - len(sections)
        text = ""
        if remaining > 0:
            text = f"*...and {remaining} more findings. See the database for the full list.*"

        return {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": theme_color,
            "summary": summary,
            "title": summary,
            "text": text,
            "sections": sections
        }

    def _build_facts(self, f: Dict[str, Any]) -> List[Dict[str, str]]:
        facts = [
            {"name": "Technology", "value": f['technology']},
            {"name": "Severity", "value": f['severity']},
            {"name": "Source", "value": f['source']}
        ]
        
        desc = f.get('description', '')
        if desc:
            if len(desc) > 300:
                desc = desc[:297] + "..."
            facts.append({"name": "Description", "value": desc})
            
        fixed = f.get('fixed_version', '')
        if fixed:
            facts.append({"name": "Fixed in", "value": fixed})
            
        return facts

    def _severity_theme_color(self, findings: List[Dict[str, Any]]) -> str:
        highest = Severity.UNKNOWN
        for f in findings:
            if SEVERITY_ORDER.get(f['severity'], 0) > SEVERITY_ORDER.get(highest, 0):
                highest = f['severity']
                
        if highest == Severity.CRITICAL:
            return "8B0000"
        elif highest == Severity.HIGH:
            return "D73A49"
        elif highest == Severity.MEDIUM:
            return "E36209"
        else:
            return "0075CA"

    def _post(self, card: Dict[str, Any]):
        try:
            response = requests.post(self.webhook_url, json=card, timeout=10)
            response.raise_for_status()
        except requests.RequestException as e:
            print(f"Failed to post to Teams: {e}")
