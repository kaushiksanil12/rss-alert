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

        card = self._build_adaptive_card(findings)
        self._post(card)

    def send_meta_alert(self, source: str, consecutive_days: int):
        if not self.is_configured():
            return
            
        card = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.2",
                        "body": [
                            {
                                "type": "TextBlock",
                                "text": "⚠️ Vulnerability Source Failure Alert",
                                "weight": "Bolder",
                                "size": "Medium",
                                "color": "Attention"
                            },
                            {
                                "type": "TextBlock",
                                "text": f"**Source `{source}`** has failed to fetch vulnerability data for **{consecutive_days} consecutive runs**. This may indicate a silent blind spot. Please investigate the source configuration and connectivity.",
                                "wrap": True
                            }
                        ]
                    }
                }
            ]
        }
        self._post(card)

    def _build_adaptive_card(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        summary = f"🛡️ {len(findings)} new security finding(s) detected"
        
        body_blocks = [
            {
                "type": "TextBlock",
                "text": summary,
                "weight": "Bolder",
                "size": "Medium",
                "wrap": True
            }
        ]
        
        for i, f in enumerate(findings):
            if i >= 20:
                break
                
            color = self._severity_theme_color(f['severity'])
            facts = [
                {"title": "Technology:", "value": f['technology']},
                {"title": "Severity:", "value": f['severity']},
                {"title": "Source:", "value": f['source']}
            ]
            
            desc = f.get('description', '')
            if desc:
                if len(desc) > 300:
                    desc = desc[:297] + "..."
                facts.append({"title": "Description:", "value": desc})
                
            fixed = f.get('fixed_version', '')
            if fixed:
                facts.append({"title": "Fixed in:", "value": fixed})
                
            title_text = f"**{f['cve_id']}**"
            if f.get('url'):
                title_text = f"[{f['cve_id']}]({f['url']})"
                
            body_blocks.append({
                "type": "Container",
                "spacing": "Medium",
                "separator": True,
                "items": [
                    {
                        "type": "TextBlock",
                        "text": title_text,
                        "weight": "Bolder",
                        "size": "Default",
                        "color": color
                    },
                    {
                        "type": "FactSet",
                        "facts": facts
                    }
                ]
            })
            
        remaining = len(findings) - min(len(findings), 20)
        if remaining > 0:
             body_blocks.append({
                 "type": "TextBlock",
                 "text": f"...and {remaining} more findings. See the database for the full list.",
                 "wrap": True,
                 "isSubtle": True
             })

        return {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.2",
                        "body": body_blocks
                    }
                }
            ]
        }

    def _severity_theme_color(self, severity: str) -> str:
        if severity in [Severity.CRITICAL, Severity.HIGH]:
            return "Attention"  # Red text in Adaptive Cards
        elif severity == Severity.MEDIUM:
            return "Warning"    # Yellow/Orange text
        return "Default"        # Standard text

    def _post(self, card: Dict[str, Any]):
        try:
            response = requests.post(self.webhook_url, json=card, timeout=10)
            response.raise_for_status()
        except requests.RequestException as e:
            print(f"Failed to post to Teams: {e}")
