import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import List, Dict, Any
from config import AppConfig
from fetchers.base import SEVERITY_ORDER

class EmailClient:
    def __init__(self, cfg: AppConfig):
        self.cfg = cfg

    def is_configured(self) -> bool:
        return bool(self.cfg.smtp_server and self.cfg.smtp_to)

    def send_findings(self, findings: List[Dict[str, Any]]):
        if not findings or not self.is_configured():
            return
            
        subject = f"Vulnerability Alert: {len(findings)} new finding(s) detected"
        
        # Determine highest severity for subject line urgency
        highest = "UNKNOWN"
        for f in findings:
            if SEVERITY_ORDER.get(f['severity'], 0) > SEVERITY_ORDER.get(highest, 0):
                highest = f['severity']
                
        if highest in ["CRITICAL", "HIGH"]:
            subject = f"[{highest}] " + subject

        # Build HTML content
        html = f"<h2>{len(findings)} New Security Findings</h2><ol>"
        for f in findings[:20]:
            html += f"<li><strong>{f['cve_id']}</strong> ({f['severity']}) - {f['technology']}<br/>"
            html += f"<em>Source: {f['source']}</em><br/>"
            
            desc = f.get('description', '')
            if len(desc) > 300:
                desc = desc[:297] + "..."
            if desc:
                html += f"Description: {desc}<br/>"
                
            if f.get('fixed_version'):
                html += f"Fixed in: {f['fixed_version']}<br/>"
                
            if f.get('url'):
                html += f"<a href='{f['url']}'>View Advisory</a>"
            html += "</li><br/>"
            
        remaining = len(findings) - 20
        if remaining > 0:
            html += f"<li>...and {remaining} more. See the database for the full list.</li>"
            
        html += "</ol>"

        self._send_email(subject, html)

    def send_meta_alert(self, source: str, consecutive_days: int):
        if not self.is_configured():
            return
            
        subject = f"Vulnerability Source Failure: {source}"
        html = f"<h2>Source '{source}' has failed for {consecutive_days} consecutive runs</h2>"
        html += "<p>This may indicate a silent blind spot. Please investigate the source configuration and connectivity.</p>"
        
        self._send_email(subject, html)

    def _send_email(self, subject: str, html_body: str):
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = self.cfg.smtp_from or self.cfg.smtp_username
        msg['To'] = self.cfg.smtp_to

        msg.attach(MIMEText(html_body, 'html'))

        try:
            with smtplib.SMTP(self.cfg.smtp_server, self.cfg.smtp_port) as server:
                server.starttls()
                if self.cfg.smtp_username and self.cfg.smtp_password:
                    server.login(self.cfg.smtp_username, self.cfg.smtp_password)
                server.send_message(msg)
            print(f"Successfully sent email to {self.cfg.smtp_to}")
        except Exception as e:
            print(f"Failed to send email: {e}")
