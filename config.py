import os
import yaml
from dataclasses import dataclass
from typing import List, Optional
from dotenv import load_dotenv

@dataclass
class SourceConfig:
    name: str
    technology: str
    type: str
    keyword: Optional[str] = None
    ecosystem: Optional[str] = None
    package: Optional[str] = None
    url: Optional[str] = None
    path: Optional[str] = None
    format: Optional[str] = None
    min_severity: Optional[str] = None

@dataclass
class AppConfig:
    teams_webhook_url: str
    nvd_api_key: str
    smtp_server: str
    smtp_port: int
    smtp_username: str
    smtp_password: str
    smtp_from: str
    smtp_to: str
    min_alert_severity: str
    weekly_digest_day: str
    failure_alert_threshold: int
    retention_days: int
    sources: List[SourceConfig]

def _get_str(key: str, default: str = "") -> str:
    val = os.getenv(key, default)
    if val:
        val = val.strip().strip("'\"")
    return val

def load_config(sources_path: str = "sources.yaml") -> AppConfig:
    load_dotenv()
    
    try:
        with open(sources_path, 'r') as f:
            data = yaml.safe_load(f)
    except FileNotFoundError:
        data = {"sources": []}
        
    sources = []
    for s in data.get("sources", []):
        sources.append(SourceConfig(
            name=s.get("name"),
            technology=s.get("technology"),
            type=s.get("type"),
            keyword=s.get("keyword"),
            ecosystem=s.get("ecosystem"),
            package=s.get("package"),
            url=s.get("url"),
            path=s.get("path"),
            format=s.get("format"),
            min_severity=s.get("min_severity")
        ))
        
    return AppConfig(
        teams_webhook_url=_get_str("TEAMS_WEBHOOK_URL", ""),
        nvd_api_key=_get_str("NVD_API_KEY", ""),
        smtp_server=_get_str("SMTP_SERVER", ""),
        smtp_port=int(_get_str("SMTP_PORT", "587")),
        smtp_username=_get_str("SMTP_USERNAME", ""),
        smtp_password=_get_str("SMTP_PASSWORD", "").replace(" ", ""),
        smtp_from=_get_str("SMTP_FROM", ""),
        smtp_to=_get_str("SMTP_TO", ""),
        min_alert_severity=_get_str("MIN_ALERT_SEVERITY", "LOW").upper(),
        weekly_digest_day=_get_str("WEEKLY_DIGEST_DAY", "Monday"),
        failure_alert_threshold=int(_get_str("FAILURE_ALERT_THRESHOLD", "3")),
        retention_days=int(_get_str("RETENTION_DAYS", "90")),
        sources=sources
    )
