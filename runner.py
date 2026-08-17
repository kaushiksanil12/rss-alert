import time
from datetime import datetime
import db
from config import AppConfig
from fetchers import NVDFetcher, OSVFetcher, RSSFetcher, Severity
from fetchers.base import SEVERITY_ORDER
from alerts import TeamsClient

class Runner:
    def __init__(self, cfg: AppConfig):
        self.cfg = cfg
        self.main_client = TeamsClient(cfg.teams_webhook_url)
        self.crit_client = TeamsClient(cfg.critical_webhook_url) if cfg.critical_webhook_url else None
        
        self.fetchers = []
        for s in cfg.sources:
            if s.type == "nvd":
                self.fetchers.append(NVDFetcher(s.name, s.technology, s.keyword, s.min_severity, cfg.nvd_api_key))
            elif s.type == "osv":
                self.fetchers.append(OSVFetcher(s.name, s.technology, s.ecosystem, s.package, s.min_severity))
            elif s.type == "vendor_rss":
                self.fetchers.append(RSSFetcher(s.name, s.technology, s.url, s.min_severity))
            else:
                print(f"Skipping unsupported source type: {s.type} for {s.name}")

    def run(self):
        print(f"[{datetime.utcnow()}] Starting vulnerability monitoring run...")
        db.init_db()
        
        all_new_findings = []
        
        for fetcher in self.fetchers:
            new_findings = self._run_fetcher(fetcher)
            if new_findings:
                all_new_findings.extend(new_findings)
                
        if all_new_findings:
            # Filter and route findings
            to_alert = []
            to_escalate = []
            
            global_min = SEVERITY_ORDER.get(self.cfg.min_alert_severity, 0)
            
            for f in all_new_findings:
                sev_score = SEVERITY_ORDER.get(f['severity'], 0)
                
                # Main channel
                if sev_score >= global_min:
                    to_alert.append(f)
                    
                # Escalation channel (HIGH and CRITICAL)
                if sev_score >= SEVERITY_ORDER[Severity.HIGH]:
                    to_escalate.append(f)
                    
            if to_alert:
                self.main_client.send_findings(to_alert)
                
            if to_escalate and self.crit_client:
                self.crit_client.send_findings(to_escalate)
                
        # Prune old findings
        pruned = db.prune_findings(self.cfg.retention_days)
        if pruned > 0:
            print(f"Pruned {pruned} old findings.")
            
        print(f"[{datetime.utcnow()}] Run complete. Total new findings: {len(all_new_findings)}")

    def _run_fetcher(self, fetcher):
        source = fetcher.name
        try:
            raw_findings = fetcher.fetch()
        except Exception as e:
            print(f"Fetcher {source} failed: {e}")
            db.record_source_status(source, False, str(e))
            
            failures = db.get_source_failures(source)
            if failures >= self.cfg.failure_alert_threshold:
                print(f"Source {source} failure threshold exceeded. Sending meta-alert.")
                self.main_client.send_meta_alert(source, failures)
            return []

        # Global safeguard: limit to 20 vulnerabilities per run per source
        if len(raw_findings) > 20:
            raw_findings = raw_findings[:20]
            
        # Baseline check
        if not db.is_baseline_done(source):
            db.mark_baseline(source, raw_findings)
            print(f"First-run baseline recorded for {source} with {len(raw_findings)} findings.")
            return []
            
        # Deduplication
        new_findings = []
        for finding in raw_findings:
            if not finding['cve_id']:
                continue
                
            if db.is_new_finding(source, finding['cve_id']):
                db.record_finding(finding)
                new_findings.append(finding)
                
        db.record_source_status(source, True)
        return new_findings
