#!/usr/bin/env python3
"""
vSAT Scheduled Scanner
======================
Wrapper script for scheduled vCenter security audits with notifications.

Features:
- Configuration file support
- Email notifications
- Historical report archiving
- Compliance report generation
- Exit codes for CI/CD integration
"""

import os
import sys
import json
import smtplib
import argparse
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from pathlib import Path

# Import the main auditor
from vcenter_security_audit import VCenterSecurityAuditor, SecurityFinding

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


def load_config(config_path: str) -> dict:
    """Load configuration from YAML or JSON file."""
    with open(config_path, 'r') as f:
        if config_path.endswith('.yaml') or config_path.endswith('.yml'):
            if not YAML_AVAILABLE:
                raise ImportError("PyYAML required for YAML config. Install with: pip install pyyaml")
            return yaml.safe_load(f)
        else:
            return json.load(f)


def send_email_notification(config: dict, report_path: str, summary: dict):
    """Send email notification with report attachment."""
    email_config = config.get('notifications', {}).get('email', {})
    
    if not email_config.get('enabled', False):
        return
    
    # Check severity threshold
    threshold = email_config.get('severity_threshold', 'HIGH')
    severity_order = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    threshold_idx = severity_order.index(threshold)
    
    # Check if we have findings above threshold
    should_send = False
    for sev in severity_order[threshold_idx:]:
        if summary.get(sev.lower(), 0) > 0:
            should_send = True
            break
    
    if not should_send:
        print(f"[*] No findings at or above {threshold} severity - skipping email")
        return
    
    # Build email
    msg = MIMEMultipart()
    msg['From'] = email_config['from_address']
    msg['To'] = ', '.join(email_config['to_addresses'])
    msg['Subject'] = f"vCenter Security Audit Report - {summary['total']} Findings"
    
    # Email body
    body = f"""
vCenter Security Audit Report
=============================

Target: {summary.get('target', 'Unknown')}
Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Summary:
--------
Total Findings: {summary['total']}
  Critical: {summary.get('critical', 0)}
  High:     {summary.get('high', 0)}
  Medium:   {summary.get('medium', 0)}
  Low:      {summary.get('low', 0)}
  Info:     {summary.get('info', 0)}

Please review the attached report for details.

--
vCenter Security Audit Tool (vSAT)
"""
    
    msg.attach(MIMEText(body, 'plain'))
    
    # Attach report
    if os.path.exists(report_path):
        with open(report_path, 'rb') as f:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(f.read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', f'attachment; filename="{os.path.basename(report_path)}"')
            msg.attach(part)
    
    # Send email
    try:
        server = smtplib.SMTP(email_config['smtp_server'], email_config.get('smtp_port', 587))
        server.starttls()
        
        if 'username' in email_config and 'password' in email_config:
            server.login(email_config['username'], email_config['password'])
        
        server.send_message(msg)
        server.quit()
        print(f"[+] Email notification sent to {email_config['to_addresses']}")
    except Exception as e:
        print(f"[-] Failed to send email: {e}")


def send_slack_notification(config: dict, summary: dict):
    """Send Slack notification."""
    try:
        import requests
    except ImportError:
        print("[-] requests library required for Slack notifications")
        return
    
    slack_config = config.get('notifications', {}).get('slack', {})
    
    if not slack_config.get('enabled', False):
        return
    
    webhook_url = slack_config.get('webhook_url')
    if not webhook_url:
        return
    
    # Check severity threshold
    threshold = slack_config.get('severity_threshold', 'CRITICAL')
    severity_order = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    threshold_idx = severity_order.index(threshold)
    
    should_send = False
    for sev in severity_order[threshold_idx:]:
        if summary.get(sev.lower(), 0) > 0:
            should_send = True
            break
    
    if not should_send:
        return
    
    # Build Slack message
    color = "#36a64f"  # Green
    if summary.get('critical', 0) > 0:
        color = "#dc3545"  # Red
    elif summary.get('high', 0) > 0:
        color = "#fd7e14"  # Orange
    elif summary.get('medium', 0) > 0:
        color = "#ffc107"  # Yellow
    
    payload = {
        "attachments": [{
            "color": color,
            "title": "vCenter Security Audit Report",
            "fields": [
                {"title": "Target", "value": summary.get('target', 'Unknown'), "short": True},
                {"title": "Total Findings", "value": str(summary['total']), "short": True},
                {"title": "Critical", "value": str(summary.get('critical', 0)), "short": True},
                {"title": "High", "value": str(summary.get('high', 0)), "short": True},
                {"title": "Medium", "value": str(summary.get('medium', 0)), "short": True},
                {"title": "Low", "value": str(summary.get('low', 0)), "short": True},
            ],
            "footer": "vCenter Security Audit Tool",
            "ts": int(datetime.now().timestamp())
        }]
    }
    
    try:
        response = requests.post(webhook_url, json=payload)
        if response.status_code == 200:
            print("[+] Slack notification sent")
        else:
            print(f"[-] Slack notification failed: {response.status_code}")
    except Exception as e:
        print(f"[-] Failed to send Slack notification: {e}")


def generate_compliance_report(findings: list, mapping_file: str) -> dict:
    """Generate compliance report based on CIS mapping."""
    if not os.path.exists(mapping_file):
        return None
    
    with open(mapping_file, 'r') as f:
        mapping = json.load(f)
    
    finding_titles = {f.title for f in findings}
    
    results = {
        "framework": mapping['framework'],
        "scan_date": datetime.now().isoformat(),
        "controls": [],
        "summary": {
            "total": len(mapping['mappings']),
            "passed": 0,
            "failed": 0,
            "not_assessed": 0
        }
    }
    
    for control in mapping['mappings']:
        control_finding_titles = set(control.get('finding_titles', []))
        
        if not control_finding_titles:
            status = "NOT_ASSESSED"
            results['summary']['not_assessed'] += 1
        elif control_finding_titles & finding_titles:
            status = "FAILED"
            results['summary']['failed'] += 1
        else:
            status = "PASSED"
            results['summary']['passed'] += 1
        
        results['controls'].append({
            "id": control['cis_id'],
            "title": control['title'],
            "status": status,
            "level": control.get('level', 1),
            "scored": control.get('scored', True)
        })
    
    return results


def main():
    parser = argparse.ArgumentParser(description='vSAT Scheduled Scanner')
    parser.add_argument('-c', '--config', required=True, help='Configuration file path')
    parser.add_argument('--no-notify', action='store_true', help='Disable notifications')
    parser.add_argument('--compliance', help='Generate compliance report with specified mapping file')
    parser.add_argument('--fail-on', choices=['critical', 'high', 'medium', 'low'],
                        default='critical', help='Exit with error if findings at this level or above')
    
    args = parser.parse_args()
    
    # Load configuration
    print(f"[*] Loading configuration from {args.config}")
    config = load_config(args.config)
    
    vcenter_config = config.get('vcenter', {})
    report_config = config.get('report', {})
    
    # Get password from environment if not in config
    password = vcenter_config.get('password') or os.environ.get('VCENTER_PASSWORD')
    if not password:
        print("[-] Password not found in config or VCENTER_PASSWORD environment variable")
        sys.exit(1)
    
    # Create output directory
    output_dir = Path(report_config.get('output_directory', './reports'))
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Run audit
    auditor = VCenterSecurityAuditor(
        host=vcenter_config['server'],
        user=vcenter_config['username'],
        password=password,
        port=vcenter_config.get('port', 443)
    )
    
    if not auditor.run_full_audit():
        print("[-] Audit failed")
        sys.exit(1)
    
    # Generate report
    output_format = report_config.get('format', 'html')
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_filename = f"vcenter_audit_{timestamp}.{output_format}"
    report_path = output_dir / report_filename
    
    report = auditor.generate_report(output_format)
    with open(report_path, 'w') as f:
        f.write(report)
    
    print(f"[+] Report saved to {report_path}")
    
    # Build summary
    summary = {
        'target': vcenter_config['server'],
        'total': len(auditor.findings),
        'critical': auditor.stats[SecurityFinding.CRITICAL],
        'high': auditor.stats[SecurityFinding.HIGH],
        'medium': auditor.stats[SecurityFinding.MEDIUM],
        'low': auditor.stats[SecurityFinding.LOW],
        'info': auditor.stats[SecurityFinding.INFO]
    }
    
    # Generate compliance report if requested
    if args.compliance:
        compliance_results = generate_compliance_report(auditor.findings, args.compliance)
        if compliance_results:
            compliance_path = output_dir / f"compliance_{timestamp}.json"
            with open(compliance_path, 'w') as f:
                json.dump(compliance_results, f, indent=2)
            print(f"[+] Compliance report saved to {compliance_path}")
            print(f"    Passed: {compliance_results['summary']['passed']}")
            print(f"    Failed: {compliance_results['summary']['failed']}")
            print(f"    Not Assessed: {compliance_results['summary']['not_assessed']}")
    
    # Send notifications
    if not args.no_notify:
        send_email_notification(config, str(report_path), summary)
        send_slack_notification(config, summary)
    
    # Determine exit code
    severity_map = {
        'critical': SecurityFinding.CRITICAL,
        'high': SecurityFinding.HIGH,
        'medium': SecurityFinding.MEDIUM,
        'low': SecurityFinding.LOW
    }
    
    exit_code = 0
    fail_severities = list(severity_map.keys())[:fail_severities.index(args.fail_on) + 1] if args.fail_on in severity_map else []
    
    for sev in ['critical', 'high', 'medium', 'low']:
        if sev == args.fail_on:
            break
        if summary.get(sev, 0) > 0:
            exit_code = 1
            break
    
    if summary.get(args.fail_on, 0) > 0:
        exit_code = 1
    
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
