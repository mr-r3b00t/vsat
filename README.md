# vCenter Security Audit Tool (vSAT)

A comprehensive security auditing tool for VMware vCenter environments. Think **RVTools**, but focused on **security**!

## 🛡️ Features

### VM Security Audits
- **VMware Tools Status** - Detects missing or outdated VMware Tools
- **Snapshot Analysis** - Identifies old snapshots (security & compliance risk)
- **Hardware Version** - Flags VMs with outdated hardware versions missing security features
- **Secure Boot** - Checks if EFI Secure Boot is enabled
- **VBS (Virtualization Based Security)** - Verifies VBS status on Windows VMs
- **Disk Configuration** - Detects independent disk modes that bypass snapshots
- **Advanced Settings** - Audits isolation settings, VNC, copy/paste restrictions

### Host (ESXi) Security Audits
- **Service Status** - Flags running SSH, ESXi Shell, SNMP services
- **Firewall Configuration** - Checks default policies and overly permissive rules
- **Lockdown Mode** - Verifies lockdown mode is enabled
- **NTP Configuration** - Ensures time synchronization is configured
- **Syslog Configuration** - Checks for centralized logging
- **ESXi Version** - Identifies unsupported or outdated versions
- **SSL Certificates** - Checks for expired or expiring certificates
- **Advanced Settings** - Audits shell timeouts, account lockout, MOB status

### Network Security Audits
- **Promiscuous Mode** - Detects enabled promiscuous mode (traffic sniffing risk)
- **MAC Address Changes** - Identifies allowed MAC spoofing
- **Forged Transmits** - Checks for allowed traffic spoofing
- **Distributed Virtual Switch Security** - Audits DVS port group security policies
- **Standard vSwitch Security** - Audits vSwitch and port group settings

### Permission Audits
- **Custom Roles** - Identifies roles with dangerous privileges
- **Administrator Accounts** - Flags excessive admin accounts
- **Root-Level Permissions** - Detects propagating permissions from root
- **Everyone Group** - Alerts on permissions granted to Everyone

### vCenter Server Audits
- **Version Check** - Identifies unsupported vCenter versions
- **Session Timeout** - Reviews session timeout configuration

## 📋 Security Checks Reference

| Category | Check | Severity | Reference |
|----------|-------|----------|-----------|
| VM | VMware Tools not installed | HIGH | CIS VMware ESXi Benchmark |
| VM | VMware Tools outdated | MEDIUM | VMware Security Best Practices |
| VM | Old snapshots (>7 days) | MEDIUM/HIGH | VMware KB 1025279 |
| VM | Outdated hardware version | MEDIUM | VMware Hardware Compatibility |
| VM | Secure Boot disabled | MEDIUM | CIS VMware Benchmark |
| VM | VNC enabled | HIGH | CIS VMware Benchmark |
| Host | SSH service running | HIGH | CIS VMware ESXi Benchmark |
| Host | ESXi Shell running | HIGH | CIS VMware ESXi Benchmark |
| Host | Lockdown mode disabled | HIGH | CIS VMware ESXi 1.1 |
| Host | No remote syslog | HIGH | CIS VMware ESXi 3.1 |
| Host | SSL certificate expired | CRITICAL | VMware Certificate Management |
| Network | Promiscuous mode enabled | HIGH | CIS VMware ESXi 7.1 |
| Network | MAC changes allowed | MEDIUM | CIS VMware ESXi 7.2 |
| Network | Forged transmits allowed | MEDIUM | CIS VMware ESXi 7.3 |
| Permissions | Root-level admin | HIGH | VMware Security Best Practices |
| Permissions | Everyone has permissions | CRITICAL | VMware Security Best Practices |

## 🚀 Quick Start

### Installation

```bash
# Clone or download the tool
git clone https://github.com/yourusername/vcenter-security-audit.git
cd vcenter-security-audit

# Install dependencies
pip install -r requirements.txt
```

### Basic Usage

```bash
# Interactive (will prompt for password)
python vcenter_security_audit.py -s vcenter.example.com -u admin@vsphere.local

# With password (not recommended for security)
python vcenter_security_audit.py -s vcenter.example.com -u admin@vsphere.local -p 'password'

# JSON output
python vcenter_security_audit.py -s vcenter.example.com -u admin@vsphere.local -o json > report.json

# HTML report
python vcenter_security_audit.py -s vcenter.example.com -u admin@vsphere.local -o html > report.html
```

### Command Line Options

```
usage: vcenter_security_audit.py [-h] -s SERVER -u USER [-p PASSWORD] 
                                  [-o {text,json,html}] [--port PORT]

Options:
  -s, --server   vCenter server hostname or IP (required)
  -u, --user     Username, e.g., admin@vsphere.local (required)
  -p, --password Password (will prompt if not provided)
  -o, --output   Output format: text, json, or html (default: text)
  --port         vCenter port (default: 443)
```

## 📊 Output Formats

### Text Report (Default)
Plain text report suitable for terminal viewing or piping to a file.

### JSON Report
Machine-readable JSON format for integration with other tools:

```json
{
  "metadata": {
    "target": "vcenter.example.com",
    "scan_date": "2024-01-15T10:30:00",
    "vcenter_version": "8.0.1",
    "vcenter_build": "21815093"
  },
  "summary": {
    "total_findings": 42,
    "critical": 2,
    "high": 8,
    "medium": 15,
    "low": 12,
    "info": 5
  },
  "findings": [...]
}
```

### HTML Report
Beautiful, interactive HTML report with:
- Executive summary dashboard
- Color-coded severity indicators
- Findings grouped by severity
- Remediation guidance

## 🔒 Required Permissions

The tool requires **read-only** access to vCenter. Minimum permissions needed:

| Object | Required Privilege |
|--------|-------------------|
| Global | View |
| Host | View |
| VM | View |
| Network | View |
| Datastore | View |
| Folder | View |

For a complete audit, the following additional permissions help:
- `Authorization.ViewRoles` - For permission auditing
- `Sessions.View` - For session auditing

## 🏗️ Architecture

```
vcenter_security_audit.py
├── SecurityFinding          # Data class for findings
├── VCenterSecurityAuditor   # Main auditor class
│   ├── VM Security Audits
│   │   ├── _audit_vm_tools()
│   │   ├── _audit_vm_snapshots()
│   │   ├── _audit_vm_hardware_version()
│   │   ├── _audit_vm_security_settings()
│   │   ├── _audit_vm_disk_settings()
│   │   ├── _audit_vm_network_settings()
│   │   └── _audit_vm_advanced_settings()
│   ├── Host Security Audits
│   │   ├── _audit_host_services()
│   │   ├── _audit_host_firewall()
│   │   ├── _audit_host_lockdown()
│   │   ├── _audit_host_ntp()
│   │   ├── _audit_host_syslog()
│   │   ├── _audit_host_version()
│   │   ├── _audit_host_certificates()
│   │   └── _audit_host_advanced_settings()
│   ├── Network Security Audits
│   │   ├── _audit_dvs_security()
│   │   └── _audit_host_vswitches()
│   ├── Permission Audits
│   │   ├── _audit_roles()
│   │   └── _audit_permissions_assignments()
│   └── Report Generation
│       ├── _generate_text_report()
│       ├── _generate_json_report()
│       └── _generate_html_report()
```

## 📈 Extending the Tool

### Adding New Checks

1. Create a new audit method in the appropriate category:

```python
def _audit_vm_encryption(self, vm: vim.VirtualMachine):
    """Check VM encryption status."""
    config = vm.config
    if not config:
        return
    
    # Check if VM is encrypted
    if hasattr(config, 'keyId') and not config.keyId:
        self.add_finding(SecurityFinding(
            category="VM Security",
            severity=SecurityFinding.MEDIUM,
            title="VM Not Encrypted",
            description="This VM is not encrypted at rest.",
            affected_object=vm.name,
            remediation="Enable VM encryption using vSphere Native Key Provider or external KMS.",
            reference="VMware vSphere Security Guide"
        ))
```

2. Call it from the parent audit method:

```python
def audit_vm_security(self):
    for vm in vms:
        self._audit_vm_encryption(vm)  # Add here
```

### Custom Severity Levels

Modify the `SecurityFinding` class to add custom severity levels:

```python
class SecurityFinding:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    COMPLIANCE = "COMPLIANCE"  # Custom level
```

## 🔗 Integration Examples

### SIEM Integration (JSON to Syslog)

```bash
python vcenter_security_audit.py -s vcenter.example.com -u admin@vsphere.local -o json | \
  jq -c '.findings[]' | \
  while read finding; do
    logger -n siem.example.com -P 514 "$finding"
  done
```

### Scheduled Scanning (Cron)

```bash
# /etc/cron.daily/vcenter-audit
#!/bin/bash
/usr/bin/python3 /opt/vcenter-audit/vcenter_security_audit.py \
  -s vcenter.example.com \
  -u svc_audit@vsphere.local \
  -p "$(cat /etc/vcenter-audit/.password)" \
  -o html > /var/www/html/reports/vcenter-audit-$(date +%Y%m%d).html
```

### CI/CD Pipeline (Exit Code Based)

```python
# Modify main() to return exit code based on findings
if auditor.stats[SecurityFinding.CRITICAL] > 0:
    sys.exit(2)  # Critical findings
elif auditor.stats[SecurityFinding.HIGH] > 0:
    sys.exit(1)  # High findings
else:
    sys.exit(0)  # Pass
```

## 📚 References

- [CIS VMware ESXi Benchmark](https://www.cisecurity.org/benchmark/vmware)
- [VMware vSphere Security Configuration Guide](https://core.vmware.com/security-configuration-guide)
- [VMware Security Hardening Guides](https://www.vmware.com/security/hardening-guides.html)
- [DISA STIGs for VMware](https://public.cyber.mil/stigs/)

## ⚠️ Disclaimer

This tool is provided for security assessment purposes. Always:
- Get proper authorization before scanning
- Test in non-production environments first
- Review findings with your security team
- Follow your organization's security policies

## 📝 License

MIT License - See LICENSE file for details.

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

---

**vSAT** - Because knowing your VMware security posture shouldn't require expensive tools!
