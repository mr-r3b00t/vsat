# 🛡️ vSAT - vCenter Security Audit Tool

[![GitHub](https://img.shields.io/badge/GitHub-mr--r3b00t%2Fvsat-blue?logo=github)](https://github.com/mr-r3b00t/vsat)
[![Python](https://img.shields.io/badge/Python-3.8+-green?logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![VMware](https://img.shields.io/badge/VMware-vCenter%206.x%2F7.x%2F8.x-orange?logo=vmware)](https://www.vmware.com/)

A comprehensive security auditing tool for VMware vCenter environments. Think **RVTools**, but focused on **security**!

> **40+ security checks** mapped to CIS Benchmarks, VMware Hardening Guides, and industry best practices.

---

## 🎯 Why vSAT?

- **Security-First**: Unlike inventory tools, vSAT focuses purely on security misconfigurations
- **AD/SSO Auditing**: Identifies Active Directory users and groups with vCenter access, flags risky groups like "Domain Users" or "Domain Admins" with elevated privileges
- **Compliance Ready**: Built-in CIS ESXi Benchmark mapping for audit reporting
- **Multiple Outputs**: Text, JSON (for SIEM), and beautiful HTML dashboards
- **Lightweight**: Single Python script, minimal dependencies
- **Extensible**: Easy to add custom checks for your environment

---

## 🛡️ Security Checks

### VM Security Audits
| Check | Severity | Reference |
|-------|----------|-----------|
| VMware Tools not installed | HIGH | CIS VMware ESXi Benchmark |
| VMware Tools outdated | MEDIUM | VMware Security Best Practices |
| Old snapshots (>7 days) | MEDIUM/HIGH | VMware KB 1025279 |
| Outdated hardware version | MEDIUM | VMware Hardware Compatibility |
| Secure Boot disabled (EFI) | MEDIUM | CIS VMware Benchmark |
| VBS not enabled (Windows) | LOW | Microsoft VBS Documentation |
| VNC remote display enabled | HIGH | CIS VMware Benchmark |
| Copy/paste enabled | LOW | VMware Hardening Guide |
| Independent disk mode | MEDIUM | VMware Best Practices |
| Host info exposed to guest | MEDIUM | VMware Hardening Guide |

### Host (ESXi) Security Audits
| Check | Severity | Reference |
|-------|----------|-----------|
| SSH service running | HIGH | CIS VMware ESXi Benchmark |
| ESXi Shell running | HIGH | CIS VMware ESXi Benchmark |
| Lockdown mode disabled | HIGH | CIS VMware ESXi 1.1 |
| No remote syslog | HIGH | CIS VMware ESXi 3.1 |
| NTP not configured | MEDIUM | CIS VMware ESXi Benchmark |
| SSL certificate expired | CRITICAL | VMware Certificate Management |
| SSL certificate expiring | HIGH | VMware Certificate Management |
| Firewall allows all IPs | MEDIUM | VMware Security Hardening |
| MOB enabled | HIGH | CIS VMware ESXi Benchmark |
| Shell timeout too long | MEDIUM | VMware Hardening Guide |
| Weak password policy | MEDIUM | CIS VMware ESXi Benchmark |
| Unsupported ESXi version | CRITICAL | VMware Lifecycle Matrix |

### Network Security Audits
| Check | Severity | Reference |
|-------|----------|-----------|
| Promiscuous mode enabled | HIGH | CIS VMware ESXi 7.1 |
| MAC address changes allowed | MEDIUM | CIS VMware ESXi 7.2 |
| Forged transmits allowed | MEDIUM | CIS VMware ESXi 7.3 |

### Permission Audits
| Check | Severity | Reference |
|-------|----------|-----------|
| Root-level admin permissions | HIGH | VMware Security Best Practices |
| Everyone group has permissions | CRITICAL | VMware Security Best Practices |
| Excessive admin accounts (>5) | MEDIUM | Security Best Practices |
| Custom roles with dangerous privileges | MEDIUM | VMware vSphere Security Guide |

### SSO & Active Directory Authentication Audits
| Check | Severity | Reference |
|-------|----------|-----------|
| AD integration detected | INFO | VMware vCenter SSO Best Practices |
| AD account with Administrator role | HIGH/MEDIUM | VMware vCenter Security Configuration |
| Excessive AD Administrator accounts (>3) | HIGH | Security Best Practices |
| Domain Users group with access | CRITICAL | Least Privilege Principle |
| Domain Admins group with access | HIGH | VMware Security Best Practices |
| Domain Computers group with access | CRITICAL | Least Privilege Principle |
| Authenticated Users with access | CRITICAL | Least Privilege Principle |
| Enterprise Admins with access | HIGH | VMware Security Best Practices |
| Generic AD group with Admin access | MEDIUM | VMware Security Best Practices |
| SSO password policy review | INFO | CIS VMware vCenter Benchmark |

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/mr-r3b00t/vsat.git
cd vsat

# Install dependencies
pip install -r requirements.txt
```

### Basic Usage

```bash
# Interactive (will prompt for password)
python vcenter_security_audit.py -s vcenter.example.com -u admin@vsphere.local

# With password (use with caution)
python vcenter_security_audit.py -s vcenter.example.com -u admin@vsphere.local -p 'password'

# JSON output (for SIEM integration)
python vcenter_security_audit.py -s vcenter.example.com -u admin@vsphere.local -o json > report.json

# HTML report (beautiful dashboard)
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

---

## 📊 Output Formats

### Text Report (Default)
Plain text report suitable for terminal viewing or piping to a file.

```
================================================================================
vCenter Security Audit Report
================================================================================
Target: vcenter.example.com
Scan Date: 2024-01-15 10:30:00
vCenter Version: 8.0.1

----------------------------------------
EXECUTIVE SUMMARY
----------------------------------------
Total Findings: 42
  Critical: 2
  High:     8
  Medium:   15
  Low:      12
  Info:     5
```

### JSON Report
Machine-readable JSON format for SIEM integration:

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
- Remediation guidance for each finding

---

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

For complete auditing, these additional permissions help:
- `Authorization.ViewRoles` - For permission auditing
- `Sessions.View` - For session auditing

---

## 🏗️ Architecture

```
vsat/
├── vcenter_security_audit.py    # Main audit tool
├── scheduled_scan.py            # Scheduled scanning wrapper
├── requirements.txt             # Python dependencies
├── config.yaml.example          # Configuration template
└── cis_esxi_8_mapping.json      # CIS Benchmark mapping
```

### Code Structure
```
VCenterSecurityAuditor
├── VM Security Audits
│   ├── _audit_vm_tools()
│   ├── _audit_vm_snapshots()
│   ├── _audit_vm_hardware_version()
│   ├── _audit_vm_security_settings()
│   ├── _audit_vm_disk_settings()
│   ├── _audit_vm_network_settings()
│   └── _audit_vm_advanced_settings()
├── Host Security Audits
│   ├── _audit_host_services()
│   ├── _audit_host_firewall()
│   ├── _audit_host_lockdown()
│   ├── _audit_host_ntp()
│   ├── _audit_host_syslog()
│   ├── _audit_host_version()
│   ├── _audit_host_certificates()
│   └── _audit_host_advanced_settings()
├── Network Security Audits
│   ├── _audit_dvs_security()
│   └── _audit_host_vswitches()
├── Permission Audits
│   ├── _audit_roles()
│   └── _audit_permissions_assignments()
├── SSO & AD Authentication Audits
│   ├── _audit_ad_identity_sources()
│   ├── _audit_ad_permissions()
│   ├── _audit_ad_admin_access()
│   ├── _audit_risky_ad_groups()
│   └── _audit_sso_password_policy()
└── Report Generation
    ├── _generate_text_report()
    ├── _generate_json_report()
    └── _generate_html_report()
```

---

## 📅 Scheduled Scanning

Use `scheduled_scan.py` for automated scans with notifications:

```bash
# Using configuration file
python scheduled_scan.py -c config.yaml

# With compliance report
python scheduled_scan.py -c config.yaml --compliance cis_esxi_8_mapping.json

# Fail on high severity (for CI/CD)
python scheduled_scan.py -c config.yaml --fail-on high
```

### Cron Example
```bash
# /etc/cron.daily/vsat-audit
#!/bin/bash
cd /opt/vsat
export VCENTER_PASSWORD="$(cat /etc/vsat/.password)"
python scheduled_scan.py -c config.yaml --compliance cis_esxi_8_mapping.json
```

---

## 🔗 Integration Examples

### SIEM Integration (JSON to Syslog)
```bash
python vcenter_security_audit.py -s vcenter.example.com -u admin@vsphere.local -o json | \
  jq -c '.findings[]' | \
  while read finding; do
    logger -n siem.example.com -P 514 "$finding"
  done
```

### Splunk HTTP Event Collector
```bash
python vcenter_security_audit.py -s vcenter.example.com -u admin@vsphere.local -o json | \
  curl -k "https://splunk:8088/services/collector" \
    -H "Authorization: Splunk YOUR-HEC-TOKEN" \
    -d @-
```

### CI/CD Pipeline (GitLab/GitHub Actions)
```yaml
security-audit:
  script:
    - pip install pyvmomi
    - python vcenter_security_audit.py -s $VCENTER_HOST -u $VCENTER_USER -p $VCENTER_PASS -o json > audit.json
    - |
      CRITICAL=$(jq '.summary.critical' audit.json)
      if [ "$CRITICAL" -gt 0 ]; then
        echo "Critical findings detected!"
        exit 1
      fi
  artifacts:
    paths:
      - audit.json
```

---

## 📈 Extending the Tool

### Adding New Checks

1. Create a new audit method:
```python
def _audit_vm_encryption(self, vm: vim.VirtualMachine):
    """Check VM encryption status."""
    config = vm.config
    if not config:
        return
    
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

---

## 📚 References

- [CIS VMware ESXi Benchmark](https://www.cisecurity.org/benchmark/vmware)
- [VMware vSphere Security Configuration Guide](https://core.vmware.com/security-configuration-guide)
- [VMware Security Hardening Guides](https://www.vmware.com/security/hardening-guides.html)
- [DISA STIGs for VMware](https://public.cyber.mil/stigs/)

---

## ⚠️ Disclaimer

This tool is provided for security assessment purposes. Always:
- Get proper authorization before scanning
- Test in non-production environments first
- Review findings with your security team
- Follow your organization's security policies

---

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-check`)
3. Commit your changes (`git commit -am 'Add new security check'`)
4. Push to the branch (`git push origin feature/new-check`)
5. Open a Pull Request

### Ideas for Contributions
- [ ] Additional VM security checks (encryption, TPM)
- [ ] Storage security audits (VMFS, vSAN)
- [ ] vCenter SSO/Identity audits
- [ ] Additional compliance framework mappings (NIST, PCI-DSS)
- [ ] Excel/CSV export format
- [ ] Comparison between scans (delta reporting)

---

## 📝 License

MIT License - See [LICENSE](LICENSE) file for details.

---

## 👤 Author

**mr-r3b00t**
- GitHub: [@mr-r3b00t](https://github.com/mr-r3b00t)

---

<p align="center">
  <b>vSAT</b> - Because knowing your VMware security posture shouldn't require expensive tools! 🛡️
</p>
