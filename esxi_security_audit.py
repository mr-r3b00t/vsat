#!/usr/bin/env python3
"""
ESXi Security Audit Tool (eSAT)
===============================
A comprehensive security auditing tool for standalone ESXi hosts.
For hosts NOT managed by vCenter - direct host connection.

Author: Security Audit Tool
License: MIT
"""

import ssl
import sys
import json
import argparse
import getpass
import os
import platform
import socket
import re
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import warnings

# Suppress SSL warnings for self-signed certificates
warnings.filterwarnings('ignore')

try:
    from pyVim.connect import SmartConnect, Disconnect
    from pyVmomi import vim, vmodl
except ImportError:
    print("ERROR: pyVmomi is required. Install with: pip install pyvmomi")
    sys.exit(1)


class SecurityFinding:
    """Represents a security finding with severity and remediation."""
    
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    
    def __init__(self, category: str, severity: str, title: str, 
                 description: str, affected_object: str, 
                 remediation: str, reference: str = ""):
        self.category = category
        self.severity = severity
        self.title = title
        self.description = description
        self.affected_object = affected_object
        self.remediation = remediation
        self.reference = reference
        self.timestamp = datetime.now().isoformat()
    
    def to_dict(self) -> Dict:
        return {
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "affected_object": self.affected_object,
            "remediation": self.remediation,
            "reference": self.reference,
            "timestamp": self.timestamp
        }


class ESXiSecurityAuditor:
    """Security auditor for standalone ESXi hosts."""
    
    def __init__(self, host: str, user: str = "root", password: str = None, port: int = 443):
        self.host = host
        self.user = user
        self.password = password
        self.port = port
        self.si = None
        self.content = None
        self.host_system = None
        self.findings: List[SecurityFinding] = []
        self.stats = defaultdict(int)
        self.host_info = {}
        
    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context that doesn't verify certificates."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    
    def connect(self) -> bool:
        """Connect to ESXi host."""
        try:
            context = self._create_ssl_context()
            
            self.si = SmartConnect(
                host=self.host,
                user=self.user,
                pwd=self.password,
                port=self.port,
                sslContext=context
            )
            self.content = self.si.RetrieveContent()
            
            # Get the host system object
            container = self.content.viewManager.CreateContainerView(
                self.content.rootFolder, [vim.HostSystem], True
            )
            hosts = list(container.view)
            container.Destroy()
            
            if hosts:
                self.host_system = hosts[0]
                self.host_info = {
                    'name': self.host_system.name,
                    'version': self.host_system.config.product.version,
                    'build': self.host_system.config.product.build,
                    'api_version': self.content.about.apiVersion
                }
                print(f"[+] Connected to ESXi host: {self.host}")
                print(f"[+] Host Name: {self.host_info['name']}")
                print(f"[+] ESXi Version: {self.host_info['version']}")
                print(f"[+] Build: {self.host_info['build']}")
                return True
            else:
                print("[-] No host system found")
                return False
                
        except vim.fault.InvalidLogin:
            print(f"[-] Invalid credentials for {self.user}@{self.host}")
            return False
        except socket.gaierror:
            print(f"[-] Cannot resolve hostname: {self.host}")
            return False
        except ConnectionRefusedError:
            print(f"[-] Connection refused by {self.host}:{self.port}")
            return False
        except Exception as e:
            print(f"[-] Failed to connect: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from ESXi host."""
        if self.si:
            try:
                Disconnect(self.si)
                print("[+] Disconnected from ESXi host")
            except:
                pass
    
    def add_finding(self, finding: SecurityFinding):
        """Add a security finding to the results."""
        self.findings.append(finding)
        self.stats[finding.severity] += 1

    # =========================================================================
    # ESXI VERSION AND PATCH AUDITS
    # =========================================================================
    
    def audit_version_and_patches(self):
        """Audit ESXi version and patch status."""
        print("\n[*] Auditing ESXi Version and Patches...")
        
        try:
            version = self.host_system.config.product.version
            build = self.host_system.config.product.build
            
            # Parse version
            version_parts = version.split('.')
            major = int(version_parts[0]) if version_parts else 0
            minor = int(version_parts[1]) if len(version_parts) > 1 else 0
            
            # Check for unsupported versions
            if major < 7:
                self.add_finding(SecurityFinding(
                    category="Version & Patches",
                    severity=SecurityFinding.CRITICAL,
                    title="Unsupported ESXi Version",
                    description=f"ESXi {version} (build {build}) is end of life and no longer receiving security updates.",
                    affected_object=self.host,
                    remediation="Upgrade to ESXi 7.x or 8.x immediately. Unsupported versions have known unpatched vulnerabilities.",
                    reference="VMware Product Lifecycle Matrix"
                ))
            elif major == 7 and minor == 0:
                self.add_finding(SecurityFinding(
                    category="Version & Patches",
                    severity=SecurityFinding.HIGH,
                    title="ESXi 7.0 - Update Recommended",
                    description=f"ESXi {version} should be updated to the latest 7.0 Update release for security fixes.",
                    affected_object=self.host,
                    remediation="Update to the latest ESXi 7.0 Update release.",
                    reference="VMware Security Advisories"
                ))
            
            # Check VIB acceptance level
            try:
                image_config = self.host_system.configManager.imageConfigManager
                if image_config:
                    acceptance_level = image_config.HostImageConfigGetAcceptance()
                    if acceptance_level in ['CommunitySupported', 'PartnerSupported']:
                        self.add_finding(SecurityFinding(
                            category="Version & Patches",
                            severity=SecurityFinding.MEDIUM,
                            title="VIB Acceptance Level Not Strict",
                            description=f"VIB acceptance level is '{acceptance_level}'. This allows unsigned or community VIBs.",
                            affected_object=self.host,
                            remediation="Set VIB acceptance level to 'VMwareCertified' or 'VMwareAccepted' for production systems.",
                            reference="CIS VMware ESXi Benchmark 1.2"
                        ))
            except:
                pass
                
        except Exception as e:
            print(f"    [-] Error checking version: {e}")

    # =========================================================================
    # SERVICE AUDITS
    # =========================================================================
    
    def audit_services(self):
        """Audit running services on ESXi host."""
        print("\n[*] Auditing Services...")
        
        try:
            service_system = self.host_system.configManager.serviceSystem
            services = service_system.serviceInfo.service
            
            # Services that pose security risks
            risky_services = {
                'TSM-SSH': ('SSH', SecurityFinding.HIGH, 
                           'SSH allows remote shell access. Should be disabled unless actively troubleshooting.'),
                'TSM': ('ESXi Shell', SecurityFinding.HIGH,
                       'ESXi Shell allows local console access. Should be disabled unless actively troubleshooting.'),
                'snmpd': ('SNMP', SecurityFinding.MEDIUM,
                         'SNMP can expose host information. Disable if not needed or ensure SNMPv3 is used.'),
                'DCUI': ('Direct Console UI', SecurityFinding.INFO,
                        'DCUI provides physical console access.'),
                'sfcbd-watchdog': ('CIM Server', SecurityFinding.LOW,
                                  'CIM provides hardware monitoring. Review if CIM access is needed.'),
                'slpd': ('SLP Daemon', SecurityFinding.MEDIUM,
                        'SLP (Service Location Protocol) has had critical vulnerabilities. Disable if not needed.'),
            }
            
            running_services = []
            for service in services:
                if service.running:
                    running_services.append(service.key)
                    
                    if service.key in risky_services:
                        name, severity, desc = risky_services[service.key]
                        self.add_finding(SecurityFinding(
                            category="Services",
                            severity=severity,
                            title=f"{name} Service Running",
                            description=desc,
                            affected_object=self.host,
                            remediation=f"Disable the {name} service: esxcli system service set --enabled false -s {service.key}",
                            reference="CIS VMware ESXi Benchmark"
                        ))
                
                # Check for services set to start automatically
                if service.key in ['TSM-SSH', 'TSM'] and service.policy == 'on':
                    self.add_finding(SecurityFinding(
                        category="Services",
                        severity=SecurityFinding.HIGH,
                        title=f"{service.key} Configured to Auto-Start",
                        description=f"Service {service.key} is configured to start automatically on boot.",
                        affected_object=self.host,
                        remediation=f"Set service to manual start: esxcli system service set --policy off -s {service.key}",
                        reference="CIS VMware ESXi Benchmark"
                    ))
            
            # Log running services for reference
            print(f"    Running services: {', '.join(running_services)}")
            
        except Exception as e:
            print(f"    [-] Error auditing services: {e}")

    # =========================================================================
    # FIREWALL AUDITS
    # =========================================================================
    
    def audit_firewall(self):
        """Audit ESXi firewall configuration."""
        print("\n[*] Auditing Firewall...")
        
        try:
            firewall = self.host_system.configManager.firewallSystem
            
            if not firewall:
                self.add_finding(SecurityFinding(
                    category="Firewall",
                    severity=SecurityFinding.HIGH,
                    title="Firewall Not Available",
                    description="Could not access firewall configuration.",
                    affected_object=self.host,
                    remediation="Verify firewall service is running.",
                    reference="VMware Security Guide"
                ))
                return
            
            # Check default policy
            default_policy = firewall.firewallInfo.defaultPolicy
            
            if not default_policy.incomingBlocked:
                self.add_finding(SecurityFinding(
                    category="Firewall",
                    severity=SecurityFinding.HIGH,
                    title="Firewall Default Incoming Policy Open",
                    description="The default firewall policy allows all incoming connections.",
                    affected_object=self.host,
                    remediation="Set default incoming policy to DROP: esxcli network firewall set --default-action false",
                    reference="CIS VMware ESXi Benchmark 2.2"
                ))
            
            if not default_policy.outgoingBlocked:
                self.add_finding(SecurityFinding(
                    category="Firewall",
                    severity=SecurityFinding.INFO,
                    title="Firewall Default Outgoing Policy Open",
                    description="The default firewall policy allows all outgoing connections.",
                    affected_object=self.host,
                    remediation="Consider restricting outgoing connections if high security is required.",
                    reference="VMware Security Hardening Guide"
                ))
            
            # Check for overly permissive rules
            for ruleset in firewall.firewallInfo.ruleset:
                if ruleset.enabled and ruleset.allowedHosts:
                    if ruleset.allowedHosts.allIp:
                        # Some rulesets allowing all IPs are more concerning than others
                        high_risk_rulesets = ['sshClient', 'sshServer', 'webAccess', 'vSphereClient',
                                             'httpClient', 'httpsClient', 'nfsClient', 'nfs41Client']
                        
                        if ruleset.key in high_risk_rulesets:
                            self.add_finding(SecurityFinding(
                                category="Firewall",
                                severity=SecurityFinding.MEDIUM,
                                title=f"Firewall Rule '{ruleset.key}' Allows All IPs",
                                description=f"Ruleset '{ruleset.key}' is enabled and allows connections from any IP address.",
                                affected_object=self.host,
                                remediation=f"Restrict to specific IPs: esxcli network firewall ruleset set -r {ruleset.key} -a false",
                                reference="CIS VMware ESXi Benchmark"
                            ))
                        
        except Exception as e:
            print(f"    [-] Error auditing firewall: {e}")

    # =========================================================================
    # LOCKDOWN MODE AUDIT
    # =========================================================================
    
    def audit_lockdown_mode(self):
        """Check lockdown mode status."""
        print("\n[*] Auditing Lockdown Mode...")
        
        try:
            access_manager = self.host_system.configManager.hostAccessManager
            lockdown_mode = access_manager.lockdownMode
            
            if lockdown_mode == vim.host.HostAccessManager.LockdownMode.lockdownDisabled:
                self.add_finding(SecurityFinding(
                    category="Access Control",
                    severity=SecurityFinding.HIGH,
                    title="Lockdown Mode Disabled",
                    description="Lockdown mode is disabled. Direct API and CLI access is allowed to the host.",
                    affected_object=self.host,
                    remediation="Enable lockdown mode. Note: Only do this if managed by vCenter, otherwise you may lose access.",
                    reference="CIS VMware ESXi Benchmark 5.5"
                ))
            elif lockdown_mode == vim.host.HostAccessManager.LockdownMode.lockdownNormal:
                self.add_finding(SecurityFinding(
                    category="Access Control",
                    severity=SecurityFinding.INFO,
                    title="Normal Lockdown Mode Enabled",
                    description="Normal lockdown mode is enabled. DCUI access is still available.",
                    affected_object=self.host,
                    remediation="Consider strict lockdown mode for highest security (vCenter managed hosts only).",
                    reference="CIS VMware ESXi Benchmark"
                ))
            elif lockdown_mode == vim.host.HostAccessManager.LockdownMode.lockdownStrict:
                self.add_finding(SecurityFinding(
                    category="Access Control",
                    severity=SecurityFinding.INFO,
                    title="Strict Lockdown Mode Enabled",
                    description="Strict lockdown mode is enabled. Highest security configuration.",
                    affected_object=self.host,
                    remediation="Ensure you have vCenter access as DCUI is disabled.",
                    reference="CIS VMware ESXi Benchmark"
                ))
        except Exception as e:
            print(f"    [-] Error checking lockdown mode: {e}")

    # =========================================================================
    # NTP AUDIT
    # =========================================================================
    
    def audit_ntp(self):
        """Audit NTP configuration."""
        print("\n[*] Auditing NTP Configuration...")
        
        try:
            datetime_system = self.host_system.configManager.dateTimeSystem
            datetime_info = datetime_system.dateTimeInfo
            
            if not datetime_info.ntpConfig or not datetime_info.ntpConfig.server:
                self.add_finding(SecurityFinding(
                    category="Time Sync",
                    severity=SecurityFinding.MEDIUM,
                    title="NTP Not Configured",
                    description="No NTP servers configured. Accurate time is critical for security logging, certificates, and authentication.",
                    affected_object=self.host,
                    remediation="Configure NTP: esxcli system ntp set --server=pool.ntp.org",
                    reference="CIS VMware ESXi Benchmark 2.1"
                ))
            elif len(datetime_info.ntpConfig.server) < 2:
                servers = ', '.join(datetime_info.ntpConfig.server)
                self.add_finding(SecurityFinding(
                    category="Time Sync",
                    severity=SecurityFinding.LOW,
                    title="Insufficient NTP Servers",
                    description=f"Only {len(datetime_info.ntpConfig.server)} NTP server(s) configured: {servers}. Multiple servers provide redundancy.",
                    affected_object=self.host,
                    remediation="Configure at least 2 NTP servers for redundancy.",
                    reference="VMware Best Practices"
                ))
            else:
                servers = ', '.join(datetime_info.ntpConfig.server)
                print(f"    NTP servers configured: {servers}")
            
            # Check if NTP service is running
            service_system = self.host_system.configManager.serviceSystem
            for service in service_system.serviceInfo.service:
                if service.key == 'ntpd':
                    if not service.running:
                        self.add_finding(SecurityFinding(
                            category="Time Sync",
                            severity=SecurityFinding.MEDIUM,
                            title="NTP Service Not Running",
                            description="NTP daemon is not running. Time synchronization is not active.",
                            affected_object=self.host,
                            remediation="Start NTP service: esxcli system ntp set --enabled true",
                            reference="CIS VMware ESXi Benchmark"
                        ))
                    break
                    
        except Exception as e:
            print(f"    [-] Error auditing NTP: {e}")

    # =========================================================================
    # SYSLOG AUDIT
    # =========================================================================
    
    def audit_syslog(self):
        """Audit syslog configuration."""
        print("\n[*] Auditing Syslog Configuration...")
        
        try:
            advanced_options = self.host_system.configManager.advancedOption
            options = {opt.key: opt.value for opt in advanced_options.QueryOptions()}
            
            syslog_host = options.get('Syslog.global.logHost', '')
            
            if not syslog_host:
                self.add_finding(SecurityFinding(
                    category="Logging",
                    severity=SecurityFinding.HIGH,
                    title="Remote Syslog Not Configured",
                    description="No remote syslog server configured. Logs are only stored locally and may be lost or tampered with.",
                    affected_object=self.host,
                    remediation="Configure remote syslog: esxcli system syslog config set --loghost=tcp://syslog.example.com:514",
                    reference="CIS VMware ESXi Benchmark 3.2"
                ))
            else:
                print(f"    Remote syslog configured: {syslog_host}")
            
            # Check log directory on persistent storage
            log_dir = options.get('Syslog.global.logDir', '')
            if log_dir and '/scratch' not in log_dir.lower():
                self.add_finding(SecurityFinding(
                    category="Logging",
                    severity=SecurityFinding.MEDIUM,
                    title="Logs May Not Persist Across Reboots",
                    description=f"Log directory '{log_dir}' may not be on persistent storage.",
                    affected_object=self.host,
                    remediation="Configure log directory on persistent storage (e.g., /scratch/log).",
                    reference="VMware KB 2003322"
                ))
                
        except Exception as e:
            print(f"    [-] Error auditing syslog: {e}")

    # =========================================================================
    # ADVANCED SETTINGS AUDIT
    # =========================================================================
    
    def audit_advanced_settings(self):
        """Audit advanced/security settings."""
        print("\n[*] Auditing Advanced Settings...")
        
        try:
            advanced_options = self.host_system.configManager.advancedOption
            options = {opt.key: opt.value for opt in advanced_options.QueryOptions()}
            
            # Security-sensitive settings
            settings_checks = [
                # (setting_key, expected_value, comparison, title, severity, description)
                ('UserVars.ESXiShellInteractiveTimeOut', 900, 'lte', 
                 'Shell Interactive Timeout Too Long', SecurityFinding.MEDIUM,
                 'ESXi shell should automatically timeout idle sessions.'),
                ('UserVars.ESXiShellTimeOut', 900, 'lte',
                 'Shell Availability Timeout Too Long', SecurityFinding.MEDIUM,
                 'ESXi shell availability should be time-limited.'),
                ('Security.AccountLockFailures', 5, 'lte',
                 'Account Lockout Threshold Too High', SecurityFinding.MEDIUM,
                 'Too many failed login attempts allowed before lockout.'),
                ('Security.AccountUnlockTime', 900, 'gte',
                 'Account Unlock Time Too Short', SecurityFinding.MEDIUM,
                 'Locked accounts should remain locked longer.'),
                ('Config.HostAgent.plugins.solo.enableMob', False, 'eq',
                 'Managed Object Browser (MOB) Enabled', SecurityFinding.HIGH,
                 'MOB provides API access that can be exploited.'),
                ('UserVars.SuppressShellWarning', 0, 'eq',
                 'Shell Warning Suppressed', SecurityFinding.LOW,
                 'Shell warning should be displayed when SSH/Shell is enabled.'),
                ('DCUI.Access', '', 'nonempty',
                 'DCUI Access Not Restricted', SecurityFinding.INFO,
                 'Consider restricting DCUI access to specific users.'),
                ('Security.PasswordQualityControl', '', 'nonempty',
                 'Password Quality Not Configured', SecurityFinding.MEDIUM,
                 'Password complexity requirements should be configured.'),
                ('Mem.ShareForceSalting', 2, 'eq',
                 'TPS Salting Not Enabled', SecurityFinding.LOW,
                 'Transparent Page Sharing salting prevents cross-VM memory attacks.'),
            ]
            
            for setting, expected, comparison, title, severity, desc in settings_checks:
                if setting in options:
                    value = options[setting]
                    issue = False
                    
                    if comparison == 'lte':
                        issue = value > expected or value == 0
                    elif comparison == 'gte':
                        issue = value < expected
                    elif comparison == 'eq':
                        issue = value != expected
                    elif comparison == 'nonempty':
                        issue = not value
                    
                    if issue:
                        self.add_finding(SecurityFinding(
                            category="Advanced Settings",
                            severity=severity,
                            title=title,
                            description=f"{desc} Current value: {value}",
                            affected_object=self.host,
                            remediation=f"Configure {setting} appropriately via esxcli or vSphere Client.",
                            reference="VMware Hardening Guide"
                        ))
                        
        except Exception as e:
            print(f"    [-] Error auditing advanced settings: {e}")

    # =========================================================================
    # NETWORK SECURITY AUDIT
    # =========================================================================
    
    def audit_network_security(self):
        """Audit network and vSwitch security."""
        print("\n[*] Auditing Network Security...")
        
        try:
            network_system = self.host_system.configManager.networkSystem
            
            # Audit standard vSwitches
            for vswitch in network_system.networkInfo.vswitch:
                spec = vswitch.spec
                if not spec or not spec.policy:
                    continue
                
                security = spec.policy.security
                if security:
                    # Promiscuous mode
                    if security.allowPromiscuous:
                        self.add_finding(SecurityFinding(
                            category="Network Security",
                            severity=SecurityFinding.HIGH,
                            title=f"Promiscuous Mode Enabled on vSwitch",
                            description=f"Promiscuous mode is enabled on vSwitch '{vswitch.name}'. VMs can see all network traffic.",
                            affected_object=f"{self.host}/{vswitch.name}",
                            remediation="Disable promiscuous mode unless required for network monitoring.",
                            reference="CIS VMware ESXi Benchmark 7.1"
                        ))
                    
                    # MAC address changes
                    if security.macChanges:
                        self.add_finding(SecurityFinding(
                            category="Network Security",
                            severity=SecurityFinding.MEDIUM,
                            title=f"MAC Address Changes Allowed on vSwitch",
                            description=f"MAC address changes are allowed on vSwitch '{vswitch.name}'. Enables MAC spoofing.",
                            affected_object=f"{self.host}/{vswitch.name}",
                            remediation="Reject MAC address changes unless specifically required.",
                            reference="CIS VMware ESXi Benchmark 7.2"
                        ))
                    
                    # Forged transmits
                    if security.forgedTransmits:
                        self.add_finding(SecurityFinding(
                            category="Network Security",
                            severity=SecurityFinding.MEDIUM,
                            title=f"Forged Transmits Allowed on vSwitch",
                            description=f"Forged transmits are allowed on vSwitch '{vswitch.name}'. Enables traffic spoofing.",
                            affected_object=f"{self.host}/{vswitch.name}",
                            remediation="Reject forged transmits unless required for nested virtualization.",
                            reference="CIS VMware ESXi Benchmark 7.3"
                        ))
            
            # Audit port groups
            for pg in network_system.networkInfo.portgroup:
                spec = pg.spec
                if not spec or not spec.policy or not spec.policy.security:
                    continue
                
                security = spec.policy.security
                
                if security.allowPromiscuous:
                    self.add_finding(SecurityFinding(
                        category="Network Security",
                        severity=SecurityFinding.HIGH,
                        title=f"Promiscuous Mode Enabled on Port Group",
                        description=f"Promiscuous mode is enabled on port group '{spec.name}'.",
                        affected_object=f"{self.host}/{spec.name}",
                        remediation="Disable promiscuous mode on the port group.",
                        reference="CIS VMware ESXi Benchmark 7.1"
                    ))
                    
        except Exception as e:
            print(f"    [-] Error auditing network security: {e}")

    # =========================================================================
    # STORAGE SECURITY AUDIT
    # =========================================================================
    
    def audit_storage_security(self):
        """Audit storage configuration security."""
        print("\n[*] Auditing Storage Security...")
        
        try:
            storage_system = self.host_system.configManager.storageSystem
            
            # Check for iSCSI CHAP authentication
            for hba in storage_system.storageDeviceInfo.hostBusAdapter:
                if isinstance(hba, vim.host.InternetScsiHba):
                    # Check CHAP settings
                    if hasattr(hba, 'authenticationProperties'):
                        auth = hba.authenticationProperties
                        if not auth.chapAuthEnabled:
                            self.add_finding(SecurityFinding(
                                category="Storage Security",
                                severity=SecurityFinding.MEDIUM,
                                title="iSCSI CHAP Authentication Disabled",
                                description=f"CHAP authentication is disabled on iSCSI adapter '{hba.device}'.",
                                affected_object=f"{self.host}/{hba.device}",
                                remediation="Enable bidirectional CHAP authentication for iSCSI.",
                                reference="CIS VMware ESXi Benchmark 6.1"
                            ))
                        elif not auth.mutualChapAuthenticationRequired:
                            self.add_finding(SecurityFinding(
                                category="Storage Security",
                                severity=SecurityFinding.LOW,
                                title="iSCSI Mutual CHAP Not Required",
                                description=f"Mutual (bidirectional) CHAP is not required on iSCSI adapter '{hba.device}'.",
                                affected_object=f"{self.host}/{hba.device}",
                                remediation="Enable mutual CHAP for stronger iSCSI authentication.",
                                reference="CIS VMware ESXi Benchmark 6.1"
                            ))
                            
        except Exception as e:
            print(f"    [-] Error auditing storage security: {e}")

    # =========================================================================
    # VM SECURITY AUDIT
    # =========================================================================
    
    def audit_vm_security(self):
        """Audit virtual machine security configurations."""
        print("\n[*] Auditing VM Security...")
        
        try:
            container = self.content.viewManager.CreateContainerView(
                self.content.rootFolder, [vim.VirtualMachine], True
            )
            vms = list(container.view)
            container.Destroy()
            
            print(f"    Found {len(vms)} VMs")
            
            for vm in vms:
                try:
                    self._audit_single_vm(vm)
                except Exception as e:
                    print(f"    [-] Error auditing VM {vm.name}: {e}")
                    
        except Exception as e:
            print(f"    [-] Error getting VMs: {e}")
    
    def _audit_single_vm(self, vm: vim.VirtualMachine):
        """Audit a single VM."""
        config = vm.config
        if not config:
            return
        
        # Check for old snapshots
        if vm.snapshot:
            self._check_snapshots(vm)
        
        # Check hardware version
        try:
            hw_version = int(config.version.split("-")[1])
            if hw_version < 14:
                self.add_finding(SecurityFinding(
                    category="VM Security",
                    severity=SecurityFinding.MEDIUM,
                    title="Outdated VM Hardware Version",
                    description=f"VM '{vm.name}' uses hardware version {config.version}. Missing modern security features.",
                    affected_object=vm.name,
                    remediation="Upgrade VM hardware version to 14 or later.",
                    reference="VMware Hardware Compatibility"
                ))
        except:
            pass
        
        # Check extra config for security settings
        if config.extraConfig:
            extra_config = {opt.key: opt.value for opt in config.extraConfig}
            
            # Check for VNC
            if extra_config.get('RemoteDisplay.vnc.enabled', 'false').lower() == 'true':
                self.add_finding(SecurityFinding(
                    category="VM Security",
                    severity=SecurityFinding.HIGH,
                    title="VNC Remote Display Enabled",
                    description=f"VNC is enabled on VM '{vm.name}'. Provides unencrypted remote console access.",
                    affected_object=vm.name,
                    remediation="Disable VNC and use VMRC or web console instead.",
                    reference="CIS VMware Benchmark"
                ))
            
            # Check copy/paste settings
            if extra_config.get('isolation.tools.copy.disable', 'false').lower() != 'true':
                if extra_config.get('isolation.tools.paste.disable', 'false').lower() != 'true':
                    self.add_finding(SecurityFinding(
                        category="VM Security",
                        severity=SecurityFinding.LOW,
                        title="Copy/Paste Not Disabled",
                        description=f"Copy/paste between guest and host is not disabled on VM '{vm.name}'.",
                        affected_object=vm.name,
                        remediation="Disable copy/paste if not needed for security-sensitive VMs.",
                        reference="VMware Hardening Guide"
                    ))
    
    def _check_snapshots(self, vm: vim.VirtualMachine):
        """Check for old snapshots on a VM."""
        def check_age(snapshot, path=""):
            current_path = f"{path}/{snapshot.name}" if path else snapshot.name
            snap_age = datetime.now() - snapshot.createTime.replace(tzinfo=None)
            
            if snap_age > timedelta(days=7):
                severity = SecurityFinding.HIGH if snap_age > timedelta(days=30) else SecurityFinding.MEDIUM
                self.add_finding(SecurityFinding(
                    category="VM Security",
                    severity=severity,
                    title="Old Snapshot Detected",
                    description=f"Snapshot '{current_path}' on VM '{vm.name}' is {snap_age.days} days old.",
                    affected_object=vm.name,
                    remediation="Review and remove unnecessary snapshots. Do not use snapshots as backups.",
                    reference="VMware KB 1025279"
                ))
            
            for child in snapshot.childSnapshotList:
                check_age(child, current_path)
        
        for snapshot in vm.snapshot.rootSnapshotList:
            check_age(snapshot)

    # =========================================================================
    # USER/ACCOUNT AUDIT
    # =========================================================================
    
    def audit_users(self):
        """Audit local user accounts."""
        print("\n[*] Auditing User Accounts...")
        
        try:
            account_manager = self.host_system.configManager.accountManager
            
            # Get local users
            users = account_manager.user
            
            for user in users:
                # Check for default/well-known accounts
                if user.key.lower() in ['dcui', 'vpxuser']:
                    continue  # System accounts
                
                if user.key.lower() == 'root':
                    # Root account always exists - check if shell access is possible
                    self.add_finding(SecurityFinding(
                        category="User Accounts",
                        severity=SecurityFinding.INFO,
                        title="Root Account Active",
                        description="The root account is active. Ensure strong password and limited use.",
                        affected_object=self.host,
                        remediation="Use non-root accounts for daily administration. Only use root when necessary.",
                        reference="CIS VMware ESXi Benchmark 4.1"
                    ))
                    
            # Check for multiple admin accounts
            admin_count = len([u for u in users if u.key.lower() not in ['dcui', 'vpxuser']])
            if admin_count > 3:
                self.add_finding(SecurityFinding(
                    category="User Accounts",
                    severity=SecurityFinding.MEDIUM,
                    title="Multiple Local Accounts",
                    description=f"Found {admin_count} local user accounts. Consider using AD integration.",
                    affected_object=self.host,
                    remediation="Minimize local accounts. Use Active Directory for centralized management.",
                    reference="VMware Security Best Practices"
                ))
                
        except Exception as e:
            print(f"    [-] Error auditing users: {e}")

    # =========================================================================
    # CERTIFICATE AUDIT
    # =========================================================================
    
    def audit_certificates(self):
        """Audit SSL certificates."""
        print("\n[*] Auditing Certificates...")
        
        try:
            cert_mgr = self.host_system.configManager.certificateManager
            if cert_mgr and cert_mgr.certificateInfo:
                cert_info = cert_mgr.certificateInfo
                
                if cert_info.notAfter:
                    expiry = cert_info.notAfter.replace(tzinfo=None)
                    days_until_expiry = (expiry - datetime.now()).days
                    
                    if days_until_expiry < 0:
                        self.add_finding(SecurityFinding(
                            category="Certificates",
                            severity=SecurityFinding.CRITICAL,
                            title="SSL Certificate Expired",
                            description=f"Host SSL certificate expired {abs(days_until_expiry)} days ago.",
                            affected_object=self.host,
                            remediation="Renew the host SSL certificate immediately.",
                            reference="VMware Certificate Management"
                        ))
                    elif days_until_expiry < 30:
                        self.add_finding(SecurityFinding(
                            category="Certificates",
                            severity=SecurityFinding.HIGH,
                            title="SSL Certificate Expiring Soon",
                            description=f"Host SSL certificate expires in {days_until_expiry} days.",
                            affected_object=self.host,
                            remediation="Renew the host SSL certificate before expiration.",
                            reference="VMware Certificate Management"
                        ))
                    elif days_until_expiry < 90:
                        self.add_finding(SecurityFinding(
                            category="Certificates",
                            severity=SecurityFinding.MEDIUM,
                            title="SSL Certificate Expiring",
                            description=f"Host SSL certificate expires in {days_until_expiry} days.",
                            affected_object=self.host,
                            remediation="Plan SSL certificate renewal.",
                            reference="VMware Certificate Management"
                        ))
                    else:
                        print(f"    SSL certificate valid for {days_until_expiry} days")
                        
        except Exception as e:
            print(f"    [-] Error auditing certificates: {e}")

    # =========================================================================
    # REPORT GENERATION
    # =========================================================================
    
    def generate_report(self, output_format: str = "text") -> str:
        """Generate audit report."""
        if output_format == "json":
            return self._generate_json_report()
        elif output_format == "html":
            return self._generate_html_report()
        else:
            return self._generate_text_report()
    
    def _generate_text_report(self) -> str:
        """Generate plain text report."""
        lines = []
        lines.append("=" * 80)
        lines.append("ESXi Security Audit Report")
        lines.append("=" * 80)
        lines.append(f"Target: {self.host}")
        lines.append(f"Host Name: {self.host_info.get('name', 'N/A')}")
        lines.append(f"ESXi Version: {self.host_info.get('version', 'N/A')}")
        lines.append(f"Build: {self.host_info.get('build', 'N/A')}")
        lines.append(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")
        
        lines.append("-" * 40)
        lines.append("EXECUTIVE SUMMARY")
        lines.append("-" * 40)
        lines.append(f"Total Findings: {len(self.findings)}")
        lines.append(f"  Critical: {self.stats[SecurityFinding.CRITICAL]}")
        lines.append(f"  High:     {self.stats[SecurityFinding.HIGH]}")
        lines.append(f"  Medium:   {self.stats[SecurityFinding.MEDIUM]}")
        lines.append(f"  Low:      {self.stats[SecurityFinding.LOW]}")
        lines.append(f"  Info:     {self.stats[SecurityFinding.INFO]}")
        lines.append("")
        
        for severity in [SecurityFinding.CRITICAL, SecurityFinding.HIGH, 
                        SecurityFinding.MEDIUM, SecurityFinding.LOW, SecurityFinding.INFO]:
            severity_findings = [f for f in self.findings if f.severity == severity]
            if severity_findings:
                lines.append("-" * 40)
                lines.append(f"{severity} FINDINGS ({len(severity_findings)})")
                lines.append("-" * 40)
                
                for i, finding in enumerate(severity_findings, 1):
                    lines.append(f"\n[{severity}:{i}] {finding.title}")
                    lines.append(f"  Category: {finding.category}")
                    lines.append(f"  Affected: {finding.affected_object}")
                    lines.append(f"  Description: {finding.description}")
                    lines.append(f"  Remediation: {finding.remediation}")
                    if finding.reference:
                        lines.append(f"  Reference: {finding.reference}")
        
        lines.append("\n" + "=" * 80)
        lines.append("End of Report")
        lines.append("=" * 80)
        
        return "\n".join(lines)
    
    def _generate_json_report(self) -> str:
        """Generate JSON report."""
        report = {
            "metadata": {
                "target": self.host,
                "host_name": self.host_info.get('name', 'N/A'),
                "esxi_version": self.host_info.get('version', 'N/A'),
                "build": self.host_info.get('build', 'N/A'),
                "scan_date": datetime.now().isoformat()
            },
            "summary": {
                "total_findings": len(self.findings),
                "critical": self.stats[SecurityFinding.CRITICAL],
                "high": self.stats[SecurityFinding.HIGH],
                "medium": self.stats[SecurityFinding.MEDIUM],
                "low": self.stats[SecurityFinding.LOW],
                "info": self.stats[SecurityFinding.INFO]
            },
            "findings": [f.to_dict() for f in self.findings]
        }
        return json.dumps(report, indent=2)
    
    def _generate_html_report(self) -> str:
        """Generate HTML report."""
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ESXi Security Audit Report - {self.host}</title>
    <style>
        :root {{
            --critical: #dc3545;
            --high: #fd7e14;
            --medium: #ffc107;
            --low: #17a2b8;
            --info: #6c757d;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f5f5;
            color: #333;
            line-height: 1.6;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        header {{
            background: linear-gradient(135deg, #2d3436 0%, #636e72 100%);
            color: white;
            padding: 40px 20px;
            margin-bottom: 30px;
        }}
        header h1 {{ font-size: 2.5rem; margin-bottom: 10px; }}
        header .meta {{ opacity: 0.9; }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .summary-card {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .summary-card.critical {{ border-top: 4px solid var(--critical); }}
        .summary-card.high {{ border-top: 4px solid var(--high); }}
        .summary-card.medium {{ border-top: 4px solid var(--medium); }}
        .summary-card.low {{ border-top: 4px solid var(--low); }}
        .summary-card.info {{ border-top: 4px solid var(--info); }}
        .summary-card .count {{ font-size: 2.5rem; font-weight: bold; }}
        .summary-card .label {{ color: #666; text-transform: uppercase; font-size: 0.8rem; }}
        .findings-section {{ margin-bottom: 30px; }}
        .findings-section h2 {{
            background: white;
            padding: 15px 20px;
            border-radius: 10px 10px 0 0;
            margin-bottom: 0;
        }}
        .finding {{
            background: white;
            padding: 20px;
            border-bottom: 1px solid #eee;
        }}
        .finding:last-child {{ border-radius: 0 0 10px 10px; }}
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 10px;
        }}
        .finding-title {{ font-weight: 600; font-size: 1.1rem; }}
        .severity-badge {{
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: bold;
            text-transform: uppercase;
            color: white;
        }}
        .severity-badge.critical {{ background: var(--critical); }}
        .severity-badge.high {{ background: var(--high); }}
        .severity-badge.medium {{ background: var(--medium); color: #333; }}
        .severity-badge.low {{ background: var(--low); }}
        .severity-badge.info {{ background: var(--info); }}
        .finding-meta {{ color: #666; font-size: 0.9rem; margin-bottom: 10px; }}
        .finding-description {{ margin-bottom: 10px; }}
        .finding-remediation {{
            background: #f8f9fa;
            padding: 10px 15px;
            border-radius: 5px;
            border-left: 3px solid #28a745;
        }}
        .finding-remediation strong {{ color: #28a745; }}
        footer {{
            text-align: center;
            padding: 20px;
            color: #666;
        }}
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>🖥️ ESXi Security Audit Report</h1>
            <div class="meta">
                <p>Target: {self.host}</p>
                <p>Host Name: {self.host_info.get('name', 'N/A')}</p>
                <p>ESXi Version: {self.host_info.get('version', 'N/A')} (Build {self.host_info.get('build', 'N/A')})</p>
                <p>Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
        </div>
    </header>
    
    <div class="container">
        <div class="summary">
            <div class="summary-card">
                <div class="count">{len(self.findings)}</div>
                <div class="label">Total Findings</div>
            </div>
            <div class="summary-card critical">
                <div class="count">{self.stats[SecurityFinding.CRITICAL]}</div>
                <div class="label">Critical</div>
            </div>
            <div class="summary-card high">
                <div class="count">{self.stats[SecurityFinding.HIGH]}</div>
                <div class="label">High</div>
            </div>
            <div class="summary-card medium">
                <div class="count">{self.stats[SecurityFinding.MEDIUM]}</div>
                <div class="label">Medium</div>
            </div>
            <div class="summary-card low">
                <div class="count">{self.stats[SecurityFinding.LOW]}</div>
                <div class="label">Low</div>
            </div>
            <div class="summary-card info">
                <div class="count">{self.stats[SecurityFinding.INFO]}</div>
                <div class="label">Info</div>
            </div>
        </div>
"""
        
        for severity in [SecurityFinding.CRITICAL, SecurityFinding.HIGH, 
                        SecurityFinding.MEDIUM, SecurityFinding.LOW, SecurityFinding.INFO]:
            severity_findings = [f for f in self.findings if f.severity == severity]
            if severity_findings:
                html += f"""
        <div class="findings-section">
            <h2>{severity} Findings ({len(severity_findings)})</h2>
"""
                for finding in severity_findings:
                    html += f"""
            <div class="finding">
                <div class="finding-header">
                    <span class="finding-title">{finding.title}</span>
                    <span class="severity-badge {severity.lower()}">{severity}</span>
                </div>
                <div class="finding-meta">
                    <strong>Category:</strong> {finding.category} | 
                    <strong>Affected:</strong> {finding.affected_object}
                </div>
                <div class="finding-description">{finding.description}</div>
                <div class="finding-remediation">
                    <strong>Remediation:</strong> {finding.remediation}
                </div>
            </div>
"""
                html += "        </div>\n"
        
        html += """
    </div>
    
    <footer>
        <p>Generated by ESXi Security Audit Tool (eSAT)</p>
    </footer>
</body>
</html>
"""
        return html
    
    def run_full_audit(self) -> bool:
        """Run complete security audit."""
        if not self.connect():
            return False
        
        try:
            self.audit_version_and_patches()
            self.audit_services()
            self.audit_firewall()
            self.audit_lockdown_mode()
            self.audit_ntp()
            self.audit_syslog()
            self.audit_advanced_settings()
            self.audit_network_security()
            self.audit_storage_security()
            self.audit_vm_security()
            self.audit_users()
            self.audit_certificates()
            
            print("\n" + "=" * 60)
            print("AUDIT COMPLETE")
            print("=" * 60)
            print(f"Total Findings: {len(self.findings)}")
            print(f"  Critical: {self.stats[SecurityFinding.CRITICAL]}")
            print(f"  High:     {self.stats[SecurityFinding.HIGH]}")
            print(f"  Medium:   {self.stats[SecurityFinding.MEDIUM]}")
            print(f"  Low:      {self.stats[SecurityFinding.LOW]}")
            print(f"  Info:     {self.stats[SecurityFinding.INFO]}")
            
            return True
        finally:
            self.disconnect()


def scan_multiple_hosts(hosts: List[str], user: str, password: str, 
                       output_format: str = "text", output_dir: str = None) -> Dict:
    """Scan multiple ESXi hosts."""
    results = {}
    
    print(f"\n[*] Scanning {len(hosts)} ESXi host(s)...")
    
    for host in hosts:
        print(f"\n{'='*60}")
        print(f"Scanning: {host}")
        print('='*60)
        
        auditor = ESXiSecurityAuditor(host=host, user=user, password=password)
        
        if auditor.run_full_audit():
            results[host] = {
                'success': True,
                'findings': len(auditor.findings),
                'critical': auditor.stats[SecurityFinding.CRITICAL],
                'high': auditor.stats[SecurityFinding.HIGH],
                'medium': auditor.stats[SecurityFinding.MEDIUM],
                'low': auditor.stats[SecurityFinding.LOW],
                'info': auditor.stats[SecurityFinding.INFO],
                'report': auditor.generate_report(output_format)
            }
            
            # Save individual reports if output directory specified
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
                ext = {'text': 'txt', 'json': 'json', 'html': 'html'}[output_format]
                filename = f"{output_dir}/{host.replace('.', '_')}_audit.{ext}"
                with open(filename, 'w') as f:
                    f.write(results[host]['report'])
                print(f"[+] Report saved: {filename}")
        else:
            results[host] = {
                'success': False,
                'error': 'Connection failed'
            }
    
    # Print summary
    print(f"\n{'='*60}")
    print("MULTI-HOST SCAN SUMMARY")
    print('='*60)
    
    total_findings = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    
    for host, result in results.items():
        if result['success']:
            print(f"\n{host}: {result['findings']} findings "
                  f"(C:{result['critical']} H:{result['high']} M:{result['medium']} "
                  f"L:{result['low']} I:{result['info']})")
            total_findings['critical'] += result['critical']
            total_findings['high'] += result['high']
            total_findings['medium'] += result['medium']
            total_findings['low'] += result['low']
            total_findings['info'] += result['info']
        else:
            print(f"\n{host}: FAILED - {result.get('error', 'Unknown error')}")
    
    print(f"\n{'─'*40}")
    print(f"TOTAL: Critical={total_findings['critical']} High={total_findings['high']} "
          f"Medium={total_findings['medium']} Low={total_findings['low']} Info={total_findings['info']}")
    
    return results


def main():
    parser = argparse.ArgumentParser(
        description='ESXi Security Audit Tool (eSAT) - Standalone ESXi Host Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan single host (will prompt for password)
  %(prog)s -s esxi01.example.com
  
  # Scan with explicit credentials
  %(prog)s -s esxi01.example.com -u root -p 'password'
  
  # Scan multiple hosts from file
  %(prog)s -f hosts.txt -u root
  
  # Scan multiple hosts with comma-separated list
  %(prog)s -s esxi01.example.com,esxi02.example.com,esxi03.example.com -u root
  
  # Generate HTML report
  %(prog)s -s esxi01.example.com -u root -o html > report.html
  
  # Scan multiple hosts and save individual reports
  %(prog)s -f hosts.txt -u root -o html --output-dir ./reports
        """
    )
    
    parser.add_argument('-s', '--server', help='ESXi host(s) - comma-separated for multiple')
    parser.add_argument('-f', '--file', help='File containing list of ESXi hosts (one per line)')
    parser.add_argument('-u', '--user', default='root', help='Username (default: root)')
    parser.add_argument('-p', '--password', help='Password (will prompt if not provided)')
    parser.add_argument('-o', '--output', choices=['text', 'json', 'html'], default='text',
                        help='Output format (default: text)')
    parser.add_argument('--port', type=int, default=443, help='ESXi port (default: 443)')
    parser.add_argument('--output-dir', help='Directory to save individual reports (for multi-host scans)')
    
    args = parser.parse_args()
    
    # Collect hosts to scan
    hosts = []
    
    if args.server:
        hosts.extend([h.strip() for h in args.server.split(',') if h.strip()])
    
    if args.file:
        try:
            with open(args.file, 'r') as f:
                hosts.extend([line.strip() for line in f if line.strip() and not line.startswith('#')])
        except FileNotFoundError:
            print(f"[-] Host file not found: {args.file}")
            sys.exit(1)
    
    if not hosts:
        print("[-] No hosts specified. Use -s or -f option.")
        parser.print_help()
        sys.exit(1)
    
    # Remove duplicates while preserving order
    hosts = list(dict.fromkeys(hosts))
    
    print("\n" + "=" * 60)
    print("ESXi Security Audit Tool (eSAT)")
    print("=" * 60)
    
    # Get password if not provided
    password = args.password
    if not password:
        password = getpass.getpass(f"Password for {args.user}: ")
    
    if not password:
        print("[-] Password is required")
        sys.exit(1)
    
    # Single host or multiple hosts
    if len(hosts) == 1:
        auditor = ESXiSecurityAuditor(
            host=hosts[0],
            user=args.user,
            password=password,
            port=args.port
        )
        
        if auditor.run_full_audit():
            report = auditor.generate_report(args.output)
            print("\n" + report)
        else:
            sys.exit(1)
    else:
        # Multiple hosts
        results = scan_multiple_hosts(
            hosts=hosts,
            user=args.user,
            password=password,
            output_format=args.output,
            output_dir=args.output_dir
        )
        
        # Check if any critical findings
        total_critical = sum(r.get('critical', 0) for r in results.values() if r.get('success'))
        if total_critical > 0:
            sys.exit(2)
        
        # Check if any hosts failed
        failed = sum(1 for r in results.values() if not r.get('success'))
        if failed > 0:
            sys.exit(1)


if __name__ == '__main__':
    main()
