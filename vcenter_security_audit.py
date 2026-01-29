#!/usr/bin/env python3
"""
vCenter Security Audit Tool (vSAT)
==================================
A comprehensive security auditing tool for VMware vCenter environments.
Think RVTools, but focused on security!

Author: Security Audit Tool
License: MIT
"""

import ssl
import sys
import json
import argparse
import getpass
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Any, Optional
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


class VCenterSecurityAuditor:
    """Main class for performing security audits on vCenter environments."""
    
    def __init__(self, host: str, user: str, password: str, port: int = 443):
        self.host = host
        self.user = user
        self.password = password
        self.port = port
        self.si = None
        self.content = None
        self.findings: List[SecurityFinding] = []
        self.stats = defaultdict(int)
        
    def connect(self) -> bool:
        """Establish connection to vCenter."""
        try:
            # Create SSL context that doesn't verify certificates
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            self.si = SmartConnect(
                host=self.host,
                user=self.user,
                pwd=self.password,
                port=self.port,
                sslContext=context
            )
            self.content = self.si.RetrieveContent()
            print(f"[+] Connected to vCenter: {self.host}")
            print(f"[+] vCenter Version: {self.content.about.version}")
            print(f"[+] Build: {self.content.about.build}")
            return True
        except Exception as e:
            print(f"[-] Failed to connect: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from vCenter."""
        if self.si:
            Disconnect(self.si)
            print("[+] Disconnected from vCenter")
    
    def add_finding(self, finding: SecurityFinding):
        """Add a security finding to the results."""
        self.findings.append(finding)
        self.stats[finding.severity] += 1
    
    def get_all_vms(self) -> List[vim.VirtualMachine]:
        """Get all VMs from vCenter."""
        container = self.content.viewManager.CreateContainerView(
            self.content.rootFolder, [vim.VirtualMachine], True
        )
        vms = list(container.view)
        container.Destroy()
        return vms
    
    def get_all_hosts(self) -> List[vim.HostSystem]:
        """Get all ESXi hosts from vCenter."""
        container = self.content.viewManager.CreateContainerView(
            self.content.rootFolder, [vim.HostSystem], True
        )
        hosts = list(container.view)
        container.Destroy()
        return hosts
    
    def get_all_networks(self) -> List:
        """Get all networks including distributed port groups."""
        container = self.content.viewManager.CreateContainerView(
            self.content.rootFolder, [vim.Network], True
        )
        networks = list(container.view)
        container.Destroy()
        return networks
    
    def get_all_dvs(self) -> List[vim.DistributedVirtualSwitch]:
        """Get all distributed virtual switches."""
        container = self.content.viewManager.CreateContainerView(
            self.content.rootFolder, [vim.DistributedVirtualSwitch], True
        )
        dvs_list = list(container.view)
        container.Destroy()
        return dvs_list

    # =========================================================================
    # VM SECURITY AUDITS
    # =========================================================================
    
    def audit_vm_security(self):
        """Perform all VM-related security audits."""
        print("\n[*] Auditing VM Security...")
        vms = self.get_all_vms()
        print(f"    Found {len(vms)} virtual machines")
        
        for vm in vms:
            try:
                self._audit_vm_tools(vm)
                self._audit_vm_snapshots(vm)
                self._audit_vm_hardware_version(vm)
                self._audit_vm_security_settings(vm)
                self._audit_vm_disk_settings(vm)
                self._audit_vm_network_settings(vm)
                self._audit_vm_advanced_settings(vm)
            except Exception as e:
                print(f"    [-] Error auditing VM {vm.name}: {e}")
    
    def _audit_vm_tools(self, vm: vim.VirtualMachine):
        """Check VMware Tools status and version."""
        if vm.runtime.powerState != vim.VirtualMachinePowerState.poweredOn:
            return
            
        tools_status = vm.guest.toolsStatus
        tools_version = vm.guest.toolsVersion
        
        if tools_status == vim.vm.GuestInfo.ToolsStatus.toolsNotInstalled:
            self.add_finding(SecurityFinding(
                category="VM Security",
                severity=SecurityFinding.HIGH,
                title="VMware Tools Not Installed",
                description=f"VMware Tools is not installed on this VM, limiting security features and monitoring capabilities.",
                affected_object=vm.name,
                remediation="Install VMware Tools to enable security features like quiesced snapshots and guest introspection.",
                reference="CIS VMware ESXi Benchmark"
            ))
        elif tools_status == vim.vm.GuestInfo.ToolsStatus.toolsOld:
            self.add_finding(SecurityFinding(
                category="VM Security",
                severity=SecurityFinding.MEDIUM,
                title="VMware Tools Outdated",
                description=f"VMware Tools version {tools_version} is outdated and may contain security vulnerabilities.",
                affected_object=vm.name,
                remediation="Update VMware Tools to the latest version.",
                reference="VMware Security Best Practices"
            ))
    
    def _audit_vm_snapshots(self, vm: vim.VirtualMachine):
        """Check for old snapshots which pose security and compliance risks."""
        if not vm.snapshot:
            return
            
        def check_snapshot_age(snapshot, path=""):
            current_path = f"{path}/{snapshot.name}" if path else snapshot.name
            snap_age = datetime.now() - snapshot.createTime.replace(tzinfo=None)
            
            if snap_age > timedelta(days=7):
                severity = SecurityFinding.HIGH if snap_age > timedelta(days=30) else SecurityFinding.MEDIUM
                self.add_finding(SecurityFinding(
                    category="VM Security",
                    severity=severity,
                    title="Old Snapshot Detected",
                    description=f"Snapshot '{current_path}' is {snap_age.days} days old. Old snapshots can contain sensitive data and impact performance.",
                    affected_object=vm.name,
                    remediation="Review and remove unnecessary snapshots. Snapshots should not be used as backups.",
                    reference="VMware KB 1025279"
                ))
            
            for child in snapshot.childSnapshotList:
                check_snapshot_age(child, current_path)
        
        for snapshot in vm.snapshot.rootSnapshotList:
            check_snapshot_age(snapshot)
    
    def _audit_vm_hardware_version(self, vm: vim.VirtualMachine):
        """Check VM hardware version for security features."""
        config = vm.config
        if not config:
            return
            
        hw_version = config.version
        # Extract version number (e.g., "vmx-19" -> 19)
        try:
            version_num = int(hw_version.split("-")[1])
        except:
            return
        
        # Hardware version 14+ supports advanced security features
        if version_num < 14:
            self.add_finding(SecurityFinding(
                category="VM Security",
                severity=SecurityFinding.MEDIUM,
                title="Outdated VM Hardware Version",
                description=f"VM hardware version {hw_version} doesn't support modern security features like VBS and Secure Boot.",
                affected_object=vm.name,
                remediation="Upgrade VM hardware version to vmx-14 or later to enable advanced security features.",
                reference="VMware Hardware Compatibility Guide"
            ))
    
    def _audit_vm_security_settings(self, vm: vim.VirtualMachine):
        """Check VM security configuration settings."""
        config = vm.config
        if not config:
            return
        
        # Check Secure Boot
        if hasattr(config, 'bootOptions') and config.bootOptions:
            if hasattr(config.bootOptions, 'efiSecureBootEnabled'):
                if not config.bootOptions.efiSecureBootEnabled:
                    # Only flag if EFI firmware is used
                    if config.firmware == vim.vm.GuestOsDescriptor.FirmwareType.efi:
                        self.add_finding(SecurityFinding(
                            category="VM Security",
                            severity=SecurityFinding.MEDIUM,
                            title="Secure Boot Disabled",
                            description="EFI Secure Boot is disabled on this VM, allowing unauthorized bootloaders.",
                            affected_object=vm.name,
                            remediation="Enable Secure Boot in VM settings for EFI-based VMs.",
                            reference="CIS VMware Benchmark - VM Security"
                        ))
        
        # Check VBS (Virtualization Based Security)
        if hasattr(config, 'flags') and config.flags:
            if hasattr(config.flags, 'vbsEnabled') and not config.flags.vbsEnabled:
                # Only check for Windows VMs
                if config.guestId and 'windows' in config.guestId.lower():
                    self.add_finding(SecurityFinding(
                        category="VM Security",
                        severity=SecurityFinding.LOW,
                        title="VBS Not Enabled",
                        description="Virtualization Based Security is not enabled on this Windows VM.",
                        affected_object=vm.name,
                        remediation="Enable VBS for enhanced Windows security features like Credential Guard.",
                        reference="Microsoft VBS Documentation"
                    ))
    
    def _audit_vm_disk_settings(self, vm: vim.VirtualMachine):
        """Audit VM disk configuration for security issues."""
        config = vm.config
        if not config or not config.hardware:
            return
        
        for device in config.hardware.device:
            if isinstance(device, vim.vm.device.VirtualDisk):
                backing = device.backing
                
                # Check for independent disks (bypass snapshots)
                if hasattr(backing, 'diskMode'):
                    if 'independent' in backing.diskMode:
                        self.add_finding(SecurityFinding(
                            category="VM Security",
                            severity=SecurityFinding.MEDIUM,
                            title="Independent Disk Mode",
                            description=f"Disk '{device.deviceInfo.label}' uses independent mode, bypassing snapshot protection.",
                            affected_object=vm.name,
                            remediation="Review if independent disk mode is necessary. It bypasses snapshot-based backups.",
                            reference="VMware Disk Mode Best Practices"
                        ))
    
    def _audit_vm_network_settings(self, vm: vim.VirtualMachine):
        """Audit VM network adapter settings."""
        config = vm.config
        if not config or not config.hardware:
            return
        
        for device in config.hardware.device:
            if isinstance(device, vim.vm.device.VirtualEthernetCard):
                # Check for promiscuous mode at VM level
                if hasattr(device, 'allowGuestControl') and device.allowGuestControl:
                    self.add_finding(SecurityFinding(
                        category="Network Security",
                        severity=SecurityFinding.LOW,
                        title="Guest Control of Network Adapter",
                        description=f"Network adapter '{device.deviceInfo.label}' allows guest OS control.",
                        affected_object=vm.name,
                        remediation="Disable guest control of network adapters unless specifically required.",
                        reference="VMware Network Security Guide"
                    ))
    
    def _audit_vm_advanced_settings(self, vm: vim.VirtualMachine):
        """Audit VM advanced/extra configuration options."""
        config = vm.config
        if not config or not config.extraConfig:
            return
        
        extra_config = {opt.key: opt.value for opt in config.extraConfig}
        
        # Security-sensitive settings to check
        security_settings = {
            'isolation.tools.copy.disable': ('true', 'Copy/Paste to VM Enabled', SecurityFinding.LOW),
            'isolation.tools.paste.disable': ('true', 'Copy/Paste from VM Enabled', SecurityFinding.LOW),
            'isolation.tools.diskShrink.disable': ('true', 'Disk Shrinking Enabled', SecurityFinding.LOW),
            'isolation.tools.diskWiper.disable': ('true', 'Disk Wiping Enabled', SecurityFinding.LOW),
            'isolation.device.connectable.disable': ('true', 'Device Hotplug Enabled', SecurityFinding.LOW),
            'isolation.device.edit.disable': ('true', 'Device Editing Enabled', SecurityFinding.LOW),
            'tools.setinfo.sizeLimit': ('1048576', 'SetInfo Size Unlimited', SecurityFinding.LOW),
            'RemoteDisplay.vnc.enabled': ('false', 'VNC Remote Display Enabled', SecurityFinding.HIGH),
            'tools.guestlib.enableHostInfo': ('false', 'Host Info Exposed to Guest', SecurityFinding.MEDIUM),
        }
        
        for setting, (expected, title, severity) in security_settings.items():
            value = extra_config.get(setting, '')
            if value.lower() != expected.lower() and setting in extra_config:
                self.add_finding(SecurityFinding(
                    category="VM Security",
                    severity=severity,
                    title=title,
                    description=f"VM setting '{setting}' is set to '{value}' instead of '{expected}'.",
                    affected_object=vm.name,
                    remediation=f"Set '{setting}' to '{expected}' in VM advanced settings.",
                    reference="VMware Hardening Guide"
                ))
        
        # Check for VNC specifically if enabled
        if extra_config.get('RemoteDisplay.vnc.enabled', 'false').lower() == 'true':
            self.add_finding(SecurityFinding(
                category="VM Security",
                severity=SecurityFinding.HIGH,
                title="VNC Remote Display Enabled",
                description="VNC remote display is enabled, providing unencrypted remote access to VM console.",
                affected_object=vm.name,
                remediation="Disable VNC and use VMRC or HTML5 console instead.",
                reference="CIS VMware Benchmark"
            ))

    # =========================================================================
    # HOST SECURITY AUDITS
    # =========================================================================
    
    def audit_host_security(self):
        """Perform all ESXi host security audits."""
        print("\n[*] Auditing Host Security...")
        hosts = self.get_all_hosts()
        print(f"    Found {len(hosts)} ESXi hosts")
        
        for host in hosts:
            try:
                self._audit_host_services(host)
                self._audit_host_firewall(host)
                self._audit_host_lockdown(host)
                self._audit_host_ntp(host)
                self._audit_host_syslog(host)
                self._audit_host_version(host)
                self._audit_host_certificates(host)
                self._audit_host_advanced_settings(host)
            except Exception as e:
                print(f"    [-] Error auditing host {host.name}: {e}")
    
    def _audit_host_services(self, host: vim.HostSystem):
        """Check for insecure services enabled on host."""
        try:
            service_system = host.configManager.serviceSystem
            services = service_system.serviceInfo.service
        except:
            return
        
        # Services that should typically be disabled
        risky_services = {
            'TSM-SSH': ('SSH', SecurityFinding.HIGH),
            'TSM': ('ESXi Shell', SecurityFinding.HIGH),
            'DCUI': ('Direct Console UI', SecurityFinding.INFO),
            'snmpd': ('SNMP', SecurityFinding.MEDIUM),
        }
        
        for service in services:
            if service.key in risky_services and service.running:
                name, severity = risky_services[service.key]
                self.add_finding(SecurityFinding(
                    category="Host Security",
                    severity=severity,
                    title=f"{name} Service Running",
                    description=f"The {name} service is running on this host, which may pose security risks in production.",
                    affected_object=host.name,
                    remediation=f"Disable the {name} service unless actively needed for troubleshooting.",
                    reference="CIS VMware ESXi Benchmark"
                ))
    
    def _audit_host_firewall(self, host: vim.HostSystem):
        """Audit host firewall configuration."""
        try:
            firewall = host.configManager.firewallSystem
            if not firewall:
                return
            
            default_policy = firewall.firewallInfo.defaultPolicy
            
            # Check if default policy allows all incoming
            if default_policy.incomingBlocked == False:
                self.add_finding(SecurityFinding(
                    category="Host Security",
                    severity=SecurityFinding.HIGH,
                    title="Firewall Default Incoming Policy Open",
                    description="ESXi firewall default policy allows all incoming connections.",
                    affected_object=host.name,
                    remediation="Set default firewall policy to block incoming connections.",
                    reference="CIS VMware ESXi Benchmark"
                ))
            
            # Check for overly permissive rules
            for ruleset in firewall.firewallInfo.ruleset:
                if ruleset.enabled and ruleset.allowedHosts:
                    if ruleset.allowedHosts.allIp:
                        self.add_finding(SecurityFinding(
                            category="Host Security",
                            severity=SecurityFinding.MEDIUM,
                            title="Firewall Rule Allows All IPs",
                            description=f"Firewall ruleset '{ruleset.key}' allows connections from any IP address.",
                            affected_object=host.name,
                            remediation=f"Restrict '{ruleset.key}' to specific IP ranges.",
                            reference="VMware Security Hardening Guide"
                        ))
        except Exception as e:
            pass
    
    def _audit_host_lockdown(self, host: vim.HostSystem):
        """Check host lockdown mode status."""
        try:
            access_manager = host.configManager.hostAccessManager
            lockdown_mode = access_manager.lockdownMode
            
            if lockdown_mode == vim.host.HostAccessManager.LockdownMode.lockdownDisabled:
                self.add_finding(SecurityFinding(
                    category="Host Security",
                    severity=SecurityFinding.HIGH,
                    title="Lockdown Mode Disabled",
                    description="Lockdown mode is disabled, allowing direct host access bypassing vCenter.",
                    affected_object=host.name,
                    remediation="Enable Normal or Strict lockdown mode to enforce vCenter-only management.",
                    reference="CIS VMware ESXi Benchmark 1.1"
                ))
        except:
            pass
    
    def _audit_host_ntp(self, host: vim.HostSystem):
        """Check NTP configuration for time synchronization."""
        try:
            datetime_system = host.configManager.dateTimeSystem
            datetime_info = datetime_system.dateTimeInfo
            
            if not datetime_info.ntpConfig or not datetime_info.ntpConfig.server:
                self.add_finding(SecurityFinding(
                    category="Host Security",
                    severity=SecurityFinding.MEDIUM,
                    title="NTP Not Configured",
                    description="No NTP servers configured. Accurate time is critical for security logging and certificates.",
                    affected_object=host.name,
                    remediation="Configure at least two NTP servers for time synchronization.",
                    reference="CIS VMware ESXi Benchmark"
                ))
            elif len(datetime_info.ntpConfig.server) < 2:
                self.add_finding(SecurityFinding(
                    category="Host Security",
                    severity=SecurityFinding.LOW,
                    title="Insufficient NTP Servers",
                    description="Only one NTP server configured. Multiple servers provide redundancy.",
                    affected_object=host.name,
                    remediation="Configure at least two NTP servers.",
                    reference="VMware Best Practices"
                ))
        except:
            pass
    
    def _audit_host_syslog(self, host: vim.HostSystem):
        """Check syslog configuration for centralized logging."""
        try:
            advanced_options = host.configManager.advancedOption
            options = {opt.key: opt.value for opt in advanced_options.QueryOptions()}
            
            syslog_host = options.get('Syslog.global.logHost', '')
            
            if not syslog_host:
                self.add_finding(SecurityFinding(
                    category="Host Security",
                    severity=SecurityFinding.HIGH,
                    title="Remote Syslog Not Configured",
                    description="No remote syslog server configured. Logs only stored locally and may be lost.",
                    affected_object=host.name,
                    remediation="Configure remote syslog server for centralized logging and forensics.",
                    reference="CIS VMware ESXi Benchmark 3.1"
                ))
        except:
            pass
    
    def _audit_host_version(self, host: vim.HostSystem):
        """Check ESXi version for known vulnerabilities."""
        try:
            version = host.config.product.version
            build = host.config.product.build
            
            # Check for very old versions (customize as needed)
            major_version = int(version.split('.')[0])
            
            if major_version < 7:
                self.add_finding(SecurityFinding(
                    category="Host Security",
                    severity=SecurityFinding.CRITICAL,
                    title="Unsupported ESXi Version",
                    description=f"ESXi version {version} (build {build}) is no longer supported and may have unpatched vulnerabilities.",
                    affected_object=host.name,
                    remediation="Upgrade to a supported ESXi version (7.x or 8.x).",
                    reference="VMware Product Lifecycle Matrix"
                ))
            elif major_version == 7 and int(version.split('.')[1]) == 0:
                self.add_finding(SecurityFinding(
                    category="Host Security",
                    severity=SecurityFinding.MEDIUM,
                    title="ESXi Version Should Be Updated",
                    description=f"ESXi version {version} should be updated to the latest patch level.",
                    affected_object=host.name,
                    remediation="Apply latest ESXi patches and updates.",
                    reference="VMware Security Advisories"
                ))
        except:
            pass
    
    def _audit_host_certificates(self, host: vim.HostSystem):
        """Check SSL certificate validity."""
        try:
            cert_mgr = host.configManager.certificateManager
            if cert_mgr:
                cert_info = cert_mgr.certificateInfo
                if cert_info:
                    # Check certificate expiration
                    not_after = cert_info.notAfter
                    if not_after:
                        days_until_expiry = (not_after.replace(tzinfo=None) - datetime.now()).days
                        
                        if days_until_expiry < 0:
                            self.add_finding(SecurityFinding(
                                category="Host Security",
                                severity=SecurityFinding.CRITICAL,
                                title="SSL Certificate Expired",
                                description=f"Host SSL certificate expired {abs(days_until_expiry)} days ago.",
                                affected_object=host.name,
                                remediation="Renew the host SSL certificate immediately.",
                                reference="VMware Certificate Management"
                            ))
                        elif days_until_expiry < 30:
                            self.add_finding(SecurityFinding(
                                category="Host Security",
                                severity=SecurityFinding.HIGH,
                                title="SSL Certificate Expiring Soon",
                                description=f"Host SSL certificate expires in {days_until_expiry} days.",
                                affected_object=host.name,
                                remediation="Renew the host SSL certificate before expiration.",
                                reference="VMware Certificate Management"
                            ))
        except:
            pass
    
    def _audit_host_advanced_settings(self, host: vim.HostSystem):
        """Audit host advanced settings for security issues."""
        try:
            advanced_options = host.configManager.advancedOption
            options = {opt.key: opt.value for opt in advanced_options.QueryOptions()}
            
            # Security-sensitive advanced settings
            settings_to_check = {
                'UserVars.ESXiShellInteractiveTimeOut': (300, 'lt', 'Shell Timeout Too Long', SecurityFinding.MEDIUM),
                'UserVars.ESXiShellTimeOut': (300, 'lt', 'Shell Availability Timeout Too Long', SecurityFinding.MEDIUM),
                'Security.AccountLockFailures': (3, 'gt', 'Account Lockout Threshold Too High', SecurityFinding.MEDIUM),
                'Security.AccountUnlockTime': (900, 'lt', 'Account Unlock Time Too Short', SecurityFinding.MEDIUM),
                'Security.PasswordQualityControl': ('', 'empty', 'Password Quality Not Configured', SecurityFinding.MEDIUM),
                'Config.HostAgent.plugins.solo.enableMob': (False, 'eq', 'MOB Enabled', SecurityFinding.HIGH),
                'DCUI.Access': ('', 'nonempty', 'DCUI Access Restricted', SecurityFinding.INFO),
            }
            
            for setting, (expected, comparison, title, severity) in settings_to_check.items():
                if setting in options:
                    value = options[setting]
                    
                    issue = False
                    if comparison == 'lt' and isinstance(value, (int, float)):
                        issue = value > expected or value == 0
                    elif comparison == 'gt' and isinstance(value, (int, float)):
                        issue = value < expected
                    elif comparison == 'eq':
                        issue = value == expected
                    elif comparison == 'empty':
                        issue = not value
                    
                    if issue:
                        self.add_finding(SecurityFinding(
                            category="Host Security",
                            severity=severity,
                            title=title,
                            description=f"Setting '{setting}' has value '{value}', expected based on security best practices.",
                            affected_object=host.name,
                            remediation=f"Review and configure '{setting}' according to security hardening guide.",
                            reference="VMware Hardening Guide"
                        ))
        except:
            pass

    # =========================================================================
    # NETWORK SECURITY AUDITS
    # =========================================================================
    
    def audit_network_security(self):
        """Perform all network-related security audits."""
        print("\n[*] Auditing Network Security...")
        
        # Audit distributed virtual switches
        dvs_list = self.get_all_dvs()
        print(f"    Found {len(dvs_list)} distributed virtual switches")
        
        for dvs in dvs_list:
            try:
                self._audit_dvs_security(dvs)
            except Exception as e:
                print(f"    [-] Error auditing DVS {dvs.name}: {e}")
        
        # Audit standard vSwitches on each host
        hosts = self.get_all_hosts()
        for host in hosts:
            try:
                self._audit_host_vswitches(host)
            except Exception as e:
                print(f"    [-] Error auditing vSwitches on {host.name}: {e}")
    
    def _audit_dvs_security(self, dvs: vim.DistributedVirtualSwitch):
        """Audit distributed virtual switch security settings."""
        try:
            # Check port groups
            for pg in dvs.portgroup:
                config = pg.config
                if not config:
                    continue
                
                policy = config.defaultPortConfig
                if not policy:
                    continue
                
                security_policy = policy.securityPolicy
                if security_policy:
                    # Check promiscuous mode
                    if hasattr(security_policy, 'allowPromiscuous') and security_policy.allowPromiscuous:
                        if security_policy.allowPromiscuous.value:
                            self.add_finding(SecurityFinding(
                                category="Network Security",
                                severity=SecurityFinding.HIGH,
                                title="Promiscuous Mode Enabled",
                                description=f"Promiscuous mode is enabled on port group '{config.name}', allowing VMs to see all network traffic.",
                                affected_object=f"{dvs.name}/{config.name}",
                                remediation="Disable promiscuous mode unless specifically required for network monitoring.",
                                reference="CIS VMware ESXi Benchmark 7.1"
                            ))
                    
                    # Check MAC address changes
                    if hasattr(security_policy, 'macChanges') and security_policy.macChanges:
                        if security_policy.macChanges.value:
                            self.add_finding(SecurityFinding(
                                category="Network Security",
                                severity=SecurityFinding.MEDIUM,
                                title="MAC Address Changes Allowed",
                                description=f"MAC address changes are allowed on port group '{config.name}', potentially enabling MAC spoofing.",
                                affected_object=f"{dvs.name}/{config.name}",
                                remediation="Reject MAC address changes unless required.",
                                reference="CIS VMware ESXi Benchmark 7.2"
                            ))
                    
                    # Check forged transmits
                    if hasattr(security_policy, 'forgedTransmits') and security_policy.forgedTransmits:
                        if security_policy.forgedTransmits.value:
                            self.add_finding(SecurityFinding(
                                category="Network Security",
                                severity=SecurityFinding.MEDIUM,
                                title="Forged Transmits Allowed",
                                description=f"Forged transmits are allowed on port group '{config.name}', potentially enabling traffic spoofing.",
                                affected_object=f"{dvs.name}/{config.name}",
                                remediation="Reject forged transmits unless required for nested virtualization or specific use cases.",
                                reference="CIS VMware ESXi Benchmark 7.3"
                            ))
        except:
            pass
    
    def _audit_host_vswitches(self, host: vim.HostSystem):
        """Audit standard vSwitches on a host."""
        try:
            network_system = host.configManager.networkSystem
            if not network_system:
                return
            
            for vswitch in network_system.networkInfo.vswitch:
                spec = vswitch.spec
                if not spec or not spec.policy:
                    continue
                
                security = spec.policy.security
                if security:
                    # Check promiscuous mode
                    if security.allowPromiscuous:
                        self.add_finding(SecurityFinding(
                            category="Network Security",
                            severity=SecurityFinding.HIGH,
                            title="Promiscuous Mode Enabled on vSwitch",
                            description=f"Promiscuous mode is enabled on vSwitch '{vswitch.name}'.",
                            affected_object=f"{host.name}/{vswitch.name}",
                            remediation="Disable promiscuous mode on the vSwitch.",
                            reference="CIS VMware ESXi Benchmark"
                        ))
                    
                    # Check MAC changes
                    if security.macChanges:
                        self.add_finding(SecurityFinding(
                            category="Network Security",
                            severity=SecurityFinding.MEDIUM,
                            title="MAC Address Changes Allowed on vSwitch",
                            description=f"MAC address changes are allowed on vSwitch '{vswitch.name}'.",
                            affected_object=f"{host.name}/{vswitch.name}",
                            remediation="Reject MAC address changes on the vSwitch.",
                            reference="CIS VMware ESXi Benchmark"
                        ))
                    
                    # Check forged transmits
                    if security.forgedTransmits:
                        self.add_finding(SecurityFinding(
                            category="Network Security",
                            severity=SecurityFinding.MEDIUM,
                            title="Forged Transmits Allowed on vSwitch",
                            description=f"Forged transmits are allowed on vSwitch '{vswitch.name}'.",
                            affected_object=f"{host.name}/{vswitch.name}",
                            remediation="Reject forged transmits on the vSwitch.",
                            reference="CIS VMware ESXi Benchmark"
                        ))
            
            # Also check port groups
            for pg in network_system.networkInfo.portgroup:
                spec = pg.spec
                if not spec or not spec.policy:
                    continue
                
                security = spec.policy.security
                if security:
                    if security.allowPromiscuous:
                        self.add_finding(SecurityFinding(
                            category="Network Security",
                            severity=SecurityFinding.HIGH,
                            title="Promiscuous Mode Enabled on Port Group",
                            description=f"Promiscuous mode is enabled on port group '{spec.name}'.",
                            affected_object=f"{host.name}/{spec.name}",
                            remediation="Disable promiscuous mode on the port group.",
                            reference="CIS VMware ESXi Benchmark"
                        ))
        except:
            pass

    # =========================================================================
    # PERMISSION AUDITS
    # =========================================================================
    
    def audit_permissions(self):
        """Audit vCenter permissions and roles."""
        print("\n[*] Auditing Permissions...")
        
        self._audit_roles()
        self._audit_permissions_assignments()
    
    def _audit_roles(self):
        """Audit custom roles for overly permissive settings."""
        try:
            auth_manager = self.content.authorizationManager
            roles = auth_manager.roleList
            
            # Dangerous privileges to flag
            dangerous_privs = {
                'VirtualMachine.Interact.ConsoleInteract': 'VM Console Access',
                'VirtualMachine.Interact.DeviceConnection': 'VM Device Connection',
                'VirtualMachine.Config.RawDevice': 'Raw Device Access',
                'VirtualMachine.Config.HostUSBDevice': 'USB Passthrough',
                'Host.Config.Settings': 'Host Configuration',
                'Global.Settings': 'Global Settings',
                'Sessions.TerminateSession': 'Terminate Sessions',
                'Extension.Register': 'Register Extensions',
                'Extension.Unregister': 'Unregister Extensions',
                'Cryptographer.ManageKeys': 'Encryption Key Management',
            }
            
            for role in roles:
                # Skip built-in roles
                if role.roleId < 0:
                    continue
                
                found_dangerous = []
                for priv in role.privilege:
                    if priv in dangerous_privs:
                        found_dangerous.append(dangerous_privs[priv])
                
                if found_dangerous:
                    self.add_finding(SecurityFinding(
                        category="Permissions",
                        severity=SecurityFinding.MEDIUM,
                        title="Custom Role with Sensitive Privileges",
                        description=f"Role '{role.name}' has sensitive privileges: {', '.join(found_dangerous)}",
                        affected_object=role.name,
                        remediation="Review if these privileges are necessary and follow least-privilege principle.",
                        reference="VMware vSphere Security Guide"
                    ))
        except:
            pass
    
    def _audit_permissions_assignments(self):
        """Audit permission assignments for security issues."""
        try:
            auth_manager = self.content.authorizationManager
            
            # Get all permissions
            permissions = auth_manager.RetrieveAllPermissions()
            
            # Track admin-level permissions
            admin_count = 0
            
            for perm in permissions:
                # Check for Administrator role (roleId = -1)
                if perm.roleId == -1:
                    admin_count += 1
                    
                    # Flag if propagating from root
                    if perm.propagate and perm.entity == self.content.rootFolder:
                        self.add_finding(SecurityFinding(
                            category="Permissions",
                            severity=SecurityFinding.HIGH,
                            title="Root-Level Administrator Permission",
                            description=f"User/Group '{perm.principal}' has propagating Administrator rights from root folder.",
                            affected_object=perm.principal,
                            remediation="Limit Administrator permissions to specific objects. Use least-privilege roles.",
                            reference="VMware Security Best Practices"
                        ))
                
                # Check for permissions on Everyone or large groups
                if 'everyone' in perm.principal.lower():
                    self.add_finding(SecurityFinding(
                        category="Permissions",
                        severity=SecurityFinding.CRITICAL,
                        title="Everyone Group Has Permissions",
                        description=f"The 'Everyone' group has been granted permissions (role ID: {perm.roleId}).",
                        affected_object="Everyone",
                        remediation="Remove permissions from 'Everyone' and assign to specific users/groups.",
                        reference="VMware Security Best Practices"
                    ))
            
            # Flag if too many admins
            if admin_count > 5:
                self.add_finding(SecurityFinding(
                    category="Permissions",
                    severity=SecurityFinding.MEDIUM,
                    title="Excessive Administrator Accounts",
                    description=f"Found {admin_count} accounts with Administrator role. Too many admins increases risk.",
                    affected_object="vCenter",
                    remediation="Review admin accounts and reduce to necessary minimum. Use role-based access.",
                    reference="Security Best Practices"
                ))
        except:
            pass

    # =========================================================================
    # VCENTER SERVER AUDITS
    # =========================================================================
    
    def audit_vcenter(self):
        """Audit vCenter server settings."""
        print("\n[*] Auditing vCenter Settings...")
        
        self._audit_vcenter_version()
        self._audit_session_timeout()
    
    def _audit_vcenter_version(self):
        """Check vCenter version."""
        try:
            about = self.content.about
            version = about.version
            build = about.build
            
            major = int(version.split('.')[0])
            
            if major < 7:
                self.add_finding(SecurityFinding(
                    category="vCenter",
                    severity=SecurityFinding.CRITICAL,
                    title="Unsupported vCenter Version",
                    description=f"vCenter version {version} (build {build}) is end of life and no longer receiving security updates.",
                    affected_object="vCenter Server",
                    remediation="Upgrade to vCenter 7.x or 8.x.",
                    reference="VMware Product Lifecycle Matrix"
                ))
        except:
            pass
    
    def _audit_session_timeout(self):
        """Check session timeout settings."""
        try:
            session_manager = self.content.sessionManager
            # Session timeout is typically configured via vCenter settings
            # This is a placeholder for the check
            self.add_finding(SecurityFinding(
                category="vCenter",
                severity=SecurityFinding.INFO,
                title="Review Session Timeout",
                description="Verify that session timeout is configured appropriately (recommended: 15-30 minutes).",
                affected_object="vCenter Server",
                remediation="Configure session timeout in vCenter Advanced Settings.",
                reference="CIS VMware vCenter Benchmark"
            ))
        except:
            pass

    # =========================================================================
    # REPORTING
    # =========================================================================
    
    def generate_report(self, output_format: str = "text") -> str:
        """Generate audit report in specified format."""
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
        lines.append("vCenter Security Audit Report")
        lines.append("=" * 80)
        lines.append(f"Target: {self.host}")
        lines.append(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"vCenter Version: {self.content.about.version}")
        lines.append("")
        
        # Summary
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
        
        # Group findings by severity
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
                "scan_date": datetime.now().isoformat(),
                "vcenter_version": self.content.about.version,
                "vcenter_build": self.content.about.build
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
    <title>vCenter Security Audit Report</title>
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
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: white;
            padding: 40px 20px;
            margin-bottom: 30px;
        }}
        header h1 {{ font-size: 2.5rem; margin-bottom: 10px; }}
        header .meta {{ opacity: 0.8; }}
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
            <h1>🛡️ vCenter Security Audit Report</h1>
            <div class="meta">
                <p>Target: {self.host}</p>
                <p>vCenter Version: {self.content.about.version} (Build {self.content.about.build})</p>
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
        
        # Group findings by severity
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
        <p>Generated by vCenter Security Audit Tool (vSAT)</p>
    </footer>
</body>
</html>
"""
        return html
    
    def run_full_audit(self):
        """Run all security audits."""
        print("\n" + "=" * 60)
        print("vCenter Security Audit Tool (vSAT)")
        print("=" * 60)
        
        if not self.connect():
            return False
        
        try:
            self.audit_vcenter()
            self.audit_host_security()
            self.audit_vm_security()
            self.audit_network_security()
            self.audit_permissions()
            
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


def main():
    parser = argparse.ArgumentParser(
        description='vCenter Security Audit Tool (vSAT)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -s vcenter.example.com -u admin@vsphere.local
  %(prog)s -s vcenter.example.com -u admin@vsphere.local -o json > report.json
  %(prog)s -s vcenter.example.com -u admin@vsphere.local -o html > report.html
        """
    )
    
    parser.add_argument('-s', '--server', required=True, help='vCenter server hostname or IP')
    parser.add_argument('-u', '--user', required=True, help='Username (e.g., admin@vsphere.local)')
    parser.add_argument('-p', '--password', help='Password (will prompt if not provided)')
    parser.add_argument('-o', '--output', choices=['text', 'json', 'html'], default='text',
                        help='Output format (default: text)')
    parser.add_argument('--port', type=int, default=443, help='vCenter port (default: 443)')
    
    args = parser.parse_args()
    
    # Get password if not provided
    password = args.password
    if not password:
        password = getpass.getpass(f"Password for {args.user}: ")
    
    # Run audit
    auditor = VCenterSecurityAuditor(
        host=args.server,
        user=args.user,
        password=password,
        port=args.port
    )
    
    if auditor.run_full_audit():
        report = auditor.generate_report(args.output)
        print("\n" + report)
    else:
        sys.exit(1)


if __name__ == '__main__':
    main()
