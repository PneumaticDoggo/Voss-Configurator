#!/usr/bin/env python3
"""
Extreme Networks VOSS Switch Configuration Manager
Supports configuration generation and live device management via SSH/Serial
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import paramiko
import serial
import serial.tools.list_ports
import time
import json
import re
import hashlib
import random
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Tuple

@dataclass
class VLANConfig:
    vlan_id: int
    name: str
    i_sid: int
    
@dataclass  
class SwitchConfig:
    hostname: str
    snmp_location: str
    mgmt_ip: str
    mgmt_mask: int = 24
    gateway: str = ""
    system_id: str = ""
    nick_name: str = ""
    vlans: List[VLANConfig] = None
    ntp_servers: List[str] = None
    snmp_host: str = ""
    snmp_community: str = "public"
    snmp_group: str = "SNMPGroup"
    snmp_user: str = "snmpuser"
    snmp_auth_password: str = "Auth_Password123"
    snmp_priv_password: str = "Priv_Password123"
    enable_ssh: bool = True
    enable_telnet: bool = False
    enable_isis: bool = True
    isis_area: str = "49.0000"
    spbm_instance: int = 1
    domain_name: str = ""
    name_servers: List[str] = None
    timezone: str = ""
    
    def __post_init__(self):
        if self.vlans is None:
            self.vlans = []
        if self.ntp_servers is None:
            self.ntp_servers = []
        if self.name_servers is None:
            self.name_servers = []

class ConnectionManager:
    def __init__(self):
        self.ssh_client = None
        self.serial_client = None
        self.connection_type = None
        self.connected = False
        self.shell = None
        
    def connect_ssh(self, host, username, password, port=22):
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh_client.connect(host, port=port, 
                                  username=username, password=password,
                                  timeout=10, allow_agent=False, look_for_keys=False)
            self.shell = self.ssh_client.invoke_shell()
            self.shell.settimeout(5)
            self.connection_type = "SSH"
            self.connected = True
            return True
        except Exception as e:
            self.connected = False
            return str(e)
    
    def connect_serial(self, port, baudrate=9600, timeout=5):
        try:
            self.serial_client = serial.Serial(
                port=port,
                baudrate=baudrate,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=timeout
            )
            self.connection_type = "Serial"
            self.connected = True
            return True
        except Exception as e:
            self.connected = False
            return str(e)
            
    def send_command(self, command, wait_time=1):
        if not self.connected:
            return "Not connected"
            
        try:
            if self.connection_type == "SSH":
                self.shell.send(command + '\n')
                time.sleep(wait_time)
                
                output = ""
                while self.shell.recv_ready():
                    data = self.shell.recv(4096).decode('utf-8', errors='ignore')
                    output += data
                return output
                
            elif self.connection_type == "Serial":
                self.serial_client.write((command + '\r\n').encode())
                time.sleep(wait_time)
                
                output = ""
                while self.serial_client.in_waiting:
                    data = self.serial_client.read(self.serial_client.in_waiting).decode('utf-8', errors='ignore')
                    output += data
                return output
                
        except Exception as e:
            return f"Error: {str(e)}"
            
    def disconnect(self):
        if self.shell:
            self.shell.close()
        if self.ssh_client:
            self.ssh_client.close()
            self.ssh_client = None
            
        if self.serial_client:
            self.serial_client.close()
            self.serial_client = None
            
        self.connected = False
        self.connection_type = None

class ConfigGenerator:
    @staticmethod
    def generate_voss_config(config: SwitchConfig) -> str:
        """Generate comprehensive VOSS configuration from SwitchConfig object"""
        lines = []
        
        # Header
        lines.extend([
            "##############################################",
            f"#  {config.hostname} Configuration",
            f"#  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "##############################################",
            "enable",
            "config term",
            ""
        ])
        
        # Basic System Configuration
        lines.extend([
            f'hostname "{config.hostname}"',
            ""
        ])
        
        # Domain and DNS Configuration
        if config.domain_name:
            lines.append(f'ip domain-name {config.domain_name}')
            
        for dns in config.name_servers:
            lines.append(f'ip name-server {dns}')
            
        if config.domain_name or config.name_servers:
            lines.append("")
        
        # Timezone Configuration
        if config.timezone:
            lines.extend([
                f'clock timezone {config.timezone}',
                ""
            ])
        
        # SNMP Configuration
        lines.extend([
            f'snmp-server name {config.hostname}',
            f'snmp-server location "{config.snmp_location}"',
            ""
        ])
        
        # VLAN Configuration
        if config.vlans:
            # Create VLANs first
            for vlan in config.vlans:
                if vlan.name:
                    lines.append(f'vlan create {vlan.vlan_id} name "{vlan.name}" type port-mstprstp 0')
                else:
                    lines.append(f'vlan create {vlan.vlan_id} type port-mstprstp 0')
            
            # Then assign I-SIDs
            if config.enable_isis:
                for vlan in config.vlans:
                    lines.append(f'vlan i-sid {vlan.vlan_id} {vlan.i_sid}')
            
            lines.append("")
        
        # Management Configuration
        mgmt_vlan = config.vlans[0].vlan_id if config.vlans else 1
        lines.extend([
            "# Management Configuration",
            "no mgmt vlan",
            f"mgmt vlan {mgmt_vlan}",
            f"ip address {config.mgmt_ip}/{config.mgmt_mask}",
            f"ip route 0.0.0.0 0.0.0.0 next-hop {config.gateway}",
            "no mgmt dhcp-client",
            ""
        ])
        
        # ISIS Configuration (SPB-M Fabric)
        if config.enable_isis and config.system_id and config.nick_name:
            lines.extend([
                "# ISIS SPB-M Configuration",
                "no router isis",
                "y",
                "router isis",
                f"sys-name {config.hostname}",
                f"system-id {config.system_id}",
                f"manual-area {config.isis_area}",
                f"spbm {config.spbm_instance} nick-name {config.nick_name}",
                "exit",
                "",
                "router isis enable",
                ""
            ])
        
        # Remote Access Configuration
        if config.enable_ssh:
            lines.extend([
                "# SSH Configuration",
                "ssh",
                ""
            ])
            
        if config.enable_telnet:
            lines.extend([
                "# Telnet Configuration", 
                "telnet",
                ""
            ])
        
        # NTP Configuration
        if config.ntp_servers:
            lines.append("# NTP Configuration")
            for ntp_server in config.ntp_servers:
                lines.append(f"ntp server {ntp_server}")
            lines.append("")
        
        # SNMP Security Configuration
        if config.snmp_host:
            lines.extend([
                "# SNMP Security Configuration",
                'snmp-server view ALL 1',
                f'snmp-server group "{config.snmp_group}" "" auth-priv read-view ALL write-view ALL notify-view ALL',
                f'snmp-server user {config.snmp_user} SHA {config.snmp_auth_password} aes {config.snmp_priv_password}',
                f'snmp-server user {config.snmp_user} group "{config.snmp_group}"',
                f'snmp-server host {config.snmp_host} v3 authPriv SNMPv3',
                ""
            ])
        
        # Final Configuration
        lines.extend([
            "# Disable TFTP Server",
            "no boot config flags tftpd",
            "",
            "# Save Configuration",
            "wr mem"
        ])
        
        return '\n'.join(lines)
    
    @staticmethod
    def parse_voss_config(config_text: str) -> SwitchConfig:
        """Parse existing VOSS configuration into SwitchConfig object"""
        lines = config_text.split('\n')
        
        hostname = ""
        snmp_location = ""
        mgmt_ip = ""
        gateway = ""
        system_id = ""
        nick_name = ""
        vlans = []
        ntp_servers = []
        name_servers = []
        snmp_host = ""
        domain_name = ""
        timezone = ""
        
        for line in lines:
            line = line.strip()
            
            if line.startswith('hostname '):
                hostname = line.split(' ', 1)[1].strip('"')
            elif line.startswith('snmp-server name '):
                if not hostname:  # fallback if hostname not set
                    hostname = line.split(' ', 2)[2]
            elif line.startswith('snmp-server location '):
                snmp_location = line.split('"')[1] if '"' in line else line.split(' ', 2)[2]
            elif line.startswith('ip address '):
                mgmt_ip = line.split(' ')[2].split('/')[0]
            elif line.startswith('ip route 0.0.0.0 0.0.0.0 next-hop '):
                gateway = line.split(' ')[-1]
            elif line.startswith('system-id '):
                system_id = line.split(' ')[1]
            elif line.startswith('spbm 1 nick-name '):
                nick_name = line.split(' ')[3]
            elif line.startswith('vlan create '):
                parts = line.split(' ')
                vlan_id = int(parts[2])
                name = ""
                if 'name' in line:
                    name = line.split('"')[1]
                vlans.append({'vlan_id': vlan_id, 'name': name, 'i_sid': 0})
            elif line.startswith('vlan i-sid '):
                parts = line.split(' ')
                vlan_id = int(parts[2])
                i_sid = int(parts[3])
                for vlan in vlans:
                    if vlan['vlan_id'] == vlan_id:
                        vlan['i_sid'] = i_sid
            elif line.startswith('ntp server '):
                ntp_servers.append(line.split(' ')[2])
            elif line.startswith('ip name-server '):
                name_servers.append(line.split(' ')[2])
            elif line.startswith('ip domain-name '):
                domain_name = line.split(' ')[2]
            elif line.startswith('clock timezone '):
                timezone = ' '.join(line.split(' ')[2:])
            elif line.startswith('snmp-server host '):
                snmp_host = line.split(' ')[2]
        
        vlan_configs = [VLANConfig(v['vlan_id'], v['name'], v['i_sid']) for v in vlans]
        
        return SwitchConfig(
            hostname=hostname,
            snmp_location=snmp_location,
            mgmt_ip=mgmt_ip,
            gateway=gateway,
            system_id=system_id,
            nick_name=nick_name,
            vlans=vlan_configs,
            ntp_servers=ntp_servers,
            name_servers=name_servers,
            snmp_host=snmp_host,
            domain_name=domain_name,
            timezone=timezone
        )

class VOSSManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Extreme VOSS Switch Manager")
        self.root.geometry("1400x900")
        
        # Connection Manager
        self.conn_mgr = ConnectionManager()
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create Base Config Tab (New comprehensive tab)
        self.create_base_config_tab()
        
        # Configuration Generator Tab (Simplified)
        self.create_config_tab()
        
        # Live Terminal Tab (Enhanced with Serial)
        self.create_terminal_tab()
        
        # Batch Configuration Tab
        self.create_batch_tab()
        
    def create_base_config_tab(self):
        """Comprehensive configuration builder tab"""
        base_frame = ttk.Frame(self.notebook)
        self.notebook.add(base_frame, text="Create Base Config")
        
        # Create main scrollable frame
        canvas = tk.Canvas(base_frame)
        scrollbar = ttk.Scrollbar(base_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Pack scrollable components
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Bind mousewheel
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        canvas.bind_all("<MouseWheel>", _on_mousewheel)
        
        # Main content in scrollable frame
        main_frame = scrollable_frame
        
        # === BASIC SYSTEM CONFIGURATION ===
        system_frame = ttk.LabelFrame(main_frame, text="Basic System Configuration", padding=10)
        system_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Row 1
        row = 0
        ttk.Label(system_frame, text="Hostname:*").grid(row=row, column=0, sticky=tk.W, padx=5, pady=2)
        self.base_hostname_var = tk.StringVar()
        ttk.Entry(system_frame, textvariable=self.base_hostname_var, width=20).grid(row=row, column=1, padx=5, pady=2)
        
        ttk.Label(system_frame, text="Domain Name:").grid(row=row, column=2, sticky=tk.W, padx=5, pady=2)
        self.base_domain_var = tk.StringVar()
        ttk.Entry(system_frame, textvariable=self.base_domain_var, width=20).grid(row=row, column=3, padx=5, pady=2)
        
        # Row 2
        row += 1
        ttk.Label(system_frame, text="SNMP Location:*").grid(row=row, column=0, sticky=tk.W, padx=5, pady=2)
        self.base_location_var = tk.StringVar()
        ttk.Entry(system_frame, textvariable=self.base_location_var, width=20).grid(row=row, column=1, padx=5, pady=2)
        
        ttk.Label(system_frame, text="Timezone:").grid(row=row, column=2, sticky=tk.W, padx=5, pady=2)
        self.base_timezone_var = tk.StringVar()
        timezone_combo = ttk.Combobox(system_frame, textvariable=self.base_timezone_var, width=17)
        timezone_combo['values'] = ('UTC', 'EST', 'CST', 'MST', 'PST', 'GMT', 'CET', 'JST')
        timezone_combo.grid(row=row, column=3, padx=5, pady=2)
        
        # === MANAGEMENT CONFIGURATION ===
        mgmt_frame = ttk.LabelFrame(main_frame, text="Management Configuration", padding=10)
        mgmt_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Row 1
        row = 0
        ttk.Label(mgmt_frame, text="Management IP:*").grid(row=row, column=0, sticky=tk.W, padx=5, pady=2)
        self.base_mgmt_ip_var = tk.StringVar()
        ttk.Entry(mgmt_frame, textvariable=self.base_mgmt_ip_var, width=15).grid(row=row, column=1, padx=5, pady=2)
        
        ttk.Label(mgmt_frame, text="Subnet Mask:").grid(row=row, column=2, sticky=tk.W, padx=5, pady=2)
        self.base_mgmt_mask_var = tk.StringVar(value="24")
        mask_combo = ttk.Combobox(mgmt_frame, textvariable=self.base_mgmt_mask_var, width=5)
        mask_combo['values'] = ('8', '16', '24', '25', '26', '27', '28', '29', '30')
        mask_combo.grid(row=row, column=3, padx=5, pady=2)
        
        ttk.Label(mgmt_frame, text="Gateway:*").grid(row=row, column=4, sticky=tk.W, padx=5, pady=2)
        self.base_gateway_var = tk.StringVar()
        ttk.Entry(mgmt_frame, textvariable=self.base_gateway_var, width=15).grid(row=row, column=5, padx=5, pady=2)
        
        # === ISIS SPB-M CONFIGURATION ===
        isis_frame = ttk.LabelFrame(main_frame, text="ISIS SPB-M Fabric Configuration", padding=10)
        isis_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.base_enable_isis_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(isis_frame, text="Enable ISIS SPB-M", variable=self.base_enable_isis_var,
                       command=self.toggle_isis_fields).grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        # Row 1
        row = 1
        self.isis_system_id_label = ttk.Label(isis_frame, text="System ID:*")
        self.isis_system_id_label.grid(row=row, column=0, sticky=tk.W, padx=5, pady=2)
        self.base_system_id_var = tk.StringVar()
        self.isis_system_id_entry = ttk.Entry(isis_frame, textvariable=self.base_system_id_var, width=15)
        self.isis_system_id_entry.grid(row=row, column=1, padx=5, pady=2)
        
        self.isis_nick_label = ttk.Label(isis_frame, text="Nick Name:*")
        self.isis_nick_label.grid(row=row, column=2, sticky=tk.W, padx=5, pady=2)
        self.base_nick_name_var = tk.StringVar()
        self.isis_nick_entry = ttk.Entry(isis_frame, textvariable=self.base_nick_name_var, width=15)
        self.isis_nick_entry.grid(row=row, column=3, padx=5, pady=2)
        
        self.isis_area_label = ttk.Label(isis_frame, text="ISIS Area:")
        self.isis_area_label.grid(row=row, column=4, sticky=tk.W, padx=5, pady=2)
        self.base_isis_area_var = tk.StringVar(value="49.0000")
        self.isis_area_entry = ttk.Entry(isis_frame, textvariable=self.base_isis_area_var, width=10)
        self.isis_area_entry.grid(row=row, column=5, padx=5, pady=2)
        
        # Auto-generate buttons
        row += 1
        ttk.Button(isis_frame, text="Auto-Generate System ID", 
                  command=self.auto_generate_system_id).grid(row=row, column=0, columnspan=2, pady=5)
        ttk.Button(isis_frame, text="Auto-Generate Nick Name", 
                  command=self.auto_generate_nick_name).grid(row=row, column=2, columnspan=2, pady=5)
        
        # === VLAN CONFIGURATION ===
        vlan_frame = ttk.LabelFrame(main_frame, text="VLAN Configuration", padding=10)
        vlan_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # VLAN tree
        vlan_tree_frame = ttk.Frame(vlan_frame)
        vlan_tree_frame.pack(fill=tk.BOTH, expand=True)
        
        self.base_vlan_tree = ttk.Treeview(vlan_tree_frame, columns=('VLAN ID', 'Name', 'I-SID'), show='headings', height=6)
        self.base_vlan_tree.heading('VLAN ID', text='VLAN ID')
        self.base_vlan_tree.heading('Name', text='Name')
        self.base_vlan_tree.heading('I-SID', text='I-SID')
        self.base_vlan_tree.column('VLAN ID', width=80)
        self.base_vlan_tree.column('Name', width=120)
        self.base_vlan_tree.column('I-SID', width=100)
        self.base_vlan_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # VLAN controls
        vlan_controls = ttk.Frame(vlan_tree_frame)
        vlan_controls.pack(side=tk.RIGHT, fill=tk.Y, padx=(5, 0))
        
        ttk.Button(vlan_controls, text="Add VLAN", command=self.base_add_vlan).pack(pady=2, fill=tk.X)
        ttk.Button(vlan_controls, text="Edit VLAN", command=self.base_edit_vlan).pack(pady=2, fill=tk.X)
        ttk.Button(vlan_controls, text="Remove VLAN", command=self.base_remove_vlan).pack(pady=2, fill=tk.X)
        ttk.Button(vlan_controls, text="Load Template", command=self.load_vlan_template).pack(pady=2, fill=tk.X)
        ttk.Button(vlan_controls, text="Auto I-SID", command=self.auto_generate_isids).pack(pady=2, fill=tk.X)
        
        # === NETWORK SERVICES ===
        services_frame = ttk.LabelFrame(main_frame, text="Network Services", padding=10)
        services_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Row 1 - Remote Access
        row = 0
        ttk.Label(services_frame, text="Remote Access:").grid(row=row, column=0, sticky=tk.W, padx=5, pady=2)
        self.base_enable_ssh_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(services_frame, text="SSH", variable=self.base_enable_ssh_var).grid(row=row, column=1, sticky=tk.W, padx=5)
        self.base_enable_telnet_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(services_frame, text="Telnet", variable=self.base_enable_telnet_var).grid(row=row, column=2, sticky=tk.W, padx=5)
        
        # Row 2 - NTP Servers
        row += 1
        ttk.Label(services_frame, text="NTP Servers:").grid(row=row, column=0, sticky=tk.W, padx=5, pady=2)
        self.base_ntp_var = tk.StringVar()
        ttk.Entry(services_frame, textvariable=self.base_ntp_var, width=40).grid(row=row, column=1, columnspan=3, sticky=tk.W, padx=5, pady=2)
        ttk.Label(services_frame, text="(comma separated)").grid(row=row, column=4, sticky=tk.W, padx=5, pady=2)
        
        # Row 3 - DNS Servers
        row += 1
        ttk.Label(services_frame, text="DNS Servers:").grid(row=row, column=0, sticky=tk.W, padx=5, pady=2)
        self.base_dns_var = tk.StringVar()
        ttk.Entry(services_frame, textvariable=self.base_dns_var, width=40).grid(row=row, column=1, columnspan=3, sticky=tk.W, padx=5, pady=2)
        ttk.Label(services_frame, text="(comma separated)").grid(row=row, column=4, sticky=tk.W, padx=5, pady=2)
        
        # === SNMP CONFIGURATION ===
        snmp_frame = ttk.LabelFrame(main_frame, text="SNMP Configuration", padding=10)
        snmp_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Row 1 - Basic SNMP
        row = 0
        ttk.Label(snmp_frame, text="Community:").grid(row=row, column=0, sticky=tk.W, padx=5, pady=2)
        self.base_snmp_community_var = tk.StringVar(value="public")
        ttk.Entry(snmp_frame, textvariable=self.base_snmp_community_var, width=15).grid(row=row, column=1, padx=5, pady=2)
        
        ttk.Label(snmp_frame, text="SNMP Host:").grid(row=row, column=2, sticky=tk.W, padx=5, pady=2)
        self.base_snmp_host_var = tk.StringVar()
        ttk.Entry(snmp_frame, textvariable=self.base_snmp_host_var, width=15).grid(row=row, column=3, padx=5, pady=2)
        
        # Row 2 - SNMPv3 Group
        row += 1
        ttk.Label(snmp_frame, text="SNMP Group:").grid(row=row, column=0, sticky=tk.W, padx=5, pady=2)
        self.base_snmp_group_var = tk.StringVar(value="SNMPGroup")
        ttk.Entry(snmp_frame, textvariable=self.base_snmp_group_var, width=15).grid(row=row, column=1, padx=5, pady=2)
        
        ttk.Label(snmp_frame, text="SNMP User:").grid(row=row, column=2, sticky=tk.W, padx=5, pady=2)
        self.base_snmp_user_var = tk.StringVar(value="snmpuser")
        ttk.Entry(snmp_frame, textvariable=self.base_snmp_user_var, width=15).grid(row=row, column=3, padx=5, pady=2)
        
        # Row 3 - SNMPv3 Authentication
        row += 1
        ttk.Label(snmp_frame, text="Auth Password:").grid(row=row, column=0, sticky=tk.W, padx=5, pady=2)
        self.base_snmp_auth_pass_var = tk.StringVar(value="Auth_Password123")
        ttk.Entry(snmp_frame, textvariable=self.base_snmp_auth_pass_var, width=15, show="*").grid(row=row, column=1, padx=5, pady=2)
        
        ttk.Label(snmp_frame, text="Privacy Password:").grid(row=row, column=2, sticky=tk.W, padx=5, pady=2)
        self.base_snmp_priv_pass_var = tk.StringVar(value="Priv_Password123")
        ttk.Entry(snmp_frame, textvariable=self.base_snmp_priv_pass_var, width=15, show="*").grid(row=row, column=3, padx=5, pady=2)
        
        # === BUTTONS ===
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, padx=5, pady=10)
        
        ttk.Button(button_frame, text="Generate Base Configuration", 
                  command=self.generate_base_config).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Load Template", 
                  command=self.load_base_template).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Save Template", 
                  command=self.save_base_template).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear All", 
                  command=self.clear_base_config).pack(side=tk.LEFT, padx=5)
        
        # === CONFIG OUTPUT ===
        output_frame = ttk.LabelFrame(main_frame, text="Generated Configuration", padding=5)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.base_config_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, height=15)
        self.base_config_text.pack(fill=tk.BOTH, expand=True)
        
    def toggle_isis_fields(self):
        """Enable/disable ISIS configuration fields"""
        state = tk.NORMAL if self.base_enable_isis_var.get() else tk.DISABLED
        
        widgets = [
            self.isis_system_id_entry, self.isis_nick_entry, self.isis_area_entry
        ]
        
        for widget in widgets:
            widget.config(state=state)
    
    def auto_generate_system_id(self):
        """Auto-generate a System ID based on hostname or random"""
        hostname = self.base_hostname_var.get()
        
        # Get a random suffix between 01-99 if no specific pattern is needed
        random_suffix = f"{random.randint(1, 99):02d}"
        
        # Try to use hostname if available
        suffix = random_suffix
        if hostname:
            # Try to extract numbers from hostname
            numbers = re.findall(r'\d+', hostname)
            if numbers:
                # Use the last number found, padded to 2 digits
                extracted_suffix = numbers[-1].zfill(2)[-2:]
                # Add some randomness - 50% chance to use the extracted number
                # and 50% chance to use a random number
                if random.choice([True, False]):
                    suffix = extracted_suffix
        
        # Add some variation to the middle part occasionally
        middle_part = "0122"
        if random.random() < 0.3:  # 30% chance to vary the middle part
            middle_options = ["0122", "0123", "0124", "0125"]
            middle_part = random.choice(middle_options)
        
        # Format as 02e0.XXXX.00YY where XXXX varies occasionally and YY is the suffix
        system_id = f"02e0.{middle_part}.00{suffix}"
        
        self.base_system_id_var.set(system_id)
    
    def auto_generate_nick_name(self):
        """Auto-generate a Nick Name matching the format e.XX.YY where YY matches system ID"""
        # Get the system ID or generate one if not set
        system_id = self.base_system_id_var.get()
        if not system_id:
            self.auto_generate_system_id()
            system_id = self.base_system_id_var.get()
        
        # Extract the suffix from system ID (last 2 digits)
        if system_id and len(system_id) >= 2:
            suffix = system_id[-2:]
        else:
            # Random suffix if no system ID
            suffix = f"{random.randint(1, 99):02d}"
        
        # Get hostname for the first part
        hostname = self.base_hostname_var.get()
        
        # Prefix options with some variation
        prefix_options = ["e", "a", "b", "c"]
        prefix_weights = [0.7, 0.1, 0.1, 0.1]  # 70% chance for "e", 10% for others
        prefix = random.choices(prefix_options, weights=prefix_weights)[0]
        
        # Try to extract a number from hostname for middle part
        middle_options = ["22", "23", "24", "25", "26"]
        middle_weights = [0.6, 0.1, 0.1, 0.1, 0.1]  # 60% chance for "22", 10% for others
        middle = random.choices(middle_options, weights=middle_weights)[0]
        
        if hostname:
            # Try to extract numbers from hostname
            numbers = re.findall(r'\d+', hostname)
            if numbers and len(numbers[0]) >= 2:
                # Use first 2 digits of the first number found
                extracted_middle = numbers[0][:2]
                # 50% chance to use extracted number
                if random.choice([True, False]):
                    middle = extracted_middle
        
        # Format as e.XX.YY where XX is from hostname and YY is from system ID
        nick_name = f"{prefix}.{middle}.{suffix}"
        
        self.base_nick_name_var.set(nick_name)
    
    def base_add_vlan(self):
        """Add VLAN to base configuration"""
        self.base_vlan_dialog()
        
    def base_edit_vlan(self):
        """Edit selected VLAN in base configuration"""
        selection = self.base_vlan_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a VLAN to edit")
            return
            
        item = selection[0]
        values = self.base_vlan_tree.item(item, 'values')
        self.base_vlan_dialog(values)
        
    def base_remove_vlan(self):
        """Remove selected VLAN from base configuration"""
        selection = self.base_vlan_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a VLAN to remove")
            return
            
        if messagebox.askyesno("Confirm", "Remove selected VLAN?"):
            self.base_vlan_tree.delete(selection[0])
    
    def base_vlan_dialog(self, existing_values=None):
        """VLAN configuration dialog for base config"""
        dialog = tk.Toplevel(self.root)
        dialog.title("VLAN Configuration")
        dialog.geometry("350x200")
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text="VLAN ID:").grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
        vlan_id_var = tk.StringVar(value=existing_values[0] if existing_values else "")
        ttk.Entry(dialog, textvariable=vlan_id_var, width=20).grid(row=0, column=1, padx=10, pady=5)
        
        ttk.Label(dialog, text="Name:").grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)
        name_var = tk.StringVar(value=existing_values[1] if existing_values else "")
        ttk.Entry(dialog, textvariable=name_var, width=20).grid(row=1, column=1, padx=10, pady=5)
        
        ttk.Label(dialog, text="I-SID:").grid(row=2, column=0, sticky=tk.W, padx=10, pady=5)
        isid_var = tk.StringVar(value=existing_values[2] if existing_values else "")
        ttk.Entry(dialog, textvariable=isid_var, width=20).grid(row=2, column=1, padx=10, pady=5)
        
        ttk.Button(dialog, text="Auto-Generate I-SID", 
                  command=lambda: isid_var.set(str(1040000 + int(vlan_id_var.get()) if vlan_id_var.get().isdigit() else 1040001))).grid(row=2, column=2, padx=5)
        
        def save_vlan():
            try:
                vlan_id = int(vlan_id_var.get())
                name = name_var.get()
                i_sid = int(isid_var.get()) if isid_var.get() else 1040000 + vlan_id
                
                if existing_values:
                    # Update existing
                    selection = self.base_vlan_tree.selection()[0]
                    self.base_vlan_tree.item(selection, values=(vlan_id, name, i_sid))
                else:
                    # Add new
                    self.base_vlan_tree.insert('', 'end', values=(vlan_id, name, i_sid))
                    
                dialog.destroy()
            except ValueError:
                messagebox.showerror("Error", "VLAN ID and I-SID must be numbers")
        
        button_frame = ttk.Frame(dialog)
        button_frame.grid(row=3, column=0, columnspan=3, pady=10)
        
        ttk.Button(button_frame, text="Save", command=save_vlan).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def load_vlan_template(self):
        """Load predefined VLAN templates"""
        template_dialog = tk.Toplevel(self.root)
        template_dialog.title("VLAN Templates")
        template_dialog.geometry("400x300")
        template_dialog.transient(self.root)
        template_dialog.grab_set()
        
        templates = {
            "Enterprise Standard": [
                (10, "Management", 1040010),
                (20, "Staff", 1040020),
                (40, "Guest", 1040040),
                (50, "Servers", 1040050),
                (60, "Printers", 1040060)
            ],
            "Extended Network": [
                (100, "Management", 1040100),
                (110, "Printers", 1040110),
                (120, "Staff", 1040120),
                (140, "AP-Control", 1040140),
                (150, "AP-Data", 1040150),
                (160, "AP-Voice", 1040160),
                (170, "AP-IoT", 1040170),
                (180, "Guest", 1040180)
            ],
            "Basic Setup": [
                (1, "Default", 1040001),
                (100, "Management", 1040100),
                (200, "Users", 1040200)
            ]
        }
        
        ttk.Label(template_dialog, text="Select a VLAN template:").pack(pady=10)
        
        template_var = tk.StringVar()
        for template_name in templates.keys():
            ttk.Radiobutton(template_dialog, text=template_name, variable=template_var, 
                           value=template_name).pack(anchor=tk.W, padx=20, pady=2)
        
        def apply_template():
            selected = template_var.get()
            if selected:
                # Clear existing VLANs
                for item in self.base_vlan_tree.get_children():
                    self.base_vlan_tree.delete(item)
                
                # Add template VLANs
                for vlan_id, name, i_sid in templates[selected]:
                    self.base_vlan_tree.insert('', 'end', values=(vlan_id, name, i_sid))
                
                template_dialog.destroy()
        
        button_frame = ttk.Frame(template_dialog)
        button_frame.pack(pady=20)
        ttk.Button(button_frame, text="Apply Template", command=apply_template).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=template_dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def auto_generate_isids(self):
        """Auto-generate I-SIDs for all VLANs"""
        for item in self.base_vlan_tree.get_children():
            values = list(self.base_vlan_tree.item(item, 'values'))
            vlan_id = int(values[0])
            # Generate I-SID as 1040000 + VLAN ID
            values[2] = 1040000 + vlan_id
            self.base_vlan_tree.item(item, values=values)
    
    def get_base_vlans_from_tree(self):
        """Get VLANs from base configuration tree"""
        vlans = []
        for item in self.base_vlan_tree.get_children():
            values = self.base_vlan_tree.item(item, 'values')
            vlans.append(VLANConfig(int(values[0]), values[1], int(values[2])))
        return vlans
    
    def generate_base_config(self):
        """Generate configuration from base config tab"""
        # Validate required fields
        required_fields = [
            (self.base_hostname_var.get(), "Hostname"),
            (self.base_location_var.get(), "SNMP Location"),
            (self.base_mgmt_ip_var.get(), "Management IP"),
            (self.base_gateway_var.get(), "Gateway")
        ]
        
        for value, field_name in required_fields:
            if not value.strip():
                messagebox.showerror("Error", f"{field_name} is required")
                return
        
        if self.base_enable_isis_var.get():
            isis_required = [
                (self.base_system_id_var.get(), "System ID"),
                (self.base_nick_name_var.get(), "Nick Name")
            ]
            for value, field_name in isis_required:
                if not value.strip():
                    messagebox.showerror("Error", f"{field_name} is required when ISIS is enabled")
                    return
        
        # Parse list fields
        ntp_servers = [s.strip() for s in self.base_ntp_var.get().split(',') if s.strip()]
        name_servers = [s.strip() for s in self.base_dns_var.get().split(',') if s.strip()]
        
        # Create configuration object
        config = SwitchConfig(
            hostname=self.base_hostname_var.get(),
            snmp_location=self.base_location_var.get(),
            mgmt_ip=self.base_mgmt_ip_var.get(),
            mgmt_mask=int(self.base_mgmt_mask_var.get()),
            gateway=self.base_gateway_var.get(),
            system_id=self.base_system_id_var.get(),
            nick_name=self.base_nick_name_var.get(),
            vlans=self.get_base_vlans_from_tree(),
            ntp_servers=ntp_servers,
            snmp_host=self.base_snmp_host_var.get(),
            snmp_community=self.base_snmp_community_var.get(),
            snmp_group=self.base_snmp_group_var.get(),
            snmp_user=self.base_snmp_user_var.get(),
            snmp_auth_password=self.base_snmp_auth_pass_var.get(),
            snmp_priv_password=self.base_snmp_priv_pass_var.get(),
            enable_ssh=self.base_enable_ssh_var.get(),
            enable_telnet=self.base_enable_telnet_var.get(),
            enable_isis=self.base_enable_isis_var.get(),
            isis_area=self.base_isis_area_var.get(),
            domain_name=self.base_domain_var.get(),
            name_servers=name_servers,
            timezone=self.base_timezone_var.get()
        )
        
        # Generate configuration
        generated_config = ConfigGenerator.generate_voss_config(config)
        
        # Display in text area
        self.base_config_text.delete(1.0, tk.END)
        self.base_config_text.insert(1.0, generated_config)
        
        messagebox.showinfo("Success", "Configuration generated successfully!")
    
    def load_base_template(self):
        """Load a saved base configuration template"""
        file_path = filedialog.askopenfilename(
            title="Load Configuration Template",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    template_data = json.load(f)
                
                # Load basic fields
                self.base_hostname_var.set(template_data.get('hostname', ''))
                self.base_location_var.set(template_data.get('snmp_location', ''))
                self.base_mgmt_ip_var.set(template_data.get('mgmt_ip', ''))
                self.base_mgmt_mask_var.set(str(template_data.get('mgmt_mask', 24)))
                self.base_gateway_var.set(template_data.get('gateway', ''))
                self.base_system_id_var.set(template_data.get('system_id', ''))
                self.base_nick_name_var.set(template_data.get('nick_name', ''))
                self.base_domain_var.set(template_data.get('domain_name', ''))
                self.base_timezone_var.set(template_data.get('timezone', ''))
                self.base_snmp_community_var.set(template_data.get('snmp_community', 'public'))
                self.base_snmp_host_var.set(template_data.get('snmp_host', ''))
                self.base_snmp_group_var.set(template_data.get('snmp_group', 'ExtremeSNMPGroup'))
                self.base_snmp_user_var.set(template_data.get('snmp_user', 'wcsmanager'))
                self.base_snmp_auth_pass_var.set(template_data.get('snmp_auth_password', '3JyjHr9iYC'))
                self.base_snmp_priv_pass_var.set(template_data.get('snmp_priv_password', '3JyjHr9iYC'))
                self.base_enable_ssh_var.set(template_data.get('enable_ssh', True))
                self.base_enable_telnet_var.set(template_data.get('enable_telnet', False))
                self.base_enable_isis_var.set(template_data.get('enable_isis', True))
                self.base_isis_area_var.set(template_data.get('isis_area', '49.0000'))
                
                # Load list fields
                self.base_ntp_var.set(', '.join(template_data.get('ntp_servers', [])))
                self.base_dns_var.set(', '.join(template_data.get('name_servers', [])))
                
                # Load VLANs
                for item in self.base_vlan_tree.get_children():
                    self.base_vlan_tree.delete(item)
                
                for vlan in template_data.get('vlans', []):
                    self.base_vlan_tree.insert('', 'end', values=(vlan['vlan_id'], vlan['name'], vlan['i_sid']))
                
                self.toggle_isis_fields()
                messagebox.showinfo("Success", "Template loaded successfully")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load template: {str(e)}")
    
    def save_base_template(self):
        """Save current base configuration as template"""
        # Collect all configuration data
        template_data = {
            'hostname': self.base_hostname_var.get(),
            'snmp_location': self.base_location_var.get(),
            'mgmt_ip': self.base_mgmt_ip_var.get(),
            'mgmt_mask': int(self.base_mgmt_mask_var.get()),
            'gateway': self.base_gateway_var.get(),
            'system_id': self.base_system_id_var.get(),
            'nick_name': self.base_nick_name_var.get(),
            'domain_name': self.base_domain_var.get(),
            'timezone': self.base_timezone_var.get(),
            'snmp_community': self.base_snmp_community_var.get(),
            'snmp_host': self.base_snmp_host_var.get(),
            'snmp_group': self.base_snmp_group_var.get(),
            'snmp_user': self.base_snmp_user_var.get(),
            'snmp_auth_password': self.base_snmp_auth_pass_var.get(),
            'snmp_priv_password': self.base_snmp_priv_pass_var.get(),
            'enable_ssh': self.base_enable_ssh_var.get(),
            'enable_telnet': self.base_enable_telnet_var.get(),
            'enable_isis': self.base_enable_isis_var.get(),
            'isis_area': self.base_isis_area_var.get(),
            'ntp_servers': [s.strip() for s in self.base_ntp_var.get().split(',') if s.strip()],
            'name_servers': [s.strip() for s in self.base_dns_var.get().split(',') if s.strip()],
            'vlans': []
        }
        
        # Add VLANs
        for item in self.base_vlan_tree.get_children():
            values = self.base_vlan_tree.item(item, 'values')
            template_data['vlans'].append({
                'vlan_id': int(values[0]),
                'name': values[1],
                'i_sid': int(values[2])
            })
        
        file_path = filedialog.asksaveasfilename(
            title="Save Configuration Template",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    json.dump(template_data, f, indent=2)
                messagebox.showinfo("Success", "Template saved successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save template: {str(e)}")
    
    def clear_base_config(self):
        """Clear all base configuration fields"""
        if messagebox.askyesno("Confirm", "Clear all configuration fields?"):
            # Clear all string variables
            for var in [self.base_hostname_var, self.base_location_var, self.base_mgmt_ip_var,
                       self.base_gateway_var, self.base_system_id_var, self.base_nick_name_var,
                       self.base_domain_var, self.base_timezone_var, self.base_snmp_community_var,
                       self.base_snmp_host_var, self.base_ntp_var, self.base_dns_var]:
                var.set('')
                
            # Reset SNMP security fields to defaults
            self.base_snmp_group_var.set('SNMPGroup')
            self.base_snmp_user_var.set('snmpuser')
            self.base_snmp_auth_pass_var.set('Auth_Password123')
            self.base_snmp_priv_pass_var.set('Priv_Password123')
            
            # Reset defaults
            self.base_mgmt_mask_var.set('24')
            self.base_snmp_community_var.set('public')
            self.base_enable_ssh_var.set(True)
            self.base_enable_telnet_var.set(False)
            self.base_enable_isis_var.set(True)
            self.base_isis_area_var.set('49.0000')
            
            # Clear VLANs
            for item in self.base_vlan_tree.get_children():
                self.base_vlan_tree.delete(item)
            
            # Clear config text
            self.base_config_text.delete(1.0, tk.END)
    
    def create_config_tab(self):
        """Simplified configuration generator tab"""
        config_frame = ttk.Frame(self.notebook)
        self.notebook.add(config_frame, text="Quick Config")
        
        # Left panel for configuration inputs
        left_frame = ttk.LabelFrame(config_frame, text="Quick Switch Configuration", padding=10)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        # Basic Configuration
        ttk.Label(left_frame, text="Hostname:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.hostname_var = tk.StringVar()
        ttk.Entry(left_frame, textvariable=self.hostname_var, width=30).grid(row=0, column=1, sticky=tk.W, pady=2)
        
        ttk.Label(left_frame, text="SNMP Location:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.location_var = tk.StringVar()
        ttk.Entry(left_frame, textvariable=self.location_var, width=30).grid(row=1, column=1, sticky=tk.W, pady=2)
        
        ttk.Label(left_frame, text="Management IP:").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.mgmt_ip_var = tk.StringVar()
        ttk.Entry(left_frame, textvariable=self.mgmt_ip_var, width=30).grid(row=2, column=1, sticky=tk.W, pady=2)
        
        ttk.Label(left_frame, text="System ID:").grid(row=3, column=0, sticky=tk.W, pady=2)
        self.system_id_var = tk.StringVar()
        ttk.Entry(left_frame, textvariable=self.system_id_var, width=30).grid(row=3, column=1, sticky=tk.W, pady=2)
        
        ttk.Label(left_frame, text="Nick Name:").grid(row=4, column=0, sticky=tk.W, pady=2)
        self.nick_name_var = tk.StringVar()
        ttk.Entry(left_frame, textvariable=self.nick_name_var, width=30).grid(row=4, column=1, sticky=tk.W, pady=2)
        
        # VLAN Configuration
        vlan_frame = ttk.LabelFrame(left_frame, text="VLAN Configuration", padding=5)
        vlan_frame.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
        
        self.vlan_tree = ttk.Treeview(vlan_frame, columns=('VLAN ID', 'Name', 'I-SID'), show='headings', height=8)
        self.vlan_tree.heading('VLAN ID', text='VLAN ID')
        self.vlan_tree.heading('Name', text='Name')
        self.vlan_tree.heading('I-SID', text='I-SID')
        self.vlan_tree.column('VLAN ID', width=80)
        self.vlan_tree.column('Name', width=120)
        self.vlan_tree.column('I-SID', width=100)
        self.vlan_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # VLAN controls
        vlan_controls = ttk.Frame(vlan_frame)
        vlan_controls.pack(side=tk.RIGHT, fill=tk.Y, padx=(5, 0))
        
        ttk.Button(vlan_controls, text="Add VLAN", command=self.add_vlan).pack(pady=2)
        ttk.Button(vlan_controls, text="Edit VLAN", command=self.edit_vlan).pack(pady=2)
        ttk.Button(vlan_controls, text="Remove VLAN", command=self.remove_vlan).pack(pady=2)
        ttk.Button(vlan_controls, text="Load Defaults", command=self.load_default_vlans).pack(pady=2)
        
        # SNMP Security Configuration
        snmp_security_frame = ttk.LabelFrame(left_frame, text="SNMP Security", padding=5)
        snmp_security_frame.grid(row=6, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        # SNMP Group and User
        ttk.Label(snmp_security_frame, text="SNMP Group:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.snmp_group_var = tk.StringVar(value="SNMPGroup")
        ttk.Entry(snmp_security_frame, textvariable=self.snmp_group_var, width=20).grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(snmp_security_frame, text="SNMP User:").grid(row=0, column=2, sticky=tk.W, padx=5, pady=2)
        self.snmp_user_var = tk.StringVar(value="snmpuser")
        ttk.Entry(snmp_security_frame, textvariable=self.snmp_user_var, width=20).grid(row=0, column=3, sticky=tk.W, padx=5, pady=2)
        
        # SNMP Authentication
        ttk.Label(snmp_security_frame, text="Auth Password:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        self.snmp_auth_pass_var = tk.StringVar(value="Auth_Password123")
        ttk.Entry(snmp_security_frame, textvariable=self.snmp_auth_pass_var, width=20, show="*").grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(snmp_security_frame, text="Priv Password:").grid(row=1, column=2, sticky=tk.W, padx=5, pady=2)
        self.snmp_priv_pass_var = tk.StringVar(value="Priv_Password123")
        ttk.Entry(snmp_security_frame, textvariable=self.snmp_priv_pass_var, width=20, show="*").grid(row=1, column=3, sticky=tk.W, padx=5, pady=2)
        
        # Buttons
        button_frame = ttk.Frame(left_frame)
        button_frame.grid(row=7, column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="Generate Config", command=self.generate_config).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Load Config", command=self.load_config).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Save Config", command=self.save_config).pack(side=tk.LEFT, padx=5)
        
        # Right panel for generated configuration
        right_frame = ttk.LabelFrame(config_frame, text="Generated Configuration", padding=10)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        self.config_text = scrolledtext.ScrolledText(right_frame, wrap=tk.WORD, width=60, height=35)
        self.config_text.pack(fill=tk.BOTH, expand=True)
        
    def create_terminal_tab(self):
        """Enhanced terminal tab with SSH and Serial support"""
        terminal_frame = ttk.Frame(self.notebook)
        self.notebook.add(terminal_frame, text="Live Terminal")
        
        # Connection frame
        conn_frame = ttk.LabelFrame(terminal_frame, text="Device Connection", padding=10)
        conn_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Connection type selection
        self.conn_type_var = tk.StringVar(value="SSH")
        ttk.Radiobutton(conn_frame, text="SSH", variable=self.conn_type_var, value="SSH",
                       command=self.toggle_connection_fields).grid(row=0, column=0, sticky=tk.W, padx=5)
        ttk.Radiobutton(conn_frame, text="Serial", variable=self.conn_type_var, value="Serial",
                       command=self.toggle_connection_fields).grid(row=0, column=1, sticky=tk.W, padx=5)
        
        # SSH Connection fields
        self.ssh_frame = ttk.Frame(conn_frame)
        self.ssh_frame.grid(row=1, column=0, columnspan=8, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(self.ssh_frame, text="Host:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.ssh_host_var = tk.StringVar()
        ttk.Entry(self.ssh_frame, textvariable=self.ssh_host_var, width=15).grid(row=0, column=1, padx=5)
        
        ttk.Label(self.ssh_frame, text="Username:").grid(row=0, column=2, sticky=tk.W, padx=5)
        self.ssh_user_var = tk.StringVar(value="admin")
        ttk.Entry(self.ssh_frame, textvariable=self.ssh_user_var, width=15).grid(row=0, column=3, padx=5)
        
        ttk.Label(self.ssh_frame, text="Password:").grid(row=0, column=4, sticky=tk.W, padx=5)
        self.ssh_pass_var = tk.StringVar()
        ttk.Entry(self.ssh_frame, textvariable=self.ssh_pass_var, width=15, show="*").grid(row=0, column=5, padx=5)
        
        # Serial Connection fields
        self.serial_frame = ttk.Frame(conn_frame)
        self.serial_frame.grid(row=2, column=0, columnspan=8, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(self.serial_frame, text="Port:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.serial_port_var = tk.StringVar()
        self.serial_port_combo = ttk.Combobox(self.serial_frame, textvariable=self.serial_port_var, width=12)
        self.serial_port_combo.grid(row=0, column=1, padx=5)
        
        ttk.Button(self.serial_frame, text="Refresh Ports", command=self.refresh_serial_ports).grid(row=0, column=2, padx=5)
        
        ttk.Label(self.serial_frame, text="Baud Rate:").grid(row=0, column=3, sticky=tk.W, padx=5)
        self.serial_baud_var = tk.StringVar(value="9600")
        baud_combo = ttk.Combobox(self.serial_frame, textvariable=self.serial_baud_var, width=8)
        baud_combo['values'] = ('9600', '19200', '38400', '57600', '115200')
        baud_combo.grid(row=0, column=4, padx=5)
        
        # Connection controls
        control_frame = ttk.Frame(conn_frame)
        control_frame.grid(row=3, column=0, columnspan=8, pady=10)
        
        self.connect_btn = ttk.Button(control_frame, text="Connect", command=self.toggle_connection)
        self.connect_btn.pack(side=tk.LEFT, padx=5)
        
        self.connection_status = ttk.Label(control_frame, text="Disconnected", foreground="red")
        self.connection_status.pack(side=tk.LEFT, padx=10)
        
        # Initialize serial ports and toggle fields
        self.refresh_serial_ports()
        self.toggle_connection_fields()
        
        # Terminal output
        terminal_output_frame = ttk.LabelFrame(terminal_frame, text="Terminal Output", padding=5)
        terminal_output_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.terminal_output = scrolledtext.ScrolledText(terminal_output_frame, wrap=tk.WORD, 
                                                        bg="black", fg="green", 
                                                        font=("Consolas", 10))
        self.terminal_output.pack(fill=tk.BOTH, expand=True)
        
        # Command input
        cmd_frame = ttk.Frame(terminal_frame)
        cmd_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(cmd_frame, text="Command:").pack(side=tk.LEFT)
        self.command_var = tk.StringVar()
        cmd_entry = ttk.Entry(cmd_frame, textvariable=self.command_var, width=50)
        cmd_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        cmd_entry.bind('<Return>', self.send_command)
        
        ttk.Button(cmd_frame, text="Send", command=self.send_command).pack(side=tk.RIGHT, padx=5)
        
        # Quick commands
        quick_frame = ttk.LabelFrame(terminal_frame, text="Quick Commands", padding=5)
        quick_frame.pack(fill=tk.X, padx=5, pady=5)
        
        quick_commands = [
            ("Show VLANs", "show vlan"),
            ("Show Interfaces", "show interface gigabitethernet"),
            ("Show ISIS", "show isis"),
            ("Show Running Config", "show running-config"),
            ("Enable Config", "enable\nconfig term"),
            ("Save Config", "wr mem"),
            ("Show Version", "show version"),
            ("Show IP", "show ip interface")
        ]
        
        for i, (label, cmd) in enumerate(quick_commands):
            ttk.Button(quick_frame, text=label, 
                      command=lambda c=cmd: self.send_quick_command(c)).grid(row=i//4, column=i%4, padx=5, pady=2)
        
        # Live Configuration Frame
        live_config_frame = ttk.LabelFrame(terminal_frame, text="Live Configuration", padding=5)
        live_config_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Create notebook for different configuration categories
        live_config_notebook = ttk.Notebook(live_config_frame)
        live_config_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # VLAN Configuration Tab
        vlan_tab = ttk.Frame(live_config_notebook)
        live_config_notebook.add(vlan_tab, text="VLAN Config")
        
        # VLAN Creation Frame
        vlan_create_frame = ttk.LabelFrame(vlan_tab, text="Create/Configure VLAN", padding=5)
        vlan_create_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(vlan_create_frame, text="VLAN ID:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.live_vlan_id_var = tk.StringVar()
        ttk.Entry(vlan_create_frame, textvariable=self.live_vlan_id_var, width=10).grid(row=0, column=1, padx=5, pady=2)
        
        ttk.Label(vlan_create_frame, text="VLAN Name:").grid(row=0, column=2, sticky=tk.W, padx=5, pady=2)
        self.live_vlan_name_var = tk.StringVar()
        ttk.Entry(vlan_create_frame, textvariable=self.live_vlan_name_var, width=15).grid(row=0, column=3, padx=5, pady=2)
        
        ttk.Label(vlan_create_frame, text="I-SID:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        self.live_isid_var = tk.StringVar()
        ttk.Entry(vlan_create_frame, textvariable=self.live_isid_var, width=10).grid(row=1, column=1, padx=5, pady=2)
        
        ttk.Button(vlan_create_frame, text="Auto I-SID", 
                  command=self.auto_generate_live_isid).grid(row=1, column=2, padx=5, pady=2)
        
        vlan_btn_frame = ttk.Frame(vlan_create_frame)
        vlan_btn_frame.grid(row=2, column=0, columnspan=4, pady=5)
        
        ttk.Button(vlan_btn_frame, text="Create VLAN", 
                  command=self.create_live_vlan).pack(side=tk.LEFT, padx=5)
        ttk.Button(vlan_btn_frame, text="Delete VLAN", 
                  command=self.delete_live_vlan).pack(side=tk.LEFT, padx=5)
        ttk.Button(vlan_btn_frame, text="Set I-SID", 
                  command=self.set_live_isid).pack(side=tk.LEFT, padx=5)
        
        # Interface Configuration Tab
        interface_tab = ttk.Frame(live_config_notebook)
        live_config_notebook.add(interface_tab, text="Interface Config")
        
        # Interface Configuration Frame
        interface_frame = ttk.LabelFrame(interface_tab, text="Configure Interface", padding=5)
        interface_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(interface_frame, text="Interface:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.live_interface_var = tk.StringVar()
        ttk.Entry(interface_frame, textvariable=self.live_interface_var, width=20).grid(row=0, column=1, padx=5, pady=2)
        ttk.Label(interface_frame, text="(e.g. 1/1 or 1/1-10)").grid(row=0, column=2, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(interface_frame, text="VLAN:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        self.live_port_vlan_var = tk.StringVar()
        ttk.Entry(interface_frame, textvariable=self.live_port_vlan_var, width=10).grid(row=1, column=1, padx=5, pady=2)
        
        ttk.Label(interface_frame, text="Mode:").grid(row=1, column=2, sticky=tk.W, padx=5, pady=2)
        self.live_port_mode_var = tk.StringVar(value="access")
        port_mode_combo = ttk.Combobox(interface_frame, textvariable=self.live_port_mode_var, width=10)
        port_mode_combo['values'] = ('access', 'trunk')
        port_mode_combo.grid(row=1, column=3, padx=5, pady=2)
        
        interface_btn_frame = ttk.Frame(interface_frame)
        interface_btn_frame.grid(row=2, column=0, columnspan=4, pady=5)
        
        ttk.Button(interface_btn_frame, text="Configure Port", 
                  command=self.configure_live_interface).pack(side=tk.LEFT, padx=5)
        ttk.Button(interface_btn_frame, text="Show Interface", 
                  command=self.show_live_interface).pack(side=tk.LEFT, padx=5)
        
        # Advanced Configuration Tab
        advanced_tab = ttk.Frame(live_config_notebook)
        live_config_notebook.add(advanced_tab, text="Advanced Config")
        
        # Templates Frame
        templates_frame = ttk.LabelFrame(advanced_tab, text="Configuration Templates", padding=5)
        templates_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(templates_frame, text="Template:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.live_template_var = tk.StringVar()
        template_combo = ttk.Combobox(templates_frame, textvariable=self.live_template_var, width=30)
        template_combo['values'] = ('Basic VLAN Setup', 'Campus Network VLANs', 'Interface Reset', 'NTP Configuration')
        template_combo.grid(row=0, column=1, padx=5, pady=2)
        
        ttk.Button(templates_frame, text="Apply Template", 
                  command=self.apply_live_template).grid(row=0, column=2, padx=5, pady=2)
        
        # Status indicator for live configuration
        self.live_config_status = ttk.Label(live_config_frame, text="Ready", foreground="blue")
        self.live_config_status.pack(anchor=tk.E, padx=5, pady=2)
    
    def toggle_connection_fields(self):
        """Show/hide connection fields based on selected type"""
        if self.conn_type_var.get() == "SSH":
            self.ssh_frame.grid()
            self.serial_frame.grid_remove()
        else:
            self.ssh_frame.grid_remove()
            self.serial_frame.grid()
    
    def refresh_serial_ports(self):
        """Refresh available serial ports"""
        ports = [port.device for port in serial.tools.list_ports.comports()]
        self.serial_port_combo['values'] = ports
        if ports:
            self.serial_port_var.set(ports[0])
    
    def toggle_connection(self):
        """Connect or disconnect based on current state"""
        if self.conn_mgr.connected:
            self.disconnect_device()
        else:
            self.connect_device()
    
    def connect_device(self):
        """Connect to device via SSH or Serial"""
        conn_type = self.conn_type_var.get()
        
        if conn_type == "SSH":
            host = self.ssh_host_var.get()
            username = self.ssh_user_var.get()
            password = self.ssh_pass_var.get()
            
            if not all([host, username, password]):
                messagebox.showerror("Error", "Please fill in all SSH connection details")
                return
            
            self.terminal_output.insert(tk.END, f"Connecting to {host} via SSH...\n")
            self.terminal_output.see(tk.END)
            
            def connect_thread():
                result = self.conn_mgr.connect_ssh(host, username, password)
                if result == True:
                    self.root.after(0, self.on_connection_success)
                else:
                    self.root.after(0, lambda: self.on_connection_error(result))
            
            threading.Thread(target=connect_thread, daemon=True).start()
            
        else:  # Serial
            port = self.serial_port_var.get()
            baudrate = int(self.serial_baud_var.get())
            
            if not port:
                messagebox.showerror("Error", "Please select a serial port")
                return
            
            self.terminal_output.insert(tk.END, f"Connecting to {port} at {baudrate} baud...\n")
            self.terminal_output.see(tk.END)
            
            def connect_thread():
                result = self.conn_mgr.connect_serial(port, baudrate)
                if result == True:
                    self.root.after(0, self.on_connection_success)
                else:
                    self.root.after(0, lambda: self.on_connection_error(result))
            
            threading.Thread(target=connect_thread, daemon=True).start()
    
    def on_connection_success(self):
        """Handle successful connection"""
        self.connection_status.config(text=f"Connected ({self.conn_mgr.connection_type})", foreground="green")
        self.connect_btn.config(text="Disconnect")
        self.terminal_output.insert(tk.END, f"Connected successfully via {self.conn_mgr.connection_type}!\n")
        self.terminal_output.see(tk.END)
        
        # Get initial output
        def get_initial():
            initial_output = self.conn_mgr.send_command("", 2)
            if initial_output:
                self.root.after(0, lambda: self.display_command_output(initial_output))
        
        threading.Thread(target=get_initial, daemon=True).start()
    
    def on_connection_error(self, error):
        """Handle connection error"""
        self.connection_status.config(text="Disconnected", foreground="red")
        self.terminal_output.insert(tk.END, f"Connection failed: {error}\n")
        self.terminal_output.see(tk.END)
        
    def disconnect_device(self):
        """Disconnect from device"""
        self.conn_mgr.disconnect()
        self.connection_status.config(text="Disconnected", foreground="red")
        self.connect_btn.config(text="Connect")
        self.terminal_output.insert(tk.END, "Disconnected.\n")
        self.terminal_output.see(tk.END)
    
    def send_command(self, event=None):
        """Send command to connected device"""
        if not self.conn_mgr.connected:
            messagebox.showerror("Error", "Not connected to device")
            return
            
        command = self.command_var.get().strip()
        if not command:
            return
            
        self.terminal_output.insert(tk.END, f"\n> {command}\n")
        self.terminal_output.see(tk.END)
        
        def send_thread():
            output = self.conn_mgr.send_command(command)
            self.root.after(0, lambda: self.display_command_output(output))
        
        threading.Thread(target=send_thread, daemon=True).start()
        self.command_var.set("")
        
    def send_quick_command(self, command):
        """Send quick command to device"""
        if not self.conn_mgr.connected:
            messagebox.showerror("Error", "Not connected to device")
            return
            
        self.terminal_output.insert(tk.END, f"\n> {command}\n")
        self.terminal_output.see(tk.END)
        
        def send_thread():
            # Handle multi-line commands
            commands = command.split('\n')
            for cmd in commands:
                if cmd.strip():
                    output = self.conn_mgr.send_command(cmd.strip())
                    self.root.after(0, lambda o=output: self.display_command_output(o))
                    time.sleep(0.5)  # Small delay between commands
        
        threading.Thread(target=send_thread, daemon=True).start()
        
    def display_command_output(self, output):
        """Display command output in terminal"""
        if output:
            self.terminal_output.insert(tk.END, output + "\n")
            self.terminal_output.see(tk.END)
    
    # Live Configuration Methods
    def auto_generate_live_isid(self):
        """Auto-generate I-SID based on VLAN ID"""
        vlan_id = self.live_vlan_id_var.get()
        if vlan_id.isdigit():
            # Generate I-SID as 1040000 + VLAN ID
            isid = 1040000 + int(vlan_id)
            self.live_isid_var.set(str(isid))
        else:
            messagebox.showerror("Error", "Please enter a valid VLAN ID first")
    
    def create_live_vlan(self):
        """Create VLAN on connected device"""
        if not self.conn_mgr.connected:
            messagebox.showerror("Error", "Not connected to device")
            return
        
        vlan_id = self.live_vlan_id_var.get()
        vlan_name = self.live_vlan_name_var.get()
        
        if not vlan_id.isdigit():
            messagebox.showerror("Error", "Please enter a valid VLAN ID")
            return
            
        self.live_config_status.config(text="Creating VLAN...", foreground="orange")
        
        # Build command
        if vlan_name:
            cmd = f'vlan create {vlan_id} name "{vlan_name}" type port-mstprstp 0'
        else:
            cmd = f'vlan create {vlan_id} type port-mstprstp 0'
        
        def create_vlan_thread():
            # Ensure we're in config mode
            self.conn_mgr.send_command("enable", wait_time=0.5)
            self.conn_mgr.send_command("config term", wait_time=0.5)
            
            # Send VLAN creation command
            output = self.conn_mgr.send_command(cmd, wait_time=2)
            
            # Update UI
            self.root.after(0, lambda: self.terminal_output.insert(tk.END, f"\n> {cmd}\n{output}\n"))
            self.root.after(0, lambda: self.terminal_output.see(tk.END))
            self.root.after(0, lambda: self.live_config_status.config(text="VLAN Created", foreground="green"))
            
            # If I-SID is provided, set it too
            isid = self.live_isid_var.get()
            if isid.isdigit():
                isid_cmd = f'vlan i-sid {vlan_id} {isid}'
                isid_output = self.conn_mgr.send_command(isid_cmd, wait_time=2)
                self.root.after(0, lambda: self.terminal_output.insert(tk.END, f"\n> {isid_cmd}\n{isid_output}\n"))
                self.root.after(0, lambda: self.terminal_output.see(tk.END))
            
            # Reset status after delay
            self.root.after(3000, lambda: self.live_config_status.config(text="Ready", foreground="blue"))
        
        threading.Thread(target=create_vlan_thread, daemon=True).start()
    
    def delete_live_vlan(self):
        """Delete VLAN on connected device"""
        if not self.conn_mgr.connected:
            messagebox.showerror("Error", "Not connected to device")
            return
        
        vlan_id = self.live_vlan_id_var.get()
        
        if not vlan_id.isdigit():
            messagebox.showerror("Error", "Please enter a valid VLAN ID")
            return
            
        if not messagebox.askyesno("Confirm", f"Delete VLAN {vlan_id}?"):
            return
            
        self.live_config_status.config(text="Deleting VLAN...", foreground="orange")
        
        def delete_vlan_thread():
            # Ensure we're in config mode
            self.conn_mgr.send_command("enable", wait_time=0.5)
            self.conn_mgr.send_command("config term", wait_time=0.5)
            
            # Send VLAN deletion command
            cmd = f'no vlan {vlan_id}'
            output = self.conn_mgr.send_command(cmd, wait_time=2)
            
            # Update UI
            self.root.after(0, lambda: self.terminal_output.insert(tk.END, f"\n> {cmd}\n{output}\n"))
            self.root.after(0, lambda: self.terminal_output.see(tk.END))
            self.root.after(0, lambda: self.live_config_status.config(text="VLAN Deleted", foreground="green"))
            
            # Reset status after delay
            self.root.after(3000, lambda: self.live_config_status.config(text="Ready", foreground="blue"))
        
        threading.Thread(target=delete_vlan_thread, daemon=True).start()
    
    def set_live_isid(self):
        """Set I-SID for VLAN on connected device"""
        if not self.conn_mgr.connected:
            messagebox.showerror("Error", "Not connected to device")
            return
        
        vlan_id = self.live_vlan_id_var.get()
        isid = self.live_isid_var.get()
        
        if not vlan_id.isdigit():
            messagebox.showerror("Error", "Please enter a valid VLAN ID")
            return
            
        if not isid.isdigit():
            messagebox.showerror("Error", "Please enter a valid I-SID")
            return
            
        self.live_config_status.config(text="Setting I-SID...", foreground="orange")
        
        def set_isid_thread():
            # Ensure we're in config mode
            self.conn_mgr.send_command("enable", wait_time=0.5)
            self.conn_mgr.send_command("config term", wait_time=0.5)
            
            # Send I-SID command
            cmd = f'vlan i-sid {vlan_id} {isid}'
            output = self.conn_mgr.send_command(cmd, wait_time=2)
            
            # Update UI
            self.root.after(0, lambda: self.terminal_output.insert(tk.END, f"\n> {cmd}\n{output}\n"))
            self.root.after(0, lambda: self.terminal_output.see(tk.END))
            self.root.after(0, lambda: self.live_config_status.config(text="I-SID Set", foreground="green"))
            
            # Reset status after delay
            self.root.after(3000, lambda: self.live_config_status.config(text="Ready", foreground="blue"))
        
        threading.Thread(target=set_isid_thread, daemon=True).start()
    
    def configure_live_interface(self):
        """Configure interface on connected device"""
        if not self.conn_mgr.connected:
            messagebox.showerror("Error", "Not connected to device")
            return
        
        interface = self.live_interface_var.get()
        vlan = self.live_port_vlan_var.get()
        mode = self.live_port_mode_var.get()
        
        if not interface:
            messagebox.showerror("Error", "Please enter an interface")
            return
            
        if not vlan.isdigit():
            messagebox.showerror("Error", "Please enter a valid VLAN ID")
            return
            
        self.live_config_status.config(text="Configuring Interface...", foreground="orange")
        
        def config_interface_thread():
            # Ensure we're in config mode
            self.conn_mgr.send_command("enable", wait_time=0.5)
            self.conn_mgr.send_command("config term", wait_time=0.5)
            
            # Enter interface configuration
            interface_cmd = f'interface gigabitEthernet {interface}'
            self.conn_mgr.send_command(interface_cmd, wait_time=1)
            
            # Configure interface based on mode
            if mode == "access":
                cmd = f'vlan members add {vlan}'
            else:  # trunk
                cmd = f'vlan members add {vlan} tagging tagAll'
            
            output = self.conn_mgr.send_command(cmd, wait_time=2)
            
            # Exit interface configuration
            self.conn_mgr.send_command("exit", wait_time=0.5)
            
            # Update UI
            self.root.after(0, lambda: self.terminal_output.insert(tk.END, f"\n> {interface_cmd}\n> {cmd}\n{output}\n"))
            self.root.after(0, lambda: self.terminal_output.see(tk.END))
            self.root.after(0, lambda: self.live_config_status.config(text="Interface Configured", foreground="green"))
            
            # Reset status after delay
            self.root.after(3000, lambda: self.live_config_status.config(text="Ready", foreground="blue"))
        
        threading.Thread(target=config_interface_thread, daemon=True).start()
    
    def show_live_interface(self):
        """Show interface status on connected device"""
        if not self.conn_mgr.connected:
            messagebox.showerror("Error", "Not connected to device")
            return
        
        interface = self.live_interface_var.get()
        
        if not interface:
            messagebox.showerror("Error", "Please enter an interface")
            return
            
        self.live_config_status.config(text="Querying Interface...", foreground="orange")
        
        def show_interface_thread():
            # Send show command
            cmd = f'show interfaces gigabitEthernet {interface}'
            output = self.conn_mgr.send_command(cmd, wait_time=2)
            
            # Update UI
            self.root.after(0, lambda: self.terminal_output.insert(tk.END, f"\n> {cmd}\n{output}\n"))
            self.root.after(0, lambda: self.terminal_output.see(tk.END))
            self.root.after(0, lambda: self.live_config_status.config(text="Ready", foreground="blue"))
        
        threading.Thread(target=show_interface_thread, daemon=True).start()
    
    def apply_live_template(self):
        """Apply selected configuration template"""
        if not self.conn_mgr.connected:
            messagebox.showerror("Error", "Not connected to device")
            return
        
        template_name = self.live_template_var.get()
        if not template_name:
            messagebox.showerror("Error", "Please select a template")
            return
            
        # Confirm template application
        if not messagebox.askyesno("Confirm", f"Apply template '{template_name}'?\nThis will execute multiple commands on the device."):
            return
            
        self.live_config_status.config(text=f"Applying {template_name}...", foreground="orange")
        
        def apply_template_thread():
            # Ensure we're in config mode
            self.conn_mgr.send_command("enable", wait_time=0.5)
            self.conn_mgr.send_command("config term", wait_time=0.5)
            
            # Get commands for selected template
            commands = self.get_template_commands(template_name)
            
            # Execute each command
            for cmd in commands:
                self.root.after(0, lambda c=cmd: self.terminal_output.insert(tk.END, f"\n> {c}\n"))
                output = self.conn_mgr.send_command(cmd, wait_time=1.5)
                self.root.after(0, lambda o=output: self.terminal_output.insert(tk.END, f"{o}\n"))
                self.root.after(0, lambda: self.terminal_output.see(tk.END))
                time.sleep(0.5)  # Small delay between commands
            
            # Update status
            self.root.after(0, lambda: self.live_config_status.config(text="Template Applied", foreground="green"))
            
            # Reset status after delay
            self.root.after(5000, lambda: self.live_config_status.config(text="Ready", foreground="blue"))
        
        threading.Thread(target=apply_template_thread, daemon=True).start()
    
    def get_template_commands(self, template_name):
        """Get commands for the selected template"""
        templates = {
            "Basic VLAN Setup": [
                "vlan create 10 name \"Management\" type port-mstprstp 0",
                "vlan i-sid 10 1040010",
                "vlan create 20 name \"Staff\" type port-mstprstp 0",
                "vlan i-sid 20 1040020",
                "vlan create 30 name \"Guest\" type port-mstprstp 0",
                "vlan i-sid 30 1040030",
                "vlan create 40 name \"Voice\" type port-mstprstp 0",
                "vlan i-sid 40 1040040",
                "vlan create 50 name \"IoT\" type port-mstprstp 0",
                "vlan i-sid 50 1040050"
            ],
            "Enterprise Network VLANs": [
                "vlan create 100 name \"Management\" type port-mstprstp 0",
                "vlan i-sid 100 1040100",
                "vlan create 110 name \"Printers\" type port-mstprstp 0",
                "vlan i-sid 110 1040110",
                "vlan create 120 name \"Staff\" type port-mstprstp 0",
                "vlan i-sid 120 1040120",
                "vlan create 140 name \"AP-Control\" type port-mstprstp 0",
                "vlan i-sid 140 1040140",
                "vlan create 150 name \"AP-Data\" type port-mstprstp 0",
                "vlan i-sid 150 1040150",
                "vlan create 160 name \"AP-Voice\" type port-mstprstp 0",
                "vlan i-sid 160 1040160",
                "vlan create 170 name \"AP-IoT\" type port-mstprstp 0",
                "vlan i-sid 170 1040170",
                "vlan create 180 name \"Guest\" type port-mstprstp 0",
                "vlan i-sid 180 1040180"
            ],
            "Interface Reset": [
                "interface gigabitEthernet 1/1",
                "no shutdown",
                "default-vlan-id 1",
                "vlan members remove 2-4094",
                "exit"
            ],
            "NTP Configuration": [
                "ntp server 10.0.0.1",
                "ntp server 10.0.0.2",
                "ntp enable"
            ]
        }
        
        return templates.get(template_name, [])
    
    def configure_live_isis(self):
        """Configure ISIS on connected device"""
        if not self.conn_mgr.connected:
            messagebox.showerror("Error", "Not connected to device")
            return
        
        system_id = self.live_system_id_var.get()
        nick_name = self.live_nick_name_var.get()
        
        if not system_id or not nick_name:
            messagebox.showerror("Error", "Please enter System ID and Nick Name")
            return
            
        self.live_config_status.config(text="Configuring ISIS...", foreground="orange")
        
        def config_isis_thread():
            # Ensure we're in config mode
            self.conn_mgr.send_command("enable", wait_time=0.5)
            self.conn_mgr.send_command("config term", wait_time=0.5)
            
            # Configure ISIS
            commands = [
                "no router isis",
                "y",  # Confirm reset
                "router isis",
                f"system-id {system_id}",
                "manual-area 49.0000",
                f"spbm 1 nick-name {nick_name}",
                "exit",
                "router isis enable"
            ]
            
            # Execute each command
            for cmd in commands:
                self.root.after(0, lambda c=cmd: self.terminal_output.insert(tk.END, f"\n> {c}\n"))
                output = self.conn_mgr.send_command(cmd, wait_time=1.5)
                self.root.after(0, lambda o=output: self.terminal_output.insert(tk.END, f"{o}\n"))
                self.root.after(0, lambda: self.terminal_output.see(tk.END))
                time.sleep(0.5)  # Small delay between commands
            
            # Update status
            self.root.after(0, lambda: self.live_config_status.config(text="ISIS Configured", foreground="green"))
            
            # Reset status after delay
            self.root.after(3000, lambda: self.live_config_status.config(text="Ready", foreground="blue"))
        
        threading.Thread(target=config_isis_thread, daemon=True).start()
    
    def configure_live_mgmt(self):
        """Configure management IP on connected device"""
        if not self.conn_mgr.connected:
            messagebox.showerror("Error", "Not connected to device")
            return
        
        mgmt_ip = self.live_mgmt_ip_var.get()
        gateway = self.live_gateway_var.get()
        
        if not mgmt_ip or not gateway:
            messagebox.showerror("Error", "Please enter Management IP and Gateway")
            return
            
        # Add subnet mask if not provided
        if "/" not in mgmt_ip:
            mgmt_ip += "/24"
            
        self.live_config_status.config(text="Configuring Management...", foreground="orange")
        
        def config_mgmt_thread():
            # Ensure we're in config mode
            self.conn_mgr.send_command("enable", wait_time=0.5)
            self.conn_mgr.send_command("config term", wait_time=0.5)
            
            # Configure Management IP
            commands = [
                "no mgmt vlan",
                "mgmt vlan 2024",  # Using default management VLAN
                f"ip address {mgmt_ip}",
                f"ip route 0.0.0.0 0.0.0.0 next-hop {gateway}",
                "no mgmt dhcp-client"
            ]
            
            # Execute each command
            for cmd in commands:
                self.root.after(0, lambda c=cmd: self.terminal_output.insert(tk.END, f"\n> {c}\n"))
                output = self.conn_mgr.send_command(cmd, wait_time=1.5)
                self.root.after(0, lambda o=output: self.terminal_output.insert(tk.END, f"{o}\n"))
                self.root.after(0, lambda: self.terminal_output.see(tk.END))
                time.sleep(0.5)  # Small delay between commands
            
            # Update status
            self.root.after(0, lambda: self.live_config_status.config(text="Management Configured", foreground="green"))
            
            # Reset status after delay
            self.root.after(3000, lambda: self.live_config_status.config(text="Ready", foreground="blue"))
        
        threading.Thread(target=config_mgmt_thread, daemon=True).start()
    
    def execute_bulk_commands(self):
        """Execute bulk commands from text area"""
        if not self.conn_mgr.connected:
            messagebox.showerror("Error", "Not connected to device")
            return
        
        commands_text = self.bulk_commands_text.get(1.0, tk.END).strip()
        if not commands_text:
            messagebox.showerror("Error", "Please enter commands to execute")
            return
            
        # Split into individual commands
        commands = [cmd.strip() for cmd in commands_text.split('\n') if cmd.strip()]
        
        if not commands:
            return
            
        # Confirm execution
        if not messagebox.askyesno("Confirm", f"Execute {len(commands)} commands?\nThis could modify device configuration."):
            return
            
        self.live_config_status.config(text="Executing Commands...", foreground="orange")
        
        def execute_commands_thread():
            # Ensure we're in config mode
            self.conn_mgr.send_command("enable", wait_time=0.5)
            self.conn_mgr.send_command("config term", wait_time=0.5)
            
            # Execute each command
            for cmd in commands:
                self.root.after(0, lambda c=cmd: self.terminal_output.insert(tk.END, f"\n> {c}\n"))
                output = self.conn_mgr.send_command(cmd, wait_time=1.5)
                self.root.after(0, lambda o=output: self.terminal_output.insert(tk.END, f"{o}\n"))
                self.root.after(0, lambda: self.terminal_output.see(tk.END))
                time.sleep(0.5)  # Small delay between commands
            
            # Update status
            self.root.after(0, lambda: self.live_config_status.config(text="Commands Executed", foreground="green"))
            
            # Reset status after delay
            self.root.after(5000, lambda: self.live_config_status.config(text="Ready", foreground="blue"))
        
        threading.Thread(target=execute_commands_thread, daemon=True).start()
    
    def create_batch_tab(self):
        """Batch configuration tab"""
        batch_frame = ttk.Frame(self.notebook)
        self.notebook.add(batch_frame, text="Batch Config")
        
        # File selection
        file_frame = ttk.LabelFrame(batch_frame, text="Configuration File", padding=10)
        file_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.config_file_var = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.config_file_var, width=50).pack(side=tk.LEFT, padx=5)
        ttk.Button(file_frame, text="Browse", command=self.browse_config_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(file_frame, text="Apply to Device", command=self.apply_batch_config).pack(side=tk.LEFT, padx=10)
        
        # Connection status for batch
        status_frame = ttk.Frame(file_frame)
        status_frame.pack(side=tk.RIGHT, padx=10)
        ttk.Label(status_frame, text="Connection:").pack(side=tk.LEFT)
        self.batch_status_label = ttk.Label(status_frame, text="Check Terminal Tab", foreground="orange")
        self.batch_status_label.pack(side=tk.LEFT, padx=5)
        
        # Progress and output
        self.batch_output = scrolledtext.ScrolledText(batch_frame, wrap=tk.WORD, height=25)
        self.batch_output.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def browse_config_file(self):
        """Browse for configuration file"""
        file_path = filedialog.askopenfilename(
            title="Select Configuration File",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if file_path:
            self.config_file_var.set(file_path)
    
    def apply_batch_config(self):
        """Apply batch configuration to device"""
        config_file = self.config_file_var.get()
        if not config_file:
            messagebox.showerror("Error", "Please select a configuration file")
            return
            
        if not self.conn_mgr.connected:
            messagebox.showerror("Error", "Please establish connection in Terminal tab first")
            return
        
        try:
            with open(config_file, 'r') as f:
                config_lines = f.readlines()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read config file: {str(e)}")
            return
            
        self.batch_output.delete(1.0, tk.END)
        self.batch_output.insert(tk.END, f"Starting batch configuration from: {config_file}\n")
        self.batch_output.insert(tk.END, f"Connection: {self.conn_mgr.connection_type}\n")
        self.batch_output.insert(tk.END, "=" * 60 + "\n\n")
        
        def apply_config_thread():
            for line_num, line in enumerate(config_lines, 1):
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                
                self.root.after(0, lambda l=line, n=line_num: 
                               self.batch_output.insert(tk.END, f"[{n:03d}] Sending: {l}\n"))
                
                output = self.conn_mgr.send_command(line, wait_time=1.5)
                
                self.root.after(0, lambda o=output: 
                               self.batch_output.insert(tk.END, f"Response: {o}\n\n"))
                self.root.after(0, lambda: self.batch_output.see(tk.END))
                
                # Add delay for configuration commands
                if any(keyword in line.lower() for keyword in ['vlan', 'ip', 'isis', 'snmp']):
                    time.sleep(1)
            
            self.root.after(0, lambda: 
                           self.batch_output.insert(tk.END, "\nBatch configuration completed!\n"))
            self.root.after(0, lambda: self.batch_output.see(tk.END))
        
        threading.Thread(target=apply_config_thread, daemon=True).start()
    
    # Quick Config Tab Methods
    def load_default_vlans(self):
        """Load default VLAN configuration"""
        default_vlans = [
            VLANConfig(100, "Management", 1040100),
            VLANConfig(110, "Printers", 1040110),
            VLANConfig(120, "Staff", 1040120),
            VLANConfig(140, "AP-Control", 1040140),
            VLANConfig(150, "AP-Data", 1040150),
            VLANConfig(160, "AP-Voice", 1040160),
            VLANConfig(170, "AP-IoT", 1040170),
            VLANConfig(180, "Guest", 1040180)
        ]
        
        # Clear existing items
        for item in self.vlan_tree.get_children():
            self.vlan_tree.delete(item)
            
        # Add default VLANs
        for vlan in default_vlans:
            self.vlan_tree.insert('', 'end', values=(vlan.vlan_id, vlan.name, vlan.i_sid))
    
    def add_vlan(self):
        """Add VLAN to quick config"""
        self.vlan_dialog()
        
    def edit_vlan(self):
        """Edit VLAN in quick config"""
        selection = self.vlan_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a VLAN to edit")
            return
            
        item = selection[0]
        values = self.vlan_tree.item(item, 'values')
        self.vlan_dialog(values)
        
    def remove_vlan(self):
        """Remove VLAN from quick config"""
        selection = self.vlan_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a VLAN to remove")
            return
            
        if messagebox.askyesno("Confirm", "Remove selected VLAN?"):
            self.vlan_tree.delete(selection[0])
    
    def vlan_dialog(self, existing_values=None):
        """VLAN configuration dialog for quick config"""
        dialog = tk.Toplevel(self.root)
        dialog.title("VLAN Configuration")
        dialog.geometry("300x150")
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text="VLAN ID:").grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
        vlan_id_var = tk.StringVar(value=existing_values[0] if existing_values else "")
        ttk.Entry(dialog, textvariable=vlan_id_var, width=20).grid(row=0, column=1, padx=10, pady=5)
        
        ttk.Label(dialog, text="Name:").grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)
        name_var = tk.StringVar(value=existing_values[1] if existing_values else "")
        ttk.Entry(dialog, textvariable=name_var, width=20).grid(row=1, column=1, padx=10, pady=5)
        
        ttk.Label(dialog, text="I-SID:").grid(row=2, column=0, sticky=tk.W, pady=5)
        isid_var = tk.StringVar(value=existing_values[2] if existing_values else "")
        ttk.Entry(dialog, textvariable=isid_var, width=20).grid(row=2, column=1, padx=10, pady=5)
        
        def save_vlan():
            try:
                vlan_id = int(vlan_id_var.get())
                name = name_var.get()
                i_sid = int(isid_var.get())
                
                if existing_values:
                    # Update existing
                    selection = self.vlan_tree.selection()[0]
                    self.vlan_tree.item(selection, values=(vlan_id, name, i_sid))
                else:
                    # Add new
                    self.vlan_tree.insert('', 'end', values=(vlan_id, name, i_sid))
                    
                dialog.destroy()
            except ValueError:
                messagebox.showerror("Error", "VLAN ID and I-SID must be numbers")
        
        button_frame = ttk.Frame(dialog)
        button_frame.grid(row=3, column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="Save", command=save_vlan).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def get_vlans_from_tree(self):
        """Get VLANs from quick config tree"""
        vlans = []
        for item in self.vlan_tree.get_children():
            values = self.vlan_tree.item(item, 'values')
            vlans.append(VLANConfig(int(values[0]), values[1], int(values[2])))
        return vlans
        
    def generate_config(self):
        """Generate configuration from quick config"""
        config = SwitchConfig(
            hostname=self.hostname_var.get(),
            snmp_location=self.location_var.get(),
            mgmt_ip=self.mgmt_ip_var.get(),
            system_id=self.system_id_var.get(),
            nick_name=self.nick_name_var.get(),
            vlans=self.get_vlans_from_tree(),
            snmp_group=self.snmp_group_var.get(),
            snmp_user=self.snmp_user_var.get(),
            snmp_auth_password=self.snmp_auth_pass_var.get(),
            snmp_priv_password=self.snmp_priv_pass_var.get()
        )
        
        generated_config = ConfigGenerator.generate_voss_config(config)
        
        self.config_text.delete(1.0, tk.END)
        self.config_text.insert(1.0, generated_config)
        
    def load_config(self):
        """Load configuration file into quick config"""
        file_path = filedialog.askopenfilename(
            title="Load Configuration File",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    config_text = f.read()
                
                # Parse and populate fields
                config = ConfigGenerator.parse_voss_config(config_text)
                
                self.hostname_var.set(config.hostname)
                self.location_var.set(config.snmp_location)
                self.mgmt_ip_var.set(config.mgmt_ip)
                self.system_id_var.set(config.system_id)
                self.nick_name_var.set(config.nick_name)
                
                # Clear and populate VLANs
                for item in self.vlan_tree.get_children():
                    self.vlan_tree.delete(item)
                
                for vlan in config.vlans:
                    self.vlan_tree.insert('', 'end', values=(vlan.vlan_id, vlan.name, vlan.i_sid))
                
                # Display in text area
                self.config_text.delete(1.0, tk.END)
                self.config_text.insert(1.0, config_text)
                
                messagebox.showinfo("Success", "Configuration loaded successfully")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load configuration: {str(e)}")
    
    def save_config(self):
        """Save configuration from quick config"""
        config_content = self.config_text.get(1.0, tk.END)
        if not config_content.strip():
            messagebox.showwarning("Warning", "No configuration to save")
            return
            
        file_path = filedialog.asksaveasfilename(
            title="Save Configuration",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(config_content)
                messagebox.showinfo("Success", "Configuration saved successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save configuration: {str(e)}")

    def on_closing(self):
        """Handle application closing"""
        if self.conn_mgr.connected:
            self.conn_mgr.disconnect()
        self.root.destroy()

def main():
    """Main application entry point"""
    root = tk.Tk()
    app = VOSSManagerGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    
    # Style configuration
    style = ttk.Style()
    if 'clam' in style.theme_names():
        style.theme_use('clam')
    
    # Center window on screen
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f"{width}x{height}+{x}+{y}")
    
    root.mainloop()

if __name__ == "__main__":
    main()