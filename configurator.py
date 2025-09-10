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
import csv
import urllib.request
import webbrowser
import shutil
import tempfile
import os
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Tuple

__version__ = "0.1.1"

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
        
        lines.extend([
            f'hostname "{config.hostname}"',
            ""
        ])
        
        if config.domain_name:
            lines.append(f'ip domain-name {config.domain_name}')
            
        for dns in config.name_servers:
            lines.append(f'ip name-server {dns}')
            
        if config.domain_name or config.name_servers:
            lines.append("")
        
        if config.timezone:
            lines.extend([
                f'clock timezone {config.timezone}',
                ""
            ])
        
        lines.extend([
            f'snmp-server name {config.hostname}',
            f'snmp-server location "{config.snmp_location}"',
            ""
        ])
        
        if config.vlans:
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
        
        if config.ntp_servers:
            lines.append("# NTP Configuration")
            for ntp_server in config.ntp_servers:
                lines.append(f"ntp server {ntp_server}")
            lines.append("")
        
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
        
        self.conn_mgr = ConnectionManager()
        
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.create_base_config_tab()
        
        self.create_config_tab()
        
        self.create_terminal_tab()
        
        self.create_batch_tab()

        self.root.after(1000, self.check_for_updates_safely)

    def check_for_updates_safely(self):
        try:
            self.check_for_updates()
        except Exception:
            pass

    def _parse_version(self, version_str: str) -> Tuple[int, ...]:
        parts = re.findall(r"\d+", version_str or "")
        if not parts:
            return (0,)
        return tuple(int(p) for p in parts[:4])

    def _read_local_version(self) -> str:
        try:
            here = os.path.dirname(__file__)
            version_path = os.path.join(here, "VERSION")
            if os.path.isfile(version_path):
                with open(version_path, "r", encoding="utf-8") as f:
                    line = f.readline().strip()
                    if line:
                        return line
        except Exception:
            pass
        try:
            return __version__ 
        except Exception:
            return "0.0.0"

    def _fetch_remote_version(self, timeout: int = 8) -> Optional[str]:
        try:
            version_url = (
                "https://raw.githubusercontent.com/PneumaticDoggo/Voss-Configurator/main/VERSION"
            )
            with urllib.request.urlopen(version_url, timeout=timeout) as resp:
                text = resp.read().decode("utf-8", errors="ignore").strip()
                if text:
                    return text.splitlines()[0].strip()
        except Exception:
            return None

    def check_for_updates(self):
        """Check GitHub for a newer version; prefer VERSION file, fallback to hash compare."""
        try:
            remote_version = self._fetch_remote_version()
            if remote_version is not None:
                local_version = self._read_local_version()
                if self._parse_version(remote_version) > self._parse_version(local_version):
                    # Ask user for permission to update
                    if self.prompt_for_update(local_version, remote_version):
                        github_raw_url = (
                            "https://raw.githubusercontent.com/PneumaticDoggo/Voss-Configurator/main/configurator.py"
                        )
                        with urllib.request.urlopen(github_raw_url, timeout=10) as resp:
                            latest_bytes = resp.read()
                        self.perform_auto_update(latest_bytes)
                return

            github_raw_url = (
                "https://raw.githubusercontent.com/PneumaticDoggo/Voss-Configurator/main/configurator.py"
            )
            with urllib.request.urlopen(github_raw_url, timeout=10) as resp:
                latest_bytes = resp.read()
            latest_hash = hashlib.sha256(latest_bytes).hexdigest()

            try:
                with open(__file__, "rb") as f:
                    current_bytes = f.read()
                current_hash = hashlib.sha256(current_bytes).hexdigest()
            except Exception:
                current_hash = ""

            if not current_hash or latest_hash != current_hash:
                if self.prompt_for_update("current", "latest"):
                    self.perform_auto_update(latest_bytes)
        except Exception:
            pass

    def prompt_for_update(self, current_version, new_version):
        """Ask user if they want to update to the newer version."""
        try:
            result = messagebox.askyesno(
                "Update Available",
                f"A newer version of VOSS Configurator is available!\n\n"
                f"Current version: {current_version}\n"
                f"New version: {new_version}\n\n"
                f"Would you like to update now?\n\n"
                f"Note: The application will restart after the update.",
                icon='question'
            )
            return result
        except Exception:
            return False

    def perform_auto_update(self, latest_bytes):
        """Safely download and prepare the latest version for next restart."""
        try:
            current_file = __file__
            backup_file = current_file + ".backup"
            shutil.copy2(current_file, backup_file)

            with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.py') as temp_file:
                temp_file.write(latest_bytes)
                temp_path = temp_file.name

            try:
                with open(temp_path, 'r', encoding='utf-8') as f:
                    compile(f.read(), temp_path, 'exec')
            except SyntaxError:
                os.unlink(temp_path)
                return

            shutil.move(temp_path, current_file)

            messagebox.showinfo(
                "Update Complete",
                "VOSS Configurator has been updated to the latest version!\n\n"
                "The update will take effect when you restart the application.\n\n"
                f"Backup saved as: {os.path.basename(backup_file)}"
            )

        except Exception as e:
            messagebox.showerror(
                "Update Failed",
                f"Failed to update VOSS Configurator:\n{str(e)}\n\n"
                "You can manually download the latest version from:\n"
                "https://github.com/PneumaticDoggo/Voss-Configurator"
            )
        
    def create_base_config_tab(self):
        """Comprehensive configuration builder tab"""
        base_frame = ttk.Frame(self.notebook)
        self.notebook.add(base_frame, text="Create Base Config")
        
        canvas = tk.Canvas(base_frame)
        scrollbar = ttk.Scrollbar(base_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        canvas.bind_all("<MouseWheel>", _on_mousewheel)
        
        main_frame = scrollable_frame
        
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
                self.base_snmp_user_var.set(template_data.get('snmp_user', ''))
                self.base_snmp_auth_pass_var.set(template_data.get('snmp_auth_password', ''))
                self.base_snmp_priv_pass_var.set(template_data.get('snmp_priv_password', ''))
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
        ttk.Button(button_frame, text="Export as Template", command=self.export_as_template).pack(side=tk.LEFT, padx=5)
        
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
        """Enhanced batch configuration tab with CSV support"""
        batch_frame = ttk.Frame(self.notebook)
        self.notebook.add(batch_frame, text="Batch Config")
        
        # Create notebook for different batch modes
        batch_notebook = ttk.Notebook(batch_frame)
        batch_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # CSV Batch Generation Tab
        csv_frame = ttk.Frame(batch_notebook)
        batch_notebook.add(csv_frame, text="CSV Batch Generation")
        
        # CSV file selection
        csv_file_frame = ttk.LabelFrame(csv_frame, text="CSV Input File", padding=10)
        csv_file_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.csv_file_var = tk.StringVar()
        ttk.Entry(csv_file_frame, textvariable=self.csv_file_var, width=50).pack(side=tk.LEFT, padx=5)
        ttk.Button(csv_file_frame, text="Browse CSV", command=self.browse_csv_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(csv_file_frame, text="Load CSV", command=self.load_csv_data).pack(side=tk.LEFT, padx=5)
        
        # Template source selection
        template_frame = ttk.LabelFrame(csv_frame, text="Configuration Template Source", padding=10)
        template_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.template_source_var = tk.StringVar(value="base_config")
        
        # Radio buttons for template source
        source_frame = ttk.Frame(template_frame)
        source_frame.pack(fill=tk.X, pady=5)
        
        ttk.Radiobutton(source_frame, text="Use Base Config Tab", 
                       variable=self.template_source_var, value="base_config",
                       command=self.toggle_template_source).pack(side=tk.LEFT, padx=10)
        ttk.Radiobutton(source_frame, text="Use Template File", 
                       variable=self.template_source_var, value="file",
                       command=self.toggle_template_source).pack(side=tk.LEFT, padx=10)
        
        # Template file selection (initially hidden)
        self.template_file_frame = ttk.Frame(template_frame)
        self.template_file_var = tk.StringVar()
        ttk.Entry(self.template_file_frame, textvariable=self.template_file_var, width=50).pack(side=tk.LEFT, padx=5)
        ttk.Button(self.template_file_frame, text="Browse Template", command=self.browse_template_file).pack(side=tk.LEFT, padx=5)
        
        # Base config status
        self.base_config_status_frame = ttk.Frame(template_frame)
        self.base_config_status_frame.pack(fill=tk.X, pady=5)
        self.base_config_status_label = ttk.Label(self.base_config_status_frame, 
                                                 text="✓ Using Base Config as template", 
                                                 foreground="green")
        self.base_config_status_label.pack(side=tk.LEFT)
        
        # Output directory selection
        output_frame = ttk.LabelFrame(csv_frame, text="Output Directory", padding=10)
        output_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.output_dir_var = tk.StringVar()
        ttk.Entry(output_frame, textvariable=self.output_dir_var, width=50).pack(side=tk.LEFT, padx=5)
        ttk.Button(output_frame, text="Browse Folder", command=self.browse_output_dir).pack(side=tk.LEFT, padx=5)
        ttk.Button(output_frame, text="Generate All Configs", command=self.generate_batch_configs).pack(side=tk.LEFT, padx=10)
        
        # Device data management
        device_frame = ttk.LabelFrame(csv_frame, text="Device Configuration Data", padding=5)
        device_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Device list controls
        controls_frame = ttk.Frame(device_frame)
        controls_frame.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Button(controls_frame, text="Add Device", command=self.add_device_manual).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls_frame, text="Edit Device", command=self.edit_device).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls_frame, text="Preview Config", command=self.preview_device_config).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls_frame, text="Auto-detect Gateway", command=self.manual_gateway_detection).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls_frame, text="Remove Device", command=self.remove_device).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls_frame, text="Clear All", command=self.clear_all_devices).pack(side=tk.LEFT, padx=10)
        
        # Create treeview for device data
        columns = ("IP-Address", "Device", "Location", "Nick-name", "sys-id", "sys-name", "Notes", "VLAN Range")
        self.csv_tree = ttk.Treeview(device_frame, columns=columns, show='headings', height=10)
        
        for col in columns:
            self.csv_tree.heading(col, text=col)
            self.csv_tree.column(col, width=100)
        
        # Add scrollbar for device tree
        csv_scrollbar = ttk.Scrollbar(device_frame, orient=tk.VERTICAL, command=self.csv_tree.yview)
        self.csv_tree.configure(yscrollcommand=csv_scrollbar.set)
        
        self.csv_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        csv_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind double-click to preview config
        self.csv_tree.bind('<Double-1>', lambda e: self.preview_device_config())
        
        # Initialize device data list
        self.csv_data = []
        
        # Single Config Application Tab
        single_frame = ttk.Frame(batch_notebook)
        batch_notebook.add(single_frame, text="Apply Single Config")
        
        # File selection for single config
        file_frame = ttk.LabelFrame(single_frame, text="Configuration File", padding=10)
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
        self.batch_output = scrolledtext.ScrolledText(single_frame, wrap=tk.WORD, height=25)
        self.batch_output.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Config Preview/Edit Tab
        preview_frame = ttk.Frame(batch_notebook)
        batch_notebook.add(preview_frame, text="Config Preview/Edit")
        
        # Preview controls
        preview_controls = ttk.Frame(preview_frame)
        preview_controls.pack(fill=tk.X, padx=5, pady=5)
        
        self.preview_device_label = ttk.Label(preview_controls, text="No device selected", font=("Arial", 10, "bold"))
        self.preview_device_label.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(preview_controls, text="Refresh Preview", command=self.refresh_preview).pack(side=tk.RIGHT, padx=5)
        ttk.Button(preview_controls, text="Save Config", command=self.save_preview_config).pack(side=tk.RIGHT, padx=5)
        ttk.Button(preview_controls, text="Apply to Device", command=self.apply_preview_config).pack(side=tk.RIGHT, padx=5)
        
        # Preview text area
        self.preview_text = scrolledtext.ScrolledText(preview_frame, wrap=tk.WORD, height=30, font=("Consolas", 9))
        self.preview_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Store current preview device
        self.current_preview_device = None
        
        # VLAN and Port Configuration Tab
        vlan_config_frame = ttk.Frame(batch_notebook)
        batch_notebook.add(vlan_config_frame, text="VLAN & Port Config")
        
        # Create two main sections
        vlan_config_paned = ttk.PanedWindow(vlan_config_frame, orient=tk.HORIZONTAL)
        vlan_config_paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Left panel - VLAN Assignment
        vlan_assignment_frame = ttk.LabelFrame(vlan_config_paned, text="VLAN Assignment per Switch", padding=10)
        vlan_config_paned.add(vlan_assignment_frame, weight=1)
        
        # VLAN assignment controls
        vlan_controls = ttk.Frame(vlan_assignment_frame)
        vlan_controls.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(vlan_controls, text="Auto-assign VLANs", command=self.auto_assign_vlans).pack(side=tk.LEFT, padx=5)
        ttk.Button(vlan_controls, text="Clear All Assignments", command=self.clear_vlan_assignments).pack(side=tk.LEFT, padx=5)
        ttk.Button(vlan_controls, text="Apply to Selected", command=self.apply_vlan_assignments).pack(side=tk.LEFT, padx=5)
        ttk.Button(vlan_controls, text="Refresh Switch List", command=self.refresh_switch_list).pack(side=tk.LEFT, padx=5)
        
        # VLAN assignment tree
        vlan_tree_frame = ttk.Frame(vlan_assignment_frame)
        vlan_tree_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create treeview for VLAN assignments
        vlan_columns = ("Switch", "IP Address", "VLANs", "Port Configs", "Actions")
        self.vlan_assignment_tree = ttk.Treeview(vlan_tree_frame, columns=vlan_columns, show='headings', height=15)
        
        for col in vlan_columns:
            self.vlan_assignment_tree.heading(col, text=col)
            self.vlan_assignment_tree.column(col, width=120)
        
        vlan_tree_scrollbar = ttk.Scrollbar(vlan_tree_frame, orient=tk.VERTICAL, command=self.vlan_assignment_tree.yview)
        self.vlan_assignment_tree.configure(yscrollcommand=vlan_tree_scrollbar.set)
        
        self.vlan_assignment_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vlan_tree_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind double-click to edit port configuration
        self.vlan_assignment_tree.bind('<Double-1>', lambda e: self.edit_switch_port_config())
        
        # Add helpful message when empty
        self.add_empty_message_to_vlan_tree()
        
        # Right panel - VLAN Management
        vlan_config_right = ttk.LabelFrame(vlan_config_paned, text="VLAN Management", padding=10)
        vlan_config_paned.add(vlan_config_right, weight=1)
        
        # VLAN management controls
        vlan_mgmt_controls = ttk.Frame(vlan_config_right)
        vlan_mgmt_controls.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(vlan_mgmt_controls, text="Add VLAN", command=self.add_vlan_to_batch).pack(side=tk.LEFT, padx=2)
        ttk.Button(vlan_mgmt_controls, text="Edit VLAN", command=self.edit_vlan_in_batch).pack(side=tk.LEFT, padx=2)
        ttk.Button(vlan_mgmt_controls, text="Remove VLAN", command=self.remove_vlan_from_batch).pack(side=tk.LEFT, padx=2)
        ttk.Button(vlan_mgmt_controls, text="Load Template", command=self.load_vlan_template_batch).pack(side=tk.LEFT, padx=2)
        ttk.Button(vlan_mgmt_controls, text="Auto I-SID", command=self.auto_generate_isids_batch).pack(side=tk.LEFT, padx=2)
        
        # VLAN list tree
        vlan_list_frame = ttk.Frame(vlan_config_right)
        vlan_list_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Create VLAN management tree
        vlan_mgmt_columns = ("VLAN ID", "Name", "I-SID")
        self.batch_vlan_tree = ttk.Treeview(vlan_list_frame, columns=vlan_mgmt_columns, show='headings', height=12)
        
        for col in vlan_mgmt_columns:
            self.batch_vlan_tree.heading(col, text=col)
            self.batch_vlan_tree.column(col, width=100)
        
        vlan_mgmt_scrollbar = ttk.Scrollbar(vlan_list_frame, orient=tk.VERTICAL, command=self.batch_vlan_tree.yview)
        self.batch_vlan_tree.configure(yscrollcommand=vlan_mgmt_scrollbar.set)
        
        self.batch_vlan_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vlan_mgmt_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind double-click to edit
        self.batch_vlan_tree.bind('<Double-1>', lambda e: self.edit_vlan_in_batch())
        
        # Port configuration options
        port_config_frame = ttk.LabelFrame(vlan_config_right, text="Port Configuration", padding=5)
        port_config_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.port_config_type = tk.StringVar(value="auto")
        ttk.Radiobutton(port_config_frame, text="Auto (based on VLANs)", 
                       variable=self.port_config_type, value="auto").pack(anchor=tk.W)
        ttk.Radiobutton(port_config_frame, text="All Trunk", 
                       variable=self.port_config_type, value="trunk").pack(anchor=tk.W)
        ttk.Radiobutton(port_config_frame, text="All Access", 
                       variable=self.port_config_type, value="access").pack(anchor=tk.W)
        
        # Port range configuration
        port_range_frame = ttk.Frame(port_config_frame)
        port_range_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(port_range_frame, text="Port Range:").pack(side=tk.LEFT)
        self.port_range_var = tk.StringVar(value="1/1-1/48")
        ttk.Entry(port_range_frame, textvariable=self.port_range_var, width=15).pack(side=tk.LEFT, padx=5)
        
        # Management VLAN configuration
        mgmt_vlan_frame = ttk.LabelFrame(vlan_config_right, text="Management VLAN", padding=5)
        mgmt_vlan_frame.pack(fill=tk.X)
        
        ttk.Label(mgmt_vlan_frame, text="Management VLAN ID:").pack(anchor=tk.W)
        self.mgmt_vlan_var = tk.StringVar(value="3005")
        ttk.Entry(mgmt_vlan_frame, textvariable=self.mgmt_vlan_var, width=10).pack(anchor=tk.W, pady=2)
        
        # Initialize VLAN assignment data
        self.vlan_assignments = {}  # {device_name: [vlan_list]}
        self.port_configurations = {}  # {device_name: [port_config_list]}
        self.port_config_list = {}  # {device_name: [{'range': '1/1-1/12', 'type': 'trunk', 'vlans': [2024, 2152], 'default_vlan': 2024}]}
        
        # Initialize batch VLAN tree with existing VLANs
        self.sync_base_vlans_to_batch()
    
    def browse_config_file(self):
        """Browse for configuration file"""
        file_path = filedialog.askopenfilename(
            title="Select Configuration File",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if file_path:
            self.config_file_var.set(file_path)
    
    def browse_csv_file(self):
        """Browse for CSV input file"""
        file_path = filedialog.askopenfilename(
            title="Select CSV Input File",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        
        if file_path:
            self.csv_file_var.set(file_path)
    
    def browse_template_file(self):
        """Browse for configuration template file"""
        file_path = filedialog.askopenfilename(
            title="Select Configuration Template",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if file_path:
            self.template_file_var.set(file_path)
    
    def toggle_template_source(self):
        """Toggle between base config and template file as source"""
        if self.template_source_var.get() == "base_config":
            self.template_file_frame.pack_forget()
            self.base_config_status_frame.pack(fill=tk.X, pady=5)
        else:
            self.base_config_status_frame.pack_forget()
            self.template_file_frame.pack(fill=tk.X, pady=5)
    
    def browse_output_dir(self):
        """Browse for output directory"""
        dir_path = filedialog.askdirectory(
            title="Select Output Directory"
        )
        
        if dir_path:
            self.output_dir_var.set(dir_path)
    
    def load_csv_data(self):
        """Load and display CSV data"""
        csv_file = self.csv_file_var.get()
        if not csv_file:
            messagebox.showerror("Error", "Please select a CSV file first")
            return
        
        try:
            for item in self.csv_tree.get_children():
                self.csv_tree.delete(item)
            
            with open(csv_file, 'r', newline='', encoding='utf-8') as file:
                csv_reader = csv.DictReader(file)
                
                self.csv_data = []
                
                for row in csv_reader:
                    values = (
                        row.get('IP-Address', ''),
                        row.get('Device', ''),
                        row.get('Location', ''),
                        row.get('Nick-name', ''),
                        row.get('sys-id', ''),
                        row.get('sys-name', ''),
                        row.get('Notes', ''),
                        row.get('VLAN Range', '')
                    )
                    self.csv_tree.insert('', 'end', values=values)
                    
                    self.csv_data.append(row)
                
                detected_gateway = self.analyze_network_and_detect_gateway()
                if detected_gateway:
                    self.base_gateway_var.set(detected_gateway)
                    gateway_message = f"\n\nAuto-detected gateway: {detected_gateway}"
                    if hasattr(self, 'base_config_status_label'):
                        self.base_config_status_label.config(
                            text=f"✓ Using Base Config as template (Gateway: {detected_gateway})", 
                            foreground="green"
                        )
                else:
                    gateway_message = "\n\nCould not auto-detect gateway - please set manually in Base Config"
                    if hasattr(self, 'base_config_status_label'):
                        self.base_config_status_label.config(
                            text="⚠ Base Config ready (Please set gateway manually)", 
                            foreground="orange"
                        )
                # Auto-import VLANs from CSV "VLAN Range" column
                csv_vlans = self.extract_vlans_from_csv()
                if csv_vlans:
                    # Prepare tuples: (vlan_id, name, isid)
                    vlans_to_add = []
                    for vid in sorted(csv_vlans):
                        # Check if VLAN already exists in base tree
                        exists = False
                        if hasattr(self, 'base_vlan_tree'):
                            for item in self.base_vlan_tree.get_children():
                                values = self.base_vlan_tree.item(item, 'values')
                                if int(values[0]) == vid:
                                    exists = True
                                    break
                        if not exists:
                            vlans_to_add.append((vid, f"VLAN {vid}", 1040000 + vid))
                    if vlans_to_add:
                        self.add_vlans_to_base_config(vlans_to_add)
                        if hasattr(self, 'batch_vlan_tree'):
                            self.sync_base_vlans_to_batch()

                # Determine whether to prompt for management VLAN
                should_prompt_mgmt = True
                current_mgmt = self.mgmt_vlan_var.get() if hasattr(self, 'mgmt_vlan_var') else ""
                if current_mgmt and current_mgmt.isdigit():
                    should_prompt_mgmt = False
                elif csv_vlans:
                    # Use the smallest VLAN ID from CSV as default management VLAN
                    chosen = min(csv_vlans)
                    self.mgmt_vlan_var.set(str(chosen))
                    should_prompt_mgmt = False
                    # Ensure batch panel reflects any new base VLANs
                    if hasattr(self, 'batch_vlan_tree'):
                        self.sync_base_vlans_to_batch()

                # Only prompt if nothing recognized
                if should_prompt_mgmt:
                    self.prompt_management_vlan()
                else:
                    # Final sync to ensure both panels match
                    if hasattr(self, 'batch_vlan_tree'):
                        self.sync_base_vlans_to_batch()
                
                messagebox.showinfo("Success", f"Loaded {len(self.csv_data)} devices from CSV{gateway_message}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load CSV file: {str(e)}")
    
    def add_device_manual(self):
        """Add a device manually through dialog"""
        self.device_dialog()
    
    def edit_device(self):
        """Edit selected device"""
        selection = self.csv_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a device to edit")
            return
        
        item = selection[0]
        values = self.csv_tree.item(item, 'values')
        self.device_dialog(values, item)
    
    def remove_device(self):
        """Remove selected device"""
        selection = self.csv_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a device to remove")
            return
        
        if messagebox.askyesno("Confirm", "Remove selected device?"):
            item = selection[0]
            self.csv_tree.delete(item)
            self.update_csv_data_from_tree()
    
    def clear_all_devices(self):
        """Clear all devices"""
        if messagebox.askyesno("Confirm", "Remove all devices?"):
            for item in self.csv_tree.get_children():
                self.csv_tree.delete(item)
            self.csv_data = []
    
    def device_dialog(self, existing_values=None, item=None):
        """Device configuration dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Device Configuration")
        dialog.geometry("400x300")
        dialog.transient(self.root)
        dialog.grab_set()
        
        fields = [
            ("IP Address:", "IP-Address"),
            ("Device Name:", "Device"),
            ("Location:", "Location"),
            ("Nick Name:", "Nick-name"),
            ("System ID:", "sys-id"),
            ("System Name:", "sys-name"),
            ("Notes:", "Notes")
        ]
        
        vars_dict = {}
        
        for i, (label, key) in enumerate(fields):
            ttk.Label(dialog, text=label).grid(row=i, column=0, sticky=tk.W, padx=10, pady=5)
            var = tk.StringVar(value=existing_values[i] if existing_values else "")
            vars_dict[key] = var
            ttk.Entry(dialog, textvariable=var, width=30).grid(row=i, column=1, padx=10, pady=5)
        
        def save_device():
            try:
                required_fields = ["IP-Address", "Device", "Location", "Nick-name", "sys-id", "sys-name"]
                for field in required_fields:
                    if not vars_dict[field].get().strip():
                        messagebox.showerror("Error", f"{field.replace('-', ' ').title()} is required")
                        return
                
                values = tuple(vars_dict[key].get() for key, _ in [(f[1], None) for f in fields])
                
                if item:
                    self.csv_tree.item(item, values=values)
                else:
                    self.csv_tree.insert('', 'end', values=values)
                
                self.update_csv_data_from_tree()
                
                if not item and not self.base_gateway_var.get().strip():
                    detected_gateway = self.analyze_network_and_detect_gateway()
                    if detected_gateway:
                        self.base_gateway_var.set(detected_gateway)
                        if hasattr(self, 'base_config_status_label'):
                            self.base_config_status_label.config(
                                text=f"✓ Using Base Config as template (Gateway: {detected_gateway})", 
                                foreground="green"
                            )
                
                dialog.destroy()
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save device: {str(e)}")
        
        auto_frame = ttk.Frame(dialog)
        auto_frame.grid(row=len(fields), column=0, columnspan=2, pady=10)
        
        ttk.Button(auto_frame, text="Auto-generate System ID", 
                  command=lambda: self.auto_generate_device_system_id(vars_dict)).pack(side=tk.LEFT, padx=5)
        ttk.Button(auto_frame, text="Auto-generate Nick Name", 
                  command=lambda: self.auto_generate_device_nick_name(vars_dict)).pack(side=tk.LEFT, padx=5)
        
        # Buttons
        button_frame = ttk.Frame(dialog)
        button_frame.grid(row=len(fields)+1, column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="Save", command=save_device).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def auto_generate_device_system_id(self, vars_dict):
        """Auto-generate system ID for device dialog"""
        hostname = vars_dict["sys-name"].get() or vars_dict["Device"].get()
        if hostname:
            # Extract numbers from hostname
            numbers = re.findall(r'\d+', hostname)
            if numbers:
                # Use last number found
                host_num = int(numbers[-1])
                area = max(1, (host_num // 100) + 1)
                system_id = f"0.e{area}.{host_num:02d}"
                vars_dict["sys-id"].set(system_id)
            else:
                # Fallback: use a random number if no numbers in hostname
                import random
                random_num = random.randint(10, 99)
                system_id = f"0.e1.{random_num}"
                vars_dict["sys-id"].set(system_id)
    
    def auto_generate_device_nick_name(self, vars_dict):
        """Auto-generate nick name for device dialog"""
        hostname = vars_dict["sys-name"].get()
        system_id = vars_dict["sys-id"].get()
        
        if hostname and system_id:
            parts = system_id.split('.')
            if len(parts) >= 3:
                suffix = parts[-1]
                numbers = re.findall(r'\d+', hostname)
                if numbers:
                    host_num = numbers[-1]
                    area_part = parts[1] if len(parts) > 1 else "e1"
                    area_code = area_part[1:] if area_part.startswith('e') else "1"
                    nick_name = f"{area_code}.e{area_code}.{suffix}"
                    vars_dict["Nick-name"].set(nick_name)
    
    def update_csv_data_from_tree(self):
        """Update internal CSV data from tree view"""
        self.csv_data = []
        for item in self.csv_tree.get_children():
            values = self.csv_tree.item(item, 'values')
            device_dict = {
                'IP-Address': values[0],
                'Device': values[1],
                'Location': values[2],
                'Nick-name': values[3],
                'sys-id': values[4],
                'sys-name': values[5],
                'Notes': values[6],
                'VLAN Range': values[7] if len(values) > 7 else ''
            }
            self.csv_data.append(device_dict)
    
    def analyze_network_and_detect_gateway(self):
        """Analyze IP addresses from CSV data and auto-detect gateway"""
        if not self.csv_data:
            return None
        
        try:
            import ipaddress
            
            ip_addresses = []
            for device in self.csv_data:
                ip_str = device.get('IP-Address', '').strip()
                if ip_str:
                    try:
                        if '/' in ip_str:
                            ip_obj = ipaddress.IPv4Interface(ip_str)
                            ip_addresses.append(ip_obj.ip)
                        else:
                            ip_obj = ipaddress.IPv4Address(ip_str)
                            ip_addresses.append(ip_obj)
                    except ValueError:
                        continue 
            
            if not ip_addresses:
                return None
            
            networks = {}
            for ip in ip_addresses:
                for prefix in [24, 23, 22, 25, 16]:  
                    try:
                        network = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
                        network_str = str(network.network_address) + f"/{prefix}"
                        
                        if network_str not in networks:
                            networks[network_str] = []
                        networks[network_str].append(ip)
                        break  
                    except ValueError:
                        continue
            
            if not networks:
                return None
            
            best_network = max(networks.keys(), key=lambda k: len(networks[k]))
            best_network_obj = ipaddress.IPv4Network(best_network)
            
            gateway_ip = best_network_obj.network_address + 1
            
            return str(gateway_ip)
            
        except ImportError:
            return self.simple_gateway_detection()
        except Exception:
            return self.simple_gateway_detection()
    
    def simple_gateway_detection(self):
        """Simple gateway detection without ipaddress module"""
        if not self.csv_data:
            return None
        
        try:
            for device in self.csv_data:
                ip_str = device.get('IP-Address', '').strip()
                if ip_str and '.' in ip_str:
                    ip_str = ip_str.split('/')[0]
                    
                    parts = ip_str.split('.')
                    if len(parts) == 4:
                        try:
                            for part in parts:
                                int(part)
                            
                            gateway = f"{parts[0]}.{parts[1]}.{parts[2]}.1"
                            return gateway
                        except ValueError:
                            continue
            
            return None
            
        except Exception:
            return None
    
    def manual_gateway_detection(self):
        """Manually trigger gateway detection and update base config"""
        if not self.csv_data:
            messagebox.showwarning("Warning", "Please add some devices first")
            return
        
        detected_gateway = self.analyze_network_and_detect_gateway()
        if detected_gateway:
            # Ask user for confirmation
            current_gateway = self.base_gateway_var.get()
            if current_gateway and current_gateway != detected_gateway:
                msg = f"Current gateway: {current_gateway}\nDetected gateway: {detected_gateway}\n\nReplace current gateway?"
                if not messagebox.askyesno("Gateway Detection", msg):
                    return
            
            # Set the detected gateway
            self.base_gateway_var.set(detected_gateway)
            
            # Update status label
            if hasattr(self, 'base_config_status_label'):
                self.base_config_status_label.config(
                    text=f"✓ Using Base Config as template (Gateway: {detected_gateway})", 
                    foreground="green"
                )
            
            # Show analysis details
            analysis_details = self.get_network_analysis_details()
            messagebox.showinfo("Gateway Detection", f"Gateway set to: {detected_gateway}\n\n{analysis_details}")
        else:
            messagebox.showwarning("Gateway Detection", "Could not auto-detect gateway from current device IP addresses.\n\nPlease set gateway manually in Base Config tab.")
    
    def get_network_analysis_details(self):
        """Get detailed network analysis for user information"""
        if not self.csv_data:
            return "No devices loaded"
        
        try:
            ip_count = 0
            ip_ranges = set()
            
            for device in self.csv_data:
                ip_str = device.get('IP-Address', '').strip()
                if ip_str and '.' in ip_str:
                    ip_str = ip_str.split('/')[0]  # Remove subnet mask
                    parts = ip_str.split('.')
                    if len(parts) == 4:
                        try:
                            # Validate IP
                            for part in parts:
                                int(part)
                            ip_count += 1
                            
                            # Track network ranges
                            network_base = f"{parts[0]}.{parts[1]}.{parts[2]}.x"
                            ip_ranges.add(network_base)
                        except ValueError:
                            continue
            
            details = f"Analyzed {ip_count} valid IP addresses\n"
            details += f"Found {len(ip_ranges)} network range(s):\n"
            for range_str in sorted(ip_ranges):
                details += f"  • {range_str}\n"
            
            return details
            
        except Exception:
            return "Analysis details unavailable"
    
    def analyze_and_detect_vlans(self):
        """Analyze CSV data and detect VLANs from VLAN Range field"""
        if not self.csv_data:
            return []
        
        detected_vlans = set()
        
        try:
            for device in self.csv_data:
                vlan_range = device.get('VLAN Range', '').strip()
                if vlan_range:
                    # Handle different VLAN range formats
                    vlans = self.parse_vlan_range(vlan_range)
                    detected_vlans.update(vlans)
            
            return sorted(list(detected_vlans))
            
        except Exception:
            return []
    
    def extract_vlans_from_csv(self):
        """Extract VLAN IDs from the CSV 'VLAN Range' column across all rows."""
        if not self.csv_data:
            return set()
        vlans = set()
        for device in self.csv_data:
            vlan_range = (device.get('VLAN Range', '') or '').strip()
            if not vlan_range:
                continue
            try:
                parsed = self.parse_vlan_range(vlan_range)
                vlans.update(parsed)
            except Exception:
                continue
        return vlans

    def parse_vlan_range(self, vlan_range_str):
        """Parse VLAN range string and return list of VLAN IDs"""
        vlans = []
        
        try:
            # Remove whitespace and split by common delimiters
            ranges = re.split(r'[,;]', vlan_range_str)
            
            for range_part in ranges:
                range_part = range_part.strip()
                if not range_part:
                    continue
                
                # Handle single VLAN
                if '-' not in range_part:
                    try:
                        vlan_id = int(range_part)
                        if 1 <= vlan_id <= 4094:  # Valid VLAN range
                            vlans.append(vlan_id)
                    except ValueError:
                        continue
                else:
                    # Handle VLAN range (e.g., "100-110")
                    try:
                        start_str, end_str = range_part.split('-', 1)
                        start = int(start_str.strip())
                        end = int(end_str.strip())
                        
                        if 1 <= start <= end <= 4094:
                            vlans.extend(range(start, end + 1))
                    except ValueError:
                        continue
            
            return vlans
            
        except Exception:
            return []
    
    def prompt_management_vlan(self):
        """Prompt user to configure management VLAN"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Management VLAN Configuration")
        dialog.geometry("480x340")
        dialog.transient(self.root)
        dialog.grab_set()
        # Set a sensible minimum size to avoid hidden buttons on high-DPI displays
        dialog.minsize(460, 320)
        
        # Header
        ttk.Label(dialog, text="Configure Management VLAN", 
                 font=("Arial", 12, "bold")).pack(pady=10)
        
        ttk.Label(dialog, text="Please configure the management VLAN before adding other VLANs:", 
                 font=("Arial", 9)).pack(pady=5)
        
        # Management VLAN frame
        mgmt_frame = ttk.LabelFrame(dialog, text="Management VLAN", padding=10)
        mgmt_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # VLAN ID
        ttk.Label(mgmt_frame, text="VLAN ID:").grid(row=0, column=0, sticky=tk.W, pady=5)
        mgmt_vlan_id_var = tk.StringVar(value="3005")
        ttk.Entry(mgmt_frame, textvariable=mgmt_vlan_id_var, width=15).grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        # VLAN Name
        ttk.Label(mgmt_frame, text="Name:").grid(row=1, column=0, sticky=tk.W, pady=5)
        mgmt_vlan_name_var = tk.StringVar(value="Management")
        ttk.Entry(mgmt_frame, textvariable=mgmt_vlan_name_var, width=15).grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        # I-SID
        ttk.Label(mgmt_frame, text="I-SID:").grid(row=2, column=0, sticky=tk.W, pady=5)
        mgmt_vlan_isid_var = tk.StringVar(value="1043005")
        ttk.Entry(mgmt_frame, textvariable=mgmt_vlan_isid_var, width=15).grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Auto-generate I-SID button
        ttk.Button(mgmt_frame, text="Auto-generate I-SID", 
                  command=lambda: mgmt_vlan_isid_var.set(str(1040000 + int(mgmt_vlan_id_var.get() or "3005")))).grid(row=2, column=2, padx=5, pady=5)
        
        # Buttons
        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=20)
        
        def save_management_vlan():
            try:
                vlan_id = int(mgmt_vlan_id_var.get())
                name = mgmt_vlan_name_var.get()
                i_sid = int(mgmt_vlan_isid_var.get())
                
                # Add management VLAN to base config
                if hasattr(self, 'base_vlan_tree'):
                    # Check if management VLAN already exists
                    existing = False
                    for item in self.base_vlan_tree.get_children():
                        values = self.base_vlan_tree.item(item, 'values')
                        if int(values[0]) == vlan_id:
                            existing = True
                            break
                    
                    if not existing:
                        self.base_vlan_tree.insert('', 'end', values=(vlan_id, name, i_sid))
                
                # Update management VLAN variable
                self.mgmt_vlan_var.set(str(vlan_id))
                
                # Sync to batch VLAN tree
                if hasattr(self, 'batch_vlan_tree'):
                    self.sync_base_vlans_to_batch()
                
                messagebox.showinfo("Success", f"Management VLAN {vlan_id} configured successfully")
                dialog.destroy()
                
            except ValueError:
                messagebox.showerror("Error", "Please enter valid numbers for VLAN ID and I-SID")
        
        ttk.Button(button_frame, text="Save Management VLAN", command=save_management_vlan).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Skip", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
        
        # Ensure window is large enough for all content
        dialog.update_idletasks()
        req_w = dialog.winfo_reqwidth()
        req_h = dialog.winfo_reqheight()
        cur_w = max(req_w + 20, 480)
        cur_h = max(req_h + 20, 340)
        dialog.geometry(f"{cur_w}x{cur_h}")
    
    def prompt_vlan_addition(self, detected_vlans):
        """Prompt user to add detected VLANs to base config"""
        if not detected_vlans:
            return
        
        # Create dialog for VLAN selection
        dialog = tk.Toplevel(self.root)
        dialog.title("Detected VLANs")
        dialog.geometry("500x400")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Header
        header_label = ttk.Label(dialog, text=f"Found {len(detected_vlans)} VLAN(s) in CSV data:", 
                                font=("Arial", 10, "bold"))
        header_label.pack(pady=10)
        
        # VLAN list frame
        list_frame = ttk.LabelFrame(dialog, text="Detected VLANs", padding=10)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create checkboxes for each VLAN
        if not hasattr(self, 'vlan_vars'):
            self.vlan_vars = {}
        if not hasattr(self, 'vlan_isid_vars'):
            self.vlan_isid_vars = {}
        
        canvas = tk.Canvas(list_frame)
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        for i, vlan_id in enumerate(detected_vlans):
            vlan_frame = ttk.Frame(scrollable_frame)
            vlan_frame.grid(row=i, column=0, sticky="ew", padx=5, pady=2)
            
            # Checkbox for VLAN
            var = tk.BooleanVar(value=True)  # Default to selected
            self.vlan_vars[vlan_id] = var
            
            ttk.Checkbutton(vlan_frame, text=f"VLAN {vlan_id}", variable=var).grid(row=0, column=0, sticky="w")
            
            # Name field
            ttk.Label(vlan_frame, text="Name:").grid(row=0, column=1, padx=(20, 5))
            name_var = tk.StringVar(value=f"Management_{vlan_id}" if vlan_id in [3005] else f"VLAN_{vlan_id}")
            ttk.Entry(vlan_frame, textvariable=name_var, width=15).grid(row=0, column=2, padx=5)
            
            # I-SID field
            ttk.Label(vlan_frame, text="I-SID:").grid(row=0, column=3, padx=(10, 5))
            isid_var = tk.StringVar(value=str(1040000 + vlan_id))  # Auto-generate I-SID
            isid_entry = ttk.Entry(vlan_frame, textvariable=isid_var, width=10)
            isid_entry.grid(row=0, column=4, padx=5)
            
            # Auto-generate button
            ttk.Button(vlan_frame, text="Auto", 
                      command=lambda v=vlan_id, var=isid_var: var.set(str(1040000 + v))).grid(row=0, column=5, padx=2)
            
            # Store variables
            self.vlan_isid_vars[vlan_id] = {'name': name_var, 'isid': isid_var}
        
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # I-SID generation options
        isid_frame = ttk.LabelFrame(dialog, text="I-SID Generation", padding=10)
        isid_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(isid_frame, text="Auto-generate All I-SIDs", 
                  command=self.auto_generate_all_isids).pack(side=tk.LEFT, padx=5)
        ttk.Button(isid_frame, text="Use Sequential I-SIDs (1040001, 1040002...)", 
                  command=self.use_sequential_isids).pack(side=tk.LEFT, padx=5)
        
        # Buttons
        button_frame = ttk.Frame(dialog)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        def add_selected_vlans():
            selected_vlans = []
            for vlan_id, var in self.vlan_vars.items():
                if var.get():
                    name = self.vlan_isid_vars[vlan_id]['name'].get()
                    isid = self.vlan_isid_vars[vlan_id]['isid'].get()
                    try:
                        isid_int = int(isid)
                        selected_vlans.append((vlan_id, name, isid_int))
                    except ValueError:
                        messagebox.showerror("Error", f"Invalid I-SID for VLAN {vlan_id}: {isid}")
                        return
            
            if selected_vlans:
                self.add_vlans_to_base_config(selected_vlans)
                messagebox.showinfo("Success", f"Added {len(selected_vlans)} VLAN(s) to Base Config")
            
            dialog.destroy()
        
        ttk.Button(button_frame, text="Add Selected VLANs", command=add_selected_vlans).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Skip", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
        
        # Store reference for button commands
        self.current_vlan_dialog = dialog
    
    def auto_generate_all_isids(self):
        """Auto-generate I-SIDs for all VLANs in dialog"""
        for vlan_id, vars_dict in self.vlan_isid_vars.items():
            vars_dict['isid'].set(str(1040000 + vlan_id))
    
    def use_sequential_isids(self):
        """Use sequential I-SIDs starting from 1040001"""
        isid_counter = 1040001
        for vlan_id in sorted(self.vlan_isid_vars.keys()):
            self.vlan_isid_vars[vlan_id]['isid'].set(str(isid_counter))
            isid_counter += 1
    
    def add_vlans_to_base_config(self, vlans_list):
        """Add VLANs to base configuration"""
        # Ensure base_vlan_tree exists
        if not hasattr(self, 'base_vlan_tree'):
            messagebox.showerror("Error", "Base VLAN tree not initialized. Please configure Base Config first.")
            return
            
        for vlan_id, name, isid in vlans_list:
            # Check if VLAN already exists
            existing = False
            for item in self.base_vlan_tree.get_children():
                values = self.base_vlan_tree.item(item, 'values')
                if int(values[0]) == vlan_id:
                    existing = True
                    break
            
            if not existing:
                self.base_vlan_tree.insert('', 'end', values=(vlan_id, name, isid))
    
    def refresh_switch_list(self):
        """Refresh the switch list from CSV data"""
        if not hasattr(self, 'csv_data') or not self.csv_data:
            messagebox.showwarning("Warning", "Please load CSV data first. Go to 'CSV Batch Generation' tab and load a CSV file.")
            return
        
        # Clear existing assignments
        self.vlan_assignments = {}
        self.port_configurations = {}
        self.port_config_list = {}
        
        # Populate with basic switch information
        for device in self.csv_data:
            device_name = device.get('Device', '')
            ip_address = device.get('IP-Address', '')
            
            # Initialize with empty VLANs and empty port config list
            self.vlan_assignments[device_name] = []
            self.port_config_list[device_name] = []
        
        # Update the VLAN assignment tree
        self.update_vlan_assignment_tree()
        
        messagebox.showinfo("Success", f"Loaded {len(self.csv_data)} switches. You can now assign VLANs and configure ports.")
    
    def auto_assign_vlans(self):
        """Auto-assign VLANs to switches based on detected VLANs and switch characteristics"""
        if not hasattr(self, 'csv_data') or not self.csv_data:
            messagebox.showwarning("Warning", "Please load device data first. Go to 'CSV Batch Generation' tab and load a CSV file.")
            return
        
        # Get available VLANs from base config
        available_vlans = []
        for item in self.base_vlan_tree.get_children():
            values = self.base_vlan_tree.item(item, 'values')
            available_vlans.append(int(values[0]))
        
        if not available_vlans:
            messagebox.showwarning("Warning", "No VLANs configured in Base Config. Please add VLANs in the VLAN Management section first.")
            return
        
        # Clear existing assignments
        self.vlan_assignments = {}
        
        # Auto-assign VLANs based on switch characteristics
        for device in self.csv_data:
            device_name = device.get('Device', '')
            ip_address = device.get('IP-Address', '')
            
            # Determine VLANs for this switch
            assigned_vlans = self.determine_switch_vlans(device, available_vlans)
            self.vlan_assignments[device_name] = assigned_vlans
            
            # Determine port configuration
            port_config = self.determine_port_configuration(assigned_vlans)
            self.port_configurations[device_name] = port_config
            self.port_configurations[f"{device_name}_range"] = "1/1-1/48"
        
        # Update the VLAN assignment tree
        self.update_vlan_assignment_tree()
        
        messagebox.showinfo("Success", f"Auto-assigned VLANs to {len(self.vlan_assignments)} switches")
    
    def determine_switch_vlans(self, device, available_vlans):
        """Determine which VLANs should be assigned to a specific switch"""
        assigned_vlans = []
        
        # Always include management VLAN
        mgmt_vlan = int(self.mgmt_vlan_var.get()) if self.mgmt_vlan_var.get().isdigit() else 3005
        if mgmt_vlan in available_vlans:
            assigned_vlans.append(mgmt_vlan)
        
        # Determine additional VLANs based on switch characteristics
        device_name = device.get('Device', '').upper()
        location = device.get('Location', '').upper()
        
        # Add VLANs based on naming patterns
        if 'EDGE' in device_name or 'ACCESS' in device_name:
            # Edge switches get more VLANs
            for vlan in available_vlans:
                if vlan not in assigned_vlans and vlan != mgmt_vlan:
                    assigned_vlans.append(vlan)
        elif 'CORE' in device_name or 'DIST' in device_name:
            # Core switches get all VLANs
            for vlan in available_vlans:
                if vlan not in assigned_vlans:
                    assigned_vlans.append(vlan)
        else:
            # Default: include management VLAN and a few common ones
            common_vlans = [100, 200, 300, 400, 500]  # Common VLAN IDs
            for vlan in available_vlans:
                if vlan in common_vlans and vlan not in assigned_vlans:
                    assigned_vlans.append(vlan)
        
        return sorted(assigned_vlans)
    
    def determine_port_configuration(self, vlans):
        """Determine port configuration based on VLANs"""
        if len(vlans) > 1:
            return "trunk"  # Multiple VLANs = trunk
        else:
            return "access"  # Single VLAN = access
    
    def update_vlan_assignment_tree(self):
        """Update the VLAN assignment tree view"""
        # Clear existing items
        for item in self.vlan_assignment_tree.get_children():
            self.vlan_assignment_tree.delete(item)
        
        # Check if we have CSV data
        if not hasattr(self, 'csv_data') or not self.csv_data:
            self.add_empty_message_to_vlan_tree()
            return
        
        # Add assignments
        for device in self.csv_data:
            device_name = device.get('Device', '')
            ip_address = device.get('IP-Address', '')
            
            vlans = self.vlan_assignments.get(device_name, [])
            port_configs = self.port_config_list.get(device_name, [])
            
            vlan_str = ', '.join(map(str, vlans)) if vlans else 'None'
            
            # Format port configurations for display
            if port_configs:
                port_config_str = f"{len(port_configs)} config(s): "
                port_details = []
                for i, config in enumerate(port_configs, 1):
                    port_type = config.get('type', 'auto')
                    port_range = config.get('range', '1/1-1/48')
                    config_vlans = config.get('vlans', [])
                    vlan_count = len(config_vlans)
                    port_details.append(f"{port_range} ({port_type}, {vlan_count} VLANs)")
                port_config_str += "; ".join(port_details)
            else:
                port_config_str = "No port configs"
            
            self.vlan_assignment_tree.insert('', 'end', values=(
                device_name, ip_address, vlan_str, port_config_str, "Configure"
            ))
    
    def add_empty_message_to_vlan_tree(self):
        """Add helpful message when VLAN assignment tree is empty"""
        # Clear existing items
        for item in self.vlan_assignment_tree.get_children():
            self.vlan_assignment_tree.delete(item)
        
        # Add helpful message
        self.vlan_assignment_tree.insert('', 'end', values=(
            "No switches loaded", 
            "Please load CSV data first", 
            "Go to 'CSV Batch Generation' tab", 
            "Click 'Refresh Switch List'", 
            "after loading CSV"
        ))
    
    def clear_vlan_assignments(self):
        """Clear all VLAN assignments"""
        self.vlan_assignments = {}
        self.port_configurations = {}
        self.update_vlan_assignment_tree()
        messagebox.showinfo("Success", "Cleared all VLAN assignments")
    
    def apply_vlan_assignments(self):
        """Apply VLAN assignments to selected switches"""
        selection = self.vlan_assignment_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select switches to configure")
            return
        
        selected_devices = []
        for item in selection:
            values = self.vlan_assignment_tree.item(item, 'values')
            device_name = values[0]
            selected_devices.append(device_name)
        
        # Generate configurations for selected devices
        configs_generated = 0
        output_dir = self.output_dir_var.get()
        
        if not output_dir:
            messagebox.showerror("Error", "Please select an output directory first")
            return
        
        for device_name in selected_devices:
            try:
                # Find device data
                device_data = None
                for device in self.csv_data:
                    if device.get('Device', '') == device_name:
                        device_data = device
                        break
                
                if device_data:
                    # Generate configuration with VLAN and port config
                    print(f"DEBUG: Exporting config for {device_name}")
                    config = self.generate_device_config(device_data)
                    if config:
                        # Save configuration to file
                        sys_name = device_data.get('sys-name', device_name)
                        filename = f"{sys_name}_config.txt"
                        filepath = os.path.join(output_dir, filename)
                        
                        print(f"DEBUG: Saving config to {filepath}")
                        with open(filepath, 'w', encoding='utf-8') as f:
                            f.write(config)
                        
                        configs_generated += 1
                        print(f"DEBUG: Successfully saved config for {device_name}")
                    else:
                        print(f"DEBUG: No config generated for {device_name}")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to generate config for {device_name}: {str(e)}")
        
        if configs_generated > 0:
            messagebox.showinfo("Success", f"Generated and saved configurations for {configs_generated} switches to {output_dir}")
        else:
            messagebox.showwarning("Warning", "No configurations were generated. Please check VLAN and port assignments.")
    
    def generate_enhanced_device_config(self, device_dict):
        """Generate configuration with VLAN and port configuration"""
        try:
            # Get base configuration
            base_config = self.generate_device_config(device_dict)
            if not base_config:
                return None
            
            # Add VLAN and port configuration
            device_name = device_dict.get('Device', '')
            vlans = self.vlan_assignments.get(device_name, [])
            port_config = self.port_configurations.get(device_name, 'auto')
            
            # Generate VLAN configuration commands
            vlan_commands = self.generate_vlan_commands(vlans)
            
            # Generate port configuration commands
            port_range = self.port_configurations.get(f"{device_name}_range", "1/1-1/48")
            default_vlan = self.port_configurations.get(f"{device_name}_default_vlan", None)
            port_commands = self.generate_port_commands(port_config, vlans, port_range, default_vlan)
            
            # Combine configurations
            enhanced_config = base_config + "\n\n" + vlan_commands + "\n" + port_commands
            
            return enhanced_config
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate enhanced config: {str(e)}")
            return None
    
    def generate_vlan_commands(self, vlans):
        """Generate VLAN configuration commands"""
        commands = []
        
        if not vlans:
            return ""
        
        commands.append("# VLAN CONFIGURATION")
        commands.append("")
        
        # Get VLAN details from base config
        vlan_details = {}
        for item in self.base_vlan_tree.get_children():
            values = self.base_vlan_tree.item(item, 'values')
            vlan_id = int(values[0])
            vlan_name = values[1]
            i_sid = int(values[2])
            vlan_details[vlan_id] = {'name': vlan_name, 'i_sid': i_sid}
        
        for vlan_id in vlans:
            if vlan_id in vlan_details:
                vlan_info = vlan_details[vlan_id]
                commands.append(f"vlan create {vlan_id} name \"{vlan_info['name']}\" type port-mstprstp 0")
                commands.append(f"vlan i-sid {vlan_id} {vlan_info['i_sid']}")
                commands.append("")
        
        return "\n".join(commands)
    
    def generate_port_commands(self, port_config, vlans, port_range="1/1-1/48", default_vlan=None):
        """Generate port configuration commands based on running config pattern"""
        commands = []
        
        if not vlans:
            return ""
        
        commands.append("# PORT CONFIGURATION")
        commands.append("")
        
        # Use provided default VLAN or first VLAN as fallback
        if default_vlan is None:
            default_vlan = vlans[0] if vlans else None
        
        if port_config == "trunk":
            commands.append(f"interface GigabitEthernet {port_range}")
            commands.append("untag-port-default-vlan enable")
            commands.append(f"default-vlan-id {default_vlan}")
            commands.append("no shutdown")
            commands.append("exit")
            
            for vlan_id in vlans:
                if vlan_id != default_vlan:
                    commands.append(f"vlan members add {vlan_id} {port_range}")
            
            
        else:
            for vlan_id in vlans:
                    # remove vlan 1 if exists
                    commands.append(f"vlan members remove 1 {port_range}")
                    commands.append(f"vlan members add {vlan_id} {port_range}")            
        
        return "\n".join(commands)
    
    def add_vlan_to_batch(self):
        """Add VLAN to batch VLAN management"""
        self.batch_vlan_dialog()
    
    def edit_vlan_in_batch(self):
        """Edit VLAN in batch VLAN management"""
        selection = self.batch_vlan_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a VLAN to edit")
            return
        
        item = selection[0]
        values = self.batch_vlan_tree.item(item, 'values')
        self.batch_vlan_dialog(values, item)
    
    def remove_vlan_from_batch(self):
        """Remove VLAN from batch VLAN management"""
        selection = self.batch_vlan_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a VLAN to remove")
            return
        
        if messagebox.askyesno("Confirm", "Remove selected VLAN?"):
            self.batch_vlan_tree.delete(selection[0])
            self.sync_batch_vlans_to_base()
    
    def load_vlan_template_batch(self):
        """Load VLAN template for batch configuration"""
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
                for item in self.batch_vlan_tree.get_children():
                    self.batch_vlan_tree.delete(item)
                
                # Add template VLANs
                for vlan_id, name, i_sid in templates[selected]:
                    self.batch_vlan_tree.insert('', 'end', values=(vlan_id, name, i_sid))
                
                # Sync to base config
                self.sync_batch_vlans_to_base()
                template_dialog.destroy()
        
        button_frame = ttk.Frame(template_dialog)
        button_frame.pack(pady=20)
        ttk.Button(button_frame, text="Apply Template", command=apply_template).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=template_dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def auto_generate_isids_batch(self):
        """Auto-generate I-SIDs for all VLANs in batch management"""
        for item in self.batch_vlan_tree.get_children():
            values = list(self.batch_vlan_tree.item(item, 'values'))
            vlan_id = int(values[0])
            # Generate I-SID as 1040000 + VLAN ID
            values[2] = 1040000 + vlan_id
            self.batch_vlan_tree.item(item, values=values)
        
        # Sync to base config
        self.sync_batch_vlans_to_base()
        messagebox.showinfo("Success", "Auto-generated I-SIDs for all VLANs")
    
    def batch_vlan_dialog(self, existing_values=None, item=None):
        """VLAN configuration dialog for batch management"""
        dialog = tk.Toplevel(self.root)
        dialog.title("VLAN Configuration")
        dialog.geometry("300x200")
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
        
        # Auto-generate button
        ttk.Button(dialog, text="Auto-generate I-SID", 
                  command=lambda: self.auto_generate_single_isid(vlan_id_var, isid_var)).grid(row=3, column=0, columnspan=2, pady=10)
        
        def save_vlan():
            try:
                vlan_id = int(vlan_id_var.get())
                name = name_var.get()
                i_sid = int(isid_var.get())
                
                if existing_values:
                    # Update existing
                    self.batch_vlan_tree.item(item, values=(vlan_id, name, i_sid))
                else:
                    # Add new
                    self.batch_vlan_tree.insert('', 'end', values=(vlan_id, name, i_sid))
                
                # Sync to base config
                self.sync_batch_vlans_to_base()
                dialog.destroy()
            except ValueError:
                messagebox.showerror("Error", "VLAN ID and I-SID must be numbers")
        
        button_frame = ttk.Frame(dialog)
        button_frame.grid(row=4, column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="Save", command=save_vlan).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def auto_generate_single_isid(self, vlan_id_var, isid_var):
        """Auto-generate I-SID for single VLAN"""
        try:
            vlan_id = int(vlan_id_var.get())
            isid = 1040000 + vlan_id
            isid_var.set(str(isid))
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid VLAN ID first")
    
    def sync_batch_vlans_to_base(self):
        """Sync VLANs from batch management to base config"""
        if not hasattr(self, 'base_vlan_tree'):
            return
        
        # Clear base VLAN tree
        for item in self.base_vlan_tree.get_children():
            self.base_vlan_tree.delete(item)
        
        # Add VLANs from batch management
        for item in self.batch_vlan_tree.get_children():
            values = self.batch_vlan_tree.item(item, 'values')
            vlan_id = int(values[0])
            name = values[1]
            i_sid = int(values[2])
            self.base_vlan_tree.insert('', 'end', values=(vlan_id, name, i_sid))
    
    def sync_base_vlans_to_batch(self):
        """Sync VLANs from base config to batch management"""
        if not hasattr(self, 'base_vlan_tree'):
            return
        
        # Clear batch VLAN tree
        for item in self.batch_vlan_tree.get_children():
            self.batch_vlan_tree.delete(item)
        
        # Add VLANs from base config
        for item in self.base_vlan_tree.get_children():
            values = self.base_vlan_tree.item(item, 'values')
            self.batch_vlan_tree.insert('', 'end', values=values)
    
    def edit_switch_port_config(self):
        """Edit port configuration for selected switch"""
        selection = self.vlan_assignment_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a switch to configure")
            return
        
        item = selection[0]
        values = self.vlan_assignment_tree.item(item, 'values')
        device_name = values[0]
        ip_address = values[1]
        
        # Create multi-port configuration dialog
        dialog = tk.Toplevel(self.root)
        dialog.title(f"Multi-Port Configuration - {device_name}")
        dialog.geometry("700x600")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Header
        ttk.Label(dialog, text=f"Configure Multiple Port Ranges for {device_name}", 
                 font=("Arial", 12, "bold")).pack(pady=10)
        ttk.Label(dialog, text=f"IP Address: {ip_address}", 
                 font=("Arial", 9)).pack(pady=5)
        
        # Main content frame
        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Left panel - Port configurations list
        left_frame = ttk.LabelFrame(main_frame, text="Current Port Configurations", padding=10)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        # Port configurations tree
        port_tree_frame = ttk.Frame(left_frame)
        port_tree_frame.pack(fill=tk.BOTH, expand=True)
        
        port_columns = ("Port Range", "Type", "VLANs", "Default VLAN")
        self.port_config_tree = ttk.Treeview(port_tree_frame, columns=port_columns, show='headings', height=8)
        
        for col in port_columns:
            self.port_config_tree.heading(col, text=col)
            self.port_config_tree.column(col, width=120)
        
        port_tree_scrollbar = ttk.Scrollbar(port_tree_frame, orient=tk.VERTICAL, command=self.port_config_tree.yview)
        self.port_config_tree.configure(yscrollcommand=port_tree_scrollbar.set)
        
        self.port_config_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        port_tree_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Port config buttons
        port_buttons_frame = ttk.Frame(left_frame)
        port_buttons_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(port_buttons_frame, text="Add Port Config", 
                  command=lambda: self.add_port_config_dialog(device_name)).pack(side=tk.LEFT, padx=2)
        ttk.Button(port_buttons_frame, text="Edit Selected", 
                  command=lambda: self.edit_port_config_dialog(device_name)).pack(side=tk.LEFT, padx=2)
        ttk.Button(port_buttons_frame, text="Remove Selected", 
                  command=lambda: self.remove_port_config(device_name)).pack(side=tk.LEFT, padx=2)
        
        # Right panel - VLAN assignment
        right_frame = ttk.LabelFrame(main_frame, text="VLAN Assignment", padding=10)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Get available VLANs
        available_vlans = []
        for item in self.base_vlan_tree.get_children():
            values = self.base_vlan_tree.item(item, 'values')
            available_vlans.append((int(values[0]), values[1]))
        
        # Create VLAN checkboxes
        vlan_vars = {}
        for vlan_id, vlan_name in available_vlans:
            var = tk.BooleanVar()
            vlan_vars[vlan_id] = var
            
            vlan_item_frame = ttk.Frame(right_frame)
            vlan_item_frame.pack(fill=tk.X, pady=2)
            
            ttk.Checkbutton(vlan_item_frame, text=f"VLAN {vlan_id} - {vlan_name}", 
                           variable=var).pack(side=tk.LEFT)
        
        # Buttons
        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=20)
        
        def save_all_configs():
            try:
                # Get selected VLANs for the switch
                selected_vlans = [vlan_id for vlan_id, var in vlan_vars.items() if var.get()]
                self.vlan_assignments[device_name] = selected_vlans
                print(f"DEBUG: Set VLAN assignments for {device_name}: {selected_vlans}")
                
                # Update tree
                self.update_vlan_assignment_tree()
                
                messagebox.showinfo("Success", f"Port configurations updated for {device_name}")
                dialog.destroy()
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save configuration: {str(e)}")
        
        def refresh_port_tree():
            # Clear existing items
            for item in self.port_config_tree.get_children():
                self.port_config_tree.delete(item)
            
            # Add current port configurations
            port_configs = self.port_config_list.get(device_name, [])
            for config in port_configs:
                vlans = config.get('vlans', [])
                vlan_str = ', '.join(map(str, vlans)) if vlans else 'None'
                default_vlan = config.get('default_vlan', '')
                
                self.port_config_tree.insert('', 'end', values=(
                    config.get('range', ''),
                    config.get('type', ''),
                    vlan_str,
                    str(default_vlan) if default_vlan else ''
                ))
        
        # Store the refresh function for use by child dialogs
        self.refresh_port_config_tree = lambda dev_name: refresh_port_tree()
        
        # Initialize port tree
        refresh_port_tree()
        
        ttk.Button(button_frame, text="Save All Configurations", command=save_all_configs).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def add_port_config_dialog(self, device_name):
        """Add a new port configuration for a device"""
        dialog = tk.Toplevel(self.root)
        dialog.title(f"Add Port Configuration - {device_name}")
        dialog.geometry("400x300")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Port range
        ttk.Label(dialog, text="Port Range:").pack(anchor=tk.W, padx=10, pady=5)
        port_range_var = tk.StringVar(value="1/1-1/12")
        ttk.Entry(dialog, textvariable=port_range_var, width=20).pack(anchor=tk.W, padx=10, pady=5)
        
        # Port type
        ttk.Label(dialog, text="Port Type:").pack(anchor=tk.W, padx=10, pady=5)
        port_type_var = tk.StringVar(value="trunk")
        port_type_frame = ttk.Frame(dialog)
        port_type_frame.pack(anchor=tk.W, padx=10, pady=5)
        
        ttk.Radiobutton(port_type_frame, text="Trunk", variable=port_type_var, value="trunk").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(port_type_frame, text="Access", variable=port_type_var, value="access").pack(side=tk.LEFT, padx=5)
        # ttk.Radiobutton(port_type_frame, text="Auto", variable=port_type_var, value="auto").pack(side=tk.LEFT, padx=5)
        
        # VLAN selection
        ttk.Label(dialog, text="Select VLANs for this port range:").pack(anchor=tk.W, padx=10, pady=(10, 5))
        
        vlan_frame = ttk.Frame(dialog)
        vlan_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Get available VLANs
        available_vlans = []
        for item in self.base_vlan_tree.get_children():
            values = self.base_vlan_tree.item(item, 'values')
            available_vlans.append((int(values[0]), values[1]))
        
        vlan_vars = {}
        default_vlan_var = tk.StringVar()
        vlan_checkboxes = {}  # Store references to VLAN selection checkboxes for enabling/disabling
        default_selection_vars = {}  # Store BooleanVars for default selection per VLAN
        default_checkbuttons = {}  # Store references to default selection checkbuttons
        
        def update_vlan_restrictions():
            """Update VLAN checkbox and radio button states based on port type and current selections"""
            port_type = port_type_var.get()
            selected_vlans = [vlan_id for vlan_id, var in vlan_vars.items() if var.get()]
            
            if port_type == "access":
                # For access ports, only allow one VLAN
                if len(selected_vlans) >= 1:
                    # Disable all other VLAN checkboxes
                    for vlan_id, checkbox in vlan_checkboxes.items():
                        if vlan_id not in selected_vlans:
                            checkbox.config(state='disabled')
                else:
                    # Enable all VLAN checkboxes if none selected
                    for checkbox in vlan_checkboxes.values():
                        checkbox.config(state='normal')
            else:
                # For trunk/auto ports, allow multiple VLANs
                for checkbox in vlan_checkboxes.values():
                    checkbox.config(state='normal')
            
            # Update default checkbox states - enable for selected VLANs, disable for unselected
            for vlan_id, var in vlan_vars.items():
                if vlan_id in default_checkbuttons:
                    if var.get():
                        default_checkbuttons[vlan_id].config(state='normal')
                    else:
                        # If disabling and this VLAN is currently default, clear it
                        if default_selection_vars.get(vlan_id) and default_selection_vars[vlan_id].get():
                            default_selection_vars[vlan_id].set(False)
                            if default_vlan_var.get() == str(vlan_id):
                                default_vlan_var.set("")
                        default_checkbuttons[vlan_id].config(state='disabled')
        
        # Trace port type changes
        port_type_var.trace('w', lambda *args: update_vlan_restrictions())
        
        for vlan_id, vlan_name in available_vlans:
            var = tk.BooleanVar()
            vlan_vars[vlan_id] = var
            
            vlan_item_frame = ttk.Frame(vlan_frame)
            vlan_item_frame.pack(fill=tk.X, pady=2)
            
            checkbox = ttk.Checkbutton(vlan_item_frame, text=f"VLAN {vlan_id} - {vlan_name}", 
                           variable=var)
            checkbox.pack(side=tk.LEFT)
            vlan_checkboxes[vlan_id] = checkbox
            
            # Default VLAN checkbox (single-select behavior enforced)
            def create_default_checkbox(vid, frame, vlan_var):
                default_var = tk.BooleanVar(value=False)
                
                def on_toggle():
                    if default_var.get():
                        # Uncheck all other default checkboxes
                        for other_id, other_var in default_selection_vars.items():
                            if other_id != vid and other_var.get():
                                other_var.set(False)
                        default_vlan_var.set(str(vid))
                    else:
                        if default_vlan_var.get() == str(vid):
                            default_vlan_var.set("")
                
                # Keep default selection in sync with VLAN selection
                def on_vlan_select_change(*_):
                    if not vlan_var.get():
                        # If VLAN deselected, also clear default for this VLAN
                        if default_var.get():
                            default_var.set(False)
                        if default_vlan_var.get() == str(vid):
                            default_vlan_var.set("")
                
                vlan_var.trace('w', on_vlan_select_change)
                btn = ttk.Checkbutton(frame, text="Default", variable=default_var, command=on_toggle)
                default_selection_vars[vid] = default_var
                return btn
            
            default_chk = create_default_checkbox(vlan_id, vlan_item_frame, var)
            default_chk.pack(side=tk.LEFT, padx=(20, 0))
            default_checkbuttons[vlan_id] = default_chk  # Store reference for enabling/disabling
            
            if not var.get():
                default_chk.config(state='disabled')
            
        # Trace VLAN selection changes for access port restrictions (apply to all)
        for _vid, _v in vlan_vars.items():
            _v.trace('w', lambda *args: update_vlan_restrictions())
        
        # Apply initial restrictions based on current port type
        update_vlan_restrictions()
        
        # Buttons
        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=10)
        
        def save_port_config():
            try:
                port_range = port_range_var.get()
                port_type = port_type_var.get()
                
                # Get selected VLANs
                selected_vlans = [vlan_id for vlan_id, var in vlan_vars.items() if var.get()]
                
                # Validate access port restrictions
                if port_type == "access" and len(selected_vlans) > 1:
                    messagebox.showerror("Error", "Access ports can only have one VLAN selected. Please select only one VLAN or change the port type to Trunk.")
                    return
                
                if not selected_vlans:
                    messagebox.showerror("Error", "Please select at least one VLAN for this port configuration.")
                    return
                
                # Get default VLAN
                default_vlan = default_vlan_var.get()
                if default_vlan and default_vlan.isdigit():
                    default_vlan = int(default_vlan)
                else:
                    default_vlan = selected_vlans[0] if selected_vlans else None
                
                # Add to port config list
                if device_name not in self.port_config_list:
                    self.port_config_list[device_name] = []
                
                new_config = {
                    'range': port_range,
                    'type': port_type,
                    'vlans': selected_vlans,
                    'default_vlan': default_vlan
                }
                
                self.port_config_list[device_name].append(new_config)
                print(f"DEBUG: Added port config for {device_name}: {new_config}")
                print(f"DEBUG: Total port configs for {device_name}: {len(self.port_config_list[device_name])}")
                
                # Refresh the port configuration tree in the parent dialog
                if hasattr(self, 'port_config_tree'):
                    self.refresh_port_config_tree(device_name)
                
                messagebox.showinfo("Success", f"Port configuration added for {port_range}")
                dialog.destroy()
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save port configuration: {str(e)}")
        
        ttk.Button(button_frame, text="Add Configuration", command=save_port_config).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def edit_port_config_dialog(self, device_name):
        """Edit selected port configuration"""
        selection = self.port_config_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a port configuration to edit")
            return
        
        # Get the selected configuration
        item = selection[0]
        values = self.port_config_tree.item(item, 'values')
        port_range = values[0]
        
        # Find the configuration in the list
        port_configs = self.port_config_list.get(device_name, [])
        config_to_edit = None
        config_index = -1
        
        for i, config in enumerate(port_configs):
            if config.get('range') == port_range:
                config_to_edit = config
                config_index = i
                break
        
        if not config_to_edit:
            messagebox.showerror("Error", "Port configuration not found")
            return
        
        # Create edit dialog (similar to add dialog but pre-filled)
        dialog = tk.Toplevel(self.root)
        dialog.title(f"Edit Port Configuration - {device_name}")
        dialog.geometry("400x300")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Port range
        ttk.Label(dialog, text="Port Range:").pack(anchor=tk.W, padx=10, pady=5)
        port_range_var = tk.StringVar(value=config_to_edit.get('range', ''))
        ttk.Entry(dialog, textvariable=port_range_var, width=20).pack(anchor=tk.W, padx=10, pady=5)
        
        # Port type
        ttk.Label(dialog, text="Port Type:").pack(anchor=tk.W, padx=10, pady=5)
        port_type_var = tk.StringVar(value=config_to_edit.get('type', 'trunk'))
        port_type_frame = ttk.Frame(dialog)
        port_type_frame.pack(anchor=tk.W, padx=10, pady=5)
        
        ttk.Radiobutton(port_type_frame, text="Trunk", variable=port_type_var, value="trunk").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(port_type_frame, text="Access", variable=port_type_var, value="access").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(port_type_frame, text="Auto", variable=port_type_var, value="auto").pack(side=tk.LEFT, padx=5)
        
        # VLAN selection
        ttk.Label(dialog, text="Select VLANs for this port range:").pack(anchor=tk.W, padx=10, pady=(10, 5))
        
        vlan_frame = ttk.Frame(dialog)
        vlan_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Get available VLANs
        available_vlans = []
        for item in self.base_vlan_tree.get_children():
            values = self.base_vlan_tree.item(item, 'values')
            available_vlans.append((int(values[0]), values[1]))
        
        vlan_vars = {}
        default_vlan_var = tk.StringVar()
        vlan_checkboxes = {}  # Store references to VLAN selection checkboxes for enabling/disabling
        default_selection_vars = {}  # Store BooleanVars for default selection per VLAN
        default_checkbuttons = {}  # Store references to default selection checkbuttons
        current_vlans = config_to_edit.get('vlans', [])
        current_default = config_to_edit.get('default_vlan', '')
        
        def update_vlan_restrictions():
            """Update VLAN checkbox and radio button states based on port type and current selections"""
            port_type = port_type_var.get()
            selected_vlans = [vlan_id for vlan_id, var in vlan_vars.items() if var.get()]
            
            if port_type == "access":
                # For access ports, only allow one VLAN
                if len(selected_vlans) >= 1:
                    # Disable all other VLAN checkboxes
                    for vlan_id, checkbox in vlan_checkboxes.items():
                        if vlan_id not in selected_vlans:
                            checkbox.config(state='disabled')
                else:
                    # Enable all VLAN checkboxes if none selected
                    for checkbox in vlan_checkboxes.values():
                        checkbox.config(state='normal')
            else:
                # For trunk/auto ports, allow multiple VLANs
                for checkbox in vlan_checkboxes.values():
                    checkbox.config(state='normal')
            
            # Update default checkbox states - enable for selected VLANs, disable for unselected
            for vlan_id, var in vlan_vars.items():
                if vlan_id in default_checkbuttons:
                    if var.get():
                        default_checkbuttons[vlan_id].config(state='normal')
                    else:
                        # If disabling and this VLAN is currently default, clear it
                        if default_selection_vars.get(vlan_id) and default_selection_vars[vlan_id].get():
                            default_selection_vars[vlan_id].set(False)
                            if default_vlan_var.get() == str(vlan_id):
                                default_vlan_var.set("")
                        default_checkbuttons[vlan_id].config(state='disabled')
        
        # Trace port type changes
        port_type_var.trace('w', lambda *args: update_vlan_restrictions())
        
        for vlan_id, vlan_name in available_vlans:
            var = tk.BooleanVar(value=vlan_id in current_vlans)
            vlan_vars[vlan_id] = var
            
            vlan_item_frame = ttk.Frame(vlan_frame)
            vlan_item_frame.pack(fill=tk.X, pady=2)
            
            checkbox = ttk.Checkbutton(vlan_item_frame, text=f"VLAN {vlan_id} - {vlan_name}", 
                           variable=var)
            checkbox.pack(side=tk.LEFT)
            vlan_checkboxes[vlan_id] = checkbox
            
            # Default VLAN checkbox (single-select behavior enforced)
            def create_default_checkbox(vid, frame, vlan_var):
                default_var = tk.BooleanVar(value=(vid == current_default))
                
                def on_toggle():
                    if default_var.get():
                        # Uncheck all other default checkboxes
                        for other_id, other_var in default_selection_vars.items():
                            if other_id != vid and other_var.get():
                                other_var.set(False)
                        default_vlan_var.set(str(vid))
                    else:
                        if default_vlan_var.get() == str(vid):
                            default_vlan_var.set("")
                
                # Keep default selection in sync with VLAN selection
                def on_vlan_select_change(*_):
                    if not vlan_var.get():
                        # If VLAN deselected, also clear default for this VLAN
                        if default_var.get():
                            default_var.set(False)
                        if default_vlan_var.get() == str(vid):
                            default_vlan_var.set("")
                
                vlan_var.trace('w', on_vlan_select_change)
                btn = ttk.Checkbutton(frame, text="Default", variable=default_var, command=on_toggle)
                default_selection_vars[vid] = default_var
                return btn
            
            default_chk = create_default_checkbox(vlan_id, vlan_item_frame, var)
            default_chk.pack(side=tk.LEFT, padx=(20, 0))
            default_checkbuttons[vlan_id] = default_chk  # Store reference for enabling/disabling
            
            if not var.get():
                default_chk.config(state='disabled')
            
            # Trace VLAN selection changes for access port restrictions
            var.trace('w', lambda *args: update_vlan_restrictions())
        
        # Set current default VLAN (sync with checkbox state)
        if current_default:
            default_vlan_var.set(str(current_default))
        
        # Apply initial restrictions based on current port type
        update_vlan_restrictions()
        
        # Buttons
        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=10)
        
        def save_port_config():
            try:
                port_range = port_range_var.get()
                port_type = port_type_var.get()
                
                # Get selected VLANs
                selected_vlans = [vlan_id for vlan_id, var in vlan_vars.items() if var.get()]
                
                # Validate access port restrictions
                if port_type == "access" and len(selected_vlans) > 1:
                    messagebox.showerror("Error", "Access ports can only have one VLAN selected. Please select only one VLAN or change the port type to Trunk.")
                    return
                
                if not selected_vlans:
                    messagebox.showerror("Error", "Please select at least one VLAN for this port configuration.")
                    return
                
                # Get default VLAN
                default_vlan = default_vlan_var.get()
                if default_vlan and default_vlan.isdigit():
                    default_vlan = int(default_vlan)
                else:
                    default_vlan = selected_vlans[0] if selected_vlans else None
                
                # Update the configuration
                updated_config = {
                    'range': port_range,
                    'type': port_type,
                    'vlans': selected_vlans,
                    'default_vlan': default_vlan
                }
                
                self.port_config_list[device_name][config_index] = updated_config
                
                # Refresh the port configuration tree in the parent dialog
                if hasattr(self, 'port_config_tree'):
                    self.refresh_port_config_tree(device_name)
                
                messagebox.showinfo("Success", f"Port configuration updated for {port_range}")
                dialog.destroy()
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save port configuration: {str(e)}")
        
        ttk.Button(button_frame, text="Update Configuration", command=save_port_config).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def remove_port_config(self, device_name):
        """Remove selected port configuration"""
        selection = self.port_config_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a port configuration to remove")
            return
        
        if messagebox.askyesno("Confirm", "Remove selected port configuration?"):
            item = selection[0]
            values = self.port_config_tree.item(item, 'values')
            port_range = values[0]
            
            # Remove from port config list
            port_configs = self.port_config_list.get(device_name, [])
            self.port_config_list[device_name] = [config for config in port_configs if config.get('range') != port_range]
            
            # Refresh the port configuration tree in the parent dialog
            if hasattr(self, 'port_config_tree'):
                self.refresh_port_config_tree(device_name)
            
            messagebox.showinfo("Success", f"Port configuration removed for {port_range}")
    
    def preview_device_config(self):
        """Preview configuration for selected device"""
        selection = self.csv_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a device to preview")
            return
        
        # Get device data
        item = selection[0]
        values = self.csv_tree.item(item, 'values')
        device_dict = {
            'IP-Address': values[0],
            'Device': values[1],
            'Location': values[2],
            'Nick-name': values[3],
            'sys-id': values[4],
            'sys-name': values[5],
            'Notes': values[6],
            'VLAN Range': values[7]
        }
        
        # Store current device
        self.current_preview_device = device_dict
        
        # Generate configuration
        try:
            config_content = self.generate_device_config(device_dict)
            if config_content:
                # Update preview tab
                self.preview_device_label.config(text=f"Device: {device_dict['Device']} ({device_dict['IP-Address']})")
                self.preview_text.delete(1.0, tk.END)
                self.preview_text.insert(1.0, config_content)
                
                # Switch to preview tab
                # Find the batch notebook and switch to preview tab
                batch_notebook = self.preview_text.master.master.master  # Navigate up to batch notebook
                if hasattr(batch_notebook, 'select'):
                    batch_notebook.select(2)  # Preview tab is index 2
                    
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate preview: {str(e)}")
    
    def generate_device_config(self, device_dict):
        """Generate configuration for a specific device"""
        try:
            device_name = device_dict.get('Device', '')
            print(f"DEBUG: Generating config for device: {device_name}")
            print(f"DEBUG: Has vlan_assignments: {hasattr(self, 'vlan_assignments')}")
            print(f"DEBUG: Has port_config_list: {hasattr(self, 'port_config_list')}")
            if hasattr(self, 'vlan_assignments'):
                print(f"DEBUG: vlan_assignments keys: {list(self.vlan_assignments.keys())}")
            if hasattr(self, 'port_config_list'):
                print(f"DEBUG: port_config_list keys: {list(self.port_config_list.keys())}")
            
            # Get template content based on source
            if self.template_source_var.get() == "base_config":
                # Use base config as template
                template_content = self.generate_base_config_template()
                if not template_content:
                    messagebox.showerror("Error", "Please configure the Base Config tab first")
                    return None
                
                # Apply substitutions for base config templates
                config_content = template_content
                config_content = config_content.replace('$sys-name$', device_dict.get('sys-name', ''))
                config_content = config_content.replace('$ip-address$', device_dict.get('IP-Address', ''))
                config_content = config_content.replace('$location$', device_dict.get('Location', ''))
                config_content = config_content.replace('$nick-name$', device_dict.get('Nick-name', ''))
                config_content = config_content.replace('$sys-id$', device_dict.get('sys-id', ''))
                
            else:
                # Use template file
                template_file = self.template_file_var.get()
                if not template_file or not os.path.isfile(template_file):
                    messagebox.showerror("Error", "Please select a valid template file")
                    return None
                
                with open(template_file, 'r', encoding='utf-8') as file:
                    template_content = file.read()
                
                # Apply substitutions for file templates (PowerShell script format)
                substitutions = {
                    '\\$sys-name\\$': device_dict.get('sys-name', ''),
                    '\\$ip-address\\$': device_dict.get('IP-Address', ''),
                    '\\$location\\$': device_dict.get('Location', ''),
                    '\\$nick-name\\$': device_dict.get('Nick-name', ''),
                    '\\$sys-id\\$': device_dict.get('sys-id', '')
                }
                
                config_content = template_content
                for pattern, replacement in substitutions.items():
                    config_content = re.sub(pattern, replacement, config_content)
            
            # Check if we should add port configuration
            device_name = device_dict.get('Device', '')
            print(f"DEBUG: Checking port config for device: {device_name}")
            
            # Check if we have port configurations for this device
            has_port_configs = (hasattr(self, 'port_config_list') and 
                              device_name in self.port_config_list and 
                              len(self.port_config_list.get(device_name, [])) > 0)
            
            print(f"DEBUG: Has port configs: {has_port_configs}")
            
            if has_port_configs:
                # Get VLAN and port configurations for this device
                vlans = self.vlan_assignments.get(device_name, []) if hasattr(self, 'vlan_assignments') else []
                port_configs = self.port_config_list.get(device_name, [])
                
                # Debug: Print what we found
                print(f"DEBUG: Device {device_name} - VLANs: {vlans}, Port Configs: {len(port_configs)}")
                
                if port_configs:  # Only add port config if port configs are assigned
                    print(f"DEBUG: Processing {len(port_configs)} port configurations")
                    
                    # Check if VLAN commands already exist in the config
                    vlan_commands = ""
                    if "vlan create" not in config_content:
                        # Generate VLAN configuration commands (use VLANs from port configs if no global VLANs)
                        if vlans:
                            vlan_commands = self.generate_vlan_commands(vlans)
                        else:
                            # Get VLANs from port configurations
                            all_vlans = set()
                            for port_config in port_configs:
                                all_vlans.update(port_config.get('vlans', []))
                            vlan_commands = self.generate_vlan_commands(list(all_vlans))
                        print(f"DEBUG: Adding VLAN commands (not found in base config)")
                    else:
                        print(f"DEBUG: VLAN commands already exist in base config, skipping VLAN creation")
                    
                    # Generate port configuration commands for all port configs
                    all_port_commands = []
                    for i, port_config in enumerate(port_configs):
                        print(f"DEBUG: Processing port config {i+1}: {port_config}")
                        port_range = port_config.get('range', '1/1-1/48')
                        port_type = port_config.get('type', 'auto')
                        config_vlans = port_config.get('vlans', [])
                        default_vlan = port_config.get('default_vlan', None)
                        
                        print(f"DEBUG: Port range: {port_range}, type: {port_type}, vlans: {config_vlans}, default: {default_vlan}")
                        
                        if config_vlans:  # Only generate commands if VLANs are assigned to this port range
                            port_commands = self.generate_port_commands(port_type, config_vlans, port_range, default_vlan)
                            all_port_commands.append(port_commands)
                            print(f"DEBUG: Generated port commands:\n{port_commands}")
                        else:
                            print(f"DEBUG: No VLANs assigned to port range {port_range}, skipping")
                    
                    # Combine all port commands
                    combined_port_commands = "\n\n".join(all_port_commands) if all_port_commands else ""
                    
                    # Debug: Print what we're about to insert
                    print(f"DEBUG: VLAN Commands:\n{vlan_commands}")
                    print(f"DEBUG: Port Commands:\n{combined_port_commands}")
                    
                    # Debug: Show a sample of the config content to check TFTP section
                    print(f"DEBUG: Config content sample (last 500 chars):\n{config_content[-500:]}")
                    
                    # Only insert if we have commands to insert
                    if vlan_commands or combined_port_commands:
                        # Insert port configuration after "Disable TFTP Server" section
                        # Try multiple TFTP section formats
                        tftp_patterns = [
                            "# Disable TFTP Server\nno boot config flags tftpd",
                            "# Disable TFTP Server\nno boot config flags tftpd\n",
                            "no boot config flags tftpd"
                        ]
                        
                        inserted = False
                        for tftp_pattern in tftp_patterns:
                            if tftp_pattern in config_content:
                                print(f"DEBUG: Found TFTP pattern: {repr(tftp_pattern)}")
                                # Insert VLAN and port configuration before the TFTP section
                                enhanced_section = f"\n{vlan_commands}\n{combined_port_commands}\n\n{tftp_pattern}"
                                config_content = config_content.replace(tftp_pattern, enhanced_section)
                                inserted = True
                                break
                        
                        if not inserted:
                            print("DEBUG: TFTP section not found, using fallback insertion")
                        
                        if not inserted:
                            # If TFTP section not found, append at the end before "wr mem"
                            if "wr mem" in config_content:
                                enhanced_section = f"\n{vlan_commands}\n{combined_port_commands}\n\n"
                                config_content = config_content.replace("wr mem", f"{enhanced_section}wr mem")
                            else:
                                # Fallback: append at the end
                                config_content += f"\n\n{vlan_commands}\n{combined_port_commands}"
                    else:
                        print("DEBUG: No VLAN or port commands to insert")
                    
                    # Debug: Check if port configuration was actually inserted
                    if "interface gig" in config_content:
                        print("DEBUG: Port configuration successfully inserted into config")
                    else:
                        print("DEBUG: WARNING - Port configuration was NOT inserted into config")
            
            return config_content
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate device config: {str(e)}")
            return None
    
    def refresh_preview(self):
        """Refresh the preview for current device"""
        if self.current_preview_device:
            try:
                config_content = self.generate_device_config(self.current_preview_device)
                if config_content:
                    self.preview_text.delete(1.0, tk.END)
                    self.preview_text.insert(1.0, config_content)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to refresh preview: {str(e)}")
        else:
            messagebox.showwarning("Warning", "No device selected for preview")
    
    def save_preview_config(self):
        """Save the current preview configuration to file"""
        if not self.current_preview_device:
            messagebox.showwarning("Warning", "No device selected for preview")
            return
        
        config_content = self.preview_text.get(1.0, tk.END)
        if not config_content.strip():
            messagebox.showwarning("Warning", "No configuration to save")
            return
        
        # Generate default filename
        device_name = self.current_preview_device.get('Device', 'unknown_device')
        safe_device_name = re.sub(r'[^\w\-_.]', '_', device_name)
        default_filename = f"{safe_device_name}_config.txt"
        
        file_path = filedialog.asksaveasfilename(
            title="Save Device Configuration",
            defaultextension=".txt",
            initialfile=default_filename,
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(config_content)
                messagebox.showinfo("Success", f"Configuration saved successfully to:\n{file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save configuration: {str(e)}")
    
    def apply_preview_config(self):
        """Apply the current preview configuration to device"""
        if not self.current_preview_device:
            messagebox.showwarning("Warning", "No device selected for preview")
            return
        
        if not self.conn_mgr.connected:
            messagebox.showerror("Error", "Please establish connection in Terminal tab first")
            return
        
        config_content = self.preview_text.get(1.0, tk.END)
        if not config_content.strip():
            messagebox.showwarning("Warning", "No configuration to apply")
            return
        
        # Confirm action
        device_name = self.current_preview_device.get('Device', 'selected device')
        device_ip = self.current_preview_device.get('IP-Address', 'unknown IP')
        
        if not messagebox.askyesno("Confirm", f"Apply configuration to device {device_name} ({device_ip})?\n\nThis will send commands to the connected device."):
            return
        
        # Apply configuration in thread
        def apply_config_thread():
            try:
                config_lines = config_content.split('\n')
                success_count = 0
                failed_commands = []
                
                for line_num, line in enumerate(config_lines, 1):
                    line = line.strip()
                    
                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue
                    
                    try:
                        output = self.conn_mgr.send_command(line, wait_time=1.5)
                        success_count += 1
                        
                        # Add delay for configuration commands
                        if any(keyword in line.lower() for keyword in ['vlan', 'ip', 'isis', 'snmp']):
                            time.sleep(1)
                            
                    except Exception as cmd_error:
                        failed_commands.append(f"Line {line_num}: {line} - {str(cmd_error)}")
                
                # Show results
                result_msg = f"Configuration applied to {device_name}\n"
                result_msg += f"Successful commands: {success_count}\n"
                
                if failed_commands:
                    result_msg += f"Failed commands: {len(failed_commands)}\n\n"
                    result_msg += "Failed commands:\n" + "\n".join(failed_commands[:5])
                    if len(failed_commands) > 5:
                        result_msg += f"\n... and {len(failed_commands) - 5} more"
                
                self.root.after(0, lambda: messagebox.showinfo("Apply Complete", result_msg))
                
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to apply configuration: {str(e)}"))
        
        threading.Thread(target=apply_config_thread, daemon=True).start()
    
    def generate_base_config_template(self):
        """Generate template from base configuration tab"""
        try:
            # Create a temporary config using base config settings
            config = SwitchConfig(
                hostname="$sys-name$",
                snmp_location="$location$",
                mgmt_ip="$ip-address$",
                gateway=self.base_gateway_var.get(),
                system_id="$sys-id$" if self.base_enable_isis_var.get() else "",
                nick_name="$nick-name$" if self.base_enable_isis_var.get() else "",
                vlans=self.get_base_vlans_from_tree(),
                enable_isis=self.base_enable_isis_var.get(),
                snmp_community=self.base_snmp_community_var.get(),
                snmp_host=self.base_snmp_host_var.get(),
                snmp_group=self.base_snmp_group_var.get(),
                snmp_user=self.base_snmp_user_var.get(),
                snmp_auth_password=self.base_snmp_auth_pass_var.get(),
                snmp_priv_password=self.base_snmp_priv_pass_var.get(),
                timezone=self.base_timezone_var.get(),
                ntp_servers=[s.strip() for s in self.base_ntp_var.get().split(',') if s.strip()] if self.base_ntp_var.get() else []
            )
            
            # Generate the configuration
            template_content = ConfigGenerator.generate_voss_config(config)
            
            # Validate that base config has required fields
            # Note: Gateway is now auto-detected from CSV, so not strictly required
            gateway = self.base_gateway_var.get()
            if not gateway.strip():
                # Try to auto-detect gateway if not set
                detected_gateway = self.analyze_network_and_detect_gateway()
                if detected_gateway:
                    self.base_gateway_var.set(detected_gateway)
                    gateway = detected_gateway
                else:
                    messagebox.showwarning("Warning", "No gateway configured and auto-detection failed. Using default gateway 192.168.1.1")
                    gateway = "192.168.1.1"
                    self.base_gateway_var.set(gateway)
            
            if self.base_enable_isis_var.get():
                if not self.get_base_vlans_from_tree():
                    messagebox.showwarning("Warning", "No VLANs configured in Base Config")
            
            return template_content
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate template from base config: {str(e)}")
            return None
    
    def generate_batch_configs(self):
        """Generate configuration files for all devices using base config or template file"""
        # Validate inputs
        if not hasattr(self, 'csv_data') or not self.csv_data:
            messagebox.showerror("Error", "Please add devices first (via CSV or manually)")
            return
        
        output_dir = self.output_dir_var.get()
        if not output_dir:
            messagebox.showerror("Error", "Please select an output directory")
            return
        
        # Validate output directory exists and is writable
        if not os.path.isdir(output_dir):
            messagebox.showerror("Error", "Output directory does not exist")
            return
        
        try:
            # Get template content based on source
            if self.template_source_var.get() == "base_config":
                # Use base config as template
                template_content = self.generate_base_config_template()
                if not template_content:
                    messagebox.showerror("Error", "Please configure the Base Config tab first")
                    return
            else:
                # Use template file
                template_file = self.template_file_var.get()
                if not template_file:
                    messagebox.showerror("Error", "Please select a configuration template file")
                    return
                
                if not os.path.isfile(template_file):
                    messagebox.showerror("Error", "Template file does not exist")
                    return
                
                with open(template_file, 'r', encoding='utf-8') as file:
                    template_content = file.read()
            
            # Validate template contains expected placeholders (only for file templates)
            if self.template_source_var.get() == "file":
                required_placeholders = ['\\$sys-name\\$', '\\$ip-address\\$', '\\$location\\$', '\\$nick-name\\$', '\\$sys-id\\$']
                missing_placeholders = []
                for placeholder in required_placeholders:
                    if placeholder not in template_content:
                        missing_placeholders.append(placeholder.replace('\\$', '$'))
                
                if missing_placeholders:
                    warning_msg = f"Warning: Template is missing placeholders: {', '.join(missing_placeholders)}\nContinue anyway?"
                    if not messagebox.askyesno("Missing Placeholders", warning_msg):
                        return
            
            # Create progress dialog
            progress_dialog = tk.Toplevel(self.root)
            progress_dialog.title("Generating Configurations")
            progress_dialog.geometry("400x150")
            progress_dialog.transient(self.root)
            progress_dialog.grab_set()
            
            progress_label = ttk.Label(progress_dialog, text="Initializing...")
            progress_label.pack(pady=10)
            
            progress_var = tk.DoubleVar()
            progress_bar = ttk.Progressbar(progress_dialog, variable=progress_var, maximum=len(self.csv_data))
            progress_bar.pack(fill=tk.X, padx=20, pady=10)
            
            status_label = ttk.Label(progress_dialog, text="")
            status_label.pack(pady=5)
            
            # Generate configs for each device
            generated_count = 0
            failed_devices = []
            
            for i, device in enumerate(self.csv_data):
                try:
                    # Update progress
                    device_name = device.get('Device', f"switch_{i + 1}")
                    progress_label.config(text=f"Processing device {i + 1} of {len(self.csv_data)}")
                    status_label.config(text=f"Generating config for: {device_name}")
                    progress_var.set(i)
                    progress_dialog.update()
                    
                    # Validate required fields for device
                    required_fields = ['sys-name', 'IP-Address', 'Location', 'Nick-name', 'sys-id']
                    missing_fields = [field for field in required_fields if not device.get(field, '').strip()]
                    
                    if missing_fields:
                        failed_devices.append(f"{device_name}: Missing required fields: {', '.join(missing_fields)}")
                        continue
                    
                    # Generate full device config (includes VLAN and port configs if present)
                    config_content = self.generate_device_config(device)
                    if not config_content:
                        failed_devices.append(f"{device_name}: Failed to generate configuration")
                        continue
                    
                    # Generate output filename (sanitize filename)
                    safe_device_name = re.sub(r'[^\w\-_.]', '_', device_name)
                    output_filename = f"{safe_device_name}_config.txt"
                    output_path = os.path.join(output_dir, output_filename)
                    
                    # Write configuration file
                    with open(output_path, 'w', encoding='utf-8') as output_file:
                        output_file.write(config_content)
                    
                    generated_count += 1
                    
                except Exception as e:
                    failed_devices.append(f"{device.get('Device', 'Unknown')}: {str(e)}")
            
            # Complete progress
            progress_var.set(len(self.csv_data))
            progress_label.config(text="Generation complete!")
            status_label.config(text=f"Generated {generated_count} configuration files")
            
            # Close progress dialog after a brief delay
            progress_dialog.after(1500, progress_dialog.destroy)
            
            # Show results
            result_message = f"Successfully generated {generated_count} configuration files in:\n{output_dir}"
            if failed_devices:
                result_message += f"\n\nFailed devices ({len(failed_devices)}):\n" + "\n".join(failed_devices[:10])
                if len(failed_devices) > 10:
                    result_message += f"\n... and {len(failed_devices) - 10} more"
            
            messagebox.showinfo("Batch Generation Complete", result_message)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate batch configurations: {str(e)}")
    
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
    
    def export_as_template(self):
        """Export current configuration as a template with placeholders"""
        config_content = self.config_text.get(1.0, tk.END)
        if not config_content.strip():
            messagebox.showwarning("Warning", "No configuration to export")
            return
        
        # Create template by replacing values with placeholders
        template_content = config_content
        
        # Get current values from form
        hostname = self.hostname_var.get()
        location = self.location_var.get()
        mgmt_ip = self.mgmt_ip_var.get()
        system_id = self.system_id_var.get()
        nick_name = self.nick_name_var.get()
        
        # Replace actual values with template placeholders
        replacements = []
        if hostname:
            replacements.append((hostname, '$sys-name$'))
        if location:
            replacements.append((location, '$location$'))
        if mgmt_ip:
            # Extract just the IP part (without subnet mask)
            ip_part = mgmt_ip.split('/')[0] if '/' in mgmt_ip else mgmt_ip
            replacements.append((ip_part, '$ip-address$'))
        if system_id:
            replacements.append((system_id, '$sys-id$'))
        if nick_name:
            replacements.append((nick_name, '$nick-name$'))
        
        # Apply replacements
        for old_value, placeholder in replacements:
            template_content = template_content.replace(old_value, placeholder)
        
        # Save template file
        file_path = filedialog.asksaveasfilename(
            title="Export Configuration Template",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                # Add header comment to template
                header = f"""##############################################
#  $sys-name$ configuration template
#  Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
#  
#  Placeholders:
#  $sys-name$ - System hostname
#  $location$ - SNMP location
#  $ip-address$ - Management IP address
#  $sys-id$ - ISIS System ID
#  $nick-name$ - ISIS Nick name
##############################################

"""
                
                with open(file_path, 'w') as f:
                    f.write(header + template_content)
                
                messagebox.showinfo("Success", f"Template exported successfully to:\n{file_path}")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export template: {str(e)}")

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