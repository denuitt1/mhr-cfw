#!/usr/bin/env python3
"""
Desktop GUI for DomainFront Tunnel – PyQt5 version.
Fully responsive layout with proper threading and asyncio integration.
Modern dark mode with refined styling.
"""

import asyncio
import json
import os
import sys
import threading
import time
import socket
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from queue import Queue, Empty

# PyQt5 imports
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QSize
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QTabWidget, QGroupBox, QLabel,
                             QLineEdit, QTextEdit, QCheckBox, QPushButton,
                             QComboBox, QSpinBox, QTreeWidget, QTreeWidgetItem,
                             QHeaderView, QMessageBox, QFileDialog)

# Add src/ to path if running from project root
_SRC_DIR = Path(__file__).resolve().parent / "src"
if _SRC_DIR.exists() and str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

# ----- Import your existing modules (with fallback dummies) -----
try:
    from constants import __version__
    from cert_installer import install_ca, uninstall_ca, is_ca_trusted
    from mitm import CA_CERT_FILE, MITMCertManager
    from proxy_server import ProxyServer
    from logging_utils import configure as configure_logging
    from scan_ips import scan_sync as scan_ips_sync
except ImportError:
    __version__ = "0.1.0-dev"
    CA_CERT_FILE = Path("ca-cert.pem")
    def install_ca(*args): print("Dummy install_ca"); return True
    def uninstall_ca(*args): print("Dummy uninstall_ca"); return True
    def is_ca_trusted(*args): print("Dummy is_ca_trusted"); return False
    class MITMCertManager: pass
    class ProxyServer:
        def __init__(self, *args): pass
        async def start(self): await asyncio.sleep(3600)
        async def stop(self): pass
    def configure_logging(*args): pass
    def scan_ips_sync(*args):
        print("Dummy scan_ips_sync")
        time.sleep(2)
        return [("8.8.8.8", 50.1), ("8.8.4.4", 60.2)]

try:
    import aiohttp
except ImportError:
    aiohttp = None

# ----- Constants -----
DEFAULT_GOOGLE_SNI_POOL = [
    "www.google.com", "google.com", "accounts.google.com", "mail.google.com",
    "drive.google.com", "calendar.google.com", "docs.google.com", "photos.google.com",
    "maps.google.com", "news.google.com"
]
LOG_MAX = 200
POLL_INTERVAL_MS = 700


def fmt_bytes(b: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if b < 1024.0:
            return f"{b:.1f} {unit}"
        b /= 1024.0
    return f"{b:.1f} TB"

def fmt_duration(seconds: int) -> str:
    h = seconds // 3600
    m = (seconds % 3600) // 60
    s = seconds % 60
    return f"{h:02d}:{m:02d}:{s:02d}"

def save_config(config: Dict, path: Path) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)
        f.write("\n")

def load_config(path: Path) -> Dict:
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}


# ----------------------------------------------------------------------
# Background thread for running the asyncio proxy + stats/log polling
# ----------------------------------------------------------------------
class ProxyThread(QThread):
    log_signal = pyqtSignal(str)
    stats_signal = pyqtSignal(dict)
    stopped_signal = pyqtSignal()

    def __init__(self, config: Dict):
        super().__init__()
        self.config = config
        self.stop_event = threading.Event()
        self.loop = None

    def run(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        try:
            self.loop.run_until_complete(self._proxy_main())
        except Exception as e:
            self.log_signal.emit(f"Proxy thread error: {e}")
        finally:
            self.loop.close()
            self.stopped_signal.emit()

    async def _proxy_main(self):
        server = ProxyServer(self.config)

        async def stats_poller():
            while not self.stop_event.is_set():
                try:
                    stats = getattr(server, 'get_stats', lambda: {})()
                except:
                    stats = {}
                self.stats_signal.emit(stats)
                await asyncio.sleep(2)

        stats_task = asyncio.create_task(stats_poller())
        try:
            await server.start()
        except Exception as e:
            self.log_signal.emit(f"Proxy error: {e}")
        finally:
            stats_task.cancel()
            await server.stop()

    def stop(self):
        self.stop_event.set()
        if self.loop and self.loop.is_running():
            self.loop.call_soon_threadsafe(self.loop.stop)


# ----------------------------------------------------------------------
# SNI probe worker
# ----------------------------------------------------------------------
class SNIProbeThread(QThread):
    result_signal = pyqtSignal(str, str)
    finished_signal = pyqtSignal()

    def __init__(self, google_ip: str, sni_list: List[str]):
        super().__init__()
        self.google_ip = google_ip
        self.sni_list = sni_list

    def run(self):
        asyncio.run(self._probe_all())

    async def _probe_all(self):
        import ssl
        for sni in self.sni_list:
            try:
                start = asyncio.get_running_loop().time()
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.google_ip, 443, ssl=ctx, server_hostname=sni),
                    timeout=4
                )
                writer.write(b"HEAD / HTTP/1.1\r\nHost: " + sni.encode() + b"\r\nConnection: close\r\n\r\n")
                await writer.drain()
                resp = await asyncio.wait_for(reader.read(1024), timeout=4)
                writer.close()
                await writer.wait_closed()
                latency = (asyncio.get_running_loop().time() - start) * 1000
                if resp.startswith(b"HTTP/"):
                    self.result_signal.emit(sni, f"OK {latency:.0f} ms")
                else:
                    self.result_signal.emit(sni, "FAIL: bad response")
            except Exception as e:
                self.result_signal.emit(sni, f"FAIL: {str(e)[:30]}")
            await asyncio.sleep(0.1)
        self.finished_signal.emit()


# ----------------------------------------------------------------------
# Main GUI Window with Modern Dark Mode
# ----------------------------------------------------------------------
class DomainFrontGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"DomainFront Tunnel v{__version__}")
        self.resize(800, 400)
        self.setMinimumSize(800, 400)

        # Configuration
        self.config_path = Path("config.json")
        self.config = load_config(self.config_path)
        if not self.config:
            self.config = self._default_config()
        self._migrate_config()

        # State
        self.proxy_running = False
        self.proxy_thread = None
        self.sni_probe_cache: Dict[str, str] = {}
        self.dark_mode = False

        # Build UI
        self._build_ui()
        self._apply_light_theme()  # start with light theme
        self._refresh_config_ui()
        self._refresh_sni_tree()

        # Periodic log update
        self.log_queue = Queue()
        self._log_timer = QTimer()
        self._log_timer.timeout.connect(self._poll_log)
        self._log_timer.start(500)

    # ------------------------------------------------------------------
    # Configuration defaults & migration
    # ------------------------------------------------------------------
    def _default_config(self) -> Dict:
        return {
            "mode": "apps_script",
            "google_ip": "216.239.38.120",
            "front_domain": "www.google.com",
            "script_id": "YOUR_APPS_SCRIPT_DEPLOYMENT_ID",
            "auth_key": "CHANGE_ME_TO_A_STRONG_SECRET",
            "listen_host": "127.0.0.1",
            "socks5_enabled": True,
            "listen_port": 8085,
            "socks5_port": 1080,
            "log_level": "INFO",
            "verify_ssl": True,
            "lan_sharing": True,
            "relay_timeout": 25,
            "tls_connect_timeout": 15,
            "tcp_connect_timeout": 10,
            "max_response_body_bytes": 209715200,
            "parallel_relay": 1,
            "chunked_download_extensions": [
                ".bin", ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
                ".exe", ".msi", ".dmg", ".deb", ".rpm", ".apk", ".iso", ".img",
                ".mp4", ".mkv", ".avi", ".mov", ".webm", ".mp3", ".flac", ".wav",
                ".aac", ".pdf", ".doc", ".docx", ".ppt", ".pptx", ".wasm"
            ],
            "chunked_download_min_size": 5242880,
            "chunked_download_chunk_size": 524288,
            "chunked_download_max_parallel": 8,
            "chunked_download_max_chunks": 256,
            "block_hosts": [],
            "bypass_hosts": [
                "localhost",
                ".local",
                ".lan",
                ".home.arpa"
            ],
            "forwarder_hosts": [],
            "direct_google_exclude": [
                "gemini.google.com",
                "aistudio.google.com",
                "notebooklm.google.com",
                "labs.google.com",
                "meet.google.com",
                "accounts.google.com",
                "ogs.google.com",
                "mail.google.com",
                "calendar.google.com",
                "drive.google.com",
                "docs.google.com",
                "chat.google.com",
                "maps.google.com",
                "play.google.com",
                "translate.google.com",
                "assistant.google.com",
                "lens.google.com"
            ],
            "direct_google_allow": [
                "www.google.com",
                "safebrowsing.google.com"
            ],
            "youtube_via_relay": False,
            "hosts": {},
            "script_ids": [],
            "sni_hosts": DEFAULT_GOOGLE_SNI_POOL.copy(),
            "normalize_x_graphql": False,
            "block_quic": True,
            "upstream_socks5": "",
            "fetch_ips_from_api": True,
            "max_ips_to_scan": 100,
            "scan_batch_size": 20,
            "google_ip_validation": True,
        }

    def _migrate_config(self):
        defaults = self._default_config()
        for k, v in defaults.items():
            if k not in self.config:
                self.config[k] = v
        if "script_id" in self.config and self.config["script_id"]:
            if isinstance(self.config["script_id"], str):
                self.config["script_ids"] = [self.config["script_id"]]
            else:
                self.config["script_ids"] = self.config["script_id"]
        if not self.config.get("sni_hosts"):
            self.config["sni_hosts"] = DEFAULT_GOOGLE_SNI_POOL.copy()

    # ------------------------------------------------------------------
    # UI Construction
    # ------------------------------------------------------------------
    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(12, 12, 12, 12)
        main_layout.setSpacing(10)

        # Header
        header_layout = QHBoxLayout()
        title = QLabel(f"DomainFront Tunnel <b>v{__version__}</b>")
        title.setStyleSheet("font-size: 18pt;")
        header_layout.addWidget(title)
        self.status_label = QLabel("● stopped")
        self.status_label.setStyleSheet("color: #e74c3c; font-weight: bold;")
        header_layout.addWidget(self.status_label)
        header_layout.addStretch()
        main_layout.addLayout(header_layout)

        # Tab widget
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        # Create tabs
        self.config_tab = QWidget()
        self.sni_tab = QWidget()
        self.log_tab = QWidget()
        self.tabs.addTab(self.config_tab, "Configuration")
        self.tabs.addTab(self.sni_tab, "SNI Pool")
        self.tabs.addTab(self.log_tab, "Log & Stats")

        self._build_config_tab()
        self._build_sni_tab()
        self._build_log_tab()

        # Action buttons
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(8)
        self.start_btn = QPushButton("▶ Start")
        self.start_btn.clicked.connect(self._start_proxy)
        self.stop_btn = QPushButton("■ Stop")
        self.stop_btn.clicked.connect(self._stop_proxy)
        self.stop_btn.setEnabled(False)
        save_btn = QPushButton("💾 Save Config")
        save_btn.clicked.connect(self._save_config)
        install_ca_btn = QPushButton("🔐 Install CA")
        install_ca_btn.clicked.connect(self._install_ca)
        remove_ca_btn = QPushButton("🗑 Remove CA")
        remove_ca_btn.clicked.connect(self._remove_ca)
        test_relay_btn = QPushButton("🔌 Test Relay")
        test_relay_btn.clicked.connect(self._test_relay)
        scan_ips_btn = QPushButton("📡 Scan IPs")
        scan_ips_btn.clicked.connect(self._scan_ips)
        dark_btn = QPushButton("🌙 Dark Mode")
        dark_btn.clicked.connect(self._toggle_dark_mode)

        for btn in [self.start_btn, self.stop_btn, save_btn, install_ca_btn,
                    remove_ca_btn, test_relay_btn, scan_ips_btn, dark_btn]:
            btn.setMinimumHeight(32)
            btn_layout.addWidget(btn)
        btn_layout.addStretch()
        self.toast_label = QLabel("")
        self.toast_label.setStyleSheet("color: #f39c12; font-style: italic;")
        btn_layout.addWidget(self.toast_label)
        main_layout.addLayout(btn_layout)

    # ------------------------------------------------------------------
    # Configuration Tab
    # ------------------------------------------------------------------
    def _build_config_tab(self):
        layout = QVBoxLayout(self.config_tab)
        scroll = QtWidgets.QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QtWidgets.QFrame.NoFrame)
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_layout.setSpacing(12)
        scroll.setWidget(scroll_content)
        layout.addWidget(scroll)

        def add_field(label_text, widget):
            row = QHBoxLayout()
            lbl = QLabel(label_text)
            lbl.setMinimumWidth(200)
            row.addWidget(lbl)
            row.addWidget(widget)
            row.addStretch()
            scroll_layout.addLayout(row)

        # Apps Script section
        group_script = QGroupBox("Apps Script Relay")
        script_layout = QVBoxLayout(group_script)
        self.script_ids_text = QTextEdit()
        self.script_ids_text.setMaximumHeight(120)
        script_layout.addWidget(QLabel("Deployment ID(s) (one per line):"))
        script_layout.addWidget(self.script_ids_text)
        self.script_ids_count_label = QLabel("0 ID(s) entered")
        script_layout.addWidget(self.script_ids_count_label)
        scroll_layout.addWidget(group_script)

        self.auth_key_edit = QLineEdit()
        self.auth_key_edit.setEchoMode(QLineEdit.Password)
        add_field("Auth Key:", self.auth_key_edit)

        # Network section
        group_net = QGroupBox("Network")
        net_layout = QVBoxLayout(group_net)
        self.google_ip_edit = QLineEdit()
        self.front_domain_edit = QLineEdit()
        self.listen_host_edit = QLineEdit()
        self.listen_port_edit = QLineEdit()
        self.socks5_port_edit = QLineEdit()
        net_layout.addLayout(self._make_row("Google IP:", self.google_ip_edit))
        net_layout.addLayout(self._make_row("Front Domain (SNI):", self.front_domain_edit))
        net_layout.addLayout(self._make_row("Listen Host:", self.listen_host_edit))
        net_layout.addLayout(self._make_row("HTTP Port:", self.listen_port_edit))
        self.lan_sharing_cb = QCheckBox("Share with other devices on LAN (binds to 0.0.0.0)")
        net_layout.addWidget(self.lan_sharing_cb)
        self.socks5_enabled_cb = QCheckBox("Enable SOCKS5 proxy")
        net_layout.addWidget(self.socks5_enabled_cb)
        net_layout.addLayout(self._make_row("SOCKS5 Port:", self.socks5_port_edit))
        scroll_layout.addWidget(group_net)

        # Advanced section
        group_adv = QGroupBox("Advanced")
        adv_layout = QVBoxLayout(group_adv)
        self.verify_ssl_cb = QCheckBox("Verify TLS certificates")
        self.normalize_graphql_cb = QCheckBox("Normalize X/Twitter GraphQL URLs")
        self.youtube_relay_cb = QCheckBox("Send YouTube through relay (slower, better visibility)")
        self.block_quic_cb = QCheckBox("Block QUIC (UDP/443) to prevent TCP meltdown")
        self.upstream_socks5_edit = QLineEdit()
        adv_layout.addWidget(self.verify_ssl_cb)
        adv_layout.addWidget(self.normalize_graphql_cb)
        adv_layout.addWidget(self.youtube_relay_cb)
        adv_layout.addWidget(self.block_quic_cb)
        adv_layout.addLayout(self._make_row("Upstream SOCKS5 (host:port):", self.upstream_socks5_edit))
        scroll_layout.addWidget(group_adv)

        # IP Scanner section
        group_scan = QGroupBox("IP Scanner")
        scan_layout = QVBoxLayout(group_scan)
        self.fetch_ips_cb = QCheckBox("Fetch IPs from Google API (recommended)")
        scan_layout.addWidget(self.fetch_ips_cb)
        self.max_ips_spin = QSpinBox()
        self.max_ips_spin.setRange(10, 500)
        self.batch_size_spin = QSpinBox()
        self.batch_size_spin.setRange(5, 100)
        self.ip_validation_cb = QCheckBox("Validate Google headers (strict mode)")
        scan_layout.addLayout(self._make_row("Max IPs to scan:", self.max_ips_spin))
        scan_layout.addLayout(self._make_row("Batch size:", self.batch_size_spin))
        scan_layout.addWidget(self.ip_validation_cb)
        scroll_layout.addWidget(group_scan)

        # Log Level
        group_log = QGroupBox("Log Level")
        log_layout = QVBoxLayout(group_log)
        self.log_level_combo = QComboBox()
        self.log_level_combo.addItems(["DEBUG", "INFO", "WARNING", "ERROR"])
        log_layout.addWidget(self.log_level_combo)
        scroll_layout.addWidget(group_log)

        scroll_layout.addStretch()

    def _make_row(self, label_text, widget):
        row = QHBoxLayout()
        row.addWidget(QLabel(label_text))
        row.addWidget(widget)
        row.addStretch()
        return row

    def _refresh_config_ui(self):
        self.google_ip_edit.setText(self.config.get("google_ip", ""))
        self.front_domain_edit.setText(self.config.get("front_domain", ""))
        self.listen_host_edit.setText(self.config.get("listen_host", ""))
        self.listen_port_edit.setText(str(self.config.get("listen_port", 8085)))
        self.socks5_port_edit.setText(str(self.config.get("socks5_port", 1080)))
        self.auth_key_edit.setText(self.config.get("auth_key", ""))
        self.script_ids_text.setPlainText("\n".join(self.config.get("script_ids", [])))
        self._update_script_ids_count()
        self.lan_sharing_cb.setChecked(self.config.get("lan_sharing", False))
        self.socks5_enabled_cb.setChecked(self.config.get("socks5_enabled", True))
        self.verify_ssl_cb.setChecked(self.config.get("verify_ssl", True))
        self.normalize_graphql_cb.setChecked(self.config.get("normalize_x_graphql", False))
        self.youtube_relay_cb.setChecked(self.config.get("youtube_via_relay", False))
        self.block_quic_cb.setChecked(self.config.get("block_quic", True))
        self.upstream_socks5_edit.setText(self.config.get("upstream_socks5", ""))
        self.fetch_ips_cb.setChecked(self.config.get("fetch_ips_from_api", True))
        self.max_ips_spin.setValue(self.config.get("max_ips_to_scan", 100))
        self.batch_size_spin.setValue(self.config.get("scan_batch_size", 20))
        self.ip_validation_cb.setChecked(self.config.get("google_ip_validation", True))
        self.log_level_combo.setCurrentText(self.config.get("log_level", "INFO"))

    def _gather_config_from_ui(self) -> Dict:
        cfg = self.config.copy()
        cfg["google_ip"] = self.google_ip_edit.text().strip()
        cfg["front_domain"] = self.front_domain_edit.text().strip()
        cfg["listen_host"] = self.listen_host_edit.text().strip()
        try:
            cfg["listen_port"] = int(self.listen_port_edit.text().strip())
        except:
            pass
        try:
            cfg["socks5_port"] = int(self.socks5_port_edit.text().strip())
        except:
            pass
        cfg["auth_key"] = self.auth_key_edit.text().strip()
        ids_text = self.script_ids_text.toPlainText()
        ids = [l.strip() for l in ids_text.splitlines() if l.strip()]
        cfg["script_ids"] = ids
        cfg["lan_sharing"] = self.lan_sharing_cb.isChecked()
        cfg["socks5_enabled"] = self.socks5_enabled_cb.isChecked()
        cfg["verify_ssl"] = self.verify_ssl_cb.isChecked()
        cfg["normalize_x_graphql"] = self.normalize_graphql_cb.isChecked()
        cfg["youtube_via_relay"] = self.youtube_relay_cb.isChecked()
        cfg["block_quic"] = self.block_quic_cb.isChecked()
        cfg["upstream_socks5"] = self.upstream_socks5_edit.text().strip()
        cfg["fetch_ips_from_api"] = self.fetch_ips_cb.isChecked()
        cfg["max_ips_to_scan"] = self.max_ips_spin.value()
        cfg["scan_batch_size"] = self.batch_size_spin.value()
        cfg["google_ip_validation"] = self.ip_validation_cb.isChecked()
        cfg["log_level"] = self.log_level_combo.currentText()

        if cfg["lan_sharing"] and cfg.get("listen_host") == "127.0.0.1":
            cfg["listen_host"] = "0.0.0.0"
        elif not cfg["lan_sharing"] and cfg.get("listen_host") == "0.0.0.0":
            cfg["listen_host"] = "127.0.0.1"
        return cfg

    def _update_script_ids_count(self):
        content = self.script_ids_text.toPlainText()
        lines = [l.strip() for l in content.splitlines() if l.strip()]
        self.script_ids_count_label.setText(f"{len(lines)} ID(s) entered")

    # ------------------------------------------------------------------
    # SNI Pool Tab
    # ------------------------------------------------------------------
    def _build_sni_tab(self):
        layout = QVBoxLayout(self.sni_tab)
        self.sni_tree = QTreeWidget()
        self.sni_tree.setHeaderLabels(["Active", "SNI Name", "Last Test"])
        self.sni_tree.setColumnWidth(0, 60)
        self.sni_tree.setColumnWidth(1, 350)
        self.sni_tree.setColumnWidth(2, 200)
        self.sni_tree.header().setStretchLastSection(False)
        self.sni_tree.header().setSectionResizeMode(1, QHeaderView.Stretch)
        layout.addWidget(self.sni_tree)

        btn_layout = QHBoxLayout()
        test_all_btn = QPushButton("▶ Test All")
        test_all_btn.clicked.connect(self._test_all_sni)
        keep_working_btn = QPushButton("✓ Keep Working Only")
        keep_working_btn.clicked.connect(self._keep_working_only)
        reset_btn = QPushButton("↺ Reset to Defaults")
        reset_btn.clicked.connect(self._reset_sni_defaults)
        remove_btn = QPushButton("✗ Remove Selected")
        remove_btn.clicked.connect(self._remove_selected_sni)
        for btn in [test_all_btn, keep_working_btn, reset_btn, remove_btn]:
            btn.setMinimumHeight(30)
            btn_layout.addWidget(btn)
        layout.addLayout(btn_layout)

        add_layout = QHBoxLayout()
        add_layout.addWidget(QLabel("Add SNI:"))
        self.new_sni_edit = QLineEdit()
        add_layout.addWidget(self.new_sni_edit)
        add_btn = QPushButton("+ Add")
        add_btn.clicked.connect(self._add_custom_sni)
        add_layout.addWidget(add_btn)
        add_layout.addStretch()
        layout.addLayout(add_layout)

    def _refresh_sni_tree(self):
        self.sni_tree.clear()
        sni_list = self.config.get("sni_hosts", DEFAULT_GOOGLE_SNI_POOL)
        for sni in sni_list:
            status = self.sni_probe_cache.get(sni, "untested")
            item = QTreeWidgetItem(["✓", sni, status])
            self.sni_tree.addTopLevelItem(item)

    def _remove_selected_sni(self):
        selected = self.sni_tree.selectedItems()
        if not selected:
            self._show_toast("No SNI selected", is_error=True)
            return
        for item in selected:
            sni = item.text(1)
            if sni in self.config["sni_hosts"]:
                self.config["sni_hosts"].remove(sni)
        self._refresh_sni_tree()

    def _save_sni_list(self, new_list: List[str]):
        self.config["sni_hosts"] = new_list
        self._refresh_sni_tree()

    def _test_all_sni(self):
        google_ip = self.google_ip_edit.text().strip()
        if not google_ip:
            self._show_toast("Google IP is empty", is_error=True)
            return
        snis = self.config.get("sni_hosts", [])
        if not snis:
            return
        for sni in snis:
            self.sni_probe_cache[sni] = "testing..."
        self._refresh_sni_tree()
        self.probe_thread = SNIProbeThread(google_ip, snis)
        self.probe_thread.result_signal.connect(self._on_sni_probe_result)
        self.probe_thread.finished_signal.connect(lambda: self._show_toast("SNI testing finished"))
        self.probe_thread.start()

    def _on_sni_probe_result(self, sni: str, status: str):
        self.sni_probe_cache[sni] = status
        for i in range(self.sni_tree.topLevelItemCount()):
            item = self.sni_tree.topLevelItem(i)
            if item.text(1) == sni:
                item.setText(2, status)
                break

    def _keep_working_only(self):
        new_list = [sni for sni in self.config.get("sni_hosts", []) if self.sni_probe_cache.get(sni, "").startswith("OK")]
        if not new_list:
            self._show_toast("No working SNIs found. Keeping all.", is_error=True)
            return
        self._save_sni_list(new_list)

    def _reset_sni_defaults(self):
        self.config["sni_hosts"] = DEFAULT_GOOGLE_SNI_POOL.copy()
        self.sni_probe_cache.clear()
        self._refresh_sni_tree()

    def _add_custom_sni(self):
        new_sni = self.new_sni_edit.text().strip()
        if new_sni and new_sni not in self.config["sni_hosts"]:
            self.config["sni_hosts"].append(new_sni)
            self._refresh_sni_tree()
            self.new_sni_edit.clear()
            google_ip = self.google_ip_edit.text().strip()
            if google_ip:
                probe = SNIProbeThread(google_ip, [new_sni])
                probe.result_signal.connect(self._on_sni_probe_result)
                probe.start()

    # ------------------------------------------------------------------
    # Log & Stats Tab
    # ------------------------------------------------------------------
    def _build_log_tab(self):
        layout = QVBoxLayout(self.log_tab)

        # Stats area
        self.stats_label = QLabel("No proxy running")
        self.stats_label.setWordWrap(True)
        self.stats_label.setStyleSheet("font-family: 'Courier New', monospace; padding: 8px; background: rgba(0,0,0,0.05); border-radius: 6px;")
        layout.addWidget(self.stats_label)

        # Log area
        log_group = QGroupBox("Recent Log")
        log_layout = QVBoxLayout(log_group)
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        log_layout.addWidget(self.log_text)
        clear_btn = QPushButton("Clear Log")
        clear_btn.clicked.connect(self._clear_log)
        log_layout.addWidget(clear_btn)
        layout.addWidget(log_group)

    def _append_log(self, msg: str):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        self.log_queue.put(f"{timestamp}  {msg}")

    def _poll_log(self):
        try:
            while True:
                line = self.log_queue.get_nowait()
                self.log_text.append(line)
                doc = self.log_text.document()
                if doc.blockCount() > LOG_MAX:
                    cursor = self.log_text.textCursor()
                    cursor.movePosition(QtGui.QTextCursor.Start)
                    cursor.select(QtGui.QTextCursor.BlockUnderCursor)
                    cursor.removeSelectedText()
                    cursor.deleteChar()
        except:
            pass

    def _clear_log(self):
        self.log_text.clear()

    def _update_stats(self, stats: dict):
        txt = (
            f"Relay calls: {stats.get('relay_calls',0)}  |  Failures: {stats.get('relay_failures',0)}\n"
            f"Cache hits: {stats.get('cache_hits',0)}  |  Misses: {stats.get('cache_misses',0)}\n"
            f"Bytes relayed: {fmt_bytes(stats.get('bytes_relayed',0))}\n"
            f"Active scripts: {stats.get('active_scripts',0)}"
        )
        self.stats_label.setText(txt)

    # ------------------------------------------------------------------
    # Proxy Control
    # ------------------------------------------------------------------
    def _validate_start_conditions(self) -> bool:
        cfg = self._gather_config_from_ui()
        if not cfg.get("script_ids"):
            self._show_toast("❌ Please enter at least one Deployment ID", is_error=True)
            return False
        if not cfg.get("auth_key"):
            self._show_toast("❌ Auth Key is required", is_error=True)
            return False
        return True

    def _start_proxy(self):
        if self.proxy_running:
            return
        if not self._validate_start_conditions():
            return

        self.config = self._gather_config_from_ui()
        try:
            save_config(self.config, self.config_path)
        except Exception as e:
            self._show_toast(f"Failed to save config: {e}", is_error=True)
            return

        configure_logging(self.config.get("log_level", "INFO"))

        if not os.path.exists(CA_CERT_FILE):
            try:
                MITMCertManager()
            except Exception as e:
                self._append_log(f"Failed to create MITM CA: {e}")
                self._show_toast("CA generation failed", is_error=True)
                return

        self.proxy_thread = ProxyThread(self.config)
        self.proxy_thread.log_signal.connect(self._append_log)
        self.proxy_thread.stats_signal.connect(self._update_stats)
        self.proxy_thread.stopped_signal.connect(self._proxy_stopped_cleanup)
        self.proxy_thread.start()

        self.proxy_running = True
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_label.setText("● running")
        self.status_label.setStyleSheet("color: #2ecc71; font-weight: bold;")
        self._append_log("Proxy starting...")

    def _proxy_stopped_cleanup(self):
        self.proxy_running = False
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("● stopped")
        self.status_label.setStyleSheet("color: #e74c3c; font-weight: bold;")
        self._append_log("Proxy stopped")

    def _stop_proxy(self):
        if not self.proxy_running:
            return
        self._append_log("Stopping proxy...")
        if self.proxy_thread:
            self.proxy_thread.stop()
            self.proxy_thread.wait(3000)
            self.proxy_thread = None
        self.proxy_running = False

    # ------------------------------------------------------------------
    # Utility Actions
    # ------------------------------------------------------------------
    def _save_config(self):
        self.config = self._gather_config_from_ui()
        try:
            save_config(self.config, self.config_path)
            self._show_toast(f"Saved to {self.config_path}")
            self._append_log(f"Configuration saved to {self.config_path}")
        except Exception as e:
            self._show_toast(f"Save failed: {e}", is_error=True)

    def _install_ca(self):
        def install():
            try:
                if not os.path.exists(CA_CERT_FILE):
                    MITMCertManager()
                ok = install_ca(CA_CERT_FILE)
                self._show_toast("CA installed" if ok else "Install failed", is_error=not ok)
                self._append_log("CA installation " + ("successful" if ok else "failed"))
            except Exception as e:
                self._show_toast(f"Install failed: {e}", is_error=True)
        threading.Thread(target=install, daemon=True).start()

    def _remove_ca(self):
        def remove():
            try:
                ok = uninstall_ca(CA_CERT_FILE)
                self._show_toast("CA removed" if ok else "Removal failed", is_error=not ok)
                self._append_log("CA removal " + ("successful" if ok else "failed"))
            except Exception as e:
                self._show_toast(f"Removal failed: {e}", is_error=True)
        threading.Thread(target=remove, daemon=True).start()

    def _test_relay(self):
        if not self.proxy_running:
            self._show_toast("Start the proxy first", is_error=True)
            return
        self._append_log("Testing relay (HTTP GET via proxy)...")
        def test():
            try:
                import urllib.request
                proxy_host = self.config.get("listen_host", "127.0.0.1")
                proxy_port = self.config.get("listen_port", 8085)
                proxy = f"http://{proxy_host}:{proxy_port}"
                req = urllib.request.Request("http://www.google.com/", method="HEAD")
                req.set_proxy(proxy, "http")
                resp = urllib.request.urlopen(req, timeout=10)
                if 200 <= resp.status < 300:
                    self._append_log(f"Test passed (HTTP {resp.status})")
                    self._show_toast("Test passed")
                else:
                    self._append_log(f"Test failed: HTTP {resp.status}")
                    self._show_toast(f"Test failed (HTTP {resp.status})", is_error=True)
            except Exception as e:
                self._append_log(f"Test error: {e}")
                self._show_toast("Test failed", is_error=True)
        threading.Thread(target=test, daemon=True).start()

    def _scan_ips(self):
        self.config = self._gather_config_from_ui()
        self._append_log(f"Starting Google IP scan (front: {self.config['front_domain']})...")
        self._show_toast("Scanning IPs, see log for results...")

        def scan_worker():
            try:
                results = scan_ips_sync(self.config)
                if not results:
                    self._append_log("[scan] No working Google IPs found.")
                    self._show_toast("No working IPs found", is_error=True)
                    return
                self._append_log(f"[scan] Found {len(results)} working IPs (fastest first):")
                for i, (ip, ms) in enumerate(results[:10], 1):
                    self._append_log(f"  {i}. {ip}  ({ms:.0f} ms)")
                if len(results) > 10:
                    self._append_log(f"  ... and {len(results)-10} more.")
                fastest_ip, fastest_ms = results[0]
                self._append_log(
                    f"[scan] Fastest: {fastest_ip} ({fastest_ms:.0f} ms). "
                    "You can copy and paste this into the 'Google IP' field."
                )
                self._show_toast(f"Scan done. Fastest IP: {fastest_ip}")
            except Exception as scan_err:
                self._append_log(f"[scan] Error: {scan_err}")
                self._show_toast(f"Scan failed: {scan_err}", is_error=True)

        threading.Thread(target=scan_worker, daemon=True).start()

    def _toggle_dark_mode(self):
        self.dark_mode = not self.dark_mode
        if self.dark_mode:
            self._apply_dark_theme()
        else:
            self._apply_light_theme()

    # ------------------------------------------------------------------
    # Modern Theming
    # ------------------------------------------------------------------
    def _apply_light_theme(self):
        self.setStyleSheet("""
            QMainWindow { background-color: #f5f5f5; }
            QLabel, QCheckBox, QRadioButton, QGroupBox { color: #2c3e50; }
            QTextEdit, QLineEdit, QComboBox, QSpinBox {
                background-color: #ffffff;
                color: #2c3e50;
                border: 1px solid #dcdde1;
                border-radius: 5px;
                padding: 5px;
            }
            QTextEdit:focus, QLineEdit:focus, QComboBox:focus, QSpinBox:focus {
                border: 1px solid #3498db;
            }
            QPushButton {
                background-color: #ecf0f1;
                color: #2c3e50;
                border: 1px solid #bdc3c7;
                border-radius: 5px;
                padding: 6px 12px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #dfe6e9;
                border-color: #95a5a6;
            }
            QPushButton:pressed {
                background-color: #bdc3c7;
            }
            QPushButton:disabled {
                background-color: #f5f5f5;
                color: #95a5a6;
            }
            QTabWidget::pane {
                background: #ffffff;
                border: 1px solid #dcdde1;
                border-radius: 5px;
            }
            QTabBar::tab {
                background: #ecf0f1;
                color: #2c3e50;
                padding: 8px 16px;
                margin-right: 2px;
                border-top-left-radius: 5px;
                border-top-right-radius: 5px;
            }
            QTabBar::tab:selected {
                background: #ffffff;
                border-bottom: 2px solid #3498db;
            }
            QTabBar::tab:hover {
                background: #dfe6e9;
            }
            QTreeWidget {
                background: #ffffff;
                color: #2c3e50;
                alternate-background-color: #f8f9fa;
                border: 1px solid #dcdde1;
                border-radius: 5px;
            }
            QHeaderView::section {
                background: #ecf0f1;
                color: #2c3e50;
                padding: 5px;
                border: none;
            }
            QGroupBox {
                border: 1px solid #dcdde1;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 10px;
                font-weight: bold;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 8px;
            }
            QScrollArea { border: none; background: transparent; }
            QScrollBar:vertical {
                background: #f0f0f0;
                width: 10px;
                border-radius: 5px;
            }
            QScrollBar::handle:vertical {
                background: #c0c0c0;
                border-radius: 5px;
                min-height: 20px;
            }
            QScrollBar::handle:vertical:hover {
                background: #a0a0a0;
            }
        """)

    def _apply_dark_theme(self):
        # Modern dark theme with deep charcoal and vibrant accents
        self.setStyleSheet("""
            QMainWindow { background-color: #1e1e1e; }
            QLabel, QCheckBox, QRadioButton, QGroupBox { color: #e0e0e0; }
            QTextEdit, QLineEdit, QComboBox, QSpinBox {
                background-color: #2d2d2d;
                color: #e0e0e0;
                border: 1px solid #3a3a3a;
                border-radius: 5px;
                padding: 5px;
                selection-background-color: #3498db;
            }
            QTextEdit:focus, QLineEdit:focus, QComboBox:focus, QSpinBox:focus {
                border: 1px solid #3498db;
            }
            QPushButton {
                background-color: #3a3a3a;
                color: #e0e0e0;
                border: 1px solid #4a4a4a;
                border-radius: 5px;
                padding: 6px 12px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #4a4a4a;
                border-color: #3498db;
            }
            QPushButton:pressed {
                background-color: #2a2a2a;
            }
            QPushButton:disabled {
                background-color: #2a2a2a;
                color: #6a6a6a;
            }
            QTabWidget::pane {
                background: #252525;
                border: 1px solid #3a3a3a;
                border-radius: 5px;
            }
            QTabBar::tab {
                background: #2d2d2d;
                color: #c0c0c0;
                padding: 8px 16px;
                margin-right: 2px;
                border-top-left-radius: 5px;
                border-top-right-radius: 5px;
            }
            QTabBar::tab:selected {
                background: #252525;
                color: #3498db;
                border-bottom: 2px solid #3498db;
            }
            QTabBar::tab:hover {
                background: #3a3a3a;
                color: #e0e0e0;
            }
            QTreeWidget {
                background: #2d2d2d;
                color: #e0e0e0;
                alternate-background-color: #252525;
                border: 1px solid #3a3a3a;
                border-radius: 5px;
            }
            QHeaderView::section {
                background: #3a3a3a;
                color: #e0e0e0;
                padding: 5px;
                border: none;
            }
            QTreeWidget::item:hover {
                background: #3a3a3a;
            }
            QTreeWidget::item:selected {
                background: #3498db;
                color: #ffffff;
            }
            QGroupBox {
                border: 1px solid #3a3a3a;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 10px;
                font-weight: bold;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 8px;
                color: #3498db;
            }
            QScrollArea { border: none; background: transparent; }
            QScrollBar:vertical {
                background: #2d2d2d;
                width: 10px;
                border-radius: 5px;
            }
            QScrollBar::handle:vertical {
                background: #4a4a4a;
                border-radius: 5px;
                min-height: 20px;
            }
            QScrollBar::handle:vertical:hover {
                background: #5a5a5a;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                border: none;
                background: none;
            }
            QComboBox QAbstractItemView {
                background-color: #2d2d2d;
                color: #e0e0e0;
                selection-background-color: #3498db;
            }
                                       
            QScrollArea, QScrollArea > QWidget {
                background: transparent;
            }
            QScrollArea QWidget {
                background: #1e1e1e;
            }
        """)

    def _show_toast(self, msg: str, is_error=False):
        self.toast_label.setText(msg)
        self.toast_label.setStyleSheet("color: #e74c3c; font-style: italic;" if is_error else "color: #f39c12; font-style: italic;")
        QTimer.singleShot(5000, lambda: self.toast_label.setText(""))


# ----------------------------------------------------------------------
# Main entry point
# ----------------------------------------------------------------------
def main():
    app = QApplication(sys.argv)
    app.setAttribute(Qt.AA_UseHighDpiPixmaps)
    window = DomainFrontGUI()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()