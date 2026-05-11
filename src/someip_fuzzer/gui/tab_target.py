"""Tab 1 — 目标配置。

涵盖：靶机网络配置、SOME/IP 服务定义表格、连通性测试、TOML 导入/导出。
"""

from __future__ import annotations

import asyncio
import socket
from pathlib import Path

import psutil
from PyQt6.QtCore import Qt, QTimer, pyqtSlot
from PyQt6.QtGui import QIntValidator
from PyQt6.QtWidgets import (
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
    QComboBox,
    QSizePolicy,
)

from someip_fuzzer.utils.config import AppConfig, ServiceDef, SdConfig, TargetConfig, load_config, save_config


_DEFAULT_TEMPLATES: dict[str, AppConfig] = {
    "vsomeip 默认": AppConfig(
        target=TargetConfig(
            name="vsomeip 默认靶机",
            ip="192.168.81.129",
            port=30509,
            transport="udp",
            interface="VMnet8",
        ),
        sd=SdConfig(multicast="224.224.224.245", port=30490),
        services=[
            ServiceDef(service_id=0x1111, instance_id=0x2222, major_version=0, minor_version=0,
                       methods=[0x3333], events=[]),
        ],
    ),
    "空模板": AppConfig(),
}


class TargetTab(QWidget):
    """Tab 1：目标配置。"""

    def __init__(self, bridge=None, parent=None) -> None:
        super().__init__(parent)
        self._bridge = bridge
        self._recent_configs: list[Path] = []
        self._current_path: Path | None = None

        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(12, 12, 12, 12)
        root_layout.setSpacing(12)

        root_layout.addWidget(self._build_network_group())
        root_layout.addWidget(self._build_services_group())
        root_layout.addWidget(self._build_config_group())
        root_layout.addStretch()

    # ── 靶机网络配置组 ────────────────────────────────────────────────────────

    def _build_network_group(self) -> QGroupBox:
        grp = QGroupBox("靶机网络配置")
        layout = QVBoxLayout(grp)
        layout.setSpacing(8)

        # IP 地址（可编辑下拉框，保留历史）
        row_ip = QHBoxLayout()
        row_ip.addWidget(QLabel("IP 地址："))
        self.cmb_ip = QComboBox()
        self.cmb_ip.setEditable(True)
        self.cmb_ip.setInsertPolicy(QComboBox.InsertPolicy.InsertAtTop)
        self.cmb_ip.addItem("192.168.81.128")
        self.cmb_ip.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        row_ip.addWidget(self.cmb_ip)
        layout.addLayout(row_ip)

        # 端口
        row_port = QHBoxLayout()
        row_port.addWidget(QLabel("端口："))
        self.spin_port = QSpinBox()
        self.spin_port.setRange(1, 65535)
        self.spin_port.setValue(30509)
        self.spin_port.setFixedWidth(100)
        row_port.addWidget(self.spin_port)
        row_port.addStretch()
        layout.addLayout(row_port)

        # 传输协议
        row_proto = QHBoxLayout()
        row_proto.addWidget(QLabel("传输协议："))
        self.radio_udp = QRadioButton("UDP")
        self.radio_tcp = QRadioButton("TCP")
        self.radio_both = QRadioButton("TCP+UDP")
        self.radio_udp.setChecked(True)
        row_proto.addWidget(self.radio_udp)
        row_proto.addWidget(self.radio_tcp)
        row_proto.addWidget(self.radio_both)
        row_proto.addStretch()
        layout.addLayout(row_proto)

        # 网络接口
        row_iface = QHBoxLayout()
        row_iface.addWidget(QLabel("网络接口："))
        self.cmb_iface = QComboBox()
        self.cmb_iface.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self._load_network_interfaces()
        row_iface.addWidget(self.cmb_iface)
        layout.addLayout(row_iface)

        # SD 多播
        row_sd = QHBoxLayout()
        row_sd.addWidget(QLabel("SD 多播组："))
        self.edit_sd_mc = QLineEdit("224.224.224.245")
        self.edit_sd_mc.setFixedWidth(160)
        row_sd.addWidget(self.edit_sd_mc)
        row_sd.addWidget(QLabel("端口："))
        self.spin_sd_port = QSpinBox()
        self.spin_sd_port.setRange(1, 65535)
        self.spin_sd_port.setValue(30490)
        self.spin_sd_port.setFixedWidth(80)
        row_sd.addWidget(self.spin_sd_port)
        row_sd.addStretch()
        layout.addLayout(row_sd)

        # 连通性测试
        row_ping = QHBoxLayout()
        self.btn_ping = QPushButton("连通性测试")
        self.btn_ping.setObjectName("btn_primary")
        self.btn_ping.setFixedWidth(140)
        self.btn_ping.clicked.connect(self._on_ping_clicked)
        self.lbl_ping_result = QLabel("")
        row_ping.addWidget(self.btn_ping)
        row_ping.addWidget(self.lbl_ping_result)
        row_ping.addStretch()
        layout.addLayout(row_ping)

        return grp

    # ── 服务定义表格组 ────────────────────────────────────────────────────────

    def _build_services_group(self) -> QGroupBox:
        grp = QGroupBox("SOME/IP 服务定义")
        layout = QVBoxLayout(grp)
        layout.setSpacing(6)

        self.tbl_services = QTableWidget(0, 6)
        self.tbl_services.setHorizontalHeaderLabels(
            ["Service ID", "Instance ID", "Major", "Minor", "Methods", "Events"]
        )
        self.tbl_services.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.tbl_services.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.tbl_services.setAlternatingRowColors(True)
        self.tbl_services.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.tbl_services.setMinimumHeight(160)
        layout.addWidget(self.tbl_services)

        row_btns = QHBoxLayout()
        self.btn_add_row = QPushButton("+ 添加")
        self.btn_add_row.clicked.connect(self._add_service_row)
        self.btn_del_row = QPushButton("- 删除")
        self.btn_del_row.clicked.connect(self._del_service_row)
        row_btns.addWidget(self.btn_add_row)
        row_btns.addWidget(self.btn_del_row)
        row_btns.addStretch()
        layout.addLayout(row_btns)

        return grp

    # ── 配置管理组 ────────────────────────────────────────────────────────────

    def _build_config_group(self) -> QGroupBox:
        grp = QGroupBox("配置管理")
        layout = QHBoxLayout(grp)
        layout.setSpacing(10)

        layout.addWidget(QLabel("模板："))
        self.cmb_template = QComboBox()
        self.cmb_template.addItems(list(_DEFAULT_TEMPLATES.keys()))
        self.cmb_template.currentTextChanged.connect(self._on_template_changed)
        layout.addWidget(self.cmb_template)

        layout.addSpacing(16)

        self.btn_import = QPushButton("导入 TOML")
        self.btn_import.clicked.connect(self._import_config)
        self.btn_export = QPushButton("导出 TOML")
        self.btn_export.clicked.connect(self._export_config)
        layout.addWidget(self.btn_import)
        layout.addWidget(self.btn_export)

        layout.addSpacing(16)
        self.lbl_current_path = QLabel("（未保存）")
        self.lbl_current_path.setStyleSheet("color: #8C959F; font-size: 11px;")
        layout.addWidget(self.lbl_current_path)
        layout.addStretch()

        return grp

    # ── 辅助：加载网卡列表 ────────────────────────────────────────────────────

    def _load_network_interfaces(self) -> None:
        self.cmb_iface.clear()
        self.cmb_iface.addItem("")  # 空 = 系统默认
        try:
            addrs = psutil.net_if_addrs()
            for name, addr_list in addrs.items():
                ipv4 = [a.address for a in addr_list if a.family == socket.AF_INET]
                label = f"{name}  ({ipv4[0]})" if ipv4 else name
                self.cmb_iface.addItem(label, userData=name)
        except Exception:
            pass

    # ── 辅助：连通性测试（同步 UDP ping） ────────────────────────────────────

    @pyqtSlot()
    def _on_ping_clicked(self) -> None:
        self.btn_ping.setEnabled(False)
        self.lbl_ping_result.setText("测试中…")
        QTimer.singleShot(0, self._do_ping)

    def _do_ping(self) -> None:
        ip = self.cmb_ip.currentText().strip()
        port = self.spin_port.value()
        target_str = f"{ip}:{port}"
        ok = False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0)
            # 发送配置的第一个 Service ID 探针（16 字节头）
            svc_id = 0x1111
            if self.tbl_services.rowCount() > 0:
                item = self.tbl_services.item(0, 0)
                if item:
                    try:
                        svc_id = int(item.text().strip(), 16)
                    except ValueError:
                        pass
            probe = bytes([
                (svc_id >> 8) & 0xFF, svc_id & 0xFF,  # Service ID
                0x00, 0x01,                              # Method ID
                0x00, 0x00, 0x00, 0x08,                 # Length
                0xDE, 0xAD, 0xBE, 0xEF,                 # Client/Session ID
                0x01, 0x01, 0x00, 0x00,                 # Proto/Iface/Type/RC
            ])
            sock.sendto(probe, (ip, port))
            try:
                sock.recvfrom(256)
                self.lbl_ping_result.setObjectName("label_status_ok")
                self.lbl_ping_result.setText(f"{target_str} — 已响应")
                ok = True
            except socket.timeout:
                # UDP 无响应是正常的 — vsomeip 静默丢弃未知服务请求
                self.lbl_ping_result.setObjectName("label_status_ok")
                self.lbl_ping_result.setText(f"{target_str} — 端口可达（UDP 无响应属正常）")
                ok = True
            finally:
                sock.close()
        except OSError as exc:
            self.lbl_ping_result.setObjectName("label_status_err")
            self.lbl_ping_result.setText(f"连接失败：{exc}")
        self.lbl_ping_result.style().unpolish(self.lbl_ping_result)
        self.lbl_ping_result.style().polish(self.lbl_ping_result)
        self.btn_ping.setEnabled(True)
        if self._bridge is not None:
            self._bridge.connectivity_result.emit(ok, target_str if ok else "")

    # ── 辅助：表格增删行 ──────────────────────────────────────────────────────

    @pyqtSlot()
    def _add_service_row(self) -> None:
        row = self.tbl_services.rowCount()
        self.tbl_services.insertRow(row)
        defaults = ["0x1234", "0x0001", "1", "0", "0x8001", ""]
        for col, val in enumerate(defaults):
            self.tbl_services.setItem(row, col, QTableWidgetItem(val))

    @pyqtSlot()
    def _del_service_row(self) -> None:
        rows = sorted({idx.row() for idx in self.tbl_services.selectedIndexes()}, reverse=True)
        for row in rows:
            self.tbl_services.removeRow(row)

    # ── 辅助：模板切换 ────────────────────────────────────────────────────────

    def _on_template_changed(self, template_name: str) -> None:
        cfg = _DEFAULT_TEMPLATES.get(template_name)
        if cfg:
            self.load_config_obj(cfg)

    # ── 公开 API：加载 / 保存配置对象 ────────────────────────────────────────

    def load_config_obj(self, cfg: AppConfig) -> None:
        """将 AppConfig 对象填充到界面控件。"""
        self.cmb_ip.setCurrentText(cfg.target.ip)
        self.spin_port.setValue(cfg.target.port)
        transport = cfg.target.transport.lower()
        if transport == "tcp":
            self.radio_tcp.setChecked(True)
        elif transport in ("tcp+udp", "both"):
            self.radio_both.setChecked(True)
        else:
            self.radio_udp.setChecked(True)

        # 网卡
        for i in range(self.cmb_iface.count()):
            if self.cmb_iface.itemData(i) == cfg.target.interface:
                self.cmb_iface.setCurrentIndex(i)
                break

        self.edit_sd_mc.setText(cfg.sd.multicast)
        self.spin_sd_port.setValue(cfg.sd.port)

        self.tbl_services.setRowCount(0)
        for svc in cfg.services:
            row = self.tbl_services.rowCount()
            self.tbl_services.insertRow(row)
            self.tbl_services.setItem(row, 0, QTableWidgetItem(f"0x{svc.service_id:04X}"))
            self.tbl_services.setItem(row, 1, QTableWidgetItem(f"0x{svc.instance_id:04X}"))
            self.tbl_services.setItem(row, 2, QTableWidgetItem(str(svc.major_version)))
            self.tbl_services.setItem(row, 3, QTableWidgetItem(str(svc.minor_version)))
            methods_str = ",".join(f"0x{m:04X}" for m in svc.methods)
            events_str = ",".join(f"0x{e:04X}" for e in svc.events)
            self.tbl_services.setItem(row, 4, QTableWidgetItem(methods_str))
            self.tbl_services.setItem(row, 5, QTableWidgetItem(events_str))

    def build_config_obj(self) -> AppConfig:
        """从界面控件读取并构建 AppConfig 对象。"""
        transport = "udp"
        if self.radio_tcp.isChecked():
            transport = "tcp"
        elif self.radio_both.isChecked():
            transport = "tcp+udp"

        iface_name = self.cmb_iface.currentData() or ""

        target = TargetConfig(
            name="自定义",
            ip=self.cmb_ip.currentText().strip(),
            port=self.spin_port.value(),
            transport=transport,
            interface=iface_name,
        )
        sd = SdConfig(
            multicast=self.edit_sd_mc.text().strip(),
            port=self.spin_sd_port.value(),
        )

        services: list[ServiceDef] = []
        for row in range(self.tbl_services.rowCount()):
            def cell(c: int) -> str:
                item = self.tbl_services.item(row, c)
                return item.text().strip() if item else ""

            def parse_hex(s: str) -> int:
                try:
                    return int(s, 16) if s.startswith("0x") or s.startswith("0X") else int(s, 0)
                except ValueError:
                    return 0

            def parse_list(s: str) -> list[int]:
                return [parse_hex(v.strip()) for v in s.split(",") if v.strip()]

            services.append(ServiceDef(
                service_id=parse_hex(cell(0)),
                instance_id=parse_hex(cell(1)),
                major_version=int(cell(2) or "1"),
                minor_version=int(cell(3) or "0"),
                methods=parse_list(cell(4)),
                events=parse_list(cell(5)),
            ))

        return AppConfig(target=target, sd=sd, services=services)

    def save_config(self, path: Path) -> None:
        """将当前配置保存到指定路径。"""
        cfg = self.build_config_obj()
        save_config(cfg, path)
        self._current_path = path
        self.lbl_current_path.setText(str(path))

    def load_config(self, path: Path) -> None:
        """从指定路径加载配置并填充界面。"""
        cfg = load_config(path)
        self.load_config_obj(cfg)
        self._current_path = path
        self.lbl_current_path.setText(str(path))

    # ── 导入 / 导出槽 ─────────────────────────────────────────────────────────

    @pyqtSlot()
    def _import_config(self) -> None:
        path_str, _ = QFileDialog.getOpenFileName(
            self, "导入配置", str(Path.cwd()), "TOML 配置文件 (*.toml)"
        )
        if not path_str:
            return
        try:
            self.load_config(Path(path_str))
            self._recent_configs.insert(0, Path(path_str))
        except Exception as exc:
            QMessageBox.critical(self, "导入失败", str(exc))

    @pyqtSlot()
    def _export_config(self) -> None:
        default = str(self._current_path or Path.cwd() / "target.toml")
        path_str, _ = QFileDialog.getSaveFileName(
            self, "导出配置", default, "TOML 配置文件 (*.toml)"
        )
        if not path_str:
            return
        try:
            self.save_config(Path(path_str))
            QMessageBox.information(self, "导出成功", f"已保存至：\n{path_str}")
        except Exception as exc:
            QMessageBox.critical(self, "导出失败", str(exc))
