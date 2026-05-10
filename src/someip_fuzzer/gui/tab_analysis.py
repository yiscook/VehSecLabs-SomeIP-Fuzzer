"""Tab 2 — 协议分析。

提供实时抓包（Npcap）和 pcap 文件加载，虚拟报文列表 + 字段树 + Hex View 三联面板。
"""

from __future__ import annotations

import socket
from pathlib import Path

import psutil
from PyQt6.QtCore import Qt, pyqtSlot
from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableView,
    QHeaderView,
    QVBoxLayout,
    QWidget,
    QAbstractItemView,
)

from someip_fuzzer.core.protocol import SomeIpPacket
from someip_fuzzer.gui.widgets.hex_view import HexView
from someip_fuzzer.gui.widgets.packet_table import PacketTableModel, PacketRow
from someip_fuzzer.gui.widgets.packet_tree import PacketTreeWidget


class AnalysisTab(QWidget):
    """Tab 2：协议分析。"""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._model = PacketTableModel(capacity=10000)
        self._build_ui()

    # ── UI 构建 ───────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(6)

        root.addWidget(self._build_control_bar())

        # 主区：上半 报文列表+字段树，下半 Hex
        splitter_v = QSplitter(Qt.Orientation.Vertical)

        # 上半：报文列表（左）+ 字段树（右）
        splitter_h = QSplitter(Qt.Orientation.Horizontal)
        splitter_h.addWidget(self._build_packet_list())
        splitter_h.addWidget(self._build_detail_panel())
        splitter_h.setSizes([620, 380])

        splitter_v.addWidget(splitter_h)
        splitter_v.addWidget(self._build_hex_panel())
        splitter_v.setSizes([400, 200])

        root.addWidget(splitter_v)
        root.addWidget(self._build_toolbar())

    def _build_control_bar(self) -> QWidget:
        bar = QWidget()
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        layout.addWidget(QLabel("抓包源："))
        self.cmb_source = QComboBox()
        self.cmb_source.addItem("📄  加载 pcap 文件", userData="file")
        self._load_interfaces()
        self.cmb_source.setMinimumWidth(240)
        layout.addWidget(self.cmb_source)

        layout.addWidget(QLabel("BPF 过滤："))
        self.edit_bpf = QLineEdit()
        self.edit_bpf.setPlaceholderText("例：udp port 30490  （留空不过滤）")
        self.edit_bpf.setMinimumWidth(220)
        layout.addWidget(self.edit_bpf)

        self.btn_open_file = QPushButton("📂  打开 pcap")
        self.btn_open_file.clicked.connect(self._open_pcap)
        layout.addWidget(self.btn_open_file)

        layout.addStretch()
        self.lbl_count = QLabel("共 0 条")
        layout.addWidget(self.lbl_count)
        return bar

    def _build_packet_list(self) -> QWidget:
        grp = QGroupBox("📋  报文列表")
        layout = QVBoxLayout(grp)
        layout.setContentsMargins(4, 4, 4, 4)

        self.table_view = QTableView()
        self.table_view.setModel(self._model)
        self.table_view.setAlternatingRowColors(True)
        self.table_view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table_view.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table_view.verticalHeader().setVisible(False)
        self.table_view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.table_view.horizontalHeader().setStretchLastSection(True)
        self.table_view.setShowGrid(False)
        self.table_view.selectionModel().currentRowChanged.connect(self._on_row_selected)
        layout.addWidget(self.table_view)
        return grp

    def _build_detail_panel(self) -> QWidget:
        grp = QGroupBox("🔍  字段详情")
        layout = QVBoxLayout(grp)
        layout.setContentsMargins(4, 4, 4, 4)
        self.packet_tree = PacketTreeWidget()
        self.packet_tree.set_hex_highlight_callback(self._on_field_selected)
        layout.addWidget(self.packet_tree)
        return grp

    def _build_hex_panel(self) -> QWidget:
        grp = QGroupBox("🔢  原始字节")
        layout = QVBoxLayout(grp)
        layout.setContentsMargins(4, 4, 4, 4)
        self.hex_view = HexView()
        layout.addWidget(self.hex_view)
        return grp

    def _build_toolbar(self) -> QWidget:
        bar = QWidget()
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        self.btn_add_corpus = QPushButton("➕  加入 corpus")
        self.btn_add_corpus.clicked.connect(self._add_to_corpus)
        layout.addWidget(self.btn_add_corpus)

        self.btn_export_pcap = QPushButton("📤  导出 pcap")
        self.btn_export_pcap.clicked.connect(self._export_pcap)
        layout.addWidget(self.btn_export_pcap)

        self.btn_clear = QPushButton("🗑  清空")
        self.btn_clear.clicked.connect(self._clear)
        layout.addWidget(self.btn_clear)

        layout.addStretch()

        layout.addWidget(QLabel("过滤："))
        self.edit_filter = QLineEdit()
        self.edit_filter.setPlaceholderText("关键字过滤...")
        self.edit_filter.setFixedWidth(180)
        self.edit_filter.textChanged.connect(self._apply_filter)
        layout.addWidget(self.edit_filter)
        return bar

    # ── 辅助：接口列表 ────────────────────────────────────────────────────────

    def _load_interfaces(self) -> None:
        try:
            for name, addr_list in psutil.net_if_addrs().items():
                ipv4 = [a.address for a in addr_list if a.family == socket.AF_INET]
                label = f"🔌  {name}  ({ipv4[0]})" if ipv4 else f"🔌  {name}"
                self.cmb_source.addItem(label, userData=name)
        except Exception:
            pass

    # ── 槽函数 ────────────────────────────────────────────────────────────────

    @pyqtSlot()
    def _open_pcap(self) -> None:
        path_str, _ = QFileDialog.getOpenFileName(
            self, "打开 pcap 文件", str(Path.cwd()), "PCAP 文件 (*.pcap *.pcapng)"
        )
        if not path_str:
            return
        self._load_pcap_file(Path(path_str))

    def _load_pcap_file(self, path: Path) -> None:
        try:
            from scapy.utils import rdpcap
            from scapy.contrib.automotive.someip import SOMEIP
            pkts = rdpcap(str(path))
            for raw_pkt in pkts:
                if SOMEIP in raw_pkt:
                    raw = bytes(raw_pkt[SOMEIP])
                    try:
                        pkt = SomeIpPacket.from_bytes(raw)
                        self.add_packet(pkt, direction="←")
                    except Exception:
                        self._model.add_raw(raw, direction="←")
        except Exception as exc:
            QMessageBox.warning(self, "加载失败", str(exc))

    def _on_row_selected(self, current, _previous) -> None:
        row = self._model.get_row(current.row())
        if row:
            self.packet_tree.show_row(row)
            self.hex_view.load(row.raw)

    def _on_field_selected(self, start: int, length: int) -> None:
        self.hex_view.highlight(start, length)

    @pyqtSlot()
    def _add_to_corpus(self) -> None:
        idx = self.table_view.currentIndex()
        row = self._model.get_row(idx.row())
        if row and row.raw:
            # 预留接口：后续集成 SeedCorpus
            QMessageBox.information(self, "已加入 corpus", f"报文 #{row.no} 已加入种子库")

    @pyqtSlot()
    def _export_pcap(self) -> None:
        path_str, _ = QFileDialog.getSaveFileName(
            self, "导出 pcap", str(Path.cwd() / "capture.pcap"), "PCAP 文件 (*.pcap)"
        )
        if not path_str:
            return
        try:
            from scapy.utils import wrpcap
            from scapy.contrib.automotive.someip import SOMEIP
            from scapy.layers.inet import UDP, IP
            pkts = []
            for i in range(len(self._model._buf)):
                row = self._model.get_row(i)
                if row and row.raw:
                    pkts.append(IP() / UDP() / SOMEIP(row.raw))
            wrpcap(path_str, pkts)
            QMessageBox.information(self, "导出成功", f"已导出 {len(pkts)} 条报文")
        except Exception as exc:
            QMessageBox.critical(self, "导出失败", str(exc))

    @pyqtSlot()
    def _clear(self) -> None:
        self._model.clear()
        self.packet_tree.clear()
        self.hex_view.load(b"")
        self._update_count()

    def _apply_filter(self, keyword: str) -> None:
        # 简单过滤：隐藏不含关键字的行（基于 Service ID / Method ID 文本）
        kw = keyword.strip().lower()
        for row_idx in range(len(self._model._buf)):
            row = self._model.get_row(row_idx)
            visible = (
                not kw
                or kw in f"0x{row.service_id:04x}"
                or kw in f"0x{row.method_id:04x}"
                or kw in row.msg_type.lower()
            ) if row else True
            self.table_view.setRowHidden(row_idx, not visible)

    def _update_count(self) -> None:
        self.lbl_count.setText(f"共 {len(self._model._buf)} 条")

    # ── 公开 API ─────────────────────────────────────────────────────────────

    def add_packet(self, pkt: SomeIpPacket, direction: str = "→", is_crash: bool = False) -> None:
        self._model.add_packet(pkt, direction=direction, is_crash=is_crash)
        self._update_count()
        # 自动滚动到底部
        self.table_view.scrollToBottom()

    def add_raw_bytes(self, raw: bytes, direction: str = "→", is_crash: bool = False) -> None:
        self._model.add_raw(raw, direction=direction, is_crash=is_crash)
        self._update_count()
        self.table_view.scrollToBottom()
