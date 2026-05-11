"""Tab 3 — 模糊测试。

三栏布局：左侧策略控制 | 中央报文流 + 日志 | 右侧实时统计 + 状态机。
"""

from __future__ import annotations

from pathlib import Path

from PyQt6.QtCore import Qt, pyqtSlot
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from someip_fuzzer.gui.widgets.log_view import LogViewWidget
from someip_fuzzer.gui.widgets.packet_stream import PacketStreamWidget
from someip_fuzzer.gui.widgets.stats_charts import StatsChartsWidget
from someip_fuzzer.gui.widgets.state_view import StateViewWidget
from someip_fuzzer.gui.widgets.strategy_tree import StrategyTreeWidget


class FuzzerTab(QWidget):
    """Tab 3：模糊测试。"""

    def __init__(self, bridge=None, parent=None) -> None:
        super().__init__(parent)
        self._bridge = bridge
        self._running = False
        self._build_ui()
        if bridge:
            self._connect_bridge()

    # ── UI 构建 ───────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        root = QHBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(6)

        # 左侧：策略 + 参数 + 启停按钮
        left = self._build_left_panel()
        left.setFixedWidth(240)

        # 中央：报文流 + 日志（垂直分割）
        center = self._build_center_panel()

        # 右侧：图表 + 状态机
        right = self._build_right_panel()
        right.setFixedWidth(220)

        root.addWidget(left)
        root.addWidget(center, stretch=1)
        root.addWidget(right)

    def _build_left_panel(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        # 变异策略树
        self.strategy_tree = StrategyTreeWidget()
        self.strategy_tree.selection_changed.connect(self._on_strategy_changed)
        layout.addWidget(self.strategy_tree, stretch=1)

        # 攻击链选择
        grp_chain = QGroupBox("攻击链")
        chain_layout = QVBoxLayout(grp_chain)
        self.cmb_chain = QComboBox()
        self.cmb_chain.addItem("无（纯变异）", userData=None)
        self._load_attack_chains()
        chain_layout.addWidget(self.cmb_chain)
        layout.addWidget(grp_chain)

        # 测试参数
        grp_params = QGroupBox("测试参数")
        params_layout = QVBoxLayout(grp_params)

        row_cases = QHBoxLayout()
        row_cases.addWidget(QLabel("用例数:"))
        self.spin_cases = QSpinBox()
        self.spin_cases.setRange(1, 10_000_000)
        self.spin_cases.setValue(10000)
        row_cases.addWidget(self.spin_cases)
        params_layout.addLayout(row_cases)

        row_rate = QHBoxLayout()
        row_rate.addWidget(QLabel("速率(pps):"))
        self.spin_rate = QSpinBox()
        self.spin_rate.setRange(1, 10000)
        self.spin_rate.setValue(1000)
        row_rate.addWidget(self.spin_rate)
        params_layout.addLayout(row_rate)

        row_timeout = QHBoxLayout()
        row_timeout.addWidget(QLabel("超时(s):"))
        self.spin_timeout = QDoubleSpinBox()
        self.spin_timeout.setRange(0.1, 30.0)
        self.spin_timeout.setSingleStep(0.1)
        self.spin_timeout.setValue(2.0)
        row_timeout.addWidget(self.spin_timeout)
        params_layout.addLayout(row_timeout)

        layout.addWidget(grp_params)

        # pcap 导出选项
        grp_pcap = QGroupBox("抓包导出")
        pcap_layout = QVBoxLayout(grp_pcap)
        self.chk_pcap = QCheckBox("保存为 pcap 文件")
        pcap_layout.addWidget(self.chk_pcap)
        row_pcap = QHBoxLayout()
        self.edit_pcap_path = QLineEdit()
        self.edit_pcap_path.setPlaceholderText("输出路径…")
        self.edit_pcap_path.setEnabled(False)
        self.btn_pcap_browse = QPushButton("…")
        self.btn_pcap_browse.setFixedWidth(30)
        self.btn_pcap_browse.setEnabled(False)
        self.btn_pcap_browse.clicked.connect(self._browse_pcap_path)
        row_pcap.addWidget(self.edit_pcap_path)
        row_pcap.addWidget(self.btn_pcap_browse)
        pcap_layout.addLayout(row_pcap)
        self.chk_pcap.toggled.connect(self.edit_pcap_path.setEnabled)
        self.chk_pcap.toggled.connect(self.btn_pcap_browse.setEnabled)
        layout.addWidget(grp_pcap)

        # 启停按钮
        self.btn_start = QPushButton("开始 (F5)")
        self.btn_start.setObjectName("btn_primary")
        self.btn_start.clicked.connect(self.start_fuzzing)

        self.btn_pause = QPushButton("暂停 (F7)")
        self.btn_pause.clicked.connect(self.pause_fuzzing)

        self.btn_stop = QPushButton("停止 (F8)")
        self.btn_stop.setObjectName("btn_danger")
        self.btn_stop.clicked.connect(self.stop_fuzzing)

        layout.addWidget(self.btn_start)
        layout.addWidget(self.btn_pause)
        layout.addWidget(self.btn_stop)

        return panel

    def _build_center_panel(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        # 报文流（占主要空间）
        grp_stream = QGroupBox("实时报文流")
        stream_layout = QVBoxLayout(grp_stream)
        stream_layout.setContentsMargins(4, 4, 4, 4)
        self.packet_stream = PacketStreamWidget()
        stream_layout.addWidget(self.packet_stream)

        # 日志
        self.log_view = LogViewWidget()

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(grp_stream)
        splitter.addWidget(self.log_view)
        splitter.setSizes([520, 160])

        layout.addWidget(splitter)
        return panel

    def _build_right_panel(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        # 实时图表
        grp_chart = QGroupBox("实时统计")
        chart_layout = QVBoxLayout(grp_chart)
        chart_layout.setContentsMargins(4, 4, 4, 4)
        self.stats_charts = StatsChartsWidget()
        chart_layout.addWidget(self.stats_charts)
        layout.addWidget(grp_chart)

        # 状态机可视化
        grp_state = QGroupBox("状态机")
        state_layout = QVBoxLayout(grp_state)
        state_layout.setContentsMargins(4, 4, 4, 4)
        self.state_view = StateViewWidget()
        state_layout.addWidget(self.state_view)
        layout.addWidget(grp_state)

        layout.addStretch()
        return panel

    # ── 辅助：pcap 路径浏览 ──────────────────────────────────────────────────

    def _browse_pcap_path(self) -> None:
        path_str, _ = QFileDialog.getSaveFileName(
            self, "保存 pcap", str(Path.cwd() / "fuzzing.pcapng"), "PCAP 文件 (*.pcapng *.pcap)"
        )
        if path_str:
            self.edit_pcap_path.setText(path_str)

    # ── 辅助：加载攻击链 YAML ─────────────────────────────────────────────────

    def _load_attack_chains(self) -> None:
        chains_dir = Path(__file__).parents[3] / "configs" / "attack_chains"
        if not chains_dir.exists():
            return
        for yaml_file in sorted(chains_dir.glob("*.yaml")):
            self.cmb_chain.addItem(yaml_file.stem, userData=str(yaml_file))

    # ── 信号桥连接 ────────────────────────────────────────────────────────────

    def _connect_bridge(self) -> None:
        bridge = self._bridge
        bridge.packet_sent.connect(self._on_packet_sent)
        bridge.packet_received.connect(self._on_packet_received)
        bridge.crash_detected.connect(self._on_crash_detected)
        bridge.state_changed.connect(self._on_state_changed)
        bridge.stats_updated.connect(self._on_stats_updated)
        bridge.log_message.connect(self.log_view.append)

    # ── 槽函数 ────────────────────────────────────────────────────────────────

    @pyqtSlot(object)
    def _on_packet_sent(self, pkt) -> None:
        raw = pkt.to_bytes() if hasattr(pkt, "to_bytes") else b""
        self.packet_stream.add_sent(
            getattr(pkt, "service_id", 0),
            getattr(pkt, "method_id", 0),
            len(raw), raw,
        )
        self.stats_charts.record_sent()

    @pyqtSlot(object)
    def _on_packet_received(self, pkt) -> None:
        self.packet_stream.add_received(
            getattr(pkt, "service_id", 0),
            getattr(pkt, "method_id", 0),
            len(pkt.to_bytes()) if hasattr(pkt, "to_bytes") else 0,
        )

    @pyqtSlot(dict)
    def _on_crash_detected(self, info: dict) -> None:
        self.packet_stream.add_crash(
            info.get("service_id", 0),
            info.get("method_id", 0),
            info.get("length", 0),
        )
        self.stats_charts.record_crash()
        self.log_view.append("ERROR", f"崩溃：{info}")

    @pyqtSlot(str, str)
    def _on_state_changed(self, service_id: str, new_state: str) -> None:
        self.state_view.update_state(service_id, new_state)

    @pyqtSlot(dict)
    def _on_stats_updated(self, stats: dict) -> None:
        self.stats_charts.record_sent(stats.get("sent", 0))

    def _on_strategy_changed(self, enabled_names: list[str]) -> None:
        if self._bridge:
            self._bridge.update_mutation_config(enabled_names)

    # ── 公开控制 API ─────────────────────────────────────────────────────────

    @pyqtSlot()
    def start_fuzzing(self) -> None:
        self._running = True
        self.stats_charts.start()
        self.log_view.append("INFO", "模糊测试已启动")
        if self._bridge:
            if self.chk_pcap.isChecked() and self.edit_pcap_path.text().strip():
                self._bridge.set_pcap_path(Path(self.edit_pcap_path.text().strip()))
            else:
                self._bridge.set_pcap_path(None)
            self._bridge.start_fuzzing()

    @pyqtSlot()
    def pause_fuzzing(self) -> None:
        if self._bridge:
            self._bridge.pause_fuzzing()

    @pyqtSlot()
    def stop_fuzzing(self) -> None:
        self._running = False
        self.stats_charts.stop()
        self.log_view.append("INFO", "模糊测试已停止")
        if self._bridge:
            self._bridge.stop_fuzzing()

    def is_running(self) -> bool:
        return self._running

    def is_paused(self) -> bool:
        return self.packet_stream.is_paused()
