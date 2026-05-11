"""Tab 4 — 结果分析。

布局：左侧崩溃列表 + 仪表盘 | 右侧崩溃详情（字段树 + HexView + CVSS 计算器 + 操作按钮）。
"""

from __future__ import annotations

import collections
from pathlib import Path

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
    QScrollArea,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from someip_fuzzer.data.crash_store import CrashRecord, CrashStorage
from someip_fuzzer.gui.widgets.crash_list import CrashListWidget
from someip_fuzzer.gui.widgets.cvss_calculator import CvssCalculatorWidget
from someip_fuzzer.gui.widgets.dashboard import DashboardWidget
from someip_fuzzer.gui.widgets.hex_view import HexView
from someip_fuzzer.gui.widgets.packet_tree import PacketTreeWidget


class ResultsTab(QWidget):
    """Tab 4：结果分析。"""

    def __init__(self, db_path: str = ":memory:", parent=None) -> None:
        super().__init__(parent)
        self._store = CrashStorage(db_path)
        self._current_crash: CrashRecord | None = None
        self._build_ui()
        self.refresh()

    def _build_ui(self) -> None:
        root = QHBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(6)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self._build_left())
        splitter.addWidget(self._build_right())
        splitter.setSizes([380, 700])
        root.addWidget(splitter)

    # ── 左侧面板 ──────────────────────────────────────────────────────────────

    def _build_left(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        # 过滤工具栏
        filter_bar = QHBoxLayout()
        self.edit_search = QLineEdit()
        self.edit_search.setPlaceholderText("搜索策略名…")
        self.edit_search.textChanged.connect(self._apply_filter)
        filter_bar.addWidget(self.edit_search)

        self.cmb_severity = QComboBox()
        self.cmb_severity.addItems(["全部", "critical", "high", "medium", "low"])
        self.cmb_severity.currentTextChanged.connect(self._apply_filter)
        filter_bar.addWidget(self.cmb_severity)
        layout.addLayout(filter_bar)

        # 崩溃列表
        grp_list = QGroupBox("崩溃记录")
        list_layout = QVBoxLayout(grp_list)
        list_layout.setContentsMargins(4, 4, 4, 4)
        self.crash_list = CrashListWidget()
        self.crash_list.crash_selected.connect(self._on_crash_selected)
        list_layout.addWidget(self.crash_list)
        layout.addWidget(grp_list, stretch=1)

        # 刷新按钮
        self.btn_refresh = QPushButton("刷新")
        self.btn_refresh.clicked.connect(self.refresh)
        layout.addWidget(self.btn_refresh)

        # 统计仪表盘
        grp_dash = QGroupBox("统计")
        dash_layout = QVBoxLayout(grp_dash)
        dash_layout.setContentsMargins(4, 4, 4, 4)
        self.dashboard = DashboardWidget()
        dash_layout.addWidget(self.dashboard)
        layout.addWidget(grp_dash)

        return panel

    # ── 右侧面板 ──────────────────────────────────────────────────────────────

    def _build_right(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        # 摘要信息
        self.lbl_info = QLabel("← 请在左侧选择一条崩溃记录")
        self.lbl_info.setWordWrap(True)
        self.lbl_info.setStyleSheet("font-size: 11pt; padding: 8px;")
        layout.addWidget(self.lbl_info)

        # 字段树 + HexView
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        inner = QWidget()
        inner_layout = QVBoxLayout(inner)
        inner_layout.setContentsMargins(0, 0, 0, 0)
        inner_layout.setSpacing(6)

        grp_tree = QGroupBox("字段树")
        tree_layout = QVBoxLayout(grp_tree)
        tree_layout.setContentsMargins(4, 4, 4, 4)
        self.packet_tree = PacketTreeWidget()
        self.packet_tree.set_hex_highlight_callback(self._on_field_selected)
        tree_layout.addWidget(self.packet_tree)
        inner_layout.addWidget(grp_tree)

        grp_hex = QGroupBox("原始字节（触发报文）")
        hex_layout = QVBoxLayout(grp_hex)
        hex_layout.setContentsMargins(4, 4, 4, 4)
        self.hex_view = HexView()
        hex_layout.addWidget(self.hex_view)
        inner_layout.addWidget(grp_hex)

        # CVSS 计算器
        self.cvss_calc = CvssCalculatorWidget()
        self.cvss_calc.score_changed.connect(self._on_cvss_changed)
        inner_layout.addWidget(self.cvss_calc)

        scroll.setWidget(inner)
        layout.addWidget(scroll, stretch=1)

        # 操作按钮
        btn_bar = QHBoxLayout()
        self.btn_replay = QPushButton("重放")
        self.btn_replay.clicked.connect(self._replay)
        self.btn_export = QPushButton("导出脚本")
        self.btn_export.clicked.connect(self._export_script)
        self.btn_copy = QPushButton("复制 Hex")
        self.btn_copy.clicked.connect(self._copy_hex)
        btn_bar.addWidget(self.btn_replay)
        btn_bar.addWidget(self.btn_export)
        btn_bar.addWidget(self.btn_copy)
        btn_bar.addStretch()
        layout.addLayout(btn_bar)

        return panel

    # ── 槽函数 ────────────────────────────────────────────────────────────────

    @pyqtSlot(object)
    def _on_crash_selected(self, rec: CrashRecord) -> None:
        self._current_crash = rec
        severity_label = {"critical": "[CRITICAL]", "high": "[HIGH]", "medium": "[MEDIUM]", "low": "[LOW]"}.get(rec.severity, "[?]")
        self.lbl_info.setText(
            f"{severity_label} <b>{rec.crash_id[:8]}…</b>  CVSS {rec.cvss_score:.1f}  |  "
            f"{rec.timestamp[:19].replace('T', ' ')}  |  策略：{rec.mutator_name}  |  "
            f"检测：{rec.detection_method}  |  "
            f"靶机：{rec.target_addr[0]}:{rec.target_addr[1]}"
        )
        self.packet_tree.show_row_bytes(rec.triggering_bytes)
        self.hex_view.load(rec.triggering_bytes)
        self.cvss_calc.set_score_from_record(rec.cvss_score)

    def _on_field_selected(self, start: int, length: int) -> None:
        self.hex_view.highlight(start, length)

    def _on_cvss_changed(self, score: float, vector: str) -> None:
        if self._current_crash:
            self._current_crash.context["cvss_vector"] = vector

    def _apply_filter(self) -> None:
        kw = self.edit_search.text().strip().lower()
        sev = self.cmb_severity.currentText()
        sev_filter = None if sev == "全部" else sev
        records = self._store.list_all(severity=sev_filter)
        if kw:
            records = [r for r in records if kw in r.mutator_name.lower()]
        self.crash_list.load(records)

    @pyqtSlot()
    def _replay(self) -> None:
        if not self._current_crash:
            return
        try:
            from someip_fuzzer.core.replay import ReplayScriptGenerator
            gen = ReplayScriptGenerator()
            path = gen.generate(self._current_crash, Path("results/crashes"))
            QMessageBox.information(self, "重放脚本已生成", f"脚本路径：\n{path}\n\n请手动运行脚本以触发重放。")
        except Exception as exc:
            QMessageBox.critical(self, "生成失败", str(exc))

    @pyqtSlot()
    def _export_script(self) -> None:
        if not self._current_crash:
            return
        path_str, _ = QFileDialog.getSaveFileName(
            self, "导出重放脚本", "crash_replay.py", "Python 脚本 (*.py)"
        )
        if not path_str:
            return
        try:
            from someip_fuzzer.core.replay import ReplayScriptGenerator
            gen = ReplayScriptGenerator()
            gen.generate(self._current_crash, Path(path_str).parent)
            QMessageBox.information(self, "导出成功", f"已保存至：\n{path_str}")
        except Exception as exc:
            QMessageBox.critical(self, "导出失败", str(exc))

    @pyqtSlot()
    def _copy_hex(self) -> None:
        if not self._current_crash:
            return
        from PyQt6.QtWidgets import QApplication
        hex_str = self._current_crash.triggering_bytes.hex(" ").upper()
        QApplication.clipboard().setText(hex_str)

    # ── 公开 API ─────────────────────────────────────────────────────────────

    @pyqtSlot()
    def refresh(self) -> None:
        """从 CrashStorage 重新加载数据。"""
        records = self._store.list_all()
        self.crash_list.load(records)
        self.dashboard.refresh(records)

    def load_crash(self, rec: CrashRecord) -> None:
        """外部调用，用于从 bridge 收到崩溃事件时追加记录。"""
        self._store.save(rec)
        self.refresh()

    def set_db_path(self, path: str) -> None:
        self._store = CrashStorage(path)
        self.refresh()
