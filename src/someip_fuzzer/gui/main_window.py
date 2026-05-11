"""主窗口 — PyQt6 + qasync 事件循环融合。"""

from __future__ import annotations

from pathlib import Path

from PyQt6.QtCore import QSettings, QTimer, Qt, pyqtSlot
from PyQt6.QtGui import QAction, QKeySequence
from PyQt6.QtWidgets import (
    QFileDialog,
    QLabel,
    QMainWindow,
    QMessageBox,
    QStatusBar,
    QTabWidget,
    QToolBar,
    QWidget,
)

from someip_fuzzer.gui.bridge import GuiBridge
from someip_fuzzer.gui.dialogs.about import AboutDialog
from someip_fuzzer.gui.tab_analysis import AnalysisTab
from someip_fuzzer.gui.tab_fuzzer import FuzzerTab
from someip_fuzzer.gui.tab_report import ReportTab
from someip_fuzzer.gui.tab_results import ResultsTab
from someip_fuzzer.gui.tab_target import TargetTab
from someip_fuzzer.gui.widgets.project_tree import ProjectTreeDock

_THEMES = {
    "深色": "style.qss",
    "亮色": "style_light.qss",
}
_SETTINGS_THEME_KEY = "ui/theme"


class _PlaceholderTab(QWidget):
    """尚未实现的 Tab 占位符。"""

    def __init__(self, name: str, parent=None) -> None:
        super().__init__(parent)
        from PyQt6.QtWidgets import QVBoxLayout
        layout = QVBoxLayout(self)
        label = QLabel(f"📦  {name}\n\n（Phase 6 / 7 实现）")
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        label.setStyleSheet("font-size: 16px;")
        layout.addWidget(label)


class MainWindow(QMainWindow):
    """应用主窗口。"""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("VehSecLabs SomeIP Fuzzer  v0.5.0")
        self.resize(1280, 800)

        self.bridge = GuiBridge(self)
        self._stats: dict = {"sent": 0, "crashes": 0, "pps": 0.0}
        self._settings = QSettings("VehSecLabs", "SomeIPFuzzer")

        self._apply_theme(self._settings.value(_SETTINGS_THEME_KEY, "深色"))
        self._setup_tabs()
        self._setup_toolbar()
        self._setup_menu()
        self._setup_status_bar()
        self._setup_dock()
        self._connect_bridge()
        self._setup_shortcuts()

        self._clock_timer = QTimer(self)
        self._clock_timer.timeout.connect(self._update_clock)
        self._clock_timer.start(1000)

    # ── 样式 / 主题 ───────────────────────────────────────────────────────────

    def _apply_theme(self, theme_name: str) -> None:
        filename = _THEMES.get(theme_name, "style.qss")
        qss_path = Path(__file__).parent / "resources" / filename
        if qss_path.exists():
            self.setStyleSheet(qss_path.read_text(encoding="utf-8"))
        self._current_theme = theme_name
        self._settings.setValue(_SETTINGS_THEME_KEY, theme_name)

    # ── Tab 容器 ──────────────────────────────────────────────────────────────

    def _setup_tabs(self) -> None:
        self.tab_widget = QTabWidget()
        self.tab_widget.setTabPosition(QTabWidget.TabPosition.North)

        self.tab_target = TargetTab()
        self.tab_analysis = AnalysisTab()
        self.tab_fuzzer = FuzzerTab(bridge=self.bridge)
        self.tab_results = ResultsTab()
        self.tab_report = ReportTab()
        self.tab_widget.addTab(self.tab_target, "🎯  目标配置")
        self.tab_widget.addTab(self.tab_analysis, "🔍  协议分析")
        self.tab_widget.addTab(self.tab_fuzzer, "⚡  模糊测试")
        self.tab_widget.addTab(self.tab_results, "📊  结果分析")
        self.tab_widget.addTab(self.tab_report, "📄  报告生成")

        self.setCentralWidget(self.tab_widget)

    # ── 工具栏 ────────────────────────────────────────────────────────────────

    def _setup_toolbar(self) -> None:
        tb = QToolBar("主工具栏")
        tb.setMovable(False)
        self.addToolBar(tb)

        self._act_start = QAction("▶  启动 F5", self)
        self._act_start.triggered.connect(self._on_start_fuzzing)
        tb.addAction(self._act_start)

        self._act_pause = QAction("⏸  暂停 F7", self)
        self._act_pause.triggered.connect(self.bridge.pause_fuzzing)
        tb.addAction(self._act_pause)

        self._act_stop = QAction("⏹  停止 F8", self)
        self._act_stop.triggered.connect(self.bridge.stop_fuzzing)
        tb.addAction(self._act_stop)

        tb.addSeparator()

        act_import = QAction("📥  导入", self)
        act_import.triggered.connect(self._action_import)
        tb.addAction(act_import)

        act_export = QAction("📤  导出", self)
        act_export.triggered.connect(self._action_export)
        tb.addAction(act_export)

        tb.addSeparator()

        act_report = QAction("📊  报告", self)
        act_report.triggered.connect(lambda: self.tab_widget.setCurrentIndex(4))
        tb.addAction(act_report)

    # ── 菜单栏 ────────────────────────────────────────────────────────────────

    def _setup_menu(self) -> None:
        mb = self.menuBar()

        # 文件
        m_file = mb.addMenu("文件(&F)")
        m_file.addAction("导入配置 (Ctrl+O)", self._action_import)
        m_file.addAction("导出配置 (Ctrl+S)", self._action_export)
        m_file.addSeparator()
        m_file.addAction("退出", self.close)

        # 视图
        m_view = mb.addMenu("视图(&V)")
        m_view.addAction("目标配置", lambda: self.tab_widget.setCurrentIndex(0))
        m_view.addAction("协议分析", lambda: self.tab_widget.setCurrentIndex(1))
        m_view.addAction("模糊测试", lambda: self.tab_widget.setCurrentIndex(2))
        m_view.addAction("结果分析", lambda: self.tab_widget.setCurrentIndex(3))
        m_view.addAction("报告生成", lambda: self.tab_widget.setCurrentIndex(4))
        m_view.addSeparator()
        m_theme = m_view.addMenu("主题")
        for theme_name in _THEMES:
            act = QAction(theme_name, self, checkable=True)
            act.setChecked(theme_name == self._current_theme)
            act.triggered.connect(lambda checked, n=theme_name: self._switch_theme(n))
            m_theme.addAction(act)
        self._theme_menu = m_theme

        # 工具
        m_tools = mb.addMenu("工具(&T)")
        m_tools.addAction("启动模糊测试 (F5)", self._on_start_fuzzing)
        m_tools.addAction("停止模糊测试 (F8)", self.bridge.stop_fuzzing)

        # 帮助
        m_help = mb.addMenu("帮助(&H)")
        m_help.addAction("关于", self._show_about)

    # ── 状态栏 ────────────────────────────────────────────────────────────────

    def _setup_status_bar(self) -> None:
        sb = QStatusBar()
        self.setStatusBar(sb)

        self._lbl_target = QLabel("🔴  未连接")
        self._lbl_sent = QLabel("已发送: 0")
        self._lbl_crashes = QLabel("崩溃: 0")
        self._lbl_pps = QLabel("速率: 0 pps")
        self._lbl_clock = QLabel("00:00:00")

        for lbl in (self._lbl_target, self._lbl_sent, self._lbl_crashes, self._lbl_pps, self._lbl_clock):
            sb.addPermanentWidget(lbl)
            sb.addPermanentWidget(_separator())

    # ── 左侧 Dock ────────────────────────────────────────────────────────────

    def _setup_dock(self) -> None:
        self.project_tree = ProjectTreeDock(self)
        self.addDockWidget(Qt.DockWidgetArea.LeftDockWidgetArea, self.project_tree)

    # ── 信号桥 ────────────────────────────────────────────────────────────────

    def _connect_bridge(self) -> None:
        self.bridge.stats_updated.connect(self._on_stats_updated)
        self.bridge.log_message.connect(self._on_log_message)
        self.bridge.crash_detected.connect(self._on_crash_detected)
        self.bridge.connectivity_result.connect(self._on_connectivity_result)

    # ── 全局快捷键 ────────────────────────────────────────────────────────────

    def _setup_shortcuts(self) -> None:
        shortcuts = [
            ("F5", self._on_start_fuzzing),
            ("F7", self.bridge.pause_fuzzing),
            ("F8", self.bridge.stop_fuzzing),
            ("Ctrl+S", self._action_export),
            ("Ctrl+O", self._action_import),
        ]
        for key, slot in shortcuts:
            act = QAction(self)
            act.setShortcut(QKeySequence(key))
            act.triggered.connect(slot)
            self.addAction(act)

    # ── 启动入口（从 Tab 1 读取配置再启动引擎） ──────────────────────────────

    @pyqtSlot()
    def _on_start_fuzzing(self) -> None:
        cfg = self.tab_target.build_config_obj()
        self.bridge.set_config(cfg)
        self.bridge.start_fuzzing()

    # ── 槽函数 ────────────────────────────────────────────────────────────────

    @pyqtSlot(dict)
    def _on_stats_updated(self, stats: dict) -> None:
        self._stats = stats
        self._lbl_sent.setText(f"已发送: {stats.get('sent', 0)}")
        self._lbl_crashes.setText(f"崩溃: {stats.get('crashes', 0)}")
        self._lbl_pps.setText(f"速率: {stats.get('pps', 0):.0f} pps")

    @pyqtSlot(str, str)
    def _on_log_message(self, level: str, message: str) -> None:
        self.statusBar().showMessage(f"[{level}] {message}", 5000)

    @pyqtSlot(dict)
    def _on_crash_detected(self, info: dict) -> None:
        crashes = self._stats.get("crashes", 0) + 1
        self._stats["crashes"] = crashes
        self._lbl_crashes.setText(f"崩溃: {crashes}")
        self.statusBar().showMessage(f"⚠️  检测到崩溃！{info}", 8000)

    @pyqtSlot(bool, str)
    def _on_connectivity_result(self, ok: bool, target: str) -> None:
        if ok:
            self._lbl_target.setText(f"🟢  {target}")
        else:
            self._lbl_target.setText("🔴  未连接")

    @pyqtSlot()
    def _update_clock(self) -> None:
        from datetime import datetime
        self._lbl_clock.setText(datetime.now().strftime("%H:%M:%S"))

    def _switch_theme(self, theme_name: str) -> None:
        self._apply_theme(theme_name)
        # 更新菜单勾选状态
        for act in self._theme_menu.actions():
            act.setChecked(act.text() == theme_name)

    def _action_import(self) -> None:
        path_str, _ = QFileDialog.getOpenFileName(
            self, "导入配置", str(Path.cwd()), "TOML 配置文件 (*.toml)"
        )
        if path_str:
            try:
                self.tab_target.load_config(Path(path_str))
                self.tab_widget.setCurrentIndex(0)
            except Exception as exc:
                QMessageBox.critical(self, "导入失败", str(exc))

    def _action_export(self) -> None:
        path_str, _ = QFileDialog.getSaveFileName(
            self, "导出配置", str(Path.cwd() / "target.toml"), "TOML 配置文件 (*.toml)"
        )
        if path_str:
            try:
                self.tab_target.save_config(Path(path_str))
                QMessageBox.information(self, "导出成功", f"已保存至：\n{path_str}")
            except Exception as exc:
                QMessageBox.critical(self, "导出失败", str(exc))

    def _show_about(self) -> None:
        AboutDialog(self).exec()

    def current_theme(self) -> str:
        return self._current_theme


def _separator() -> QLabel:
    sep = QLabel(" │ ")
    sep.setStyleSheet("color: #45475a;")
    return sep
