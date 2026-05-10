"""Tab 5 — 报告生成。

左侧配置面板 | 右侧 QTextBrowser HTML 预览。
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

from PyQt6.QtCore import Qt, pyqtSlot
from PyQt6.QtWidgets import (
    QCheckBox,
    QDateEdit,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QSplitter,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from someip_fuzzer.core.reporter import Reporter, ReportConfig
from someip_fuzzer.data.crash_store import CrashStorage


class ReportTab(QWidget):
    """Tab 5：报告生成。"""

    def __init__(self, db_path: str = ":memory:", parent=None) -> None:
        super().__init__(parent)
        self._store = CrashStorage(db_path)
        self._reporter = Reporter()
        self._build_ui()

    def _build_ui(self) -> None:
        root = QHBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(6)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self._build_config_panel())
        splitter.addWidget(self._build_preview_panel())
        splitter.setSizes([300, 780])
        root.addWidget(splitter)

    # ── 左侧配置面板 ──────────────────────────────────────────────────────────

    def _build_config_panel(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        # 报告类型
        grp_type = QGroupBox("📋  报告类型")
        type_layout = QVBoxLayout(grp_type)
        self.radio_full   = QRadioButton("完整测试报告")
        self.radio_vuln   = QRadioButton("漏洞披露报告")
        self.radio_exec   = QRadioButton("执行摘要")
        self.radio_full.setChecked(True)
        for r in (self.radio_full, self.radio_vuln, self.radio_exec):
            type_layout.addWidget(r)
        layout.addWidget(grp_type)

        # 时间范围
        grp_date = QGroupBox("📅  时间范围")
        date_layout = QVBoxLayout(grp_date)
        row_from = QHBoxLayout()
        row_from.addWidget(QLabel("起："))
        self.date_from = QDateEdit()
        self.date_from.setCalendarPopup(True)
        self.date_from.setDate(date.today())
        row_from.addWidget(self.date_from)
        row_to = QHBoxLayout()
        row_to.addWidget(QLabel("止："))
        self.date_to = QDateEdit()
        self.date_to.setCalendarPopup(True)
        self.date_to.setDate(date.today())
        row_to.addWidget(self.date_to)
        date_layout.addLayout(row_from)
        date_layout.addLayout(row_to)
        layout.addWidget(grp_date)

        # 章节勾选
        grp_sec = QGroupBox("✅  包含章节")
        sec_layout = QVBoxLayout(grp_sec)
        self.chk_method = QCheckBox("测试方法")
        self.chk_method.setChecked(True)
        self.chk_vuln   = QCheckBox("漏洞详情")
        self.chk_vuln.setChecked(True)
        self.chk_repro  = QCheckBox("复现步骤")
        self.chk_repro.setChecked(True)
        self.chk_rec    = QCheckBox("修复建议")
        self.chk_rec.setChecked(True)
        self.chk_cvss   = QCheckBox("CVSS 评分")
        self.chk_cvss.setChecked(True)
        self.chk_raw    = QCheckBox("原始数据附录")
        self.chk_raw.setChecked(False)
        for chk in (self.chk_method, self.chk_vuln, self.chk_repro, self.chk_rec, self.chk_cvss, self.chk_raw):
            sec_layout.addWidget(chk)
        layout.addWidget(grp_sec)

        # 自定义信息
        grp_custom = QGroupBox("🎨  自定义")
        custom_layout = QVBoxLayout(grp_custom)
        custom_layout.addWidget(QLabel("公司名称："))
        self.edit_company = QLineEdit("VehSecLabs")
        custom_layout.addWidget(self.edit_company)
        custom_layout.addWidget(QLabel("作者："))
        self.edit_author = QLineEdit()
        custom_layout.addWidget(self.edit_author)
        custom_layout.addWidget(QLabel("报告标题："))
        self.edit_title = QLineEdit("SOME/IP 模糊测试安全报告")
        custom_layout.addWidget(self.edit_title)
        layout.addWidget(grp_custom)

        # 操作按钮
        self.btn_preview = QPushButton("🔄  刷新预览")
        self.btn_preview.clicked.connect(self._refresh_preview)
        layout.addWidget(self.btn_preview)

        self.btn_pdf  = QPushButton("📄  导出 PDF")
        self.btn_html = QPushButton("🌐  导出 HTML")
        self.btn_docx = QPushButton("📝  导出 DOCX")
        self.btn_pdf.clicked.connect(lambda: self._export("pdf"))
        self.btn_html.clicked.connect(lambda: self._export("html"))
        self.btn_docx.clicked.connect(lambda: self._export("docx"))
        for btn in (self.btn_pdf, self.btn_html, self.btn_docx):
            layout.addWidget(btn)

        layout.addStretch()
        return panel

    # ── 右侧预览面板 ──────────────────────────────────────────────────────────

    def _build_preview_panel(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)

        grp = QGroupBox("📄  报告预览")
        grp_layout = QVBoxLayout(grp)
        grp_layout.setContentsMargins(4, 4, 4, 4)
        self.preview = QTextBrowser()
        self.preview.setOpenExternalLinks(False)
        grp_layout.addWidget(self.preview)
        layout.addWidget(grp)
        return panel

    # ── 内部辅助 ──────────────────────────────────────────────────────────────

    def _build_config(self) -> ReportConfig:
        return ReportConfig(
            title=self.edit_title.text().strip() or "SOME/IP 模糊测试安全报告",
            company=self.edit_company.text().strip() or "VehSecLabs",
            author=self.edit_author.text().strip(),
            include_methodology=self.chk_method.isChecked(),
            include_vulnerabilities=self.chk_vuln.isChecked(),
            include_reproduction=self.chk_repro.isChecked(),
            include_recommendations=self.chk_rec.isChecked(),
            include_cvss=self.chk_cvss.isChecked(),
            include_raw_appendix=self.chk_raw.isChecked(),
        )

    def _build_session(self) -> dict:
        return {
            "id": f"SESS-{date.today().strftime('%Y%m%d')}-001",
            "target": "—",
            "date": date.today().isoformat(),
            "transport": "UDP",
            "sent": 0,
            "duration": 0,
        }

    # ── 槽函数 ────────────────────────────────────────────────────────────────

    @pyqtSlot()
    def _refresh_preview(self) -> None:
        try:
            crashes = self._store.list_all()
            html = self._reporter.render_html(self._build_session(), crashes, self._build_config())
            self.preview.setHtml(html)
        except Exception as exc:
            self.preview.setPlainText(f"预览失败：{exc}")

    def _export(self, fmt: str) -> None:
        ext_map = {"pdf": "PDF 文件 (*.pdf)", "html": "HTML 文件 (*.html)", "docx": "Word 文件 (*.docx)"}
        path_str, _ = QFileDialog.getSaveFileName(
            self, f"导出 {fmt.upper()} 报告",
            f"report.{fmt}", ext_map.get(fmt, f"文件 (*.{fmt})")
        )
        if not path_str:
            return
        try:
            crashes = self._store.list_all()
            config  = self._build_config()
            session = self._build_session()
            output  = Path(path_str)
            if fmt == "html":
                self._reporter.to_html(session, crashes, config, output)
            elif fmt == "pdf":
                self._reporter.to_pdf(session, crashes, config, output)
            elif fmt == "docx":
                self._reporter.to_docx(session, crashes, config, output)
            QMessageBox.information(self, "导出成功", f"已保存至：\n{path_str}")
        except Exception as exc:
            QMessageBox.critical(self, "导出失败", str(exc))

    # ── 公开 API ─────────────────────────────────────────────────────────────

    def set_db_path(self, path: str) -> None:
        self._store = CrashStorage(path)

    def set_session_info(self, session: dict) -> None:
        """由主窗口注入当前会话信息（靶机、发包量等）。"""
        self._session_override = session
