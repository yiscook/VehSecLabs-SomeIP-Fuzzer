"""E2E 8.13 — 报告生成完整性。

验证：
1. 从真实 CrashRecord 生成 HTML 报告，包含所有必需章节
2. PDF 输出文件非空（WeasyPrint 可用且 GTK 库存在时）
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from someip_fuzzer.core.reporter import ReportConfig, Reporter
from someip_fuzzer.data.crash_store import CrashRecord, CrashStorage
from tests.e2e.conftest import VM_IP, VM_PORT

_SESSION = {
    "id": "E2E-TEST-001",
    "target": f"{VM_IP}:{VM_PORT}",
    "sent": 456,
    "duration": 147,
    "date": "2026-05-11",
}


def _make_crash() -> CrashRecord:
    return CrashRecord(
        triggering_bytes=bytes.fromhex("1111" + "3333" + "00000008" + "00000001" + "01010200"),
        mutator_name="L1-L01.zero_length",
        severity="high",
        cvss_score=7.5,
        detection_method="agent",
        target_addr=(VM_IP, VM_PORT),
        context={"service_id": 0x1111, "method_id": 0x3333},
    )


def test_html_report_contains_required_sections() -> None:
    """HTML 报告包含摘要、崩溃列表、崩溃详情章节及 CVSS 分数。"""
    crash = _make_crash()

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "crashes.db"
        # 显式关闭 DB 后再生成报告（避免 Windows 文件锁）
        store = CrashStorage(db_path)
        store.save(crash)
        crashes = store.list_all()
        store.close()

        output = Path(tmpdir) / "report.html"
        config = ReportConfig(title="E2E 测试报告", company="VehSecLabs", author="测试")
        reporter = Reporter()
        reporter.to_html(_SESSION, crashes, config, output)
        html = output.read_text(encoding="utf-8")

    assert len(html) > 500, "HTML 报告内容过短"
    assert "执行摘要" in html or "Summary" in html, "缺少执行摘要章节"
    assert "7.5" in html or "7.50" in html, "缺少 CVSS 分数"
    assert "L1-L01" in html or "zero_length" in html, "缺少变异器名称"


def test_pdf_report_generates() -> None:
    """PDF 报告文件生成且非空（WeasyPrint + GTK 完整安装时）。"""
    try:
        import weasyprint
        from weasyprint import HTML as _HTML  # noqa: F401 — 触发 GTK 加载
    except (ImportError, OSError):
        pytest.skip("WeasyPrint 或 GTK 依赖不可用，跳过 PDF 生成测试")

    crash = _make_crash()

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "crashes.db"
        store = CrashStorage(db_path)
        store.save(crash)
        crashes = store.list_all()
        store.close()

        pdf_path = Path(tmpdir) / "report.pdf"
        config = ReportConfig(title="E2E PDF 测试", company="VehSecLabs", author="测试")
        reporter = Reporter()
        reporter.to_pdf(_SESSION, crashes, config, pdf_path)

    assert pdf_path.exists(), "PDF 文件未生成"
    assert pdf_path.stat().st_size > 1000, f"PDF 文件过小：{pdf_path.stat().st_size} bytes"
