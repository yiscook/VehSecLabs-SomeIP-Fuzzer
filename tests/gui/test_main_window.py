"""主窗口 pytest-qt 测试。"""

from __future__ import annotations

import pytest
from PyQt6.QtWidgets import QApplication

from someip_fuzzer.gui.main_window import MainWindow


@pytest.fixture
def window(qtbot):
    win = MainWindow()
    qtbot.addWidget(win)
    return win


def test_window_has_five_tabs(window):
    assert window.tab_widget.count() == 5


def test_window_tab_labels(window):
    labels = [window.tab_widget.tabText(i) for i in range(5)]
    assert any("目标配置" in lbl for lbl in labels)
    assert any("协议分析" in lbl for lbl in labels)
    assert any("模糊测试" in lbl for lbl in labels)
    assert any("结果分析" in lbl for lbl in labels)
    assert any("报告生成" in lbl for lbl in labels)


def test_window_shows(window, qtbot):
    window.show()
    assert window.isVisible()


def test_status_bar_exists(window):
    assert window.statusBar() is not None


def test_project_tree_dock_exists(window):
    assert window.project_tree is not None


def test_bridge_not_running_initially(window):
    assert window.bridge.is_running is False


def test_bridge_start_requires_config(window):
    """未设置 config 时 start_fuzzing 不应进入 running 状态。"""
    window.bridge.start_fuzzing()
    assert window.bridge.is_running is False


def test_bridge_start_stop(window, monkeypatch):
    """设置 config 后 start_fuzzing → is_running=True；stop 后重置。"""
    from unittest.mock import MagicMock
    from someip_fuzzer.utils.config import AppConfig, TargetConfig

    # 注入最小配置
    cfg = AppConfig(target=TargetConfig(ip="127.0.0.1", port=30509))
    window.bridge.set_config(cfg)

    # Mock asyncio.ensure_future 避免实际创建异步任务
    mock_task = MagicMock()
    mock_task.cancelled.return_value = False
    mock_task.exception.return_value = None
    monkeypatch.setattr("someip_fuzzer.gui.bridge.asyncio.ensure_future",
                        lambda *a, **kw: mock_task)

    window.bridge.start_fuzzing()
    assert window.bridge.is_running is True

    # 模拟 engine 完成回调
    window.bridge._on_engine_done(mock_task)
    assert window.bridge.is_running is False


def test_tab_target_is_first_tab(window):
    from someip_fuzzer.gui.tab_target import TargetTab
    assert isinstance(window.tab_widget.widget(0), TargetTab)


def test_menubar_has_items(window):
    mb = window.menuBar()
    assert mb is not None
    assert mb.actions() != []


def test_toolbar_has_actions(window):
    toolbars = window.findChildren(type(window.findChild(type(None).__class__)))
    # 只检查工具栏动作是否存在
    from PyQt6.QtWidgets import QToolBar
    bars = [c for c in window.children() if isinstance(c, QToolBar)]
    assert len(bars) >= 1
    assert len(bars[0].actions()) >= 3
