"""GUI ↔ 核心引擎信号桥。

核心引擎（asyncio 任务）通过此桥向 GUI 主线程发送信号，
GUI 通过槽函数控制引擎启停。
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from PyQt6.QtCore import QObject, pyqtSignal, pyqtSlot

from someip_fuzzer.core.engine import FuzzingEngine
from someip_fuzzer.utils.config import AppConfig

if TYPE_CHECKING:
    pass


class GuiBridge(QObject):
    """解耦 GUI 与核心引擎的信号槽桥接对象。"""

    # ── 核心引擎 → GUI ──────────────────────────────────────
    packet_sent = pyqtSignal(object)        # SomeIpPacket
    packet_received = pyqtSignal(object)    # SomeIpPacket
    crash_detected = pyqtSignal(dict)       # CrashInfo 字典
    state_changed = pyqtSignal(str, str)    # service_id, new_state
    stats_updated = pyqtSignal(dict)        # {"sent": int, "crashes": int, "pps": float}
    log_message = pyqtSignal(str, str)      # level, message
    connectivity_result = pyqtSignal(bool, str)  # ok, message

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._config: AppConfig | None = None
        self._running = False
        self._task: asyncio.Task | None = None  # type: ignore[type-arg]
        self._stop_event: asyncio.Event | None = None
        self._pause_event: asyncio.Event | None = None

    @property
    def is_running(self) -> bool:
        return self._running

    # ── 配置注入 ────────────────────────────────────────────

    def set_config(self, config: AppConfig) -> None:
        """由 MainWindow 在启动前注入当前靶机配置。"""
        self._config = config

    # ── GUI → 核心引擎 ──────────────────────────────────────

    @pyqtSlot()
    def start_fuzzing(self) -> None:
        if self._running:
            self.log_message.emit("WARNING", "模糊测试已在运行中，请先停止")
            return
        if self._config is None:
            self.log_message.emit("ERROR", "请先在 Tab 1 配置靶机信息")
            return

        self._stop_event = asyncio.Event()
        self._pause_event = asyncio.Event()
        self._running = True

        engine = FuzzingEngine()
        self._task = asyncio.ensure_future(
            engine.run(self._config, self, self._stop_event, self._pause_event)
        )
        self._task.add_done_callback(self._on_engine_done)
        self.log_message.emit(
            "INFO",
            f"▶ 模糊测试已启动 → {self._config.target.ip}:{self._config.target.port}",
        )
        self.connectivity_result.emit(
            True, f"{self._config.target.ip}:{self._config.target.port}"
        )

    @pyqtSlot()
    def stop_fuzzing(self) -> None:
        if not self._running:
            return
        if self._stop_event:
            self._stop_event.set()
        self.log_message.emit("INFO", "⏹ 正在停止…")

    @pyqtSlot()
    def pause_fuzzing(self) -> None:
        if not self._running or self._pause_event is None:
            return
        if self._pause_event.is_set():
            self._pause_event.clear()
            self.log_message.emit("INFO", "▶ 继续模糊测试")
        else:
            self._pause_event.set()
            self.log_message.emit("INFO", "⏸ 模糊测试已暂停")

    @pyqtSlot(list)
    def update_mutation_config(self, enabled_names: list[str]) -> None:
        """接收 GUI 策略树选中的变异器名单，预留给核心引擎调度器同步。"""
        self.log_message.emit("INFO", f"策略配置更新：{len(enabled_names)} 个变异器启用")

    # ── 内部回调 ────────────────────────────────────────────

    def _on_engine_done(self, task: asyncio.Task) -> None:  # type: ignore[type-arg]
        self._running = False
        self.connectivity_result.emit(False, "")
        if task.cancelled():
            self.log_message.emit("INFO", "⏹ 模糊测试已取消")
            return
        exc = task.exception()
        if exc:
            self.log_message.emit("ERROR", f"引擎异常退出：{exc}")
        self.log_message.emit("INFO", "⏹ 模糊测试已停止")
