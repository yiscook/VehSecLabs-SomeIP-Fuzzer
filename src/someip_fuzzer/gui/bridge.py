"""GUI ↔ 核心引擎信号桥。

核心引擎（asyncio 任务）通过此桥向 GUI 主线程发送信号，
GUI 通过槽函数控制引擎启停。
"""

from __future__ import annotations

from PyQt6.QtCore import QObject, pyqtSignal, pyqtSlot


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
        self._running = False

    @property
    def is_running(self) -> bool:
        return self._running

    # ── GUI → 核心引擎 ──────────────────────────────────────
    @pyqtSlot()
    def start_fuzzing(self) -> None:
        self._running = True
        self.log_message.emit("INFO", "模糊测试已启动")

    @pyqtSlot()
    def stop_fuzzing(self) -> None:
        self._running = False
        self.log_message.emit("INFO", "模糊测试已停止")

    @pyqtSlot()
    def pause_fuzzing(self) -> None:
        self.log_message.emit("INFO", "模糊测试已暂停")

    @pyqtSlot(list)
    def update_mutation_config(self, enabled_names: list[str]) -> None:
        """接收 GUI 策略树选中的变异器名单，预留给核心引擎调度器同步。"""
        self.log_message.emit("INFO", f"策略配置更新：{len(enabled_names)} 个变异器启用")
