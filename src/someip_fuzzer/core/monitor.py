"""崩溃检测三融合模块（SPEC §4.7-4.9, 4.11-4.12）。

三种检测方式任一触发即判定崩溃：
  1. HeartbeatMonitor  — 每 N 包发一次合法心跳报文，响应超时 → 崩溃
  2. ResponseAnalyzer  — 分析响应报文的异常模式（错误码 / 格式错误）
  3. AgentClient       — 与 VM 内 HTTP Agent 通信，查询 vsomeipd 进程状态

严重度分级（SPEC §4.12）：
  critical → Agent 检测到 ASan 日志
  high     → 心跳超时（进程可能崩溃）
  medium   → 响应超时（连接异常）
  low      → 异常错误码响应（仍在响应但行为异常）
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from someip_fuzzer.core.protocol import MessageType, ReturnCode, SomeIpPacket
from someip_fuzzer.data.crash_store import CrashRecord

if TYPE_CHECKING:
    from someip_fuzzer.core.mutator import MutationResult


# ── CVSS 估算常量（按严重度预设）───────────────────────────────────────────────

_CVSS_BY_SEVERITY = {
    "critical": 9.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 3.0,
}


# ── 心跳检测 ──────────────────────────────────────────────────────────────────


class HeartbeatMonitor:
    """心跳检测器（SPEC §4.7）。

    每隔 ``interval`` 个 fuzz 包发一次已知合法请求，
    若响应超时则判定目标崩溃。
    """

    def __init__(
        self,
        interval: int = 100,
        timeout: float = 2.0,
        heartbeat_service_id: int = 0x0000,
        heartbeat_method_id: int = 0x0000,
    ) -> None:
        self.interval = interval
        self.timeout = timeout
        self._heartbeat_service_id = heartbeat_service_id
        self._heartbeat_method_id = heartbeat_method_id
        self._packet_count = 0

    def tick(self) -> bool:
        """每发一个 fuzz 包调用一次，返回 True 表示本次需要发送心跳。"""
        self._packet_count += 1
        return self._packet_count % self.interval == 0

    async def probe(self, transport: object) -> bool:
        """发送心跳报文，返回 True 表示目标存活（有响应），False 表示崩溃/无响应。"""
        heartbeat_pkt = SomeIpPacket.request(
            service_id=self._heartbeat_service_id,
            method_id=self._heartbeat_method_id,
            payload=b"ping",
        )
        try:
            await transport.send(heartbeat_pkt)  # type: ignore[attr-defined]
            response = await transport.recv(timeout=self.timeout)  # type: ignore[attr-defined]
            return response is not None
        except Exception:
            return False


# ── 响应异常分析 ──────────────────────────────────────────────────────────────


class ResponseAnalyzer:
    """响应报文异常模式识别（SPEC §4.8-4.9）。

    异常判定条件（任一满足）：
    - 响应为 None（超时）
    - 返回码为 E_MALFORMED_MESSAGE
    - 消息类型为 ERROR / ERROR_ACK
    - 返回码不在预期范围内（expected_msg_type 不匹配时）
    """

    # 触发"异常响应"判定的返回码
    ANOMALOUS_RETURN_CODES = {
        ReturnCode.E_MALFORMED_MESSAGE,
        ReturnCode.E_WRONG_PROTOCOL_VERSION,
        ReturnCode.E_WRONG_INTERFACE_VERSION,
        ReturnCode.E_WRONG_MESSAGE_TYPE,
    }

    def is_anomalous(
        self,
        response: SomeIpPacket | None,
        expected_msg_type: MessageType | None = None,
    ) -> bool:
        """检查响应是否异常。"""
        if response is None:
            return True  # 超时 = 异常
        if response.message_type in (MessageType.ERROR, MessageType.ERROR_ACK):
            return True
        if response.return_code in self.ANOMALOUS_RETURN_CODES:
            return True
        if (
            expected_msg_type is not None
            and response.message_type != expected_msg_type
        ):
            return True
        return False

    def classify(self, response: SomeIpPacket | None) -> str:
        """返回异常分类描述（return_code 优先于 message_type，更具体）。"""
        if response is None:
            return "timeout"
        if response.return_code in self.ANOMALOUS_RETURN_CODES:
            return "malformed_response"
        if response.message_type in (MessageType.ERROR, MessageType.ERROR_ACK):
            return "error_response"
        return "unexpected_type"


# ── 远程 Agent 客户端 ─────────────────────────────────────────────────────────


class AgentClient:
    """与 VM 内 scripts/agent.py 通信的 HTTP 客户端（SPEC §4.11）。

    当 Agent URL 未配置时，所有方法返回"存活/无日志"的默认值，
    使 CrashDetector 在无 VM 环境下仍可工作。
    """

    def __init__(self, agent_url: str | None = None, timeout: float = 3.0) -> None:
        self._url = agent_url
        self._timeout = timeout

    async def get_status(self) -> dict:
        """GET /status → {alive, pid, memory_mb, cpu_percent, asan_log}。"""
        if self._url is None:
            return {"alive": True, "pid": -1, "memory_mb": 0.0,
                    "cpu_percent": 0.0, "asan_log": None}
        try:
            import urllib.request
            import json as _json
            loop = asyncio.get_event_loop()
            url = self._url.rstrip("/") + "/status"
            raw = await loop.run_in_executor(
                None, lambda: urllib.request.urlopen(url, timeout=self._timeout).read()
            )
            return _json.loads(raw)
        except Exception:
            return {"alive": False, "pid": -1, "memory_mb": 0.0,
                    "cpu_percent": 0.0, "asan_log": None}

    async def is_alive(self) -> bool:
        status = await self.get_status()
        return bool(status.get("alive", True))

    async def get_asan_log(self) -> str | None:
        status = await self.get_status()
        return status.get("asan_log")


# ── 三融合崩溃检测器 ─────────────────────────────────────────────────────────


class CrashDetector:
    """三路融合崩溃判断器（SPEC §4.7-4.9）。

    调用顺序：
    1. ``ResponseAnalyzer`` — 立即分析已收到的响应（无网络开销）
    2. ``HeartbeatMonitor`` — 按间隔发心跳包（有网络开销，按 interval 控制频率）
    3. ``AgentClient``      — 查询 VM 内进程状态（可选，仅配置了 agent_url 时启用）

    用法::

        detector = CrashDetector(heartbeat=HeartbeatMonitor(),
                                 analyzer=ResponseAnalyzer(),
                                 agent=AgentClient("http://192.168.1.100:9999"))
        crash = await detector.check(transport, last_result, response)
        if crash:
            print(f"崩溃！严重度={crash.severity}")
    """

    def __init__(
        self,
        heartbeat: HeartbeatMonitor,
        analyzer: ResponseAnalyzer,
        agent: AgentClient | None = None,
        target_addr: tuple[str, int] = ("", 0),
    ) -> None:
        self._heartbeat = heartbeat
        self._analyzer = analyzer
        self._agent = agent or AgentClient()
        self._target_addr = target_addr

    async def check(
        self,
        transport: object,
        last_result: "MutationResult",
        response: SomeIpPacket | None,
    ) -> CrashRecord | None:
        """执行三路检测，返回 CrashRecord（崩溃）或 None（正常）。"""
        detection_method: str | None = None
        severity: str = "low"
        asan_log: str | None = None

        # --- 第一路：响应异常分析（最快，无网络开销）---
        if self._analyzer.is_anomalous(response):
            detection_method = self._analyzer.classify(response)
            severity = "medium" if response is None else "low"

        # --- 第二路：心跳检测（按 interval 控制频率）---
        if self._heartbeat.tick():
            alive = await self._heartbeat.probe(transport)
            if not alive:
                detection_method = "heartbeat"
                severity = "high"

        # --- 第三路：远程 Agent 检查（可选）---
        agent_alive = await self._agent.is_alive()
        if not agent_alive:
            asan_log = await self._agent.get_asan_log()
            detection_method = "agent"
            severity = "critical" if asan_log else "high"

        if detection_method is None:
            return None

        # 构造 CrashRecord
        ctx = {}
        if last_result.packet is not None:
            pkt = last_result.packet
            ctx = {
                "service_id": pkt.service_id,
                "method_id": pkt.method_id,
                "session_id": pkt.session_id,
                "message_type": (pkt.message_type.name
                                 if hasattr(pkt.message_type, "name")
                                 else f"0x{int(pkt.message_type):02X}"),
            }

        return CrashRecord(
            triggering_bytes=last_result.raw_bytes,
            mutator_name=last_result.mutator_name,
            severity=severity,
            cvss_score=_CVSS_BY_SEVERITY.get(severity, 3.0),
            detection_method=detection_method,
            asan_log=asan_log,
            target_addr=self._target_addr,
            context=ctx,
        )
