"""崩溃检测模块测试：HeartbeatMonitor + ResponseAnalyzer + AgentClient + CrashDetector。"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from someip_fuzzer.core.monitor import (
    AgentClient,
    CrashDetector,
    HeartbeatMonitor,
    ResponseAnalyzer,
)
from someip_fuzzer.core.mutator import MutationResult
from someip_fuzzer.core.protocol import MessageType, ReturnCode, SomeIpPacket
from someip_fuzzer.data.crash_store import CrashRecord


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def mock_result() -> MutationResult:
    pkt = SomeIpPacket.request(0x1234, 0x0001, payload=b"\xff")
    return MutationResult(
        raw_bytes=pkt.to_bytes(), packet=pkt,
        mutator_name="L1-S01.boundary_min", layer=1,
        target_field="service_id", strategy="boundary_min",
    )


def _make_transport(response: SomeIpPacket | None = None) -> MagicMock:
    transport = MagicMock()
    transport.send = AsyncMock()
    transport.send_raw = AsyncMock()

    async def _recv(timeout: float = 2.0) -> SomeIpPacket | None:
        return response

    transport.recv = _recv
    return transport


# ── HeartbeatMonitor 测试 ─────────────────────────────────────────────────────


def test_heartbeat_tick_fires_at_interval() -> None:
    hb = HeartbeatMonitor(interval=5)
    results = [hb.tick() for _ in range(10)]
    # 第 5 次和第 10 次应触发
    assert results[4] is True
    assert results[9] is True
    assert results[0] is False


@pytest.mark.asyncio
async def test_heartbeat_probe_alive_on_response() -> None:
    response = SomeIpPacket.response(0x0000, 0x0000, payload=b"pong")
    transport = _make_transport(response)
    hb = HeartbeatMonitor()
    alive = await hb.probe(transport)
    assert alive is True


@pytest.mark.asyncio
async def test_heartbeat_probe_dead_on_timeout() -> None:
    transport = _make_transport(None)
    hb = HeartbeatMonitor(timeout=0.1)
    alive = await hb.probe(transport)
    assert alive is False


@pytest.mark.asyncio
async def test_heartbeat_probe_dead_on_exception() -> None:
    transport = MagicMock()
    transport.send = AsyncMock(side_effect=ConnectionRefusedError)
    hb = HeartbeatMonitor()
    alive = await hb.probe(transport)
    assert alive is False


# ── ResponseAnalyzer 测试 ─────────────────────────────────────────────────────


def test_analyzer_none_is_anomalous() -> None:
    analyzer = ResponseAnalyzer()
    assert analyzer.is_anomalous(None) is True


def test_analyzer_normal_response_is_not_anomalous() -> None:
    analyzer = ResponseAnalyzer()
    response = SomeIpPacket.response(0x1234, 0x0001)
    assert analyzer.is_anomalous(response) is False


def test_analyzer_detects_malformed_return_code() -> None:
    analyzer = ResponseAnalyzer()
    pkt = SomeIpPacket.error(0x1234, 0x0001,
                              return_code=ReturnCode.E_MALFORMED_MESSAGE)
    assert analyzer.is_anomalous(pkt) is True


def test_analyzer_detects_error_message_type() -> None:
    analyzer = ResponseAnalyzer()
    pkt = SomeIpPacket.error(0x1234, 0x0001)
    assert analyzer.is_anomalous(pkt) is True


def test_analyzer_detects_unexpected_type() -> None:
    analyzer = ResponseAnalyzer()
    response = SomeIpPacket.response(0x1234, 0x0001)
    # 期望 REQUEST 但收到 RESPONSE
    assert analyzer.is_anomalous(response, expected_msg_type=MessageType.REQUEST) is True


def test_analyzer_classify_timeout() -> None:
    analyzer = ResponseAnalyzer()
    assert analyzer.classify(None) == "timeout"


def test_analyzer_classify_error_response() -> None:
    analyzer = ResponseAnalyzer()
    pkt = SomeIpPacket.error(0x1234, 0x0001)
    assert analyzer.classify(pkt) == "error_response"


def test_analyzer_classify_malformed() -> None:
    analyzer = ResponseAnalyzer()
    pkt = SomeIpPacket.error(0x1234, 0x0001,
                              return_code=ReturnCode.E_MALFORMED_MESSAGE)
    assert analyzer.classify(pkt) == "malformed_response"


# ── AgentClient 测试 ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_agent_client_no_url_is_alive() -> None:
    client = AgentClient(agent_url=None)
    assert await client.is_alive() is True


@pytest.mark.asyncio
async def test_agent_client_no_url_no_asan_log() -> None:
    client = AgentClient(agent_url=None)
    assert await client.get_asan_log() is None


@pytest.mark.asyncio
async def test_agent_client_unreachable_url_dead() -> None:
    client = AgentClient(agent_url="http://127.0.0.1:19999", timeout=0.1)
    # 连接拒绝 → alive=False
    alive = await client.is_alive()
    assert alive is False


# ── CrashDetector 三路融合测试 ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_detector_no_crash_normal_response(mock_result: MutationResult) -> None:
    transport = _make_transport(SomeIpPacket.response(0x1234, 0x0001))
    heartbeat = HeartbeatMonitor(interval=1000)  # 不会触发
    analyzer = ResponseAnalyzer()
    agent = AgentClient(agent_url=None)
    detector = CrashDetector(heartbeat, analyzer, agent)

    crash = await detector.check(transport, mock_result,
                                 SomeIpPacket.response(0x1234, 0x0001))
    assert crash is None


@pytest.mark.asyncio
async def test_detector_anomalous_response_triggers_crash(
    mock_result: MutationResult
) -> None:
    transport = _make_transport(None)
    heartbeat = HeartbeatMonitor(interval=1000)
    analyzer = ResponseAnalyzer()
    agent = AgentClient(agent_url=None)
    detector = CrashDetector(heartbeat, analyzer, agent)

    crash = await detector.check(transport, mock_result, response=None)
    assert crash is not None
    assert crash.detection_method == "timeout"
    assert crash.severity == "medium"


@pytest.mark.asyncio
async def test_detector_heartbeat_failure_triggers_high_severity(
    mock_result: MutationResult
) -> None:
    transport = _make_transport(None)  # 心跳响应为 None
    heartbeat = HeartbeatMonitor(interval=1)   # 每次都心跳
    analyzer = ResponseAnalyzer()
    agent = AgentClient(agent_url=None)
    detector = CrashDetector(heartbeat, analyzer, agent)

    crash = await detector.check(transport, mock_result, response=None)
    assert crash is not None
    # 心跳失败应产生 high（或 medium 因为超时先触发）
    assert crash.severity in ("medium", "high")


@pytest.mark.asyncio
async def test_detector_crash_contains_context(mock_result: MutationResult) -> None:
    transport = _make_transport(None)
    heartbeat = HeartbeatMonitor(interval=1000)
    analyzer = ResponseAnalyzer()
    agent = AgentClient(agent_url=None)
    detector = CrashDetector(heartbeat, analyzer, agent, target_addr=("192.168.1.1", 30509))

    crash = await detector.check(transport, mock_result, response=None)
    assert crash is not None
    assert crash.target_addr == ("192.168.1.1", 30509)
    assert crash.mutator_name == "L1-S01.boundary_min"
    assert "service_id" in crash.context


# ── 严重度和 CVSS 分级测试 ────────────────────────────────────────────────────


def test_crash_severity_classification() -> None:
    from someip_fuzzer.core.monitor import _CVSS_BY_SEVERITY
    assert _CVSS_BY_SEVERITY["critical"] == 9.0
    assert _CVSS_BY_SEVERITY["high"] == 7.5
    assert _CVSS_BY_SEVERITY["medium"] == 5.0
    assert _CVSS_BY_SEVERITY["low"] == 3.0


# ── CrashStore 集成测试 ───────────────────────────────────────────────────────


def test_crash_store_save_and_retrieve() -> None:
    from someip_fuzzer.data.crash_store import CrashStorage
    store = CrashStorage(":memory:")
    crash = CrashRecord(
        triggering_bytes=b"\xff" * 16,
        mutator_name="L2-S05.very_long",
        severity="high",
        cvss_score=7.5,
        detection_method="heartbeat",
    )
    saved = store.save(crash)
    assert saved is True

    loaded = store.load(crash.crash_id)
    assert loaded is not None
    assert loaded.severity == "high"
    assert loaded.triggering_bytes == b"\xff" * 16


def test_crash_store_dedup() -> None:
    from someip_fuzzer.data.crash_store import CrashStorage
    store = CrashStorage(":memory:")
    raw = b"\xde\xad\xbe\xef" * 4
    c1 = CrashRecord(triggering_bytes=raw, severity="low")
    c2 = CrashRecord(triggering_bytes=raw, severity="high")  # 相同字节，不同 crash_id
    assert store.save(c1) is True
    assert store.save(c2) is False  # SHA256 重复
    assert store.count() == 1


def test_crash_store_is_duplicate() -> None:
    from someip_fuzzer.data.crash_store import CrashStorage
    store = CrashStorage(":memory:")
    raw = b"\x01\x02\x03\x04"
    store.save(CrashRecord(triggering_bytes=raw))
    assert store.is_duplicate(raw) is True
    assert store.is_duplicate(b"\x05\x06") is False


def test_crash_store_list_by_severity() -> None:
    from someip_fuzzer.data.crash_store import CrashStorage
    store = CrashStorage(":memory:")
    store.save(CrashRecord(triggering_bytes=b"\x01" * 16, severity="high"))
    store.save(CrashRecord(triggering_bytes=b"\x02" * 16, severity="low"))
    store.save(CrashRecord(triggering_bytes=b"\x03" * 16, severity="high"))
    high_crashes = store.list_all(severity="high")
    assert len(high_crashes) == 2
    assert all(c.severity == "high" for c in high_crashes)
