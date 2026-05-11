"""E2E 8.9 + 8.17 — 模糊测试稳定性与发包速率。

验证：
1. FuzzingEngine 向真实 VM 发 200 个变异包，不抛异常
2. 发包数 >= 100（排除网络阻断）
3. 测试结束后 VM 仍然存活（agent alive=true）
4. 发包速率 ≥ 1000 pps（三协程并行架构验证）
"""

from __future__ import annotations

import asyncio
import json
import urllib.request
from unittest.mock import MagicMock

import pytest

from someip_fuzzer.core.engine import FuzzingEngine
from someip_fuzzer.utils.config import AppConfig, ServiceDef, SdConfig, TargetConfig
from tests.e2e.conftest import AGENT_URL, VM_IP, VM_PORT

TARGET_PACKETS = 200
TIMEOUT_SEC = 60
PPS_RUN_SEC = 10
PPS_TARGET = 1000


def _make_config() -> AppConfig:
    return AppConfig(
        target=TargetConfig(name="e2e-test", ip=VM_IP, port=VM_PORT, transport="udp"),
        sd=SdConfig(multicast="224.224.224.245", port=30490),
        services=[
            ServiceDef(
                service_id=0x1111, instance_id=0x2222,
                major_version=0, minor_version=0, methods=[0x3333],
            )
        ],
    )


def _make_bridge_mock() -> MagicMock:
    bridge = MagicMock()
    for sig in ("packet_sent", "packet_received", "crash_detected",
                "stats_updated", "log_message"):
        mock = MagicMock()
        mock.emit = MagicMock()
        setattr(bridge, sig, mock)
    return bridge


@pytest.mark.asyncio
async def test_fuzz_200_packets_no_crash() -> None:
    """发 200 个包，VM 不崩溃，sent >= 100。"""
    config = _make_config()
    bridge = _make_bridge_mock()
    stop_event = asyncio.Event()
    sent_count: list[int] = [0]

    def track_stats(stats: dict) -> None:
        sent_count[0] = stats.get("sent", 0)
        if sent_count[0] >= TARGET_PACKETS:
            stop_event.set()

    bridge.stats_updated.emit.side_effect = track_stats

    engine = FuzzingEngine()
    try:
        await asyncio.wait_for(
            engine.run(config, bridge, stop_event),
            timeout=TIMEOUT_SEC,
        )
    except asyncio.TimeoutError:
        stop_event.set()

    assert sent_count[0] >= 100, f"发包数太少：{sent_count[0]}（可能网络阻断）"

    raw = urllib.request.urlopen(AGENT_URL + "/status", timeout=3).read()
    status = json.loads(raw)
    assert status.get("alive") is True, f"VM 发包后崩溃！{status}"
    print(f"发包 {sent_count[0]} 包，崩溃检测 {bridge.crash_detected.emit.call_count} 次")


@pytest.mark.asyncio
async def test_pps_exceeds_1000() -> None:
    """三协程架构下发包速率 ≥ 1000 pps（运行 10 秒测量）。"""
    config = _make_config()
    bridge = _make_bridge_mock()
    stop_event = asyncio.Event()
    final_pps: list[float] = [0.0]

    def track_stats(stats: dict) -> None:
        final_pps[0] = stats.get("pps", 0.0)

    bridge.stats_updated.emit.side_effect = track_stats

    engine = FuzzingEngine()

    async def _run_and_stop() -> None:
        await asyncio.sleep(PPS_RUN_SEC)
        stop_event.set()

    await asyncio.gather(
        engine.run(config, bridge, stop_event),
        _run_and_stop(),
        return_exceptions=True,
    )

    # VM 仍然存活
    raw = urllib.request.urlopen(AGENT_URL + "/status", timeout=3).read()
    status = json.loads(raw)
    assert status.get("alive") is True, f"速率测试后 VM 崩溃：{status}"

    print(f"测速结果：{final_pps[0]:.1f} pps")
    assert final_pps[0] >= PPS_TARGET, (
        f"发包速率 {final_pps[0]:.1f} pps < 目标 {PPS_TARGET} pps"
    )
