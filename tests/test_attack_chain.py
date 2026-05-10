"""攻击链解析器 + 编排引擎测试。"""

from __future__ import annotations

import asyncio
import random
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from someip_fuzzer.core.attack_chain import (
    AttackChain,
    AttackChainEngine,
    AttackChainLoader,
    ChainStep,
    _matches_filter,
    _resolve,
)
from someip_fuzzer.core.protocol import SomeIpPacket, MessageType

YAML_DIR = Path(__file__).parent.parent / "configs" / "attack_chains"


# ── YAML 加载测试 ─────────────────────────────────────────────────────────────


def test_load_all_yaml_count() -> None:
    """应加载 8 个攻击链 YAML 文件。"""
    chains = AttackChainLoader.load_all(YAML_DIR)
    assert len(chains) == 8, f"期望 8 个攻击链，实际 {len(chains)}"


def test_all_chains_have_required_fields() -> None:
    chains = AttackChainLoader.load_all(YAML_DIR)
    for chain in chains:
        assert chain.id.startswith("AC-"), f"{chain.id} 格式错误"
        assert chain.name, f"{chain.id} 缺少 name"
        assert len(chain.steps) >= 2, f"{chain.id} 步骤数 < 2"
        assert 0.0 <= chain.cvss <= 10.0, f"{chain.id} CVSS 超范围"
        assert chain.severity in ("low", "medium", "high", "critical")


def test_chain_ids_are_unique() -> None:
    chains = AttackChainLoader.load_all(YAML_DIR)
    ids = [c.id for c in chains]
    assert len(ids) == len(set(ids)), "存在重复的攻击链 ID"


def test_load_hijack_yaml() -> None:
    chain = AttackChainLoader.load(YAML_DIR / "hijack.yaml")
    assert chain.id == "AC-001"
    assert chain.cvss == 8.5
    assert len(chain.steps) == 4
    assert chain.steps[0].action == "wait_for"
    assert chain.steps[1].action == "send"


def test_load_dos_yaml() -> None:
    chain = AttackChainLoader.load(YAML_DIR / "dos.yaml")
    assert chain.id == "AC-002"
    flood_step = chain.steps[0]
    assert flood_step.repeat == 200


def test_load_tp_attack_yaml() -> None:
    chain = AttackChainLoader.load(YAML_DIR / "tp_attack.yaml")
    assert chain.id == "AC-007"
    assert len(chain.steps) == 6  # 最多步骤数


# ── 变量替换测试 ──────────────────────────────────────────────────────────────


def test_resolve_simple_var() -> None:
    ctx = {"step1": {"service_id": 0x1234}}
    assert _resolve("${step1.service_id}", ctx) == "4660"  # 0x1234 = 4660


def test_resolve_nested_in_dict() -> None:
    ctx = {"prev": {"addr": "192.168.1.100"}}
    result = _resolve({"ip": "${prev.addr}", "port": 30509}, ctx)
    assert result["ip"] == "192.168.1.100"
    assert result["port"] == 30509


def test_resolve_missing_var_returns_original() -> None:
    ctx: dict = {}
    result = _resolve("${nonexistent.key}", ctx)
    assert result == "${nonexistent.key}"


def test_resolve_no_var_unchanged() -> None:
    ctx: dict = {}
    assert _resolve("static_value", ctx) == "static_value"
    assert _resolve(42, ctx) == 42


# ── 报文过滤测试 ──────────────────────────────────────────────────────────────


def test_filter_by_service_id_match() -> None:
    pkt = SomeIpPacket.request(0x1234, 0x0001)
    assert _matches_filter(pkt, {"service_id": "0x1234"}) is True
    assert _matches_filter(pkt, {"service_id": "0x5678"}) is False


def test_filter_by_message_type() -> None:
    pkt = SomeIpPacket.request(0x1234, 0x0001)
    assert _matches_filter(pkt, {"message_type": "REQUEST"}) is True
    assert _matches_filter(pkt, {"message_type": "RESPONSE"}) is False


def test_filter_empty_matches_all() -> None:
    pkt = SomeIpPacket.request(0x1234, 0x0001)
    assert _matches_filter(pkt, {}) is True


def test_filter_sd_find_service() -> None:
    from someip_fuzzer.core.protocol import build_sd_find
    pkt = build_sd_find(0x1234, 0x0001)
    assert _matches_filter(pkt, {"message_type": "SD", "sd_entry_type": "FindService"}) is True
    assert _matches_filter(pkt, {"message_type": "SD", "sd_entry_type": "OfferService"}) is False


def test_filter_sd_offer_service() -> None:
    from someip_fuzzer.core.protocol import build_sd_offer
    pkt = build_sd_offer(0x1234, 0x0001, "192.168.1.1", 30509)
    assert _matches_filter(pkt, {"message_type": "SD", "sd_entry_type": "OfferService"}) is True


# ── 编排引擎测试（mock transport）────────────────────────────────────────────


def _make_mock_transport(recv_packets: list[SomeIpPacket | None] | None = None):
    """构造一个 mock transport，send/recv 都是异步函数。"""
    transport = MagicMock()
    transport.send = AsyncMock()
    transport.send_raw = AsyncMock()
    recv_queue = list(recv_packets or [])

    async def _recv(timeout: float = 5.0) -> SomeIpPacket | None:
        if recv_queue:
            return recv_queue.pop(0)
        await asyncio.sleep(timeout)
        return None

    transport.recv = _recv
    return transport


@pytest.mark.asyncio
async def test_engine_execute_send_step() -> None:
    transport = _make_mock_transport()
    engine = AttackChainEngine(transport=transport)
    chain = AttackChain(
        id="TEST-001", name="test", description="", severity="low", cvss=1.0,
        steps=[
            ChainStep(id="step1", action="send", template="request",
                      params={"service_id": "0x1234", "method_id": "0x0001"},
                      repeat=3)
        ],
    )
    result = await engine.execute(chain)
    assert result.success is True
    assert "step1" in result.completed_steps
    assert result.packets_sent == 3
    assert transport.send.call_count == 3


@pytest.mark.asyncio
async def test_engine_execute_wait_for_found() -> None:
    recv_pkt = SomeIpPacket.request(0x1234, 0x0001)
    transport = _make_mock_transport([recv_pkt])
    engine = AttackChainEngine(transport=transport)
    chain = AttackChain(
        id="TEST-002", name="test", description="", severity="low", cvss=1.0,
        steps=[
            ChainStep(id="wait1", action="wait_for",
                      filter={"service_id": "0x1234"}, timeout=2.0)
        ],
    )
    result = await engine.execute(chain)
    assert result.success is True
    assert "wait1" in result.completed_steps
    assert result.context["wait1"]["service_id"] == 0x1234


@pytest.mark.asyncio
async def test_engine_wait_for_timeout_required_fails() -> None:
    transport = _make_mock_transport([])
    engine = AttackChainEngine(transport=transport)
    chain = AttackChain(
        id="TEST-003", name="test", description="", severity="low", cvss=1.0,
        steps=[
            ChainStep(id="wait_miss", action="wait_for",
                      filter={"service_id": "0xFFFF"}, timeout=0.1, required=True)
        ],
    )
    result = await engine.execute(chain)
    assert result.success is False
    assert result.failed_at == "wait_miss"


@pytest.mark.asyncio
async def test_engine_wait_for_timeout_optional_continues() -> None:
    transport = _make_mock_transport([])
    engine = AttackChainEngine(transport=transport)
    chain = AttackChain(
        id="TEST-004", name="test", description="", severity="low", cvss=1.0,
        steps=[
            ChainStep(id="optional_wait", action="wait_for",
                      filter={"service_id": "0xFFFF"}, timeout=0.1, required=False),
            ChainStep(id="after_wait", action="send", template="request",
                      params={"service_id": "0x1234", "method_id": "0x0001"}),
        ],
        success_criteria={"after_wait_completed": True},
    )
    result = await engine.execute(chain)
    assert result.success is True
    assert "after_wait" in result.completed_steps


@pytest.mark.asyncio
async def test_engine_variable_substitution() -> None:
    recv_pkt = SomeIpPacket.request(0x5678, 0x0001)
    transport = _make_mock_transport([recv_pkt])
    engine = AttackChainEngine(transport=transport)
    chain = AttackChain(
        id="TEST-005", name="test", description="", severity="low", cvss=1.0,
        steps=[
            ChainStep(id="sniff", action="wait_for",
                      filter={"message_type": "REQUEST"}, timeout=2.0),
            ChainStep(id="reply", action="send", template="request",
                      params={"service_id": "${sniff.service_id}", "method_id": "0x0001"}),
        ],
        success_criteria={"reply_completed": True},
    )
    result = await engine.execute(chain)
    assert result.success is True
    assert transport.send.call_count == 1


@pytest.mark.asyncio
async def test_engine_delay_step() -> None:
    import time
    transport = _make_mock_transport()
    engine = AttackChainEngine(transport=transport)
    chain = AttackChain(
        id="TEST-006", name="test", description="", severity="low", cvss=1.0,
        steps=[ChainStep(id="wait_100ms", action="delay", delay_ms=100)],
    )
    t0 = time.perf_counter()
    result = await engine.execute(chain)
    elapsed_ms = (time.perf_counter() - t0) * 1000
    assert result.success is True
    assert elapsed_ms >= 90  # 允许 10ms 误差


@pytest.mark.asyncio
async def test_engine_stats_tracking() -> None:
    transport = _make_mock_transport()
    engine = AttackChainEngine(transport=transport)
    chain = AttackChain(
        id="STAT-001", name="test", description="", severity="low", cvss=1.0,
        steps=[ChainStep(id="s1", action="send", template="request",
                         params={"service_id": "0x1234", "method_id": "0x0001"})],
    )
    for _ in range(3):
        await engine.execute(chain)
    stats = engine.get_stats()
    assert stats["total_executions"] == 3
    assert stats["total_success"] == 3
    assert stats["success_rate"] == 1.0
    assert stats["avg_duration_ms"] > 0


# ── 攻击链集成测试（加载 YAML + mock 执行）───────────────────────────────────


@pytest.mark.asyncio
async def test_load_and_execute_dos_chain() -> None:
    transport = _make_mock_transport()
    engine = AttackChainEngine(transport=transport)
    chain = AttackChainLoader.load(YAML_DIR / "dos.yaml")
    result = await engine.execute(chain)
    # DoS 链全 send/mutate，无 wait_for（不需要靶机），应全部完成
    assert "flood_register" in result.completed_steps
    assert result.packets_sent >= 200
