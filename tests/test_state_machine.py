"""状态机 + Layer 3 变异器测试。"""

from __future__ import annotations

import random

import pytest

import someip_fuzzer.core.mutators  # noqa: F401（触发 L3 注册）
from someip_fuzzer.core.mutator import MUTATOR_REGISTRY
from someip_fuzzer.core.protocol import (
    SomeIpPacket,
    build_sd_find,
    build_sd_offer,
    build_sd_stop_offer,
    build_sd_subscribe,
)
from someip_fuzzer.core.state_machine import (
    ServiceInstance,
    ServiceState,
    ServiceStateMachine,
)
from someip_fuzzer.data.storage import SessionStorage


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def sm() -> ServiceStateMachine:
    return ServiceStateMachine()


@pytest.fixture
def rng() -> random.Random:
    return random.Random(42)


@pytest.fixture
def seed_packet() -> SomeIpPacket:
    return SomeIpPacket.request(0x1234, 0x0001, payload=b"\x01\x02\x03\x04",
                                client_id=0x0001, session_id=1)


INST = ServiceInstance(0x1234, 0x0001)


# ── 状态转换测试 ──────────────────────────────────────────────────────────────


def test_initial_state_is_unknown(sm: ServiceStateMachine) -> None:
    assert sm.get_state(INST) == ServiceState.UNKNOWN


def test_find_service_moves_to_discovered(sm: ServiceStateMachine) -> None:
    sm.on_packet(build_sd_find(0x1234, 0x0001))
    assert sm.get_state(INST) == ServiceState.DISCOVERED


def test_offer_service_moves_to_ready(sm: ServiceStateMachine) -> None:
    sm.on_packet(build_sd_find(0x1234, 0x0001))
    sm.on_packet(build_sd_offer(0x1234, 0x0001, "192.168.1.1", 30509))
    assert sm.get_state(INST) == ServiceState.READY


def test_subscribe_from_ready_moves_to_subscribed(sm: ServiceStateMachine) -> None:
    sm.on_packet(build_sd_offer(0x1234, 0x0001, "192.168.1.1", 30509))
    sm.on_packet(build_sd_subscribe(0x1234, 0x0001, 0x0001, "127.0.0.1", 30510))
    assert sm.get_state(INST) == ServiceState.SUBSCRIBED


def test_notification_from_subscribed_moves_to_running(sm: ServiceStateMachine) -> None:
    sm.on_packet(build_sd_offer(0x1234, 0x0001, "192.168.1.1", 30509))
    sm.on_packet(build_sd_subscribe(0x1234, 0x0001, 0x0001, "127.0.0.1", 30510))
    notification = SomeIpPacket.notification(0x1234, 0x8001, b"\xff")
    sm.on_packet(notification)
    assert sm.get_state(INST) == ServiceState.RUNNING


def test_stop_offer_resets_to_unknown(sm: ServiceStateMachine) -> None:
    sm.on_packet(build_sd_offer(0x1234, 0x0001, "192.168.1.1", 30509))
    sm.on_packet(build_sd_stop_offer(0x1234, 0x0001))
    assert sm.get_state(INST) == ServiceState.UNKNOWN


def test_expire_moves_to_expired(sm: ServiceStateMachine) -> None:
    sm.on_packet(build_sd_offer(0x1234, 0x0001, "192.168.1.1", 30509))
    sm.expire(INST)
    assert sm.get_state(INST) == ServiceState.EXPIRED


def test_full_lifecycle(sm: ServiceStateMachine) -> None:
    """完整生命周期：UNKNOWN → DISCOVERED → READY → SUBSCRIBED → RUNNING → EXPIRED。"""
    sm.on_packet(build_sd_find(0x1234, 0x0001))
    assert sm.get_state(INST) == ServiceState.DISCOVERED

    sm.on_packet(build_sd_offer(0x1234, 0x0001, "192.168.1.1", 30509))
    assert sm.get_state(INST) == ServiceState.READY

    sm.on_packet(build_sd_subscribe(0x1234, 0x0001, 0x0001, "127.0.0.1", 30510))
    assert sm.get_state(INST) == ServiceState.SUBSCRIBED

    sm.on_packet(SomeIpPacket.notification(0x1234, 0x8001))
    assert sm.get_state(INST) == ServiceState.RUNNING

    sm.expire(INST)
    assert sm.get_state(INST) == ServiceState.EXPIRED


def test_non_sd_packet_does_not_change_state(sm: ServiceStateMachine) -> None:
    sm.on_packet(build_sd_offer(0x1234, 0x0001, "192.168.1.1", 30509))
    sm.on_packet(SomeIpPacket.request(0x1234, 0x0001))  # 非 SD
    assert sm.get_state(INST) == ServiceState.READY  # 状态不变


def test_multiple_instances_independent(sm: ServiceStateMachine) -> None:
    inst2 = ServiceInstance(0x5678, 0x0002)
    sm.on_packet(build_sd_offer(0x1234, 0x0001, "192.168.1.1", 30509))
    sm.on_packet(build_sd_find(0x5678, 0x0002))
    assert sm.get_state(INST) == ServiceState.READY
    assert sm.get_state(inst2) == ServiceState.DISCOVERED


def test_get_all_states(sm: ServiceStateMachine) -> None:
    sm.on_packet(build_sd_offer(0x1234, 0x0001, "192.168.1.1", 30509))
    all_states = sm.get_all_states()
    assert INST in all_states
    assert all_states[INST] == ServiceState.READY


# ── 非法动作查询测试 ──────────────────────────────────────────────────────────


def test_invalid_actions_in_unknown_state(sm: ServiceStateMachine) -> None:
    invalid = sm.get_invalid_actions(ServiceState.UNKNOWN)
    # 在 UNKNOWN 状态，Subscribe/Notification/TTLExpired 是非法的
    assert "Subscribe" in invalid
    assert "Notification" in invalid


def test_invalid_actions_in_ready_state(sm: ServiceStateMachine) -> None:
    invalid = sm.get_invalid_actions(ServiceState.READY)
    # READY 状态可以 Subscribe/StopOffer/TTLExpired，FindService/Notification 是非法的
    assert "Notification" in invalid


def test_valid_transitions_in_discovered(sm: ServiceStateMachine) -> None:
    transitions = sm.get_valid_transitions(ServiceState.DISCOVERED)
    action_names = [a for a, _ in transitions]
    assert "OfferService" in action_names
    assert "Subscribe" in action_names


# ── 状态持久化测试 ────────────────────────────────────────────────────────────


def test_state_persistence_save_and_restore() -> None:
    storage = SessionStorage(":memory:")
    session_id = "test-session-001"

    sm1 = ServiceStateMachine(storage=storage, session_id=session_id)
    sm1.on_packet(build_sd_offer(0x1234, 0x0001, "192.168.1.1", 30509))
    assert sm1.get_state(INST) == ServiceState.READY

    # 新状态机从同一存储恢复
    sm2 = ServiceStateMachine(storage=storage, session_id=session_id)
    assert sm2.get_state(INST) == ServiceState.READY


def test_storage_delete_session() -> None:
    storage = SessionStorage(":memory:")
    sm = ServiceStateMachine(storage=storage, session_id="sess-del")
    sm.on_packet(build_sd_offer(0x1234, 0x0001, "192.168.1.1", 30509))
    assert storage.count("sess-del") == 1
    storage.delete_session("sess-del")
    assert storage.count("sess-del") == 0


# ── Mermaid 导出测试 ──────────────────────────────────────────────────────────


def test_mermaid_export_contains_all_states(sm: ServiceStateMachine) -> None:
    mermaid = sm.export_mermaid()
    for state in ServiceState:
        assert state.value.upper() in mermaid, f"状态 {state.value} 未在 Mermaid 图中"


def test_mermaid_export_starts_correctly(sm: ServiceStateMachine) -> None:
    mermaid = sm.export_mermaid()
    assert mermaid.startswith("stateDiagram-v2")
    assert "[*] --> UNKNOWN" in mermaid


# ── Layer 3 变异器注册和基础测试 ─────────────────────────────────────────────


def test_layer3_mutator_count() -> None:
    layer3 = [m for m in MUTATOR_REGISTRY.values() if m.layer == 3]
    assert len(layer3) == 12, f"期望 12 种 L3 变异器，实际 {len(layer3)}"


@pytest.mark.parametrize(
    "name,cls",
    [(n, c) for n, c in sorted(MUTATOR_REGISTRY.items()) if c.layer == 3],
)
def test_l3_mutate_returns_valid_result(
    name: str, cls: type, seed_packet: SomeIpPacket, rng: random.Random
) -> None:
    """每个 L3 变异器必须返回 raw_bytes ≥ 16 字节，元数据完整。"""
    mutator = cls()
    result = mutator.mutate(seed_packet, rng)
    assert isinstance(result.raw_bytes, bytes), f"{name}: raw_bytes 不是 bytes"
    assert len(result.raw_bytes) >= 16, f"{name}: raw_bytes 长度 {len(result.raw_bytes)} < 16"
    assert result.mutator_name == name
    assert result.layer == 3


def test_total_mutator_count() -> None:
    """Phase 3 完成后总变异器应为 105 种（93 L1-L2 + 12 L3）。"""
    assert len(MUTATOR_REGISTRY) == 105
