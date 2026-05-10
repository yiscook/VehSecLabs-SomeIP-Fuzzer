"""变异引擎测试：Layer 1 + Layer 2 全部变异器的基础验证。

测试策略：
- 每个变异器执行 mutate() 后验证 MutationResult 的基本约束
- 字符串语义变异器额外验证 payload 包含预期注入内容
- 注册系统验证总数量是否达到 93 种（53 L1 + 40 L2）
- MutationScheduler 端到端调度验证
"""

from __future__ import annotations

import random

import pytest

import someip_fuzzer.core.mutators  # noqa: F401（触发全部注册）
from someip_fuzzer.core.mutator import MUTATOR_REGISTRY, MutationScheduler
from someip_fuzzer.core.protocol import SomeIpPacket


# ── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def rng() -> random.Random:
    return random.Random(42)


@pytest.fixture
def seed_packet() -> SomeIpPacket:
    return SomeIpPacket.request(
        service_id=0x1234,
        method_id=0x5678,
        payload=b"hello_world_1234",
        client_id=0xABCD,
        session_id=10,
    )


@pytest.fixture
def short_payload_seed() -> SomeIpPacket:
    """payload 仅 2 字节的短包种子，测试边界处理。"""
    return SomeIpPacket.request(0x0001, 0x0001, payload=b"\x01\x02")


@pytest.fixture
def empty_payload_seed() -> SomeIpPacket:
    """空 payload 种子，测试零长度处理。"""
    return SomeIpPacket.request(0x0001, 0x0001, payload=b"")


# ── 注册系统验证 ──────────────────────────────────────────────────────────────


def test_registry_total_count() -> None:
    """Phase 2 完成后应有 93 种已注册变异器（53 Layer1 + 40 Layer2）。"""
    assert len(MUTATOR_REGISTRY) == 93, (
        f"期望 93 种变异器，实际 {len(MUTATOR_REGISTRY)} 种。"
        f"已注册：{sorted(MUTATOR_REGISTRY)}"
    )


def test_registry_layer1_count() -> None:
    layer1 = [m for m in MUTATOR_REGISTRY.values() if m.layer == 1]
    assert len(layer1) == 53


def test_registry_layer2_count() -> None:
    layer2 = [m for m in MUTATOR_REGISTRY.values() if m.layer == 2]
    assert len(layer2) == 40


def test_all_mutator_names_unique() -> None:
    names = list(MUTATOR_REGISTRY.keys())
    assert len(names) == len(set(names)), "存在重复的变异器名称"


# ── MutationResult 基础约束检查（所有变异器）────────────────────────────────


@pytest.mark.parametrize("name,cls", sorted(MUTATOR_REGISTRY.items()))
def test_mutate_returns_valid_result(
    name: str, cls: type, seed_packet: SomeIpPacket, rng: random.Random
) -> None:
    """每个变异器的 mutate() 必须返回长度 ≥ 16 字节的 raw_bytes，且元数据完整。"""
    mutator = cls()
    result = mutator.mutate(seed_packet, rng)
    assert isinstance(result.raw_bytes, bytes), f"{name}: raw_bytes 不是 bytes"
    assert len(result.raw_bytes) >= 16, f"{name}: raw_bytes 长度 {len(result.raw_bytes)} < 16"
    assert result.mutator_name == name, f"{name}: mutator_name 不匹配"
    assert result.layer in (1, 2), f"{name}: layer={result.layer} 不合法"
    assert result.strategy, f"{name}: strategy 为空"


@pytest.mark.parametrize("name,cls", sorted(MUTATOR_REGISTRY.items()))
def test_mutate_with_short_payload(
    name: str, cls: type, short_payload_seed: SomeIpPacket, rng: random.Random
) -> None:
    """短 payload 种子不应导致崩溃，raw_bytes ≥ 16。"""
    mutator = cls()
    result = mutator.mutate(short_payload_seed, rng)
    assert len(result.raw_bytes) >= 16, f"{name}: 短 payload 场景 raw_bytes 长度不足"


# ── Layer 2.3 字符串语义特定断言 ─────────────────────────────────────────────


def test_l2_s01_utf8_overlong_payload_contains_overlong(
    seed_packet: SomeIpPacket, rng: random.Random
) -> None:
    from someip_fuzzer.core.mutators.layer2_semantic import StringUtf8OverlongMutator
    m = StringUtf8OverlongMutator()
    result = m.mutate(seed_packet, rng)
    # 过长编码序列必须出现在 payload 中
    raw_payload = result.raw_bytes[16:]  # 跳过 16 字节 header
    assert b"\xc0\x80" in raw_payload or b"\xe0\x80\x80" in raw_payload or b"\xf0\x80\x80\x80" in raw_payload or b"\xc1\xbf" in raw_payload


def test_l2_s03_null_byte_inject(seed_packet: SomeIpPacket, rng: random.Random) -> None:
    from someip_fuzzer.core.mutators.layer2_semantic import StringNullByteInjectMutator
    m = StringNullByteInjectMutator()
    result = m.mutate(seed_packet, rng)
    raw_payload = result.raw_bytes[16:]
    assert b"\x00" in raw_payload


def test_l2_s04_format_string_payload(seed_packet: SomeIpPacket, rng: random.Random) -> None:
    from someip_fuzzer.core.mutators.layer2_semantic import StringFormatStringMutator
    m = StringFormatStringMutator()
    result = m.mutate(seed_packet, rng)
    raw_payload = result.raw_bytes[16:]
    assert b"%" in raw_payload


def test_l2_s05_very_long_payload_len(seed_packet: SomeIpPacket, rng: random.Random) -> None:
    from someip_fuzzer.core.mutators.layer2_semantic import StringVeryLongMutator
    m = StringVeryLongMutator()
    result = m.mutate(seed_packet, rng)
    raw_payload = result.raw_bytes[16:]
    assert len(raw_payload) == 1024


def test_l2_s07_bom_inject_starts_with_bom(
    seed_packet: SomeIpPacket, rng: random.Random
) -> None:
    from someip_fuzzer.core.mutators.layer2_semantic import StringBomInjectMutator
    m = StringBomInjectMutator()
    result = m.mutate(seed_packet, rng)
    raw_payload = result.raw_bytes[16:]
    assert raw_payload[:3] == b"\xef\xbb\xbf"


def test_l2_s08_control_chars_contains_full_range(
    seed_packet: SomeIpPacket, rng: random.Random
) -> None:
    from someip_fuzzer.core.mutators.layer2_semantic import StringControlCharsMutator
    m = StringControlCharsMutator()
    result = m.mutate(seed_packet, rng)
    raw_payload = result.raw_bytes[16:]
    assert len(raw_payload) == 32  # 0x00-0x1F = 32 字节


# ── Layer 2.5 字段间约束特定断言 ─────────────────────────────────────────────


def test_l2_c01_length_inconsistent_differs_from_original(
    seed_packet: SomeIpPacket, rng: random.Random
) -> None:
    from someip_fuzzer.core.mutators.layer2_semantic import ConstraintLengthPayloadMutator
    import struct
    m = ConstraintLengthPayloadMutator()
    result = m.mutate(seed_packet, rng)
    assert result.packet is None  # 使用 _make_raw_result
    # 读出变异后的 Length 字段（offset 4，4 字节 big-endian）
    mutated_length = struct.unpack(">I", result.raw_bytes[4:8])[0]
    original_length = struct.unpack(">I", seed_packet.to_bytes()[4:8])[0]
    assert mutated_length != original_length


def test_l2_c02_session_decreasing(seed_packet: SomeIpPacket, rng: random.Random) -> None:
    from someip_fuzzer.core.mutators.layer2_semantic import ConstraintSessionDecreasingMutator
    m = ConstraintSessionDecreasingMutator()
    result = m.mutate(seed_packet, rng)
    assert result.packet is not None
    assert result.packet.session_id != seed_packet.session_id


def test_l2_c03_proto_iface_swap(seed_packet: SomeIpPacket, rng: random.Random) -> None:
    from someip_fuzzer.core.mutators.layer2_semantic import ConstraintProtoIfaceSwapMutator
    m = ConstraintProtoIfaceSwapMutator()
    result = m.mutate(seed_packet, rng)
    assert result.packet is not None
    assert result.packet.protocol_version == seed_packet.interface_version
    assert result.packet.interface_version == seed_packet.protocol_version


def test_l2_c04_request_method_has_high_bit(
    seed_packet: SomeIpPacket, rng: random.Random
) -> None:
    from someip_fuzzer.core.mutators.layer2_semantic import ConstraintRequestResponseIdMutator
    m = ConstraintRequestResponseIdMutator()
    # 确保种子 method_id 高位为 0
    seed = SomeIpPacket.request(0x1234, 0x0123, payload=b"test")
    result = m.mutate(seed, rng)
    assert result.packet is not None
    assert result.packet.method_id & 0x8000 != 0


def test_l2_c05_tp_flag_without_offset(
    seed_packet: SomeIpPacket, rng: random.Random
) -> None:
    from someip_fuzzer.core.mutators.layer2_semantic import ConstraintTpFlagNoOffsetMutator
    m = ConstraintTpFlagNoOffsetMutator()
    result = m.mutate(seed_packet, rng)
    assert result.packet is None  # _make_raw_result
    # msg_type 字节（offset 14）应包含 0x20 TP flag
    assert result.raw_bytes[14] & 0x20 != 0
    # payload 前 4 字节应为 0x00000000
    assert result.raw_bytes[16:20] == b"\x00\x00\x00\x00"


# ── Layer 2.6 SD Entry/Option 特定断言 ───────────────────────────────────────


def test_l2_sd01_invalid_entry_type_raw_result(
    seed_packet: SomeIpPacket, rng: random.Random
) -> None:
    from someip_fuzzer.core.mutators.layer2_sd import SdInvalidEntryTypeMutator
    m = SdInvalidEntryTypeMutator()
    result = m.mutate(seed_packet, rng)
    assert result.packet is None  # SD 变异器均用 _make_raw_result
    assert len(result.raw_bytes) >= 16


def test_l2_sd02_conflicting_entries_length(
    seed_packet: SomeIpPacket, rng: random.Random
) -> None:
    from someip_fuzzer.core.mutators.layer2_sd import SdConflictingEntriesMutator
    m = SdConflictingEntriesMutator()
    result = m.mutate(seed_packet, rng)
    # 两个 Entry = 32 字节，SD payload header 12 字节，SOME/IP header 16 字节 → total ≥ 60
    assert len(result.raw_bytes) >= 60


def test_l2_sd03_excessive_entries_size(
    seed_packet: SomeIpPacket, rng: random.Random
) -> None:
    from someip_fuzzer.core.mutators.layer2_sd import SdExcessiveEntriesMutator
    rng2 = random.Random(99)
    m = SdExcessiveEntriesMutator()
    result = m.mutate(seed_packet, rng2)
    # 50 个 Entry × 16 字节 = 800 字节，加上各种头部应 > 800
    assert len(result.raw_bytes) > 800


def test_l2_sd07_ttl_overflow(seed_packet: SomeIpPacket, rng: random.Random) -> None:
    from someip_fuzzer.core.mutators.layer2_sd import SdTtlOverflowMutator
    m = SdTtlOverflowMutator()
    result = m.mutate(seed_packet, rng)
    assert len(result.raw_bytes) >= 16
    # 验证 TTL 字段被设置为 0xFFFFFF（在 SD payload 中 Entry 的 TTL 偏移处）
    # SOME/IP header(16) + SD header(8) + Entry TTL at offset 9
    ttl_offset = 16 + 8 + 9
    if len(result.raw_bytes) >= ttl_offset + 3:
        assert result.raw_bytes[ttl_offset:ttl_offset + 3] == b"\xff\xff\xff"


# ── MutationScheduler 端到端测试 ─────────────────────────────────────────────


def test_scheduler_selects_from_all_layers(seed_packet: SomeIpPacket) -> None:
    sch = MutationScheduler()
    rng = random.Random(0)
    seen_layers = set()
    for _ in range(200):
        mutator = sch.select(rng=rng)
        result = mutator.mutate(seed_packet, rng)
        assert len(result.raw_bytes) >= 16
        seen_layers.add(mutator.layer)
    assert 1 in seen_layers
    assert 2 in seen_layers


def test_scheduler_filter_by_layer(seed_packet: SomeIpPacket) -> None:
    sch = MutationScheduler()
    rng = random.Random(1)
    for _ in range(20):
        mutator = sch.select(layer=1, rng=rng)
        assert mutator.layer == 1
        result = mutator.mutate(seed_packet, rng)
        assert len(result.raw_bytes) >= 16


def test_scheduler_filter_layer2(seed_packet: SomeIpPacket) -> None:
    sch = MutationScheduler()
    rng = random.Random(2)
    for _ in range(20):
        mutator = sch.select(layer=2, rng=rng)
        assert mutator.layer == 2
        result = mutator.mutate(seed_packet, rng)
        assert len(result.raw_bytes) >= 16


def test_mutate_with_empty_payload(empty_payload_seed: SomeIpPacket) -> None:
    """空 payload 种子对所有变异器不应崩溃。"""
    rng = random.Random(7)
    for name, cls in MUTATOR_REGISTRY.items():
        mutator = cls()
        result = mutator.mutate(empty_payload_seed, rng)
        assert len(result.raw_bytes) >= 16, f"{name}: 空 payload 场景 raw_bytes 不足"
