"""Layer 2 协议语义变异器。

涵盖 SPEC §2.3 Layer 2.1-2.5 全部 32 种语义级变异策略：
  - 2.1 类型边界（L2-T01~T08，8 种）—— task 2.9
  - 2.4 字节序混淆（L2-E01~E03，3 种）—— task 2.9
  - 2.2 TLV 结构变异（L2-V01~V06，6 种）—— task 2.10（Opus 4.7）
  - 2.3 字符串语义（L2-S01~S10，10 种）—— task 2.11
  - 2.5 字段间约束破坏（L2-C01~C05，5 种）—— task 2.12（Opus 4.7）
"""

from __future__ import annotations

import dataclasses
import random
import struct

from someip_fuzzer.core.mutator import (
    BaseMutator,
    MutationResult,
    HEADER_LEN,
    OFFSET_SERVICE_ID,
    OFFSET_METHOD_ID,
    OFFSET_LENGTH,
    OFFSET_CLIENT_ID,
    OFFSET_SESSION_ID,
    register_mutator,
    replace_header_bytes,
)
from someip_fuzzer.core.protocol import SomeIpPacket


# ─────────────────────────────────────────────────────────────────────────────
# Layer 2.1：类型边界变异（8 种）
#
# 策略：将 payload 中随机位置的字节替换为某种数据类型的边界值。
# 由于 SOME/IP payload 的实际类型未知，这里做"最大覆盖"：
# - 1/2/4 字节对齐位置处注入 uint8/uint16/uint32 的边界值
# - 若 payload 不够长，则生成含该边界值的最小 payload
# ─────────────────────────────────────────────────────────────────────────────

def _inject_at(payload: bytes, offset: int, value: bytes, rng: random.Random) -> bytes:
    """在 payload[offset:offset+len(value)] 处注入 value 字节。

    若 payload 比 offset+len(value) 短，则用随机字节填充至所需长度再注入。
    """
    needed = offset + len(value)
    if len(payload) < needed:
        payload = payload + bytes(rng.randint(0, 0xFF) for _ in range(needed - len(payload)))
    return payload[:offset] + value + payload[offset + len(value):]


@register_mutator
class TypeBoundaryUint8Mutator(BaseMutator):
    """L2-T01：在 payload 随机 1 字节位置注入 uint8 边界值（0, 127, 128, 255）。

    uint8 的四个典型边界触发：符号翻转 / 最大值 / 零值 / 最小负数。
    """

    name = "L2-T01.uint8_boundaries"
    layer = 2
    target_field = "payload"
    strategy = "uint8_boundaries"

    _VALUES = [0x00, 0x7F, 0x80, 0xFF]

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        val = rng.choice(self._VALUES)
        offset = rng.randint(0, max(0, len(seed.payload) - 1))
        new_payload = _inject_at(seed.payload, offset, bytes([val]), rng)
        return self._make_result(
            dataclasses.replace(seed, payload=new_payload),
            injected_value=val, offset=offset,
        )


@register_mutator
class TypeBoundaryUint16Mutator(BaseMutator):
    """L2-T02：在 payload 随机 2 字节对齐位置注入 uint16 边界值（big-endian）。

    边界值：0, 32767(0x7FFF), 32768(0x8000), 65535(0xFFFF)。
    """

    name = "L2-T02.uint16_boundaries"
    layer = 2
    target_field = "payload"
    strategy = "uint16_boundaries"

    _VALUES = [0x0000, 0x7FFF, 0x8000, 0xFFFF]

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        val = rng.choice(self._VALUES)
        max_off = max(0, len(seed.payload) - 2)
        offset = (rng.randint(0, max_off) // 2) * 2  # 2 字节对齐
        value_bytes = struct.pack(">H", val)
        new_payload = _inject_at(seed.payload, offset, value_bytes, rng)
        return self._make_result(
            dataclasses.replace(seed, payload=new_payload),
            injected_value=val, offset=offset,
        )


@register_mutator
class TypeBoundaryUint32Mutator(BaseMutator):
    """L2-T03：在 payload 随机 4 字节对齐位置注入 uint32 边界值（big-endian）。

    边界值：0, 2^31-1, 2^31, 2^32-1。
    """

    name = "L2-T03.uint32_boundaries"
    layer = 2
    target_field = "payload"
    strategy = "uint32_boundaries"

    _VALUES = [0x00000000, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF]

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        val = rng.choice(self._VALUES)
        max_off = max(0, len(seed.payload) - 4)
        offset = (rng.randint(0, max_off) // 4) * 4  # 4 字节对齐
        value_bytes = struct.pack(">I", val)
        new_payload = _inject_at(seed.payload, offset, value_bytes, rng)
        return self._make_result(
            dataclasses.replace(seed, payload=new_payload),
            injected_value=val, offset=offset,
        )


@register_mutator
class TypeIntNegativeMutator(BaseMutator):
    """L2-T04：注入 -1（uint 解释：0xFFFFFFFF），测试有符号/无符号混用漏洞。

    -1 在 int32 解释下为有效负数，但在 uint32 解释下为最大正数，
    常触发 size_t 类型混用 / 下标越界。
    """

    name = "L2-T04.int_negative"
    layer = 2
    target_field = "payload"
    strategy = "int_negative"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        offset = (rng.randint(0, max(0, len(seed.payload))) // 4) * 4
        value_bytes = struct.pack(">I", 0xFFFFFFFF)  # -1 as uint32 big-endian
        new_payload = _inject_at(seed.payload, offset, value_bytes, rng)
        return self._make_result(
            dataclasses.replace(seed, payload=new_payload),
            offset=offset,
        )


@register_mutator
class TypeFloatSpecialMutator(BaseMutator):
    """L2-T05：注入 IEEE 754 特殊值（NaN / +Inf / -Inf / 最小非规格化数）。

    触发服务端浮点运算中的 NaN 传播 / Inf 比较 / 非规格化数精度丢失。
    使用 big-endian float32 字节序（与 SOME/IP 一致）。
    """

    name = "L2-T05.float_special"
    layer = 2
    target_field = "payload"
    strategy = "float_special"

    # big-endian float32 特殊值字节
    _SPECIAL_FLOATS = [
        b"\x7f\xc0\x00\x00",  # quiet NaN
        b"\x7f\x80\x00\x00",  # +Infinity
        b"\xff\x80\x00\x00",  # -Infinity
        b"\x00\x00\x00\x01",  # 最小正非规格化数（denormal）
        b"\x80\x00\x00\x01",  # 最小负非规格化数
    ]

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        val_bytes = rng.choice(self._SPECIAL_FLOATS)
        offset = (rng.randint(0, max(0, len(seed.payload))) // 4) * 4
        new_payload = _inject_at(seed.payload, offset, val_bytes, rng)
        return self._make_result(
            dataclasses.replace(seed, payload=new_payload),
            float_bytes=val_bytes.hex(), offset=offset,
        )


@register_mutator
class TypeBoolInvalidMutator(BaseMutator):
    """L2-T06：注入非 0/1 的 bool 值（如 0x02, 0xFE, 0xFF）。

    SOME/IP 的 bool 类型应为 0 或 1；非法 bool 值触发
    ``if (bool_val)`` 路径分叉（0xFF 为 true，0x02 也是 true）但
    ``if (bool_val == 1)`` 路径失配。
    """

    name = "L2-T06.bool_invalid"
    layer = 2
    target_field = "payload"
    strategy = "bool_invalid"

    _INVALID_BOOLS = [0x02, 0x03, 0x7F, 0xFE, 0xFF]

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        val = rng.choice(self._INVALID_BOOLS)
        offset = rng.randint(0, max(0, len(seed.payload) - 1))
        new_payload = _inject_at(seed.payload, offset, bytes([val]), rng)
        return self._make_result(
            dataclasses.replace(seed, payload=new_payload),
            bool_value=val, offset=offset,
        )


@register_mutator
class TypeEnumOutOfRangeMutator(BaseMutator):
    """L2-T07：注入越界枚举值（高字节填充已知枚举域外的大值）。

    汽车电子协议中大量使用枚举；越界值（如 0x100-0xFFFF）触发
    枚举 switch 的 default 分支或查表越界访问。
    """

    name = "L2-T07.enum_out_of_range"
    layer = 2
    target_field = "payload"
    strategy = "enum_out_of_range"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        # uint16 越界枚举值：[0x100, 0xFFFF] 中随机选
        val = rng.randint(0x100, 0xFFFF)
        offset = (rng.randint(0, max(0, len(seed.payload))) // 2) * 2
        value_bytes = struct.pack(">H", val)
        new_payload = _inject_at(seed.payload, offset, value_bytes, rng)
        return self._make_result(
            dataclasses.replace(seed, payload=new_payload),
            enum_value=val, offset=offset,
        )


@register_mutator
class TypeBitfieldOverflowMutator(BaseMutator):
    """L2-T08：注入位域溢出模式（0xFF 填充，使所有 bit 为 1）。

    位域 bit_field: 3 的最大合法值是 7（0b111）；若相邻字节填 0xFF，
    则溢出 3 位域且污染相邻位域，触发 bit 操作越界或值超出枚举范围。
    """

    name = "L2-T08.bitfield_overflow"
    layer = 2
    target_field = "payload"
    strategy = "bitfield_overflow"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        # 注入 2-4 字节的 0xFF，覆盖多个潜在位域
        n = rng.randint(2, 4)
        offset = rng.randint(0, max(0, len(seed.payload)))
        value_bytes = bytes([0xFF] * n)
        new_payload = _inject_at(seed.payload, offset, value_bytes, rng)
        return self._make_result(
            dataclasses.replace(seed, payload=new_payload),
            fill_len=n, offset=offset,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Layer 2.4：字节序混淆变异（3 种）
#
# SOME/IP 规范规定所有多字节字段使用大端（big-endian）字节序。
# 以下变异器通过改变字节序制造混乱。
# L2-E01 / L2-E02 修改 header 字节序，使用 _make_raw_result()；
# L2-E03 修改 payload 字节序，使用 _make_result()。
# ─────────────────────────────────────────────────────────────────────────────


def _swap_2(raw: bytes, offset: int) -> bytes:
    """将 raw[offset:offset+2] 中的 2 字节翻转（big-endian ↔ little-endian）。"""
    return raw[:offset] + raw[offset + 1:offset + 2] + raw[offset:offset + 1] + raw[offset + 2:]


def _swap_4(raw: bytes, offset: int) -> bytes:
    """将 raw[offset:offset+4] 中的 4 字节翻转。"""
    chunk = raw[offset:offset + 4][::-1]
    return raw[:offset] + chunk + raw[offset + 4:]


@register_mutator
class EndiannessForcelLittleMutator(BaseMutator):
    """L2-E01：强制将 SOME/IP header 所有多字节字段改为小端字节序。

    service_id / method_id / length / client_id / session_id 字节各自翻转，
    使原先 0x1234 的 service_id 变成 0x3412（小端），制造字段解析混乱。
    packet=None，走字节级路径。
    """

    name = "L2-E01.force_little_endian"
    layer = 2
    target_field = "raw_header"
    strategy = "force_little_endian"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        raw = bytearray(seed.to_bytes())
        # 翻转各 2/4 字节字段
        raw[OFFSET_SERVICE_ID:OFFSET_SERVICE_ID + 2] = raw[OFFSET_SERVICE_ID:OFFSET_SERVICE_ID + 2][::-1]
        raw[OFFSET_METHOD_ID:OFFSET_METHOD_ID + 2] = raw[OFFSET_METHOD_ID:OFFSET_METHOD_ID + 2][::-1]
        raw[OFFSET_LENGTH:OFFSET_LENGTH + 4] = raw[OFFSET_LENGTH:OFFSET_LENGTH + 4][::-1]
        raw[OFFSET_CLIENT_ID:OFFSET_CLIENT_ID + 2] = raw[OFFSET_CLIENT_ID:OFFSET_CLIENT_ID + 2][::-1]
        raw[OFFSET_SESSION_ID:OFFSET_SESSION_ID + 2] = raw[OFFSET_SESSION_ID:OFFSET_SESSION_ID + 2][::-1]
        return self._make_raw_result(
            bytes(raw),
            original_service=seed.service_id,
            original_method=seed.method_id,
        )


@register_mutator
class EndiannessMixedMutator(BaseMutator):
    """L2-E02：混合字节序 — service_id/length 改为小端，其余字段保持大端。

    "部分小端"比"全部小端"更难被简单校验发现，
    触发对字节序处理不一致的实现路径。
    """

    name = "L2-E02.mixed_endian"
    layer = 2
    target_field = "raw_header"
    strategy = "mixed_endian"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        raw = bytearray(seed.to_bytes())
        raw[OFFSET_SERVICE_ID:OFFSET_SERVICE_ID + 2] = raw[OFFSET_SERVICE_ID:OFFSET_SERVICE_ID + 2][::-1]
        raw[OFFSET_LENGTH:OFFSET_LENGTH + 4] = raw[OFFSET_LENGTH:OFFSET_LENGTH + 4][::-1]
        return self._make_raw_result(
            bytes(raw),
            swapped_fields=["service_id", "length"],
        )


@register_mutator
class EndiannessPayloadSwapMutator(BaseMutator):
    """L2-E03：Payload 字节翻转 — 将 payload 内每个 4 字节 chunk 翻转字节序。

    若服务端假设 payload 为大端但实际收到"小端 payload"，
    数值解析会得到完全错误的值（如把 uint32 的高低字节对调）。
    使用 _make_result()，packet 字段有效但 payload 内容已乱序。
    """

    name = "L2-E03.byte_swap_payload"
    layer = 2
    target_field = "payload"
    strategy = "byte_swap_payload"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        payload = seed.payload
        if len(payload) < 4:
            # 太短则填充至 4 字节
            payload = payload + bytes(rng.randint(0, 0xFF) for _ in range(4 - len(payload)))
        # 每 4 字节 chunk 翻转；尾部余量保持不变
        n_chunks = len(payload) // 4
        new_payload = bytearray()
        for i in range(n_chunks):
            chunk = payload[i * 4:(i + 1) * 4]
            new_payload.extend(chunk[::-1])
        new_payload.extend(payload[n_chunks * 4:])
        return self._make_result(
            dataclasses.replace(seed, payload=bytes(new_payload)),
            swapped_chunks=n_chunks,
        )
