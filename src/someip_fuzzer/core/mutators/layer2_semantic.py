"""Layer 2 协议语义变异器。

涵盖 SPEC §2.3 Layer 2.1-2.5 全部 32 种语义级变异策略：
  - 2.1 类型边界（L2-T01~T08，8 种）—— task 2.9
  - 2.4 字节序混淆（L2-E01~E03，3 种）—— task 2.9
  - 2.2 TLV 结构变异（L2-V01~V06，6 种）—— task 2.10
  - 2.3 字符串语义（L2-S01~S10，10 种）—— task 2.11
  - 2.5 字段间约束破坏（L2-C01~C05，5 种）—— task 2.13
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
    OFFSET_PROTO_VER,
    OFFSET_IFACE_VER,
    OFFSET_MSG_TYPE,
    register_mutator,
    replace_header_byte,
    replace_header_bytes,
    replace_length_field,
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


# ─────────────────────────────────────────────────────────────────────────────
# Layer 2.2：TLV 结构变异（6 种）
#
# TLV (Tag-Length-Value) 是 AUTOSAR Adaptive 在 SOME/IP 中用于可选字段
# 序列化的格式（PRS_SOMEIPProtocol_00721+）。本变异器组使用简化 TLV 模型：
#
#   Tag    : 2 字节 uint16，big-endian
#   Length : 4 字节 uint32，big-endian（声明 V 部分应有的字节数）
#   Value  : Length 字节
#
# 即每个 TLV 头部固定 6 字节。所有变异器自行生成 payload，不依赖 seed.payload
# 内容（因为 seed 不保证是 TLV 编码的），用 ``_make_result()`` 返回合法 dataclass。
#
# 攻击向量映射（与 SPEC §2.3 Layer 2.2 一致）：
#   L2-V01 length_tag_mismatch    → L 与实际 V 长度不符（局部 length 撒谎）
#   L2-V02 nested_overflow        → 50-100 层嵌套 TLV，递归栈爆炸
#   L2-V03 duplicate_tag          → 同 Tag 重复 3-8 次（dict 覆盖 / 唯一键异常）
#   L2-V04 unknown_tag            → 未定义 Tag (0xFF00-0xFFFF)，路由 default 分支
#   L2-V05 infinite_loop          → 嵌套 TLV 自引用 → 解析器无限递归
#   L2-V06 length_zero_with_value → L=0 但实际跟随 V 字节，幽灵数据污染下一帧
# ─────────────────────────────────────────────────────────────────────────────

# TLV 头部大小（Tag 2 字节 + Length 4 字节）
TLV_HEADER_LEN = 6
# 默认合法 Tag（仅作占位，与 SOME/IP 规范无强绑定）
TLV_TAG_DEFAULT = 0x0001
# Tag 未定义 / 保留范围（高位段）
TLV_TAG_UNKNOWN_LO = 0xFF00
TLV_TAG_UNKNOWN_HI = 0xFFFF


def _build_tlv(tag: int, value: bytes, length_override: int | None = None) -> bytes:
    """构造一个 TLV 字节串：Tag(2B big-endian) + Length(4B big-endian) + V。

    Args:
        tag: uint16 Tag。
        value: V 字节串。
        length_override: 若指定，作为 L 字段写入值（用于 L 与 V 不一致的变异）。
            为 ``None`` 时 L = ``len(value)``。

    Returns:
        TLV 字节串，长度为 ``6 + len(value)``。
    """
    length = length_override if length_override is not None else len(value)
    return struct.pack(">HI", tag & 0xFFFF, length & 0xFFFFFFFF) + value


def _parse_tlvs(data: bytes) -> list[tuple[int, int, bytes]]:
    """容错地解析 TLV 序列（用于测试 / GUI 显示，主流程不强依赖）。

    遇到非法长度（剩余字节不够）时停止解析返回已解析部分。

    Returns:
        list of ``(tag, length_field_value, value_bytes)`` 三元组。
    """
    out: list[tuple[int, int, bytes]] = []
    i = 0
    while i + TLV_HEADER_LEN <= len(data):
        tag, length = struct.unpack(">HI", data[i:i + TLV_HEADER_LEN])
        i += TLV_HEADER_LEN
        # 截取 min(length, 剩余字节) 防越界
        actual_v_len = min(length, len(data) - i)
        if actual_v_len < 0:
            actual_v_len = 0
        out.append((tag, length, bytes(data[i:i + actual_v_len])))
        i += actual_v_len
    return out


@register_mutator
class TLVLengthTagMismatchMutator(BaseMutator):
    """L2-V01：T-L-V 中 L 字段值与 V 实际字节数不一致。

    构造单个 TLV：Tag=0x0001，V=8~32 字节随机内容；
    L 字段以 50% 概率写为 V 长度的 1/2（缩短，类比 L1-L04），
    或写为 V 长度的 2x+100（放大，类比 L1-L05）。
    服务端按 L 切片时越界读 / 漏读单个 TLV 内部。
    """

    name = "L2-V01.length_tag_mismatch"
    layer = 2
    target_field = "tlv"
    strategy = "length_tag_mismatch"
    weight = 3.0

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        v = bytes(rng.randint(0, 0xFF) for _ in range(rng.randint(8, 32)))
        if rng.random() < 0.5:
            fake_length = len(v) // 2  # 缩短（类似 L1-L04 截断）
        else:
            fake_length = len(v) * 2 + 100  # 放大（类似 L1-L05 越界读）
        new_payload = _build_tlv(TLV_TAG_DEFAULT, v, length_override=fake_length)
        return self._make_result(
            dataclasses.replace(seed, payload=new_payload),
            real_v_len=len(v), declared_length=fake_length,
        )


@register_mutator
class TLVNestedOverflowMutator(BaseMutator):
    """L2-V02：嵌套 TLV 深度爆炸（50-100 层）。

    每层是一个 TLV，其 V 部分是下一层 TLV，最内层 V 为空。
    递归式解析器若不限制深度则栈溢出 (StackOverflow / SIGSEGV)；
    迭代式解析器在 50+ 层时多数会触发"深度限制"早停或异常。
    """

    name = "L2-V02.nested_overflow"
    layer = 2
    target_field = "tlv"
    strategy = "nested_overflow"
    weight = 0.7  # payload 较大（最长 ~600 字节），略降权防阻塞

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        depth = rng.randint(50, 100)
        nested = b""
        for _ in range(depth):
            nested = _build_tlv(TLV_TAG_DEFAULT, nested)
        return self._make_result(
            dataclasses.replace(seed, payload=nested),
            depth=depth, payload_size=len(nested),
        )


@register_mutator
class TLVDuplicateTagMutator(BaseMutator):
    """L2-V03：同一 Tag 在 payload 中重复出现 3-8 次。

    服务端处理 TLV 流时常见两种实现：
    - dict 存储 → 后值覆盖前值，丢失数据；
    - 唯一性强校验 → 抛"重复键"异常，可能 DoS。
    每个重复 TLV 的 V 内容随机，便于事后归因。
    """

    name = "L2-V03.duplicate_tag"
    layer = 2
    target_field = "tlv"
    strategy = "duplicate_tag"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        tag = rng.randint(0x0001, 0x00FF)
        n = rng.randint(3, 8)
        parts = []
        for _ in range(n):
            v = bytes(rng.randint(0, 0xFF) for _ in range(rng.randint(2, 8)))
            parts.append(_build_tlv(tag, v))
        new_payload = b"".join(parts)
        return self._make_result(
            dataclasses.replace(seed, payload=new_payload),
            duplicate_tag=tag, count=n,
        )


@register_mutator
class TLVUnknownTagMutator(BaseMutator):
    """L2-V04：使用未定义 / 保留范围的 Tag（[0xFF00, 0xFFFF]）。

    服务端按 Tag 路由到处理函数；未注册 Tag 触发 dispatch table 的
    default 分支或查表越界（如 ``handlers[tag]`` 未保护数组下标）。
    """

    name = "L2-V04.unknown_tag"
    layer = 2
    target_field = "tlv"
    strategy = "unknown_tag"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        tag = rng.randint(TLV_TAG_UNKNOWN_LO, TLV_TAG_UNKNOWN_HI)
        v = bytes(rng.randint(0, 0xFF) for _ in range(rng.randint(4, 16)))
        new_payload = _build_tlv(tag, v)
        return self._make_result(
            dataclasses.replace(seed, payload=new_payload),
            unknown_tag=tag, v_len=len(v),
        )


@register_mutator
class TLVInfiniteLoopMutator(BaseMutator):
    """L2-V05：自引用循环 — 嵌套 TLV 中外层 L 撒谎指向自身整体大小。

    构造方式：
    - 内层 TLV：Tag=0x0001, L=0, V=空 → 6 字节整体
    - 外层 TLV：Tag=0x0001, L=**12（撒谎）**, V=内层 TLV(6 字节)
    - 整个 payload = 12 字节（外层 6 头 + 内层 6 字节）

    递归式 TLV 解析器路径：
    1. 读外层 Tag/L → L=12，开始读 V 12 字节
    2. 把 V 12 字节当作 TLV 序列再次解析（这就是"递归处理"）
    3. V 的前 6 字节 = 内层 TLV，正常处理 (Tag=0x0001, L=0, V=空)
    4. V 的后 6 字节 = 外层自身的 Tag/L 字段 (!) → 解析为新 TLV
    5. 又看到 Tag=0x0001, L=12，回到第 2 步 → **无限递归**

    这是 TLV 协议家族的经典"压缩炸弹"变种。
    """

    name = "L2-V05.infinite_loop"
    layer = 2
    target_field = "tlv"
    strategy = "infinite_loop"
    weight = 2.0  # 高危但 payload 极小（12B），权重适中

    # 外层"自引用"L 值 = 6（外层头）+ 6（内层整体）= 12
    _SELF_REFERENTIAL_L = 12

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        inner = _build_tlv(TLV_TAG_DEFAULT, b"")  # 6 字节
        outer = _build_tlv(
            TLV_TAG_DEFAULT, inner,
            length_override=self._SELF_REFERENTIAL_L,
        )
        return self._make_result(
            dataclasses.replace(seed, payload=outer),
            self_referential_length=self._SELF_REFERENTIAL_L,
            real_outer_v_len=len(inner),
            payload_size=len(outer),
        )


@register_mutator
class TLVLengthZeroWithValueMutator(BaseMutator):
    """L2-V06：TLV 的 L=0，但 payload 中实际跟随 V 字节。

    服务端按 L=0 决定不读 V，但底层 socket buffer 中仍保留这些字节。
    在长连接 / TCP 流式接收场景下，这些"幽灵字节"被下一次 read
    误读为新报文头部，造成跨帧污染或路由错位。

    本变异器在 V 中放置看起来像 SOME/IP header 的字节，
    模拟"在 TLV V 中走私下一帧报文头"的攻击。
    """

    name = "L2-V06.length_zero_with_value"
    layer = 2
    target_field = "tlv"
    strategy = "length_zero_with_value"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        # V 中包含一个看起来像合法 SOME/IP header 的 16 字节序列（隐蔽走私）
        smuggled_header = struct.pack(
            ">HHIBBBB",
            rng.randint(0, 0xFFFF), rng.randint(0, 0xFFFF),  # service, method
            8,                                                  # length=8（无 payload）
            0, 1,                                              # client_id
            0, 1,                                              # session_id
        ) + bytes([0x01, 0x01, 0x00, 0x00])
        new_payload = _build_tlv(TLV_TAG_DEFAULT, smuggled_header, length_override=0)
        return self._make_result(
            dataclasses.replace(seed, payload=new_payload),
            declared_length=0,
            smuggled_v_len=len(smuggled_header),
        )


# ─────────────────────────────────────────────────────────────────────────────
# Layer 2.3：字符串语义变异（10 种）
#
# SOME/IP payload 中常携带字符串类型字段（UTF-8 编码）。
# 以下变异器将 seed.payload 替换为各类边界/攻击字符串，
# 测试服务端字符串解析器的健壮性。
# 全部使用 _make_result()（header 结构合法，仅 payload 内容变异）。
# ─────────────────────────────────────────────────────────────────────────────


@register_mutator
class StringUtf8OverlongMutator(BaseMutator):
    """L2-S01：注入 UTF-8 过长编码（overlong encoding）。

    用 2 字节过长序列 0xC0 0x80 表示 U+0000（即 null）；
    合规解析器应拒绝，但存在漏洞的解析器接受并用作字符串终止符，
    触发缓冲区读越界或路径注入。
    """

    name = "L2-S01.utf8_overlong"
    layer = 2
    target_field = "payload"
    strategy = "utf8_overlong"

    # 过长编码字节序列（均表示 U+0000）
    _OVERLONG = [
        b"\xc0\x80",                # 2 字节过长 null
        b"\xe0\x80\x80",            # 3 字节过长 null
        b"\xf0\x80\x80\x80",        # 4 字节过长 null
        b"\xc1\xbf",                # 过长编码 U+007F（ASCII DEL）
    ]

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        pattern = rng.choice(self._OVERLONG)
        # 将 pattern 重复几次填充 payload（模拟字符串字段）
        repeat = rng.randint(1, 8)
        new_payload = pattern * repeat
        return self._make_result(
            dataclasses.replace(seed, payload=new_payload),
            pattern=pattern.hex(), repeat=repeat,
        )


@register_mutator
class StringUtf8InvalidMutator(BaseMutator):
    """L2-S02：注入非法 UTF-8 字节序列。

    0xFF / 0xFE 在 UTF-8 中永远非法（BOM 感知问题）；
    0x80-0xBF 作为起始字节非法（应为 continuation byte）。
    触发 UTF-8 解码器抛异常或截断。
    """

    name = "L2-S02.utf8_invalid"
    layer = 2
    target_field = "payload"
    strategy = "utf8_invalid"

    _INVALID_SEQS = [
        b"\xff\xfe\x00\x00",            # 非法起始（UTF-32 BOM 混入 UTF-8 上下文）
        b"\x80\x81\x82\x83",            # 非法起始（continuation bytes 当起始）
        b"\xfe\xff",                    # 非法 UTF-8 字节
        b"\xed\xa0\x80",               # UTF-8 编码的代理对高位（lone surrogate）
        b"hello\xff\xfeworld",          # 合法前缀 + 非法字节（测试部分解码）
    ]

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        new_payload = rng.choice(self._INVALID_SEQS)
        return self._make_result(
            dataclasses.replace(seed, payload=new_payload),
            seq=new_payload.hex(),
        )


@register_mutator
class StringNullByteInjectMutator(BaseMutator):
    """L2-S03：在 payload 随机位置注入空字节（0x00）。

    C 字符串以 null 终止；在字符串中间注入 0x00 使 strlen() 提前截断，
    但 memcpy() 可能仍复制完整长度，导致"字符串截断 + 越界读"组合漏洞。
    """

    name = "L2-S03.null_byte_inject"
    layer = 2
    target_field = "payload"
    strategy = "null_byte_inject"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        base = seed.payload if seed.payload else b"AAAAAAAAAA"
        n_nulls = rng.randint(1, 4)
        payload_list = list(base)
        for _ in range(n_nulls):
            pos = rng.randint(0, len(payload_list))
            payload_list.insert(pos, 0x00)
        new_payload = bytes(payload_list)
        return self._make_result(
            dataclasses.replace(seed, payload=new_payload),
            nulls_injected=n_nulls,
        )


@register_mutator
class StringFormatStringMutator(BaseMutator):
    """L2-S04：注入 C 格式化字符串攻击序列。

    %n 触发写操作（格式化字符串 write primitive）；
    %s 越界读内存；%x 泄露栈地址。
    若服务端将 payload 直接传入 printf/snprintf，触发 format string 漏洞。
    """

    name = "L2-S04.format_string"
    layer = 2
    target_field = "payload"
    strategy = "format_string"
    weight = 1.5

    _PATTERNS = [
        b"%s%s%s%s%s%s%s%s",
        b"%n%n%n%n",
        b"%x%x%x%x%x%x%x%x",
        b"%d%d%d%d%d%d%d%d",
        b"%.1000d",                   # 精度溢出
        b"%p%p%p%p",                  # 指针泄露
        b"AAAA%n%n%n%n",
    ]

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        new_payload = rng.choice(self._PATTERNS)
        return self._make_result(
            dataclasses.replace(seed, payload=new_payload),
            pattern=new_payload.decode("ascii", errors="replace"),
        )


@register_mutator
class StringVeryLongMutator(BaseMutator):
    """L2-S05：发送超长字符串 payload（1024 字节 'A' 填充）。

    经典缓冲区溢出测试；若服务端用固定大小缓冲区接收字符串参数，
    超长输入触发栈/堆溢出。长度可通过 strategies.toml 中的 weight 间接控制。
    """

    name = "L2-S05.very_long"
    layer = 2
    target_field = "payload"
    strategy = "very_long"
    weight = 1.5

    _LONG_LEN = 1024

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        new_payload = b"A" * self._LONG_LEN
        return self._make_result(
            dataclasses.replace(seed, payload=new_payload),
            length=self._LONG_LEN,
        )


@register_mutator
class StringUnicodeSurrogateMutator(BaseMutator):
    """L2-S06：注入 UTF-8 编码的 Unicode 代理对字节序列。

    U+D800-U+DFFF（代理区）不应单独出现在 UTF-8 中；
    Python 在 strict 模式下拒绝解码，但许多 C/Java 实现默默接受，
    触发内部字符串状态不一致或比较错误。
    """

    name = "L2-S06.unicode_surrogate"
    layer = 2
    target_field = "payload"
    strategy = "unicode_surrogate"

    # U+D800（高代理）和 U+DC00（低代理）的非法 UTF-8 编码
    _SURROGATES = [
        b"\xed\xa0\x80",       # lone high surrogate U+D800
        b"\xed\xb0\x80",       # lone low surrogate U+DC00
        b"\xed\xa0\x80\xed\xb0\x80",  # 代理对（CESU-8 而非 UTF-8）
    ]

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        new_payload = rng.choice(self._SURROGATES)
        return self._make_result(
            dataclasses.replace(seed, payload=new_payload),
            surrogate=new_payload.hex(),
        )


@register_mutator
class StringBomInjectMutator(BaseMutator):
    """L2-S07：在 payload 开头注入 UTF-8 BOM（EF BB BF）。

    BOM 在 UTF-8 中是 U+FEFF 的编码，合法但不推荐；
    若服务端字符串比较不跳过 BOM，会导致 "\\ufeffhello" != "hello"，
    触发认证绕过或路由失配。
    """

    name = "L2-S07.bom_inject"
    layer = 2
    target_field = "payload"
    strategy = "bom_inject"

    _UTF8_BOM = b"\xef\xbb\xbf"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        base = seed.payload if seed.payload else b"service_name"
        new_payload = self._UTF8_BOM + base
        return self._make_result(
            dataclasses.replace(seed, payload=new_payload),
            bom=self._UTF8_BOM.hex(),
        )


@register_mutator
class StringControlCharsMutator(BaseMutator):
    """L2-S08：注入全套 ASCII 控制字符（0x00-0x1F）。

    控制字符在日志、XML、JSON 解析中常触发：
    - 日志注入（换行符 0x0A 伪造新日志行）
    - XML 解析器拒绝（0x00-0x08 非法字符）
    - 字符串终止（0x00 null）
    """

    name = "L2-S08.control_chars"
    layer = 2
    target_field = "payload"
    strategy = "control_chars"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        # 生成包含所有控制字符的 payload
        new_payload = bytes(range(0x00, 0x20))
        return self._make_result(
            dataclasses.replace(seed, payload=new_payload),
            length=len(new_payload),
        )


@register_mutator
class StringPathTraversalMutator(BaseMutator):
    """L2-S09：注入路径穿越（Directory Traversal）模式。

    若服务端将 payload 中的字符串用作文件路径，
    "../../../etc/passwd" 等模式触发任意文件读取漏洞。
    """

    name = "L2-S09.path_traversal"
    layer = 2
    target_field = "payload"
    strategy = "path_traversal"

    _PATTERNS = [
        b"../../../etc/passwd",
        b"..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
        b"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",   # URL 编码
        b"....//....//....//etc//passwd",                # 双重前缀绕过
        b"\x00/../../../etc/shadow",                     # null byte + 路径穿越组合
    ]

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        new_payload = rng.choice(self._PATTERNS)
        return self._make_result(
            dataclasses.replace(seed, payload=new_payload),
            pattern=new_payload[:32].decode("ascii", errors="replace"),
        )


@register_mutator
class StringSqlInjectPatternMutator(BaseMutator):
    """L2-S10：注入 SQL 注入攻击模式字节。

    若服务端将 payload 字符串拼入 SQL 查询，经典注入模式触发
    SQL 解析错误或权限绕过。车载 ECU 中 SQLite 被广泛用于诊断数据存储。
    """

    name = "L2-S10.sql_inject_pattern"
    layer = 2
    target_field = "payload"
    strategy = "sql_inject_pattern"

    _PATTERNS = [
        b"' OR '1'='1",
        b"'; DROP TABLE services;--",
        b"1; EXEC xp_cmdshell('id');--",
        b"' UNION SELECT null,null,null--",
        b"\\x27 OR 1=1--",
    ]

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        new_payload = rng.choice(self._PATTERNS)
        return self._make_result(
            dataclasses.replace(seed, payload=new_payload),
            pattern=new_payload.decode("ascii", errors="replace"),
        )


# ─────────────────────────────────────────────────────────────────────────────
# Layer 2.5：字段间约束破坏（5 种）
#
# SOME/IP 协议在多个 header 字段之间存在隐式约束关系：
#   - Length 字段必须等于 payload 实际长度 + 8（client/session/ver/type/rc）
#   - Session ID 通常单调递增
#   - proto_version 与 interface_version 遵循固定版本约定
#   - method_id 高位 0 表示 Method，高位 1（0x8000）表示 Event/Notification
#   - TP 分段标志需与 payload offset 配合
#
# 这些变异器打破上述约束，测试服务端的容错校验。
# ─────────────────────────────────────────────────────────────────────────────


@register_mutator
class ConstraintLengthPayloadMutator(BaseMutator):
    """L2-C01：Length 字段与 Payload 实际长度不一致。

    SOME/IP Length = 8 + len(payload)；此处故意写错，
    使接收方切片 payload 时越界读或读到下一帧数据。
    使用 _make_raw_result()（直接操作字节 header）。
    """

    name = "L2-C01.length_payload_inconsistent"
    layer = 2
    target_field = "length"
    strategy = "length_payload_inconsistent"
    weight = 2.0

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        raw = seed.to_bytes()
        real_length = len(raw) - 8   # SOME/IP length = total - first 8 bytes
        # 以 50% 概率偏大（越界读），50% 概率偏小（截断）
        delta = rng.randint(1, 100)
        if rng.random() < 0.5:
            fake_length = real_length + delta
        else:
            fake_length = max(8, real_length - delta)
        new_raw = replace_length_field(raw, fake_length)
        return self._make_raw_result(
            new_raw,
            real_length=real_length, fake_length=fake_length,
            delta=fake_length - real_length,
        )


@register_mutator
class ConstraintSessionDecreasingMutator(BaseMutator):
    """L2-C02：Session ID 递减（违反正常单调递增约定）。

    服务端若用 session_id 做去重或防重放检测，
    递减的 session_id 触发"旧报文"拒绝或状态机回退。
    """

    name = "L2-C02.session_decreasing"
    layer = 2
    target_field = "session_id"
    strategy = "session_decreasing"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        decrement = rng.randint(1, 0x100)
        new_session = (seed.session_id - decrement) & 0xFFFF
        return self._make_result(
            dataclasses.replace(seed, session_id=new_session),
            original_session=seed.session_id, new_session=new_session,
        )


@register_mutator
class ConstraintProtoIfaceSwapMutator(BaseMutator):
    """L2-C03：Protocol Version 与 Interface Version 互换。

    proto_version（固定 0x01）与 interface_version（服务定义的版本）
    互换后，服务端版本检查逻辑看到意外的版本号，触发拒绝或降级路径。
    """

    name = "L2-C03.proto_iface_swap"
    layer = 2
    target_field = "proto_version"
    strategy = "proto_iface_swap"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        return self._make_result(
            dataclasses.replace(
                seed,
                protocol_version=seed.interface_version,
                interface_version=seed.protocol_version,
            ),
            original_proto=seed.protocol_version,
            original_iface=seed.interface_version,
        )


@register_mutator
class ConstraintRequestResponseIdMutator(BaseMutator):
    """L2-C04：将 method_id 高位置 1，使请求看起来像事件通知 ID。

    SOME/IP method_id 规范：0x0000-0x7FFF = Method ID，0x8000-0xFFFF = Event ID。
    此变异发送 method_id | 0x8000 的"请求"，触发服务端错误路由。
    """

    name = "L2-C04.request_with_response_id"
    layer = 2
    target_field = "method_id"
    strategy = "request_with_response_id"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        event_style_id = seed.method_id | 0x8000
        return self._make_result(
            dataclasses.replace(seed, method_id=event_style_id),
            original_method=seed.method_id, mutated_method=event_style_id,
        )


@register_mutator
class ConstraintTpFlagNoOffsetMutator(BaseMutator):
    """L2-C05：msg_type 加 TP flag（0x20）但 payload 前 4 字节 offset 强制置 0。

    SOME/IP-TP 分段报文格式：msg_type bit5=1 表示 TP 报文，payload 前 4 字节是
    TP offset（大端 uint32，最低位为 More Segments flag）。
    此变异设置 TP flag 但 offset=0（"第一个分片" 但没有 More Segments），
    而 payload 内容不是合法 TP 分段，触发 TP 重组器状态错误。
    使用 _make_raw_result()（需要精确控制 msg_type 字节）。
    """

    name = "L2-C05.tp_flag_without_offset"
    layer = 2
    target_field = "msg_type"
    strategy = "tp_flag_without_offset"

    _TP_FLAG = 0x20  # msg_type bit5

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        raw = bytearray(seed.to_bytes())
        # 设置 TP 标志位
        raw[OFFSET_MSG_TYPE] = raw[OFFSET_MSG_TYPE] | self._TP_FLAG
        # 确保 payload 至少 4 字节；前 4 字节设为 0x00000000（offset=0, More=0）
        if len(raw) < HEADER_LEN + 4:
            raw.extend(b"\x00" * (HEADER_LEN + 4 - len(raw)))
        raw[HEADER_LEN:HEADER_LEN + 4] = b"\x00\x00\x00\x00"
        return self._make_raw_result(
            bytes(raw),
            tp_flag=self._TP_FLAG,
            original_msg_type=int(seed.message_type),
        )
