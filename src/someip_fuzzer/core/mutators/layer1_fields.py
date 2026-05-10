"""Layer 1 字段级变异器：SOME/IP header 各字段的边界 / 随机 / 翻转 / 交换变异。

涵盖 SPEC §2.3 的 Layer 1.1-1.7（共 53 - 12 = 41 种 = Service ID 8 + Method ID 6 +
Length 7 + Client/Session 5 + Version 4 + MsgType 6 + RetCode 5）。

────────────────────────────────────────────────────────────────────────────────
代码模板（后续所有 Layer 1 变异器都遵守）：

1. 类名：``<TargetField><Strategy>Mutator``，例如 ``ServiceIdBoundaryMinMutator``
2. 装饰器：``@register_mutator``，写在 class 行上方
3. ClassVar 顺序固定：``name`` / ``layer`` / ``target_field`` / ``strategy``
   （可选 ``weight``，默认 1.0；高/低危值在 configs/strategies.toml 调整即可）
4. ``name`` 格式：``L<layer>-<abbr><NN>.<strategy>``
   - 缩写：S=Service, M=Method, L=Length, C=Client/Session, V=Version,
     T=MsgType, R=RetCode, P=Payload；后续 Layer 2 用：T=Type, V=TLV,
     S=String, E=Endian, C=Constraint, SD=Service Discovery
   - 编号：组内从 01 递增，与 SPEC §2.3 表格一致
   - strategy 字段值与 ``name`` 末段保持一致（避免不同步）
5. ``mutate(self, seed, rng)`` 实现：
   - 用 ``dataclasses.replace(seed, ...)`` 浅拷贝改字段（不要直接改 seed）
   - 用 ``rng`` 而非全局 ``random``（确保可重放）
   - 通过 ``self._make_result(new)`` 返回（合法变异）
   - 字节级变异（如 Length 溢出）用 ``self._make_raw_result(raw_bytes)``
6. docstring 必须说明：变异内容 + 预期触发什么类型的服务端缺陷
────────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import dataclasses
import random

from someip_fuzzer.core.mutator import BaseMutator, MutationResult, register_mutator
from someip_fuzzer.core.protocol import SomeIpPacket

# ── 常量 ─────────────────────────────────────────────────────────────────────

# Service ID 取值范围（来自 SOME/IP 规范 ISO 17215-2 / AUTOSAR PRS_SOMEIPProtocol）
SERVICE_ID_MIN = 0x0000
SERVICE_ID_MAX = 0xFFFF
SERVICE_ID_RESERVED_LO = 0xFF00  # 0xFF00-0xFFFE 为协议保留域
SERVICE_ID_RESERVED_HI = 0xFFFE
SERVICE_ID_BITS = 16


# ── L1-S01 ~ L1-S08：Service ID 变异（8 种） ─────────────────────────────────


@register_mutator
class ServiceIdBoundaryMinMutator(BaseMutator):
    """L1-S01：Service ID 设为最小边界值 0x0000。

    预期触发：服务路由对 ID=0 的特殊处理分支、未初始化字段检查、整数溢出前置条件。
    """

    name = "L1-S01.boundary_min"
    layer = 1
    target_field = "service_id"
    strategy = "boundary_min"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        new = dataclasses.replace(seed, service_id=SERVICE_ID_MIN)
        return self._make_result(new)


@register_mutator
class ServiceIdBoundaryMaxMutator(BaseMutator):
    """L1-S02：Service ID 设为最大边界值 0xFFFF。

    预期触发：服务表越界、uint16 溢出、保留域校验缺失。
    """

    name = "L1-S02.boundary_max"
    layer = 1
    target_field = "service_id"
    strategy = "boundary_max"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        new = dataclasses.replace(seed, service_id=SERVICE_ID_MAX)
        return self._make_result(new)


@register_mutator
class ServiceIdBoundaryMaxMinus1Mutator(BaseMutator):
    """L1-S03：Service ID 设为 0xFFFE（最大-1）。

    用于探测"最后一个有效 ID"边界条件，常被 off-by-one 错误命中。
    """

    name = "L1-S03.boundary_max_minus_1"
    layer = 1
    target_field = "service_id"
    strategy = "boundary_max_minus_1"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        new = dataclasses.replace(seed, service_id=SERVICE_ID_MAX - 1)
        return self._make_result(new)


@register_mutator
class ServiceIdReservedRangeMutator(BaseMutator):
    """L1-S04：Service ID 取协议保留域 [0xFF00, 0xFFFE] 内的随机值。

    SOME/IP 规范保留 0xFF00-0xFFFF；多数实现应拒绝处理，未拒绝即为缺陷。
    """

    name = "L1-S04.reserved_range"
    layer = 1
    target_field = "service_id"
    strategy = "reserved_range"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        new_id = rng.randint(SERVICE_ID_RESERVED_LO, SERVICE_ID_RESERVED_HI)
        new = dataclasses.replace(seed, service_id=new_id)
        return self._make_result(new, chosen_value=new_id)


@register_mutator
class ServiceIdRandomUniformMutator(BaseMutator):
    """L1-S05：Service ID 取 [0x0000, 0xFFFF] 内的均匀随机值（广撒网）。

    权重默认降至 0.5，避免淹没定向边界变异；可在 strategies.toml 调整。
    """

    name = "L1-S05.random_uniform"
    layer = 1
    target_field = "service_id"
    strategy = "random_uniform"
    weight = 0.5

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        new_id = rng.randint(SERVICE_ID_MIN, SERVICE_ID_MAX)
        new = dataclasses.replace(seed, service_id=new_id)
        return self._make_result(new, chosen_value=new_id)


@register_mutator
class ServiceIdBitFlipSingleMutator(BaseMutator):
    """L1-S06：单 bit 翻转 — 随机翻转 service_id 的 1 个 bit。

    适合"邻近变异"：与原 ID 仅差 1 bit，常用于配合崩溃用例最小化。
    """

    name = "L1-S06.bit_flip_single"
    layer = 1
    target_field = "service_id"
    strategy = "bit_flip_single"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        bit = rng.randint(0, SERVICE_ID_BITS - 1)
        new_id = (seed.service_id ^ (1 << bit)) & SERVICE_ID_MAX
        new = dataclasses.replace(seed, service_id=new_id)
        return self._make_result(new, flipped_bit=bit)


@register_mutator
class ServiceIdBitFlipMultipleMutator(BaseMutator):
    """L1-S07：多 bit 翻转 — 同时翻转 service_id 的 2~5 个不同 bit（大幅变异）。

    与 S06 互补：覆盖更大的 ID 空间扰动，触发"远距离"邻近缺陷。
    """

    name = "L1-S07.bit_flip_multiple"
    layer = 1
    target_field = "service_id"
    strategy = "bit_flip_multiple"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        n = rng.randint(2, 5)
        bits = rng.sample(range(SERVICE_ID_BITS), n)
        mask = 0
        for b in bits:
            mask |= 1 << b
        new_id = (seed.service_id ^ mask) & SERVICE_ID_MAX
        new = dataclasses.replace(seed, service_id=new_id)
        return self._make_result(new, flipped_bits=tuple(sorted(bits)))


@register_mutator
class ServiceIdSwapWithMethodIdMutator(BaseMutator):
    """L1-S08：Service ID ↔ Method ID 互换（字段混淆攻击）。

    部分实现把 (service_id, method_id) 合并成 32-bit message_id 处理；
    互换后 message_id 仍合法，但 (service, method) 解析会进入错误分支。
    """

    name = "L1-S08.swap_with_method_id"
    layer = 1
    target_field = "service_id"
    strategy = "swap_with_method_id"

    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        new = dataclasses.replace(
            seed,
            service_id=seed.method_id & SERVICE_ID_MAX,
            method_id=seed.service_id & SERVICE_ID_MAX,
        )
        return self._make_result(
            new,
            original_service=seed.service_id,
            original_method=seed.method_id,
        )
