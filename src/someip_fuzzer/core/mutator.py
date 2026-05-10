"""变异引擎框架核心 —— BaseMutator、MutationResult、注册系统、字节工具。

这是 SOME/IP 模糊测试工具的变异引擎入口。所有变异策略（93 种 Layer 1-2，
未来扩展到 Layer 3-5）都通过 :func:`register_mutator` 注册到
:data:`MUTATOR_REGISTRY`，由 :class:`MutationScheduler`（task 2.2 实现）
按权重随机选择并调度。

设计要点：
- :class:`MutationResult` 同时承载合法报文（``packet``）和畸形字节流
  （``raw_bytes``），解决 Length / 字节序等"必须绕过 scapy 自动计算"的
  变异需求。
- 所有 ``mutate()`` 必须接受外部 :class:`random.Random` 实例，禁止使用全局
  ``random`` 模块——否则模糊测试结果不可重放。
"""

from __future__ import annotations

import random
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import ClassVar

from someip_fuzzer.core.protocol import SomeIpPacket

# ── 变异结果 ─────────────────────────────────────────────────────────────────


@dataclass
class MutationResult:
    """单次变异的输出。

    ``raw_bytes`` 是最终通过网络发送的字节流，必填。
    ``packet`` 仅在变异保持合法 :class:`SomeIpPacket` 结构时填充，否则 ``None``
    （例如 Length 字段被故意改成 0xFFFFFFFF 时报文已无法回到 dataclass）。
    """

    raw_bytes: bytes
    packet: SomeIpPacket | None
    mutator_name: str
    layer: int
    target_field: str
    strategy: str
    seed_packet_id: str | None = None
    metadata: dict = field(default_factory=dict)


# ── 变异器抽象基类 ────────────────────────────────────────────────────────────


class BaseMutator(ABC):
    """所有变异策略的基类。

    子类必须定义 4 个 ClassVar：``name`` / ``layer`` / ``target_field`` /
    ``strategy``。``name`` 必须全局唯一（注册时校验），格式约定
    ``L{layer}-{abbr}{NN}.{strategy}``，例如 ``L1-S01.boundary_min``。
    """

    name: ClassVar[str]
    layer: ClassVar[int]
    target_field: ClassVar[str]
    strategy: ClassVar[str]
    weight: ClassVar[float] = 1.0

    @abstractmethod
    def mutate(self, seed: SomeIpPacket, rng: random.Random) -> MutationResult:
        """对种子报文执行一次变异。

        Args:
            seed: 来源种子报文。变异器不得修改 seed，必须返回新对象 / 字节流。
            rng: 调用方注入的随机数发生器。变异器不得使用全局 random 模块。

        Returns:
            :class:`MutationResult` 实例，至少包含 ``raw_bytes``。
        """
        ...

    def __init_subclass__(cls, **kwargs: object) -> None:
        """子类定义时校验必备 ClassVar。

        中间抽象类（仍有 abstract 方法）跳过校验。注意 ABC 的
        ``__abstractmethods__`` 是在 ``type.__new__`` 之后才设置的，
        ``__init_subclass__`` 执行时它还不存在，所以这里直接检查
        ``mutate`` 是否仍带 ``__isabstractmethod__`` 标记。
        """
        super().__init_subclass__(**kwargs)
        if getattr(cls.mutate, "__isabstractmethod__", False):
            return
        for required in ("name", "layer", "target_field", "strategy"):
            if required not in cls.__dict__ and not any(
                required in base.__dict__
                for base in cls.__mro__[1:]
                if base is not BaseMutator
            ):
                raise TypeError(
                    f"{cls.__name__} 必须定义类变量 {required!r}"
                )


# ── 注册系统 ──────────────────────────────────────────────────────────────────


MUTATOR_REGISTRY: dict[str, type[BaseMutator]] = {}


def register_mutator(cls: type[BaseMutator]) -> type[BaseMutator]:
    """变异器注册装饰器。重名抛 :class:`ValueError`。

    用法::

        @register_mutator
        class ServiceIdBoundaryMin(BaseMutator):
            name = "L1-S01.boundary_min"
            layer = 1
            target_field = "service_id"
            strategy = "boundary_min"
            def mutate(self, seed, rng):
                ...
    """
    if not isinstance(cls, type) or not issubclass(cls, BaseMutator):
        raise TypeError(
            f"register_mutator 仅支持 BaseMutator 子类，收到 {cls!r}"
        )
    if cls.__abstractmethods__:
        raise TypeError(
            f"{cls.__name__} 仍是抽象类（未实现 {cls.__abstractmethods__}），不可注册"
        )
    name = cls.name
    if name in MUTATOR_REGISTRY:
        existing = MUTATOR_REGISTRY[name].__name__
        raise ValueError(
            f"变异器名称 {name!r} 已被 {existing} 注册，无法再注册 {cls.__name__}"
        )
    MUTATOR_REGISTRY[name] = cls
    return cls


def get_mutator(name: str) -> type[BaseMutator]:
    """按名字取出已注册的变异器类。未注册抛 :class:`KeyError`。"""
    if name not in MUTATOR_REGISTRY:
        raise KeyError(f"未注册的变异器：{name!r}")
    return MUTATOR_REGISTRY[name]


def list_mutators(
    layer: int | None = None,
    target_field: str | None = None,
) -> list[type[BaseMutator]]:
    """列出已注册变异器，可按 ``layer`` / ``target_field`` 过滤。"""
    out: list[type[BaseMutator]] = []
    for cls in MUTATOR_REGISTRY.values():
        if layer is not None and cls.layer != layer:
            continue
        if target_field is not None and cls.target_field != target_field:
            continue
        out.append(cls)
    return out


# ── 字节级工具（绕过 scapy 自动计算用） ───────────────────────────────────────

# SOME/IP header 字段偏移量（参考 plan/02-PHASE-1-PROTOCOL.md）
HEADER_LEN: int = 16
OFFSET_SERVICE_ID: int = 0    # 2 字节，big-endian
OFFSET_METHOD_ID: int = 2     # 2 字节
OFFSET_LENGTH: int = 4        # 4 字节，big-endian uint32
OFFSET_CLIENT_ID: int = 8     # 2 字节
OFFSET_SESSION_ID: int = 10   # 2 字节
OFFSET_PROTO_VER: int = 12    # 1 字节
OFFSET_IFACE_VER: int = 13    # 1 字节
OFFSET_MSG_TYPE: int = 14     # 1 字节
OFFSET_RETURN_CODE: int = 15  # 1 字节


def _check_header(raw: bytes) -> None:
    if len(raw) < HEADER_LEN:
        raise ValueError(
            f"raw 长度 {len(raw)} 不足 {HEADER_LEN} 字节 SOME/IP header"
        )


def replace_length_field(raw: bytes, new_length: int) -> bytes:
    """覆盖 SOME/IP header 第 4-7 字节（Length, big-endian uint32）。

    用于 Length 变异（L1-L01~L1-L07）和字段间约束破坏（L2-C01）。
    ``new_length`` 范围 ``[0, 2**32-1]``，超出抛 :class:`ValueError`。
    """
    if not 0 <= new_length <= 0xFFFFFFFF:
        raise ValueError(f"new_length 超出 uint32 范围: {new_length}")
    _check_header(raw)
    return raw[:OFFSET_LENGTH] + new_length.to_bytes(4, "big") + raw[OFFSET_LENGTH + 4:]


def replace_header_byte(raw: bytes, offset: int, value: int) -> bytes:
    """覆盖 SOME/IP header 单字节（如 Proto Ver / Iface Ver / MsgType / RetCode）。

    用于不希望走 dataclass-replace 的字节级变异。
    ``offset`` 必须在 ``[0, HEADER_LEN)`` 范围内，``value`` 必须在 ``[0, 0xFF]``。
    """
    if not 0 <= offset < HEADER_LEN:
        raise ValueError(f"offset {offset} 不在 [0, {HEADER_LEN}) 范围")
    if not 0 <= value <= 0xFF:
        raise ValueError(f"value {value} 不在 [0, 0xFF] 范围")
    _check_header(raw)
    return raw[:offset] + bytes([value]) + raw[offset + 1:]


def replace_header_bytes(raw: bytes, offset: int, value: bytes) -> bytes:
    """覆盖 SOME/IP header 任意区间（如 Service ID 2 字节、Length 4 字节）。

    便于将多字段集中 patch（例如 L2-C03 Proto/Iface 互换）。
    """
    end = offset + len(value)
    if offset < 0 or end > HEADER_LEN:
        raise ValueError(
            f"区间 [{offset}, {end}) 超出 header 范围 [0, {HEADER_LEN})"
        )
    _check_header(raw)
    return raw[:offset] + value + raw[end:]
