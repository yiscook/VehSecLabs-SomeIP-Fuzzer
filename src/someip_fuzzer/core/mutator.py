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

    # ── 子类构造 MutationResult 的帮助方法（统一模板，避免 93 处样板代码） ──

    def _make_result(
        self,
        mutated: SomeIpPacket,
        seed_packet_id: str | None = None,
        **metadata: object,
    ) -> MutationResult:
        """合法变异：从 mutated dataclass 构造 MutationResult。

        ``raw_bytes`` 通过 ``mutated.to_bytes()`` 序列化得到；
        ``packet`` 字段填充 mutated 本身，便于 GUI/反馈引擎查看。
        """
        return MutationResult(
            raw_bytes=mutated.to_bytes(),
            packet=mutated,
            mutator_name=self.name,
            layer=self.layer,
            target_field=self.target_field,
            strategy=self.strategy,
            seed_packet_id=seed_packet_id,
            metadata=dict(metadata),
        )

    def _make_raw_result(
        self,
        raw_bytes: bytes,
        seed_packet_id: str | None = None,
        **metadata: object,
    ) -> MutationResult:
        """畸形变异：直接发送 raw_bytes，``packet`` 字段填 None。

        用于 Length 字段溢出 / 字节序混淆 / Header 字节级损坏等
        无法回到合法 dataclass 的场景。
        """
        return MutationResult(
            raw_bytes=raw_bytes,
            packet=None,
            mutator_name=self.name,
            layer=self.layer,
            target_field=self.target_field,
            strategy=self.strategy,
            seed_packet_id=seed_packet_id,
            metadata=dict(metadata),
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


# ── 调度器 ────────────────────────────────────────────────────────────────────


class MutationScheduler:
    """加权随机变异器调度器。

    职责：
    - 在已注册的变异器集合中按 ``layer`` / ``target_field`` 过滤候选；
    - 用调用方注入的 :class:`random.Random` 做加权随机选一个；
    - 暴露 :meth:`update_weight` / :meth:`disable` 供 Phase 4 反馈引擎动态调整。

    权重语义：
    - 初始权重来自 ``BaseMutator.weight`` ClassVar（默认 1.0）。
    - ``update_weight(name, 0.0)`` 等价于禁用——``select`` 时会被过滤。
    - 全部权重为 0 时 :meth:`select` 抛 :class:`LookupError`，由调用方决定是否回退。

    用法::

        scheduler = MutationScheduler()           # 用全局 MUTATOR_REGISTRY
        m = scheduler.select(layer=1, rng=rng)    # 随机选一个 Layer 1 变异器
        result = m.mutate(seed, rng)
    """

    def __init__(
        self,
        registry: dict[str, type[BaseMutator]] | None = None,
        rng: random.Random | None = None,
    ) -> None:
        src = registry if registry is not None else MUTATOR_REGISTRY
        # 在调度器构造时一次性实例化所有变异器，避免每次 select 都重建
        self._mutators: list[BaseMutator] = [cls() for cls in src.values()]
        self._weights: dict[str, float] = {m.name: m.weight for m in self._mutators}
        # 默认 RNG 仅在调用方未传 rng 时使用；模糊测试主流程应始终显式传入
        self._default_rng = rng or random.Random()

    # ── 选择 ─────────────────────────────────────────────────────────────────

    def select(
        self,
        layer: int | None = None,
        target_field: str | None = None,
        rng: random.Random | None = None,
    ) -> BaseMutator:
        """按 ``layer`` / ``target_field`` 过滤后做加权随机选择。

        Args:
            layer: 仅考虑 ``cls.layer == layer`` 的变异器。``None`` 不过滤。
            target_field: 仅考虑 ``cls.target_field == target_field`` 的变异器。
            rng: 调用方注入的随机数发生器。``None`` 时用调度器默认 RNG。

        Returns:
            被选中的 :class:`BaseMutator` 实例（不是类）。

        Raises:
            LookupError: 没有满足条件且权重 > 0 的候选。
        """
        candidates = [
            m for m in self._mutators
            if (layer is None or m.layer == layer)
            and (target_field is None or m.target_field == target_field)
            and self._weights.get(m.name, 0.0) > 0.0
        ]
        if not candidates:
            raise LookupError(
                f"无满足条件的变异器：layer={layer}, target_field={target_field!r}"
            )
        weights = [self._weights[m.name] for m in candidates]
        chooser = rng if rng is not None else self._default_rng
        return chooser.choices(candidates, weights=weights, k=1)[0]

    # ── 反馈接口（Phase 4 用） ──────────────────────────────────────────────

    def update_weight(self, name: str, score: float) -> None:
        """调整变异器权重。``score`` 必须 ≥ 0。

        Phase 4 反馈引擎会基于覆盖率/崩溃率给"成功"的变异器加权重，
        给"无效"的降权或归零。
        """
        if name not in self._weights:
            raise KeyError(f"未注册的变异器：{name!r}")
        if score < 0:
            raise ValueError(f"score 必须 ≥ 0，收到 {score}")
        self._weights[name] = float(score)

    def disable(self, name: str) -> None:
        """临时禁用某个变异器（等价于 ``update_weight(name, 0.0)``）。"""
        self.update_weight(name, 0.0)

    def enable(self, name: str, weight: float = 1.0) -> None:
        """重新启用一个被禁用的变异器，恢复指定权重（默认 1.0）。"""
        self.update_weight(name, weight)

    def get_weight(self, name: str) -> float:
        """查询当前权重。未注册抛 :class:`KeyError`。"""
        if name not in self._weights:
            raise KeyError(f"未注册的变异器：{name!r}")
        return self._weights[name]

    # ── 查询 ─────────────────────────────────────────────────────────────────

    def list_active(self) -> list[BaseMutator]:
        """列出当前权重 > 0 的变异器实例。"""
        return [m for m in self._mutators if self._weights.get(m.name, 0.0) > 0.0]

    def list_all(self) -> list[BaseMutator]:
        """列出所有变异器实例（含已禁用）。"""
        return list(self._mutators)

    def apply_strategies_config(self, config: object) -> None:
        """从 :class:`~someip_fuzzer.utils.config.StrategiesConfig` 批量调整权重。

        按如下优先级应用：
        1. ``config.disabled`` 里的名字权重归零；
        2. ``config.weights`` 里的名字覆盖权重；
        3. 不在 ``config.enabled_layers`` 里的 layer 变异器全部禁用。

        ``config`` 接受 duck-typing，只要有 ``enabled_layers``、``weights``、
        ``disabled`` 三个属性即可，方便测试时注入 mock 对象。
        """
        # 先按 enabled_layers 过滤：layer 不在列表内一律禁用
        enabled = set(config.enabled_layers)  # type: ignore[attr-defined]
        for m in self._mutators:
            if m.layer not in enabled:
                self._weights[m.name] = 0.0

        # 再应用 weights 覆盖（跳过不在注册表内的名字，防止 typo 导致崩溃）
        for name, w in config.weights.items():  # type: ignore[attr-defined]
            if name in self._weights:
                self._weights[name] = float(w)

        # 最后禁用黑名单（优先级最高，覆盖前两步）
        for name in config.disabled:  # type: ignore[attr-defined]
            if name in self._weights:
                self._weights[name] = 0.0

    def __len__(self) -> int:
        """注册表中变异器总数（含已禁用）。"""
        return len(self._mutators)

    def __repr__(self) -> str:
        active = sum(1 for w in self._weights.values() if w > 0.0)
        return f"MutationScheduler(total={len(self._mutators)}, active={active})"
