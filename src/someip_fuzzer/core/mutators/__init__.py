"""所有变异策略集合，导入即触发自动注册。

使用方式::

    import someip_fuzzer.core.mutators  # noqa: F401（仅为副作用：注册）
    from someip_fuzzer.core import MUTATOR_REGISTRY, MutationScheduler

    print(len(MUTATOR_REGISTRY))     # ≥ 93（Phase 2 完成时）
    sch = MutationScheduler()        # 调度器自动覆盖全部已注册变异器

子模块布局（按 SPEC §2.3 的 Layer 划分）：

- ``layer1_fields``：Layer 1.1-1.7 字段级变异（Service/Method/Length/Client/Session/Version/MsgType/RetCode）
- ``layer1_payload``：Layer 1.8 Payload 变异（12 种）
- ``layer2_semantic``：Layer 2.1-2.5 协议语义变异（类型边界/TLV/字符串/字节序/字段约束）
- ``layer2_sd``：Layer 2.6 SD Entry/Option 变异（8 种）

每个子模块导入即注册自身所有变异器。在子模块未实现前，对应行可暂时注释。
"""

# 子模块导入会触发模块级 @register_mutator 装饰器执行 → 注册到 MUTATOR_REGISTRY。
# 顺序与 SPEC 一致；新模块加入时追加导入即可。
from someip_fuzzer.core.mutators import layer1_fields    # noqa: F401
from someip_fuzzer.core.mutators import layer1_payload   # noqa: F401
from someip_fuzzer.core.mutators import layer2_semantic  # noqa: F401

from someip_fuzzer.core.mutators import layer2_sd    # noqa: F401
