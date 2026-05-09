# Phase 2 - 变异引擎（核心创新点 C1）

```yaml
phase: 2
title: 变异引擎（5层架构）
status: Not Started
recommended_model: Opus 4.7（核心算法） + Sonnet 4.6（常规变异函数）
acceptance_passed: false
git_tag: v0.2.0
```

---

## 2.1 目标

实现申报书要求的**协议语义感知变异**（创新点 C1），通过 5 层变异架构覆盖：基础字段、协议语义、状态、攻击链、反馈引导。本阶段实现 **Layer 1（字段级）** 和 **Layer 2（协议语义级）**。Layer 3-5 在后续 Phase 完成。

---

## 2.2 任务清单

### Layer 1：字段级变异（基础）

| ID | 任务 | 变异策略数 | 状态 |
|----|------|-----------|------|
| 2.1 | Service ID 变异器 | 8 种 | ⬜ |
| 2.2 | Method/Event ID 变异器 | 6 种 | ⬜ |
| 2.3 | Length 字段变异器 | 7 种 | ⬜ |
| 2.4 | Client/Session ID 变异器 | 5 种 | ⬜ |
| 2.5 | Protocol/Interface Version 变异器 | 4 种 | ⬜ |
| 2.6 | Message Type 变异器 | 6 种 | ⬜ |
| 2.7 | Return Code 变异器 | 5 种 | ⬜ |
| 2.8 | Payload 通用变异器 | 12 种 | ⬜ |

**Layer 1 总计：53 种变异策略**

### Layer 2：协议语义变异

| ID | 任务 | 变异策略数 | 状态 |
|----|------|-----------|------|
| 2.9 | 类型边界变异（基于字段类型推断） | 8 种 | ⬜ |
| 2.10 | TLV 结构变异 | 6 种 | ⬜ |
| 2.11 | 字符串语义变异（UTF-8、空字节、格式串） | 10 种 | ⬜ |
| 2.12 | 字节序混淆变异 | 3 种 | ⬜ |
| 2.13 | 字段间约束破坏（如 Length 与实际不符的语义攻击） | 5 种 | ⬜ |
| 2.14 | SD Entry/Option 语义变异 | 8 种 | ⬜ |

**Layer 2 总计：40 种变异策略**

### 框架与基础设施

| ID | 任务 | 文件 | 状态 |
|----|------|------|------|
| 2.15 | 变异器抽象基类 `BaseMutator` | `core/mutator.py` | ⬜ |
| 2.16 | 变异策略注册系统（装饰器） | `core/mutator.py` | ⬜ |
| 2.17 | 变异调度器（按权重选择策略） | `core/mutator.py` | ⬜ |
| 2.18 | 种子语料库管理（SQLite） | `data/corpus.py` | ⬜ |
| 2.19 | 变异历史记录（用于反馈引擎） | `data/storage.py` | ⬜ |
| 2.20 | 变异策略 TOML 配置加载 | `configs/strategies.toml` | ⬜ |

---

## 2.3 详细变异策略目录

### Layer 1.1 - Service ID 变异（8 种）

| 编号 | 策略名 | 描述 | 用途 |
|------|--------|------|------|
| L1-S01 | boundary_min | 0x0000 | 边界 |
| L1-S02 | boundary_max | 0xFFFF | 边界 |
| L1-S03 | boundary_max_minus_1 | 0xFFFE | 边界 |
| L1-S04 | reserved_range | 0xFF00-0xFFFE | 保留域 |
| L1-S05 | random_uniform | 均匀随机 | 广撒网 |
| L1-S06 | bit_flip_single | 单位翻转 | 邻近变异 |
| L1-S07 | bit_flip_multiple | 多位翻转 | 大幅变异 |
| L1-S08 | swap_with_method_id | 与 Method ID 互换 | 字段混淆 |

### Layer 1.2 - Method/Event ID 变异（6 种）

| 编号 | 策略名 | 描述 |
|------|--------|------|
| L1-M01 | flip_event_method_bit | 第 16 位 M/E 翻转 |
| L1-M02 | boundary_method | 0x0000、0x7FFF |
| L1-M03 | boundary_event | 0x8000、0xFFFF |
| L1-M04 | random_method | 随机方法 ID |
| L1-M05 | random_event | 随机事件 ID |
| L1-M06 | reserved_range | 保留 ID 范围 |

### Layer 1.3 - Length 变异（7 种）⭐高危字段

| 编号 | 策略名 | 描述 | 攻击向量 |
|------|--------|------|---------|
| L1-L01 | overflow_4byte_max | 0xFFFFFFFF | 内存分配/整数溢出 |
| L1-L02 | underflow_too_small | < 8（小于头长） | 解析逻辑错误 |
| L1-L03 | zero | 0x00000000 | 边界 |
| L1-L04 | mismatch_actual_larger | 实际 payload 比 Length 大 | 截断攻击 |
| L1-L05 | mismatch_actual_smaller | 实际 payload 比 Length 小 | 越界读取 |
| L1-L06 | negative_signed | 负数（有符号解释） | 类型混淆 |
| L1-L07 | random_uint32 | 完全随机 | 广撒网 |

### Layer 1.4 - Client/Session ID 变异（5 种）

| 编号 | 策略名 | 描述 |
|------|--------|------|
| L1-C01 | session_replay | 重放上次 Session ID |
| L1-C02 | session_skip | 跳跃序列号 |
| L1-C03 | session_zero | Session ID = 0（部分实现非法） |
| L1-C04 | client_random | 随机 Client ID |
| L1-C05 | client_collision | 与已知 Client ID 冲突 |

### Layer 1.5 - Protocol/Interface Version 变异（4 种）

| 编号 | 策略名 | 描述 |
|------|--------|------|
| L1-V01 | proto_zero | Proto Ver = 0x00 |
| L1-V02 | proto_max | Proto Ver = 0xFF |
| L1-V03 | iface_mismatch | Interface Ver 不匹配 |
| L1-V04 | both_random | 两者都随机 |

### Layer 1.6 - Message Type 变异（6 种）

| 编号 | 策略名 | 描述 |
|------|--------|------|
| L1-T01 | invalid_type | 未定义类型（如 0x07、0x10） |
| L1-T02 | type_retcode_mismatch | Request 配 Error 返回码 |
| L1-T03 | tp_flag_inject | 注入 TP 分段位 |
| L1-T04 | ack_without_request | 无前置请求的 ACK |
| L1-T05 | error_type | 强制 Error 类型 |
| L1-T06 | random_byte | 随机字节 |

### Layer 1.7 - Return Code 变异（5 种）

| 编号 | 策略名 | 描述 |
|------|--------|------|
| L1-R01 | reserved_code | 保留返回码 |
| L1-R02 | undefined_code | 未定义码（如 0x40） |
| L1-R03 | error_when_request | 请求中带错误码 |
| L1-R04 | random | 随机 |
| L1-R05 | ok_when_error_type | Error 类型带 E_OK |

### Layer 1.8 - Payload 变异（12 种）

| 编号 | 策略名 | 描述 |
|------|--------|------|
| L1-P01 | random_bytes | 完全随机 |
| L1-P02 | bit_flip_1 | 单 bit 翻转 |
| L1-P03 | bit_flip_n | 多 bit 翻转 |
| L1-P04 | byte_boundary | 0x00/0xFF/0x7F/0x80 填充 |
| L1-P05 | overflow_huge | 超大 payload (1MB+) |
| L1-P06 | truncate_zero | 空 payload |
| L1-P07 | truncate_partial | 截断到 1/2 |
| L1-P08 | known_magic | 已知触发 crash 的魔数 |
| L1-P09 | repeated_pattern | AAAA...重复模式 |
| L1-P10 | nested_structure | 嵌套结构破坏 |
| L1-P11 | encoding_mix | 多种编码混合 |
| L1-P12 | sequential_bytes | 0x00, 0x01, 0x02... 序列 |

### Layer 2.1 - 类型边界（8 种）

| 编号 | 策略名 | 适用 |
|------|--------|------|
| L2-T01 | uint8_boundaries | 0, 127, 128, 255 |
| L2-T02 | uint16_boundaries | 0, 32767, 32768, 65535 |
| L2-T03 | uint32_boundaries | 0, 2^31-1, 2^31, 2^32-1 |
| L2-T04 | int_negative | -1（用 uint 解释）|
| L2-T05 | float_special | NaN, Inf, -Inf, denormal |
| L2-T06 | bool_invalid | 非 0/1 的 bool |
| L2-T07 | enum_out_of_range | 越界枚举 |
| L2-T08 | bitfield_overflow | 位域溢出 |

### Layer 2.2 - TLV 结构变异（6 种）

| 编号 | 策略名 |
|------|--------|
| L2-V01 | length_tag_mismatch | T-L-V 中 L 与 V 不符 |
| L2-V02 | nested_overflow | 嵌套 TLV 深度爆炸 |
| L2-V03 | duplicate_tag | 同 Tag 重复 |
| L2-V04 | unknown_tag | 未定义 Tag |
| L2-V05 | infinite_loop | TLV 自引用 |
| L2-V06 | length_zero_with_value | L=0 但有 V |

### Layer 2.3 - 字符串语义（10 种）

| 编号 | 策略名 |
|------|--------|
| L2-S01 | utf8_overlong | UTF-8 过长编码 |
| L2-S02 | utf8_invalid | 无效 UTF-8 字节 |
| L2-S03 | null_byte_inject | 嵌入 \x00 |
| L2-S04 | format_string | %s %x %n 注入 |
| L2-S05 | very_long | 极长字符串 |
| L2-S06 | unicode_surrogate | UTF-16 代理对 |
| L2-S07 | bom_inject | 字节顺序标记注入 |
| L2-S08 | control_chars | 控制字符 \x01-\x1F |
| L2-S09 | path_traversal | ../ 路径穿越 |
| L2-S10 | sql_inject_pattern | SQL 注入串（即使不是 SQL 也测） |

### Layer 2.4 - 字节序混淆（3 种）

| 编号 | 策略名 |
|------|--------|
| L2-E01 | force_little_endian | 强制小端（SOME/IP 应大端） |
| L2-E02 | mixed_endian | 部分字段大端、部分小端 |
| L2-E03 | byte_swap_payload | Payload 字节翻转 |

### Layer 2.5 - 字段间约束破坏（5 种）

| 编号 | 策略名 |
|------|--------|
| L2-C01 | length_payload_inconsistent | Length 与 payload 长度严重不符 |
| L2-C02 | session_decreasing | Session ID 倒序 |
| L2-C03 | proto_iface_swap | Proto/Iface Version 字段互换 |
| L2-C04 | request_with_response_id | 请求带响应方 Method ID |
| L2-C05 | tp_flag_without_offset | TP 标志位置 1 但无 offset 字段 |

### Layer 2.6 - SD Entry/Option 语义（8 种）

| 编号 | 策略名 |
|------|--------|
| L2-SD01 | invalid_entry_type | 未定义 Entry 类型 |
| L2-SD02 | conflicting_entries | OfferService + StopOffer 同包 |
| L2-SD03 | excessive_entries | 1000+ Entry 资源耗尽 |
| L2-SD04 | option_index_oob | Option 索引越界 |
| L2-SD05 | endpoint_invalid_ip | 0.0.0.0 / 255.255.255.255 |
| L2-SD06 | endpoint_port_zero | 端口 0 |
| L2-SD07 | ttl_overflow | TTL = 0xFFFFFF（最大） |
| L2-SD08 | major_minor_swap | Major/Minor 版本互换 |

---

## 2.4 总变异策略数

**Layer 1：53 种**
**Layer 2：40 种**
**Phase 2 合计：93 种**

加上后续 Phase：
- Layer 3（状态机变异）：12 种 → Phase 3
- Layer 4（攻击链变异）：8 种 → Phase 3
- Layer 5（反馈引导变异）：5 种 → Phase 4

**全工具总计：≥ 118 种变异策略**（业界一流水平）

申报书要求"覆盖服务发现劫持、RPC参数注入、序列化错误等场景" → 我们的 Layer 1-5 全覆盖且超出。

---

## 2.5 关键设计

### 2.5.1 变异器抽象

```python
class BaseMutator(ABC):
    """所有变异器的基类"""
    name: str
    layer: int  # 1-5
    target_field: str  # service_id, method_id, payload, ...
    weight: float = 1.0  # 调度权重
    
    @abstractmethod
    def mutate(self, packet: SomeIpPacket, rng: random.Random) -> SomeIpPacket:
        ...
```

### 2.5.2 注册装饰器

```python
@register_mutator(layer=1, target="service_id", strategy="boundary_max")
class ServiceIdBoundaryMaxMutator(BaseMutator):
    def mutate(self, packet, rng):
        new = copy.copy(packet)
        new.service_id = 0xFFFF
        return new
```

### 2.5.3 调度器

```python
class MutationScheduler:
    """按权重 + 反馈调整选择变异策略"""
    
    def select(self, layer_filter: list[int] = None) -> BaseMutator:
        """加权随机选择"""
        ...
    
    def update_weight(self, mutator_name: str, score: float):
        """根据反馈调整权重（供 Phase 4 使用）"""
        ...
```

---

## 2.6 测试

### 单元测试

每个变异策略都要有对应的测试：
```python
def test_service_id_boundary_max():
    p = SomeIpPacket.request(0x1234, 0x5678, b"x")
    m = ServiceIdBoundaryMaxMutator()
    p2 = m.mutate(p, random.Random(42))
    assert p2.service_id == 0xFFFF
    assert p2.method_id == p.method_id  # 其他字段不变
```

### 统计测试

```python
def test_mutation_diversity():
    """验证 1000 次变异结果具有足够多样性"""
    mutator = PayloadRandomMutator()
    seen = set()
    for _ in range(1000):
        p = mutator.mutate(seed_packet, random.Random())
        seen.add(p.payload[:16])
    assert len(seen) >= 990  # 几乎全不同
```

---

## 2.7 验收清单

- [ ] 93 种 Layer 1-2 变异策略全部实现
- [ ] 每种策略有对应单元测试
- [ ] 变异器注册系统工作正常（自动发现+注册）
- [ ] 调度器能按权重选择
- [ ] 单元测试覆盖率 ≥ 80%
- [ ] 性能：单次变异 < 1ms
- [ ] 可通过 TOML 配置启用/禁用任意策略组合
- [ ] git 每个 Layer 单独提交
- [ ] 推送到 GitHub

---

## 2.8 问题记录

（验收失败时在此追加）
