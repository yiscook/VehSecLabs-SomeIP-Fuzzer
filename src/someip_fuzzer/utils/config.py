from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import tomli_w


@dataclass
class ServiceDef:
    service_id: int
    instance_id: int
    major_version: int = 1
    minor_version: int = 0
    methods: list[int] = field(default_factory=list)
    events: list[int] = field(default_factory=list)


@dataclass
class SdConfig:
    multicast: str = "224.224.224.245"
    port: int = 30490


@dataclass
class TargetConfig:
    name: str = "default"
    ip: str = "192.168.81.128"
    port: int = 30509
    transport: str = "udp"
    interface: str = ""


@dataclass
class AppConfig:
    target: TargetConfig = field(default_factory=TargetConfig)
    sd: SdConfig = field(default_factory=SdConfig)
    services: list[ServiceDef] = field(default_factory=list)


def load_config(path: str | Path) -> AppConfig:
    path = Path(path)
    with open(path, "rb") as f:
        raw = tomllib.load(f)

    target_data = raw.get("target", {})
    target = TargetConfig(
        name=target_data.get("name", "default"),
        ip=target_data.get("ip", "192.168.81.128"),
        port=target_data.get("port", 30509),
        transport=target_data.get("transport", "udp"),
        interface=target_data.get("interface", ""),
    )

    sd_data = raw.get("sd", {})
    sd = SdConfig(
        multicast=sd_data.get("multicast", "224.224.224.245"),
        port=sd_data.get("port", 30490),
    )

    services = []
    for svc_raw in raw.get("services", []):
        services.append(
            ServiceDef(
                service_id=svc_raw["service_id"],
                instance_id=svc_raw.get("instance_id", 1),
                major_version=svc_raw.get("major_version", 1),
                minor_version=svc_raw.get("minor_version", 0),
                methods=svc_raw.get("methods", []),
                events=svc_raw.get("events", []),
            )
        )

    return AppConfig(target=target, sd=sd, services=services)


@dataclass
class StrategiesConfig:
    """变异策略调度配置，对应 configs/strategies.toml。

    - ``enabled_layers``：允许调度的 Layer 列表（默认 [1, 2]）。
    - ``weights``：按 mutator 名字覆盖权重；未列出则沿用 BaseMutator.weight 默认值。
    - ``disabled``：黑名单名字列表，列在里面的变异器被强制禁用（权重置 0）。
    """

    enabled_layers: list[int] = field(default_factory=lambda: [1, 2])
    weights: dict[str, float] = field(default_factory=dict)
    disabled: list[str] = field(default_factory=list)


def load_strategies(path: str | Path) -> StrategiesConfig:
    """从 TOML 文件加载变异策略配置。"""
    path = Path(path)
    with open(path, "rb") as f:
        raw: dict[str, Any] = tomllib.load(f)

    scheduler_data = raw.get("scheduler", {})
    weights_data = raw.get("weights", {})
    disabled_data = raw.get("disabled", {})

    return StrategiesConfig(
        enabled_layers=list(scheduler_data.get("enabled_layers", [1, 2])),
        weights={str(k): float(v) for k, v in weights_data.items()},
        disabled=list(disabled_data.get("names", [])),
    )


def save_strategies(config: StrategiesConfig, path: str | Path) -> None:
    """将变异策略配置写回 TOML 文件。"""
    path = Path(path)
    raw: dict[str, Any] = {
        "scheduler": {"enabled_layers": config.enabled_layers},
        "weights": config.weights,
        "disabled": {"names": config.disabled},
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        tomli_w.dump(raw, f)


def save_config(config: AppConfig, path: str | Path) -> None:
    path = Path(path)
    raw: dict = {
        "target": {
            "name": config.target.name,
            "ip": config.target.ip,
            "port": config.target.port,
            "transport": config.target.transport,
            "interface": config.target.interface,
        },
        "sd": {
            "multicast": config.sd.multicast,
            "port": config.sd.port,
        },
        "services": [
            {
                "service_id": svc.service_id,
                "instance_id": svc.instance_id,
                "major_version": svc.major_version,
                "minor_version": svc.minor_version,
                "methods": svc.methods,
                "events": svc.events,
            }
            for svc in config.services
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        tomli_w.dump(raw, f)
