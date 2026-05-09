from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

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
