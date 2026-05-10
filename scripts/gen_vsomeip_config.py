#!/usr/bin/env python3
"""从 target_vsomeip.toml 生成 vsomeip JSON 配置文件。

用法：
    python3 scripts/gen_vsomeip_config.py \
        [configs/target_vsomeip.toml] \
        [scripts/vsomeip_config.json]
"""

from __future__ import annotations

import json
import sys
import tomllib
from pathlib import Path


def generate(toml_path: str | Path, output_path: str | Path) -> None:
    toml_path = Path(toml_path)
    output_path = Path(output_path)

    with open(toml_path, "rb") as f:
        cfg = tomllib.load(f)

    target = cfg["target"]
    sd = cfg.get("sd", {})
    services = cfg.get("services", [])

    vsomeip_cfg: dict = {
        "unicast": target["ip"],
        "netmask": "255.255.255.0",
        "logging": {
            "level": "info",
            "console": "true",
            "file": {"enable": "true", "path": "/tmp/vsomeip-target.log"},
            "dlt": "false",
        },
        "applications": [
            {"name": "response-sample", "id": "0x1277"}
        ],
        "services": [
            {
                "service": hex(svc["service_id"]),
                "instance": hex(svc["instance_id"]),
                "unreliable": str(target["port"]),
            }
            for svc in services
        ],
        "routing": "response-sample",
        "service-discovery": {
            "enable": "true",
            "multicast": sd.get("multicast", "224.224.224.245"),
            "port": str(sd.get("port", 30490)),
            "protocol": "udp",
            "initial_delay_min": "10",
            "initial_delay_max": "100",
            "repetitions_base_delay": "200",
            "repetitions_max": "3",
            "ttl": "3",
            "cyclic_offer_delay": "1000",
            "request_response_delay": "1500",
        },
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(vsomeip_cfg, f, indent=4)

    print(f"✓ 生成配置：{output_path}")
    print(f"  目标 IP   ：{target['ip']}:{target['port']}")
    print(f"  SD 多播   ：{sd.get('multicast', '224.224.224.245')}:{sd.get('port', 30490)}")
    print(f"  服务数量  ：{len(services)}")
    for svc in services:
        print(f"    Service 0x{svc['service_id']:04X} / Instance 0x{svc['instance_id']:04X}")


if __name__ == "__main__":
    toml = sys.argv[1] if len(sys.argv) > 1 else "configs/target_vsomeip.toml"
    out = sys.argv[2] if len(sys.argv) > 2 else "scripts/vsomeip_config.json"
    generate(toml, out)
