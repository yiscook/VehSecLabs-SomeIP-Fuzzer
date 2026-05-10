"""状态机会话持久化（SQLite 后端）。

职责：保存/恢复 ServiceStateMachine 的运行时状态，支持中断后继续模糊测试会话。

设计要点：
- 以 (session_id, service_id, instance_id) 为主键，upsert 语义。
- state 字段存 ServiceState.value（字符串），解耦枚举定义。
- metadata 字段存 JSON blob，供未来扩展（如 TTL 剩余时间）。
- 全部 SQL 使用参数化查询，绝不字符串拼接。
- 传 ":memory:" 可做内存库（用于测试）。
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from someip_fuzzer.core.state_machine import ServiceState

# ── Schema ────────────────────────────────────────────────────────────────────

_DDL = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id  TEXT    NOT NULL,
    service_id  INTEGER NOT NULL,
    instance_id INTEGER NOT NULL,
    state       TEXT    NOT NULL,
    updated_at  TEXT    NOT NULL,
    metadata    TEXT    NOT NULL DEFAULT '{}',
    PRIMARY KEY (session_id, service_id, instance_id)
);
CREATE INDEX IF NOT EXISTS idx_session ON sessions(session_id);
"""

# ── 结果容器 ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class SessionRecord:
    session_id: str
    service_id: int
    instance_id: int
    state: str       # ServiceState.value
    updated_at: str  # ISO 8601
    metadata: dict


# ── 存储类 ────────────────────────────────────────────────────────────────────


class SessionStorage:
    """状态机会话持久化存储。

    用法::

        storage = SessionStorage("sessions.db")
        storage.save_state("sess-001", 0x1234, 0x0001, ServiceState.READY)
        state = storage.load_state("sess-001", 0x1234, 0x0001)
    """

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self._path = str(db_path)
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_DDL)
        self._conn.commit()

    # ── 写操作 ────────────────────────────────────────────────────────────────

    def save_state(
        self,
        session_id: str,
        service_id: int,
        instance_id: int,
        state: "ServiceState",
        metadata: dict | None = None,
    ) -> None:
        """保存（或更新）单个服务实例的状态。"""
        now = datetime.now(timezone.utc).isoformat()
        meta_json = json.dumps(metadata or {})
        self._conn.execute(
            """
            INSERT INTO sessions (session_id, service_id, instance_id, state, updated_at, metadata)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(session_id, service_id, instance_id)
            DO UPDATE SET state=excluded.state,
                          updated_at=excluded.updated_at,
                          metadata=excluded.metadata
            """,
            (session_id, service_id, instance_id, state.value, now, meta_json),
        )
        self._conn.commit()

    def delete_session(self, session_id: str) -> int:
        """删除整个 session 的所有记录，返回删除行数。"""
        cur = self._conn.execute(
            "DELETE FROM sessions WHERE session_id = ?", (session_id,)
        )
        self._conn.commit()
        return cur.rowcount

    # ── 读操作 ────────────────────────────────────────────────────────────────

    def load_state(
        self, session_id: str, service_id: int, instance_id: int
    ) -> "ServiceState | None":
        """查询单个服务实例的当前状态，未找到返回 None。"""
        from someip_fuzzer.core.state_machine import ServiceState  # 延迟导入避免循环

        row = self._conn.execute(
            "SELECT state FROM sessions WHERE session_id=? AND service_id=? AND instance_id=?",
            (session_id, service_id, instance_id),
        ).fetchone()
        if row is None:
            return None
        return ServiceState(row["state"])

    def load_all(
        self, session_id: str
    ) -> dict[tuple[int, int], "ServiceState"]:
        """加载整个 session 的所有服务实例状态。

        Returns:
            ``{(service_id, instance_id): ServiceState}`` 映射。
        """
        from someip_fuzzer.core.state_machine import ServiceState

        rows = self._conn.execute(
            "SELECT service_id, instance_id, state FROM sessions WHERE session_id=?",
            (session_id,),
        ).fetchall()
        return {
            (r["service_id"], r["instance_id"]): ServiceState(r["state"])
            for r in rows
        }

    def list_records(self, session_id: str) -> list[SessionRecord]:
        """返回 session 的完整记录列表（含 metadata）。"""
        rows = self._conn.execute(
            "SELECT * FROM sessions WHERE session_id=? ORDER BY updated_at",
            (session_id,),
        ).fetchall()
        return [
            SessionRecord(
                session_id=r["session_id"],
                service_id=r["service_id"],
                instance_id=r["instance_id"],
                state=r["state"],
                updated_at=r["updated_at"],
                metadata=json.loads(r["metadata"]),
            )
            for r in rows
        ]

    def count(self, session_id: str | None = None) -> int:
        """统计记录总数，可按 session_id 过滤。"""
        if session_id is None:
            return self._conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        return self._conn.execute(
            "SELECT COUNT(*) FROM sessions WHERE session_id=?", (session_id,)
        ).fetchone()[0]

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "SessionStorage":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
