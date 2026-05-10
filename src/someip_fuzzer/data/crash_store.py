"""崩溃记录持久化（SQLite 后端）。

职责：存储触发崩溃的报文及其上下文，支持去重、按严重度查询、导出。

设计要点：
- SHA256 去重：同一触发报文不重复记录。
- severity 枚举：low / medium / high / critical（按检测方式自动分级）。
- context 字段：JSON blob（service_id / method_id / session_id 等调试上下文）。
- 全部 SQL 使用参数化查询。
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# ── Schema ────────────────────────────────────────────────────────────────────

_DDL = """
CREATE TABLE IF NOT EXISTS crashes (
    crash_id         TEXT    PRIMARY KEY,
    timestamp        TEXT    NOT NULL,
    triggering_bytes BLOB    NOT NULL,
    sha256           TEXT    UNIQUE NOT NULL,
    mutator_name     TEXT    NOT NULL DEFAULT '',
    severity         TEXT    NOT NULL DEFAULT 'low',
    cvss_score       REAL    NOT NULL DEFAULT 0.0,
    detection_method TEXT    NOT NULL DEFAULT 'unknown',
    asan_log         TEXT,
    target_host      TEXT    NOT NULL DEFAULT '',
    target_port      INTEGER NOT NULL DEFAULT 0,
    context          TEXT    NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_severity ON crashes(severity);
CREATE INDEX IF NOT EXISTS idx_detection ON crashes(detection_method);
"""

# ── 数据容器 ──────────────────────────────────────────────────────────────────


@dataclass
class CrashRecord:
    """单次崩溃记录。"""
    triggering_bytes: bytes
    mutator_name: str = ""
    severity: str = "low"          # "low" | "medium" | "high" | "critical"
    cvss_score: float = 0.0
    detection_method: str = "unknown"  # "heartbeat" | "timeout" | "error_response" | "agent"
    asan_log: str | None = None
    target_addr: tuple[str, int] = ("", 0)
    context: dict = field(default_factory=dict)
    crash_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.triggering_bytes).hexdigest()


# ── 存储类 ────────────────────────────────────────────────────────────────────


class CrashStorage:
    """CrashRecord 的 SQLite 持久化存储。

    用法::

        store = CrashStorage("crashes.db")
        crash = CrashRecord(triggering_bytes=b"\\xff\\xfe...",
                            severity="high", detection_method="heartbeat")
        store.save(crash)
        records = store.list_all(severity="high")
    """

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self._path = str(db_path)
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_DDL)
        self._conn.commit()

    # ── 写操作 ────────────────────────────────────────────────────────────────

    def save(self, crash: CrashRecord) -> bool:
        """保存崩溃记录。SHA256 重复时返回 False（已存在），成功返回 True。"""
        try:
            self._conn.execute(
                """
                INSERT INTO crashes
                    (crash_id, timestamp, triggering_bytes, sha256,
                     mutator_name, severity, cvss_score, detection_method,
                     asan_log, target_host, target_port, context)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    crash.crash_id,
                    crash.timestamp,
                    crash.triggering_bytes,
                    crash.sha256,
                    crash.mutator_name,
                    crash.severity,
                    crash.cvss_score,
                    crash.detection_method,
                    crash.asan_log,
                    crash.target_addr[0],
                    crash.target_addr[1],
                    json.dumps(crash.context),
                ),
            )
            self._conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False  # SHA256 重复

    # ── 读操作 ────────────────────────────────────────────────────────────────

    def load(self, crash_id: str) -> CrashRecord | None:
        """按 crash_id 查询单条记录。"""
        row = self._conn.execute(
            "SELECT * FROM crashes WHERE crash_id = ?", (crash_id,)
        ).fetchone()
        return self._row_to_record(row) if row else None

    def list_all(
        self,
        severity: str | None = None,
        detection_method: str | None = None,
        limit: int | None = None,
    ) -> list[CrashRecord]:
        """查询记录，支持按 severity / detection_method 过滤。"""
        sql = "SELECT * FROM crashes WHERE 1=1"
        params: list = []
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        if detection_method:
            sql += " AND detection_method = ?"
            params.append(detection_method)
        sql += " ORDER BY timestamp DESC"
        if limit:
            sql += f" LIMIT {int(limit)}"
        rows = self._conn.execute(sql, params).fetchall()
        return [self._row_to_record(r) for r in rows]

    def is_duplicate(self, raw_bytes: bytes) -> bool:
        """检查是否已记录相同触发报文（按 SHA256）。"""
        sha = hashlib.sha256(raw_bytes).hexdigest()
        row = self._conn.execute(
            "SELECT 1 FROM crashes WHERE sha256 = ?", (sha,)
        ).fetchone()
        return row is not None

    def count(self, severity: str | None = None) -> int:
        """统计记录总数，可按 severity 过滤。"""
        if severity:
            return self._conn.execute(
                "SELECT COUNT(*) FROM crashes WHERE severity = ?", (severity,)
            ).fetchone()[0]
        return self._conn.execute("SELECT COUNT(*) FROM crashes").fetchone()[0]

    # ── 工具 ──────────────────────────────────────────────────────────────────

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> CrashRecord:
        return CrashRecord(
            crash_id=row["crash_id"],
            timestamp=row["timestamp"],
            triggering_bytes=bytes(row["triggering_bytes"]),
            mutator_name=row["mutator_name"],
            severity=row["severity"],
            cvss_score=row["cvss_score"],
            detection_method=row["detection_method"],
            asan_log=row["asan_log"],
            target_addr=(row["target_host"], row["target_port"]),
            context=json.loads(row["context"]),
        )

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "CrashStorage":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
