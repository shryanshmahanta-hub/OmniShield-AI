"""Incident storage service supporting in-memory and SQLite backends."""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
import json
import os
import sqlite3
import threading
from typing import Any, Dict, List, Optional
from app.config import Settings, get_settings
from app.schemas import AuditEvent, Incident, RiskLevel
from app.services.audit_sanitizer import sanitize_for_audit


class BaseIncidentStore(ABC):
    """Abstract interface for incident storage."""

    @abstractmethod
    def record(self, incident: Incident) -> Incident:
        """Store an incident record."""
        pass

    @abstractmethod
    def list_incidents(self, limit: int = 50, offset: int = 0, owner_id: Optional[str] = None) -> List[Incident]:
        """List stored incidents with pagination."""
        pass

    @abstractmethod
    def get_incident(self, incident_id: str, owner_id: Optional[str] = None) -> Optional[Incident]:
        """Retrieve an incident by ID."""
        pass

    @abstractmethod
    def count(self, owner_id: Optional[str] = None) -> int:
        """Return total incident count."""
        pass

    @abstractmethod
    def clear(self, owner_id: Optional[str] = None) -> None:
        """Clear all stored incidents."""
        pass

    def record_audit_event(self, event: AuditEvent) -> AuditEvent:
        """Persist a sanitized audit event. Implementations should override this."""
        return event

    def list_audit_events(self, limit: int = 50, offset: int = 0, owner_id: Optional[str] = None,
                          module: Optional[str] = None, result: Optional[str] = None,
                          search: Optional[str] = None) -> List[AuditEvent]:
        return []

    def count_audit_events(self, owner_id: Optional[str] = None, module: Optional[str] = None,
                           result: Optional[str] = None, search: Optional[str] = None) -> int:
        return len(self.list_audit_events(limit=100000, offset=0, owner_id=owner_id, module=module, result=result, search=search))


class MemoryIncidentStore(BaseIncidentStore):
    """In-memory thread-safe incident storage for development and testing."""

    def __init__(self) -> None:
        self._incidents: List[Incident] = []
        self._audit_events: List[AuditEvent] = []
        self._lock = threading.Lock()

    def record(self, incident: Incident) -> Incident:
        clean = incident.model_copy(update={"details": sanitize_for_audit(incident.details), "summary": str(sanitize_for_audit(incident.summary))})
        with self._lock:
            self._incidents.append(clean)
            return clean

    def list_incidents(self, limit: int = 50, offset: int = 0, owner_id: Optional[str] = None) -> List[Incident]:
        with self._lock:
            subset = [x for x in self._incidents if owner_id is None or x.owner_id == owner_id]
            sorted_list = sorted(subset, key=lambda x: x.created_at, reverse=True)
            return sorted_list[offset:offset + limit]

    def get_incident(self, incident_id: str, owner_id: Optional[str] = None) -> Optional[Incident]:
        with self._lock:
            for inc in self._incidents:
                if inc.incident_id == incident_id and (owner_id is None or inc.owner_id == owner_id):
                    return inc
            return None

    def count(self, owner_id: Optional[str] = None) -> int:
        with self._lock:
            return sum(1 for x in self._incidents if owner_id is None or x.owner_id == owner_id)

    def clear(self, owner_id: Optional[str] = None) -> None:
        with self._lock:
            if owner_id is None:
                self._incidents.clear()
            else:
                self._incidents = [x for x in self._incidents if x.owner_id != owner_id]

    def record_audit_event(self, event: AuditEvent) -> AuditEvent:
        clean = event.model_copy(update={"details": sanitize_for_audit(event.details), "summary": str(sanitize_for_audit(event.summary))})
        with self._lock:
            self._audit_events.append(clean)
        return clean

    def list_audit_events(self, limit: int = 50, offset: int = 0, owner_id: Optional[str] = None,
                          module: Optional[str] = None, result: Optional[str] = None,
                          search: Optional[str] = None) -> List[AuditEvent]:
        query = (search or "").casefold()
        with self._lock:
            events = [e for e in self._audit_events
                      if (owner_id is None or e.owner_id == owner_id)
                      and (module is None or e.module == module)
                      and (result is None or e.result == result)
                      and (not query or query in " ".join([e.event_id, e.scan_id or "", e.module, e.action, e.result, e.summary]).casefold())]
            return sorted(events, key=lambda e: e.created_at, reverse=True)[offset:offset + limit]

    def count_audit_events(self, owner_id: Optional[str] = None, module: Optional[str] = None,
                           result: Optional[str] = None, search: Optional[str] = None) -> int:
        return len(self.list_audit_events(limit=100000, offset=0, owner_id=owner_id, module=module, result=result, search=search))


class SqliteIncidentStore(BaseIncidentStore):
    """SQLite persistent incident storage."""

    def __init__(self, db_path: str = "data/incidents.db") -> None:
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        with self._lock, sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    summary TEXT NOT NULL,
                    details TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    owner_id TEXT
                )
            """)
            columns = {row[1] for row in conn.execute("PRAGMA table_info(incidents)").fetchall()}
            if "owner_id" not in columns:
                conn.execute("ALTER TABLE incidents ADD COLUMN owner_id TEXT")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_owner_created ON incidents(owner_id, created_at)")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_events (
                    event_id TEXT PRIMARY KEY,
                    scan_id TEXT,
                    module TEXT NOT NULL,
                    action TEXT NOT NULL,
                    result TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    summary TEXT NOT NULL,
                    details TEXT NOT NULL,
                    owner_id TEXT,
                    created_at TEXT NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_owner_created ON audit_events(owner_id, created_at)")
            conn.commit()

    def record(self, incident: Incident) -> Incident:
        clean = incident.model_copy(update={"details": sanitize_for_audit(incident.details), "summary": str(sanitize_for_audit(incident.summary))})
        with self._lock, sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO incidents (incident_id, scan_id, scan_type, risk_level, risk_score, summary, details, created_at, owner_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (clean.incident_id, clean.scan_id, clean.scan_type, clean.risk_level.value, clean.risk_score,
                 clean.summary, json.dumps(clean.details), clean.created_at.isoformat(), clean.owner_id)
            )
            conn.commit()
            return clean

    def list_incidents(self, limit: int = 50, offset: int = 0, owner_id: Optional[str] = None) -> List[Incident]:
        with self._lock, sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT incident_id, scan_id, scan_type, risk_level, risk_score, summary, details, created_at, owner_id
                FROM incidents
                WHERE (? IS NULL OR owner_id = ?)
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
                """,
                (owner_id, owner_id, limit, offset)
            )
            rows = cursor.fetchall()
            results: List[Incident] = []
            for row in rows:
                results.append(Incident(
                    incident_id=row[0],
                    scan_id=row[1],
                    scan_type=row[2],
                    risk_level=RiskLevel(row[3]),
                    risk_score=row[4],
                    summary=row[5],
                    details=json.loads(row[6]),
                    created_at=datetime.fromisoformat(row[7]),
                    owner_id=row[8] if len(row) > 8 else None,
                ))
            return results

    def get_incident(self, incident_id: str, owner_id: Optional[str] = None) -> Optional[Incident]:
        with self._lock, sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT incident_id, scan_id, scan_type, risk_level, risk_score, summary, details, created_at, owner_id
                FROM incidents
                WHERE incident_id = ? AND (? IS NULL OR owner_id = ?)
                """,
                (incident_id, owner_id, owner_id)
            )
            row = cursor.fetchone()
            if not row:
                return None
            return Incident(
                incident_id=row[0],
                scan_id=row[1],
                scan_type=row[2],
                risk_level=RiskLevel(row[3]),
                risk_score=row[4],
                summary=row[5],
                details=json.loads(row[6]),
                created_at=datetime.fromisoformat(row[7]),
                owner_id=row[8] if len(row) > 8 else None,
            )

    def count(self, owner_id: Optional[str] = None) -> int:
        with self._lock, sqlite3.connect(self.db_path) as conn:
            if owner_id is None:
                row = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()
            else:
                row = conn.execute("SELECT COUNT(*) FROM incidents WHERE owner_id = ?", (owner_id,)).fetchone()
            return row[0] if row else 0

    def clear(self, owner_id: Optional[str] = None) -> None:
        with self._lock, sqlite3.connect(self.db_path) as conn:
            if owner_id is None:
                conn.execute("DELETE FROM incidents")
            else:
                conn.execute("DELETE FROM incidents WHERE owner_id = ?", (owner_id,))
            conn.commit()

    def record_audit_event(self, event: AuditEvent) -> AuditEvent:
        clean = event.model_copy(update={"details": sanitize_for_audit(event.details), "summary": str(sanitize_for_audit(event.summary))})
        with self._lock, sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO audit_events (event_id, scan_id, module, action, result, risk_level, risk_score, summary, details, owner_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (clean.event_id, clean.scan_id, clean.module, clean.action, clean.result, clean.risk_level.value,
                  clean.risk_score, clean.summary, json.dumps(clean.details), clean.owner_id, clean.created_at.isoformat()))
            conn.commit()
        return clean

    def list_audit_events(self, limit: int = 50, offset: int = 0, owner_id: Optional[str] = None,
                          module: Optional[str] = None, result: Optional[str] = None,
                          search: Optional[str] = None) -> List[AuditEvent]:
        pattern = f"%{search.casefold()}%" if search else None
        with self._lock, sqlite3.connect(self.db_path) as conn:
            rows = conn.execute("""
                SELECT event_id, scan_id, module, action, result, risk_level, risk_score, summary, details, owner_id, created_at
                FROM audit_events
                WHERE (? IS NULL OR owner_id = ?)
                  AND (? IS NULL OR module = ?)
                  AND (? IS NULL OR result = ?)
                  AND (? IS NULL OR lower(coalesce(event_id,'') || ' ' || coalesce(scan_id,'') || ' ' || module || ' ' || action || ' ' || result || ' ' || summary) LIKE ?)
                ORDER BY created_at DESC LIMIT ? OFFSET ?
            """, (owner_id, owner_id, module, module, result, result, pattern, pattern, limit, offset)).fetchall()
        return [AuditEvent(event_id=r[0], scan_id=r[1], module=r[2], action=r[3], result=r[4],
                           risk_level=RiskLevel(r[5]), risk_score=r[6], summary=r[7], details=json.loads(r[8]),
                           owner_id=r[9], created_at=datetime.fromisoformat(r[10])) for r in rows]

    def count_audit_events(self, owner_id: Optional[str] = None, module: Optional[str] = None,
                           result: Optional[str] = None, search: Optional[str] = None) -> int:
        pattern = f"%{search.casefold()}%" if search else None
        with self._lock, sqlite3.connect(self.db_path) as conn:
            row = conn.execute("""
                SELECT COUNT(*) FROM audit_events
                WHERE (? IS NULL OR owner_id = ?) AND (? IS NULL OR module = ?) AND (? IS NULL OR result = ?)
                  AND (? IS NULL OR lower(coalesce(event_id,'') || ' ' || coalesce(scan_id,'') || ' ' || module || ' ' || action || ' ' || result || ' ' || summary) LIKE ?)
            """, (owner_id, owner_id, module, module, result, result, pattern, pattern)).fetchone()
        return int(row[0]) if row else 0


_global_store: Optional[BaseIncidentStore] = None


def create_incident_store(settings: Settings) -> BaseIncidentStore:
    """Create an incident store according to settings configuration."""
    backend = getattr(settings, "incident_store", "memory")
    if backend == "sqlite":
        db_path = getattr(settings, "incident_store_path", "data/incidents.db")
        return SqliteIncidentStore(db_path=db_path)
    return MemoryIncidentStore()


def get_incident_store() -> BaseIncidentStore:
    """Dependency injector / accessor for singleton incident store."""
    global _global_store
    if _global_store is None:
        settings = get_settings()
        _global_store = create_incident_store(settings)
    return _global_store


def set_incident_store(store: BaseIncidentStore) -> None:
    """Allow overriding the store in tests."""
    global _global_store
    _global_store = store
