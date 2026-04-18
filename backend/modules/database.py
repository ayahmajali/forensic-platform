"""
database.py — MongoDB persistence layer for investigation cases.

Responsibilities
----------------
* Persist every forensic case (formerly "job") so a backend restart no longer
  wipes in-flight / completed investigations.
* Provide a thin, forensic-domain-specific wrapper around pymongo so the rest
  of the app stays database-agnostic.
* Gracefully fall back to an in-memory dict when Mongo is unreachable, so the
  platform still boots during local demos / defense when the DB isn't running.

Collections
-----------
* cases           — one document per forensic case (job_id, status, progress,
                    hashes, findings, timestamps, AI summary, etc.)

Environment variables
---------------------
* MONGODB_URI     — Mongo connection string (e.g. mongodb://localhost:27017)
* MONGODB_DB      — database name (default: "forensic_platform")
* MONGODB_TIMEOUT — connect timeout in ms (default: 2000)

Notes
-----
We use pymongo (synchronous) with FastAPI's ``run_in_threadpool`` / background
tasks rather than motor (async). pymongo is already pinned in requirements.txt,
is simpler to reason about for a graduation-project defense, and the forensic
pipeline is CPU/IO heavy enough that the sync driver is not the bottleneck.
"""

from __future__ import annotations

import os
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional

try:
    from pymongo import MongoClient, ASCENDING, DESCENDING
    from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError, PyMongoError
    _PYMONGO_AVAILABLE = True
except ImportError:  # pragma: no cover - pymongo is pinned in requirements
    _PYMONGO_AVAILABLE = False


# ─────────────────────────────────────────────────────────────────────────────
# CaseStore — the single object the rest of the app talks to.
# ─────────────────────────────────────────────────────────────────────────────


class CaseStore:
    """
    Stores/retrieves forensic cases.

    The public API is deliberately small and synchronous:
        * save_case(case_id, data)
        * update_case(case_id, patch)
        * get_case(case_id)
        * list_cases()
        * delete_case(case_id)
        * load_all() — called on boot to re-hydrate the in-memory cache

    If Mongo is unreachable, every method still works against an internal
    thread-safe dict so the UI/API never breaks during a demo.
    """

    COLLECTION = "cases"

    def __init__(self) -> None:
        self._client: Optional["MongoClient"] = None
        self._db = None
        self._collection = None
        self._mem: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()
        self._connected = False
        self._connect()

    # ── connection lifecycle ────────────────────────────────────────────────

    def _connect(self) -> None:
        """Attempt to connect to MongoDB. On any failure, stay in memory mode."""
        if not _PYMONGO_AVAILABLE:
            print("[DB] pymongo not installed — running in IN-MEMORY mode")
            return

        # NOTE: Some .env loaders don't strip inline "# comment" on value lines.
        # We defensively drop anything after '#' and surrounding whitespace so
        # a line like `MONGODB_TIMEOUT=2000  # connect timeout` still works.
        def _clean(val: str) -> str:
            val = (val or "").split("#", 1)[0]
            return val.strip().strip('"').strip("'")

        uri = _clean(os.getenv("MONGODB_URI", ""))
        if not uri:
            print("[DB] MONGODB_URI not set — running in IN-MEMORY mode")
            return

        db_name = _clean(os.getenv("MONGODB_DB", "forensic_platform")) or "forensic_platform"
        try:
            timeout_ms = int(_clean(os.getenv("MONGODB_TIMEOUT", "2000")))
        except ValueError:
            timeout_ms = 2000

        try:
            self._client = MongoClient(uri, serverSelectionTimeoutMS=timeout_ms)
            # Trigger an actual connection — otherwise pymongo lazily connects.
            self._client.admin.command("ping")
            self._db = self._client[db_name]
            self._collection = self._db[self.COLLECTION]
            # Helpful indexes for the common queries we run.
            self._collection.create_index([("case_id", ASCENDING)], unique=True)
            self._collection.create_index([("created_at", DESCENDING)])
            self._collection.create_index([("status", ASCENDING)])
            self._connected = True
            print(f"[DB] Connected to MongoDB — database '{db_name}'")
        except (ConnectionFailure, ServerSelectionTimeoutError) as e:
            print(f"[DB] Could not reach MongoDB ({e}) — falling back to IN-MEMORY")
            self._client = None
            self._collection = None
        except PyMongoError as e:
            print(f"[DB] Mongo error ({e}) — falling back to IN-MEMORY")
            self._client = None
            self._collection = None

    @property
    def is_persistent(self) -> bool:
        """True when backed by Mongo; False when using the in-memory fallback."""
        return self._connected and self._collection is not None

    # ── CRUD ────────────────────────────────────────────────────────────────

    def save_case(self, case_id: str, data: Dict[str, Any]) -> None:
        """Insert or fully replace a case document."""
        doc = dict(data)
        doc["case_id"] = case_id
        doc.setdefault("created_at", datetime.utcnow().isoformat())
        doc["updated_at"] = datetime.utcnow().isoformat()

        with self._lock:
            self._mem[case_id] = doc
            if self.is_persistent:
                try:
                    self._collection.replace_one(
                        {"case_id": case_id}, doc, upsert=True
                    )
                except PyMongoError as e:
                    print(f"[DB] save_case failed for {case_id}: {e}")

    def update_case(self, case_id: str, patch: Dict[str, Any]) -> None:
        """
        Merge-patch an existing case. Safe to call many times (e.g. on each
        progress tick). If the case doesn't exist yet, behaves like save_case.
        """
        patch = dict(patch)
        patch["updated_at"] = datetime.utcnow().isoformat()

        with self._lock:
            existing = self._mem.get(case_id, {})
            existing.update(patch)
            existing["case_id"] = case_id
            existing.setdefault("created_at", datetime.utcnow().isoformat())
            self._mem[case_id] = existing

            if self.is_persistent:
                try:
                    self._collection.update_one(
                        {"case_id": case_id},
                        {"$set": patch, "$setOnInsert": {
                            "case_id": case_id,
                            "created_at": existing["created_at"],
                        }},
                        upsert=True,
                    )
                except PyMongoError as e:
                    print(f"[DB] update_case failed for {case_id}: {e}")

    def get_case(self, case_id: str) -> Optional[Dict[str, Any]]:
        """Return a case document or None."""
        with self._lock:
            if case_id in self._mem:
                return dict(self._mem[case_id])
            if self.is_persistent:
                try:
                    doc = self._collection.find_one({"case_id": case_id}, {"_id": 0})
                    if doc:
                        self._mem[case_id] = doc
                        return dict(doc)
                except PyMongoError as e:
                    print(f"[DB] get_case failed for {case_id}: {e}")
            return None

    def list_cases(self, limit: int = 200) -> List[Dict[str, Any]]:
        """Return cases sorted by created_at DESC."""
        with self._lock:
            if self.is_persistent:
                try:
                    cursor = (
                        self._collection
                        .find({}, {"_id": 0})
                        .sort("created_at", DESCENDING)
                        .limit(limit)
                    )
                    cases = list(cursor)
                    # Keep the in-memory cache in sync for fast follow-up reads.
                    for c in cases:
                        self._mem[c["case_id"]] = c
                    return cases
                except PyMongoError as e:
                    print(f"[DB] list_cases failed: {e}")

            # Fallback: sort the in-memory dict.
            cases = list(self._mem.values())
            cases.sort(key=lambda c: c.get("created_at", ""), reverse=True)
            return cases[:limit]

    def delete_case(self, case_id: str) -> bool:
        """Remove a case. Returns True if something was deleted."""
        with self._lock:
            existed = case_id in self._mem
            self._mem.pop(case_id, None)
            if self.is_persistent:
                try:
                    result = self._collection.delete_one({"case_id": case_id})
                    existed = existed or result.deleted_count > 0
                except PyMongoError as e:
                    print(f"[DB] delete_case failed for {case_id}: {e}")
            return existed

    def load_all(self) -> Dict[str, Dict[str, Any]]:
        """
        Re-hydrate the in-memory cache from Mongo at startup so the /api/jobs
        endpoint returns historical cases even right after a restart.
        """
        with self._lock:
            if not self.is_persistent:
                return dict(self._mem)
            try:
                for doc in self._collection.find({}, {"_id": 0}):
                    self._mem[doc["case_id"]] = doc
            except PyMongoError as e:
                print(f"[DB] load_all failed: {e}")
            return dict(self._mem)

    # ── diagnostics ─────────────────────────────────────────────────────────

    def health(self) -> Dict[str, Any]:
        """Small status dict for /api/health."""
        return {
            "connected": self.is_persistent,
            "backend": "mongodb" if self.is_persistent else "in-memory",
            "case_count": len(self._mem),
        }


# ─────────────────────────────────────────────────────────────────────────────
# Module-level singleton. Import this, don't instantiate CaseStore() elsewhere.
# ─────────────────────────────────────────────────────────────────────────────

case_store = CaseStore()
