"""
Ghost Data Still Exists — Identity Resolver

Builds a complete identifier graph for each user by merging:
  - user_identities.csv (current snapshot)
  - user_audit_log.csv (historical changes)

Given a request email, resolves to a user_id and all known identifiers.
"""

from __future__ import annotations

import csv
import logging
from pathlib import Path
from typing import Optional

from models import UserIdentity, IdentityGraph

logger = logging.getLogger(__name__)


class IdentityResolver:
    """Resolves an email address to a full identity graph."""

    def __init__(self, dataset_dir: Path):
        self._dataset_dir = dataset_dir
        # user_id -> IdentityGraph
        self._graphs: dict[str, IdentityGraph] = {}
        # email (lowercase) -> user_id  (covers both current and historical)
        self._email_index: dict[str, str] = {}
        # email_hash (lowercase) -> user_id
        self._hash_index: dict[str, str] = {}
        # phone -> user_id
        self._phone_index: dict[str, str] = {}

        self._load_identities()
        self._load_audit_log()
        self._build_indexes()

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _load_identities(self) -> None:
        """Load current identity snapshots."""
        path = self._dataset_dir / "user_identities.csv"
        with open(path, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                uid = row["user_id"]
                identity = UserIdentity(
                    user_id=uid,
                    name=row["name"],
                    email=row["email"],
                    phone=row["phone"],
                    email_hash=row["email_hash"],
                    updated_at=row["updated_at"],
                )
                graph = IdentityGraph(
                    user_id=uid,
                    name=identity.name,
                    current_email=identity.email,
                    current_phone=identity.phone,
                    current_email_hash=identity.email_hash,
                    all_emails={identity.email},
                    all_phones={identity.phone},
                    all_email_hashes={identity.email_hash},
                )
                self._graphs[uid] = graph

    def _load_audit_log(self) -> None:
        """Load historical identity changes to capture old identifiers."""
        path = self._dataset_dir / "user_audit_log.csv"
        with open(path, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                uid = row["user_id"]
                graph = self._graphs.get(uid)
                if graph is None:
                    logger.warning("Audit log references unknown user_id=%s", uid)
                    continue

                field = row["field_name"]
                old_val = row["old_value"]
                new_val = row["new_value"]

                if field == "email":
                    if old_val:
                        graph.all_emails.add(old_val)
                    if new_val:
                        graph.all_emails.add(new_val)
                elif field == "email_hash":
                    if old_val:
                        graph.all_email_hashes.add(old_val)
                    if new_val:
                        graph.all_email_hashes.add(new_val)
                elif field == "phone":
                    if old_val:
                        graph.all_phones.add(old_val)
                    if new_val:
                        graph.all_phones.add(new_val)

    def _build_indexes(self) -> None:
        """Build reverse indexes from identifiers to user_id."""
        for uid, graph in self._graphs.items():
            for email in graph.all_emails:
                if email:
                    self._email_index[email.lower()] = uid
            for eh in graph.all_email_hashes:
                if eh:
                    self._hash_index[eh.lower()] = uid
            for phone in graph.all_phones:
                if phone:
                    self._phone_index[phone] = uid

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def resolve_by_email(self, email: str) -> Optional[IdentityGraph]:
        """Resolve an email (current or historical) to a full identity graph."""
        uid = self._email_index.get(email.lower())
        if uid:
            return self._graphs.get(uid)
        return None

    def resolve_by_user_id(self, user_id: str) -> Optional[IdentityGraph]:
        """Resolve a user_id to a full identity graph."""
        return self._graphs.get(user_id)

    def resolve_by_email_hash(self, email_hash: str) -> Optional[IdentityGraph]:
        """Resolve an email hash to a full identity graph."""
        uid = self._hash_index.get(email_hash.lower())
        if uid:
            return self._graphs.get(uid)
        return None

    def resolve_by_phone(self, phone: str) -> Optional[IdentityGraph]:
        """Resolve a phone number to a full identity graph."""
        uid = self._phone_index.get(phone)
        if uid:
            return self._graphs.get(uid)
        return None

    def get_all_graphs(self) -> dict[str, IdentityGraph]:
        """Return all identity graphs by user_id."""
        return dict(self._graphs)

    def find_user_by_any_identifier(self, value: str) -> Optional[IdentityGraph]:
        """Try to match a value against any known identifier."""
        if not value or value.lower() == "null" or value == "":
            return None

        # Try user_id
        if value.startswith("user_"):
            g = self._graphs.get(value)
            if g:
                return g

        # Try email
        g = self.resolve_by_email(value)
        if g:
            return g

        # Try email hash
        g = self.resolve_by_email_hash(value)
        if g:
            return g

        # Try phone
        g = self.resolve_by_phone(value)
        if g:
            return g

        return None
