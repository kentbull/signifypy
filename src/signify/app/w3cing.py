# -*- encoding: utf-8 -*-
"""SignifyPy W3C projection helpers.

KERIA creates short-lived projection sessions and requests edge signatures over
the generic signed SSE channel. This module owns only the W3C-specific polling,
signature submission, and local dedupe/auto-approval behavior.
"""

import base64
from dataclasses import dataclass
from datetime import datetime, timezone

from keri.db import dbing, koming

W3C_SIGN_ROUTE = "/w3c/signing/request"
W3C_KIND_PROOF = "data_integrity_proof"
W3C_KIND_JWT = "vc_jwt"
W3C_DEDUPE_IN_FLIGHT = "in_flight"
W3C_DEDUPE_SUBMITTED = "submitted"
W3C_DEDUPE_COMPLETE = "complete"
W3C_DEDUPE_FAILED = "failed"
W3C_DEDUPE_REJECTED = "rejected"
W3C_DEDUPE_TERMINAL_RETENTION_SECONDS = 10 * 60
W3C_DEDUPE_IN_FLIGHT_RETENTION_SECONDS = 10 * 60
W3C_TERMINAL_DEDUPE_STATUSES = {
    W3C_DEDUPE_COMPLETE,
    W3C_DEDUPE_FAILED,
    W3C_DEDUPE_REJECTED,
}


class W3C:
    """Client helper for KERIA W3C projection sessions and signing requests."""

    def __init__(self, client):
        self.client = client

    def verifiers(self):
        """Return the configured verifier allowlist from KERIA."""
        return self.client.get("/w3c/verifiers").json()["verifiers"]

    def project(self, name, credentialSaid, verifierId):
        """Create one short-lived W3C projection session."""
        return self.client.post(
            f"/identifiers/{name}/w3c/projections",
            json=dict(credentialSaid=credentialSaid, verifierId=verifierId),
        ).json()

    def projection(self, name, sessionId):
        """Fetch one W3C projection session status."""
        return self.client.get(
            f"/identifiers/{name}/w3c/projections/{sessionId}"
        ).json()

    def requests(self, name=None, includeComplete=False):
        """List pending W3C signing requests, optionally across all identifiers."""
        names = [name] if name is not None else self._managedNames()
        requests = []
        params = {"includeComplete": "true"} if includeComplete else None
        for aid_name in names:
            res = self.client.get(
                f"/identifiers/{aid_name}/w3c/signing-requests", params=params
            )
            requests.extend(res.json()["requests"])
        return requests

    def submitSignature(self, request, signature):
        """Submit one edge signature for a W3C signing request."""
        return self.client.post(
            f"/identifiers/{request['name']}/w3c/signing-requests/{request['d']}/signatures",
            json=dict(signature=signature),
        ).json()

    def _managedNames(self):
        return [aid["name"] for aid in self.client.identifiers().list()["aids"]]


@dataclass
class W3CDedupeRecord:
    """Local W3C projection dedupe state for one request SAID."""

    id: str
    aid: str
    kind: str
    status: str
    updated: str
    error: str | None = None


class MemoryW3CDedupeStore:
    """In-memory W3C projection request dedupe store."""

    def __init__(self):
        self.records = {}

    def get(self, request_id):
        return self.records.get(request_id)

    def put(self, record):
        self.records[record.id] = record

    def delete(self, request_id):
        self.records.pop(request_id, None)

    def purgeTerminal(
        self, max_age_seconds=W3C_DEDUPE_TERMINAL_RETENTION_SECONDS, now=None
    ):
        now = now if now is not None else datetime.now(timezone.utc).isoformat()
        deleted = 0
        for request_id, record in list(self.records.items()):
            if shouldPurgeTerminalRecord(record, max_age_seconds, now):
                self.delete(request_id)
                deleted += 1
        return deleted


class W3CDedupeBaser(dbing.LMDBer):
    """LMDBer rooted at the SignifyPy W3C dedupe home."""

    HeadDirPath = "~"
    TailDirPath = ".keri/sigpy"
    AltTailDirPath = ".keri/sigpy"
    TempPrefix = "sigpy_w3c_"

    def reopen(self, **kwa):
        opened = super().reopen(**kwa)
        self.records = koming.Komer(
            db=self, subkey="requestDedupe.", schema=W3CDedupeRecord
        )
        return opened


class LmdbW3CDedupeStore:
    """Persistent W3C projection dedupe store under ``~/.keri/sigpy/w3c``."""

    def __init__(
        self,
        name="w3c",
        headDirPath=None,
        reopen=True,
        clear=False,
        temp=False,
    ):
        self.db = W3CDedupeBaser(
            name=name,
            headDirPath=headDirPath,
            reopen=reopen,
            clear=clear,
            temp=temp,
            reuse=True,
        )

    def get(self, request_id):
        return self.db.records.get(keys=(request_id,))

    def put(self, record):
        self.db.records.pin(keys=(record.id,), val=record)

    def delete(self, request_id):
        self.db.records.rem(keys=(request_id,))

    def purgeTerminal(
        self, max_age_seconds=W3C_DEDUPE_TERMINAL_RETENTION_SECONDS, now=None
    ):
        now = now if now is not None else datetime.now(timezone.utc).isoformat()
        deleted = 0
        for keys, record in list(self.db.records.getItemIter()):
            if shouldPurgeTerminalRecord(record, max_age_seconds, now):
                self.db.records.rem(keys=keys)
                deleted += 1
        return deleted

    def close(self, clear=False):
        self.db.close(clear=clear)


def shouldPurgeTerminalRecord(record, max_age_seconds, now):
    """Return True when a terminal dedupe record is old enough to discard."""
    if record.status not in W3C_TERMINAL_DEDUPE_STATUSES:
        return False
    return recordAgeSeconds(record, now) >= max_age_seconds


def recordAgeSeconds(record, now):
    try:
        updated = datetime.fromisoformat(record.updated)
        current = datetime.fromisoformat(now)
    except ValueError:
        return 0
    if updated.tzinfo is None:
        updated = updated.replace(tzinfo=timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    return (current - updated).total_seconds()


class W3CProjectionAutoApprover:
    """Auto-sign W3C projection requests once, deduped by request SAID."""

    def __init__(
        self,
        client,
        store=None,
        now=None,
        terminalRetentionSeconds=None,
        inFlightRetentionSeconds=None,
    ):
        self.client = client
        self.w3c = W3C(client)
        self.store = store if store is not None else LmdbW3CDedupeStore()
        self.now = now if now is not None else self._now
        self.terminalRetentionSeconds = (
            terminalRetentionSeconds
            if terminalRetentionSeconds is not None
            else W3C_DEDUPE_TERMINAL_RETENTION_SECONDS
        )
        self.inFlightRetentionSeconds = (
            inFlightRetentionSeconds
            if inFlightRetentionSeconds is not None
            else W3C_DEDUPE_IN_FLIGHT_RETENTION_SECONDS
        )

    def handleEnvelope(self, envelope):
        """Verify and handle one W3C request from the signed SSE stream."""
        verified = self.client.signals().verifyReplyEnvelope(
            envelope, route=W3C_SIGN_ROUTE
        )
        if not verified:
            return {
                "outcome": "rejected",
                "error": "W3C signing request envelope failed verification",
            }
        return self.handleRequest(envelope.get("rpy", {}).get("a"), source="sse")

    def handleRequest(self, request, source="polling"):
        """Handle one W3C signing request from SSE or polling."""
        request_id = (request or {}).get("d")
        if not request_id:
            return {
                "outcome": "rejected",
                "source": source,
                "error": "W3C signing request is missing request SAID",
            }

        now = self.now()
        self.store.purgeTerminal(self.terminalRetentionSeconds, now)
        existing = self.store.get(request_id)
        if self._shouldSkip(existing, now):
            return {
                "outcome": "skipped",
                "requestId": request_id,
                "source": source,
                "record": existing,
            }

        self._putRecord(request, W3C_DEDUPE_IN_FLIGHT)
        ownership_error = self._localOwnershipError(request)
        if ownership_error is not None:
            record = self._putRecord(request, W3C_DEDUPE_REJECTED, ownership_error)
            return {
                "outcome": "rejected",
                "requestId": request_id,
                "source": source,
                "record": record,
                "error": ownership_error,
            }

        try:
            signature = self._signRequest(request)
            self.w3c.submitSignature(request, signature)
        except Exception as ex:
            record = self._putRecord(request, W3C_DEDUPE_FAILED, str(ex))
            return {
                "outcome": "failed",
                "requestId": request_id,
                "source": source,
                "record": record,
                "error": str(ex),
            }

        record = self._putRecord(request, W3C_DEDUPE_SUBMITTED)
        return {
            "outcome": "submitted",
            "requestId": request_id,
            "source": source,
            "record": record,
        }

    def pollOnce(self, name=None):
        """Fetch pending durable requests and handle each once."""
        return [
            self.handleRequest(request, source="polling")
            for request in self.w3c.requests(name=name)
        ]

    def reconcile(self, name=None):
        """Update local dedupe records from KERIA request state."""
        self.store.purgeTerminal(self.terminalRetentionSeconds, self.now())
        records = []
        for request in self.w3c.requests(name=name, includeComplete=True):
            if request.get("state") == W3C_DEDUPE_COMPLETE:
                records.append(self._putRecord(request, W3C_DEDUPE_COMPLETE))
            elif request.get("state") == W3C_DEDUPE_FAILED:
                records.append(
                    self._putRecord(
                        request,
                        W3C_DEDUPE_FAILED,
                        request.get("error") or "KERIA reported W3C request failure",
                    )
                )
        return records

    @staticmethod
    def _now():
        return datetime.now(timezone.utc).isoformat()

    def _shouldSkip(self, record, now):
        if (
            record is not None
            and record.status == W3C_DEDUPE_IN_FLIGHT
            and recordAgeSeconds(record, now) >= self.inFlightRetentionSeconds
        ):
            return False
        return record is not None and record.status in {
            W3C_DEDUPE_IN_FLIGHT,
            W3C_DEDUPE_SUBMITTED,
            W3C_DEDUPE_COMPLETE,
            W3C_DEDUPE_FAILED,
            W3C_DEDUPE_REJECTED,
        }

    def _localOwnershipError(self, request):
        try:
            hab = self.client.identifiers().get(request["name"])
        except Exception as ex:
            return (
                f"W3C request {request['d']} targets {request['aid']}, "
                f"but local identifier {request['name']} is unavailable: {ex}"
            )
        if hab.get("prefix") != request["aid"]:
            return (
                f"W3C request {request['d']} targets {request['aid']}, "
                f"but local identifier {request['name']} is {hab.get('prefix')}"
            )
        return None

    def _signRequest(self, request):
        if request["kind"] not in {W3C_KIND_PROOF, W3C_KIND_JWT}:
            raise ValueError(f"unsupported W3C signing request kind {request['kind']}")
        hab = self.client.identifiers().get(request["name"])
        keeper = self.client.manager.get(aid=hab)
        signing_input = b64url_decode(request["signingInputB64"])
        sigs = keeper.sign(ser=signing_input, indexed=False)
        return sigs[0]

    def _putRecord(self, request, status, error=None):
        record = W3CDedupeRecord(
            id=request["d"],
            aid=request["aid"],
            kind=request["kind"],
            status=status,
            updated=self.now(),
            error=error,
        )
        self.store.put(record)
        return record


def b64url_decode(value):
    """Decode an unpadded base64url string."""
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)
