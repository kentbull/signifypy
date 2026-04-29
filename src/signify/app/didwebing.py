# -*- encoding: utf-8 -*-
"""SIGNIFY did:webs publication helpers.

This module owns the did:webs-specific durable API: request polling and
edge-side approval. Live SSE transport and KERI ``rpy`` envelope verification
belong to ``signify.app.signaling.AgentSignals`` so future KERIA topics can use
the same agent signaling channel without importing did:webs code.
"""

from dataclasses import dataclass
from datetime import datetime, timezone

from keri.db import dbing, koming

DWS_SIGN_ROUTE = "/didwebs/signing/request"
DWS_ACT_CRT_REG = "create_registry"
DWS_ACT_ISS_DA = "issue_designated_alias"
DWS_DEDUPE_IN_FLIGHT = "in_flight"
DWS_DEDUPE_SUBMITTED = "submitted"
DWS_DEDUPE_COMPLETE = "complete"
DWS_DEDUPE_FAILED = "failed"
DWS_DEDUPE_REJECTED = "rejected"
DWS_DEDUPE_TERMINAL_RETENTION_SECONDS = 10 * 60
DWS_DEDUPE_IN_FLIGHT_RETENTION_SECONDS = 10 * 60
DWS_TERMINAL_DEDUPE_STATUSES = {
    DWS_DEDUPE_COMPLETE,
    DWS_DEDUPE_FAILED,
    DWS_DEDUPE_REJECTED,
}


class DidWebs:
    """Client helper for KERIA did:webs managed-AID signing requests.

    KERIA may ask an edge client to create a registry or issue the designated
    aliases ACDC for a Signify-managed AID. Those requests are durable and
    recoverable through this helper. If the request arrived over
    ``client.signals().stream()``, verify its envelope first with
    ``client.signals().verifyReplyEnvelope(..., route=DIDWEBS_SIGNING_ROUTE)``.
    """

    def __init__(self, client):
        self.client = client

    def requests(self, aid=None, includeComplete=False):
        """List pending did:webs signing requests from the connected KERIA agent."""
        params = {}
        if aid is not None:
            params["aid"] = aid
        if includeComplete:
            params["includeComplete"] = "true"
        res = self.client.get("/didwebs/signing/requests", params=params or None)
        return res.json()["requests"]

    def request(self, requestId):
        """Fetch one did:webs signing request by SAID."""
        res = self.client.get(f"/didwebs/signing/requests/{requestId}")
        return res.json()

    def approve(self, request):
        """Perform the edge-signed work requested by KERIA.

        This method signs only through normal SignifyPy managed-AID APIs. It
        does not make KERIA sign as the managed AID.
        """
        action = request["action"]
        name = request["name"]
        if action == DWS_ACT_CRT_REG:
            return self.client.registries().create(name, request["registryName"])
        if action == DWS_ACT_ISS_DA:
            return self.client.credentials().issue(
                name,
                request["registryName"],
                request["credentialData"],
                request["schema"],
                rules=request["rules"],
            )

        raise ValueError(f"unsupported did:webs signing request action {action}")


@dataclass
class DidWebsDedupeRecord:
    """Local did:webs auto-approval dedupe state for one request SAID."""

    id: str
    aid: str
    action: str
    status: str
    updated: str
    error: str | None = None


class MemoryDidWebsDedupeStore:
    """In-memory did:webs request dedupe store."""

    def __init__(self):
        self.records = {}

    def get(self, request_id):
        return self.records.get(request_id)

    def put(self, record):
        self.records[record.id] = record

    def delete(self, request_id):
        self.records.pop(request_id, None)

    def purgeTerminal(
        self, max_age_seconds=DWS_DEDUPE_TERMINAL_RETENTION_SECONDS, now=None
    ):
        now = now if now is not None else datetime.now(timezone.utc).isoformat()
        deleted = 0
        for request_id, record in list(self.records.items()):
            if shouldPurgeTerminalRecord(record, max_age_seconds, now):
                self.delete(request_id)
                deleted += 1
        return deleted


class DidWebsDedupeBaser(dbing.LMDBer):
    """LMDBer rooted at the SignifyPy did:webs dedupe home."""

    HeadDirPath = "~"
    TailDirPath = ".keri/sigpy"
    AltTailDirPath = ".keri/sigpy"
    TempPrefix = "sigpy_didwebs_"

    def reopen(self, **kwa):
        opened = super().reopen(**kwa)
        self.records = koming.Komer(
            db=self, subkey="requestDedupe.", schema=DidWebsDedupeRecord
        )
        return opened


class LmdbDidWebsDedupeStore:
    """Persistent did:webs request dedupe store under ``~/.keri/sigpy/didwebs``."""

    def __init__(
        self,
        name="didwebs",
        headDirPath=None,
        reopen=True,
        clear=False,
        temp=False,
    ):
        self.db = DidWebsDedupeBaser(
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
        self, max_age_seconds=DWS_DEDUPE_TERMINAL_RETENTION_SECONDS, now=None
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
    if record.status not in DWS_TERMINAL_DEDUPE_STATUSES:
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


class DidWebsAutoApprover:
    """Auto-approve did:webs requests once, deduped by request SAID."""

    def __init__(
        self,
        client,
        store=None,
        now=None,
        terminalRetentionSeconds=None,
        inFlightRetentionSeconds=None,
    ):
        self.client = client
        self.didwebs = DidWebs(client)
        self.store = store if store is not None else LmdbDidWebsDedupeStore()
        self.now = now if now is not None else self._now
        self.terminalRetentionSeconds = (
            terminalRetentionSeconds
            if terminalRetentionSeconds is not None
            else DWS_DEDUPE_TERMINAL_RETENTION_SECONDS
        )
        self.inFlightRetentionSeconds = (
            inFlightRetentionSeconds
            if inFlightRetentionSeconds is not None
            else DWS_DEDUPE_IN_FLIGHT_RETENTION_SECONDS
        )

    def handleEnvelope(self, envelope):
        """Verify and handle one did:webs request from the signed SSE stream."""
        verified = self.client.signals().verifyReplyEnvelope(
            envelope, route=DWS_SIGN_ROUTE
        )
        if not verified:
            return {
                "outcome": "rejected",
                "error": "did:webs signing request envelope failed verification",
            }

        return self.handleRequest(envelope.get("rpy", {}).get("a"), source="sse")

    def handleRequest(self, request, source="polling"):
        """Handle one durable did:webs request from SSE or polling."""
        request_id = (request or {}).get("d")
        if not request_id:
            return {
                "outcome": "rejected",
                "source": source,
                "error": "did:webs signing request is missing request SAID",
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

        self._putRecord(request, DWS_DEDUPE_IN_FLIGHT)
        ownership_error = self._localOwnershipError(request)
        if ownership_error is not None:
            record = self._putRecord(request, DWS_DEDUPE_REJECTED, ownership_error)
            return {
                "outcome": "rejected",
                "requestId": request_id,
                "source": source,
                "record": record,
                "error": ownership_error,
            }

        try:
            self.didwebs.approve(request)
        except Exception as ex:
            record = self._putRecord(request, DWS_DEDUPE_FAILED, str(ex))
            return {
                "outcome": "failed",
                "requestId": request_id,
                "source": source,
                "record": record,
                "error": str(ex),
            }

        record = self._putRecord(request, DWS_DEDUPE_SUBMITTED)
        return {
            "outcome": "submitted",
            "requestId": request_id,
            "source": source,
            "record": record,
        }

    def pollOnce(self, aid=None):
        """Fetch pending durable requests and handle each once."""
        return [
            self.handleRequest(request, source="polling")
            for request in self.didwebs.requests(aid=aid)
        ]

    def reconcile(self, aid=None):
        """Update local dedupe records from KERIA's durable request state."""
        self.store.purgeTerminal(self.terminalRetentionSeconds, self.now())
        records = []
        for request in self.didwebs.requests(aid=aid, includeComplete=True):
            if request.get("state") == DWS_DEDUPE_COMPLETE:
                records.append(self._putRecord(request, DWS_DEDUPE_COMPLETE))
            elif request.get("state") == DWS_DEDUPE_FAILED:
                records.append(
                    self._putRecord(
                        request,
                        DWS_DEDUPE_FAILED,
                        request.get("error") or "KERIA reported request failure",
                    )
                )
        return records

    @staticmethod
    def _now():
        return datetime.now(timezone.utc).isoformat()

    def _shouldSkip(self, record, now):
        if (
            record is not None
            and record.status == DWS_DEDUPE_IN_FLIGHT
            and recordAgeSeconds(record, now) >= self.inFlightRetentionSeconds
        ):
            return False

        return record is not None and record.status in {
            DWS_DEDUPE_IN_FLIGHT,
            DWS_DEDUPE_SUBMITTED,
            DWS_DEDUPE_COMPLETE,
            DWS_DEDUPE_FAILED,
            DWS_DEDUPE_REJECTED,
        }

    def _localOwnershipError(self, request):
        try:
            hab = self.client.identifiers().get(request["name"])
        except Exception as ex:
            return (
                f"did:webs request {request['d']} targets {request['aid']}, "
                f"but local identifier {request['name']} is unavailable: {ex}"
            )
        if hab.get("prefix") != request["aid"]:
            return (
                f"did:webs request {request['d']} targets {request['aid']}, "
                f"but local identifier {request['name']} is {hab.get('prefix')}"
            )
        return None

    def _putRecord(self, request, status, error=None):
        record = DidWebsDedupeRecord(
            id=request["d"],
            aid=request["aid"],
            action=request["action"],
            status=status,
            updated=self.now(),
            error=error,
        )
        self.store.put(record)
        return record
