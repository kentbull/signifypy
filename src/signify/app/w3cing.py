# -*- encoding: utf-8 -*-
"""SignifyPy W3C holder workflow helpers.

This module is a thin edge-client helper over KERIA's holder-centered W3C
routes. KERIA owns orchestration records and verifier submission. SignifyPy
verifies signed SSE envelopes, polls durable KERIA queues, dedupes local
automation, and signs only bytes requested for locally owned managed AIDs.
"""

import base64
from dataclasses import dataclass
from datetime import datetime, timezone

from keri.db import dbing, koming

W3C_SIGN_ROUTE = "/w3c/signing/request"
W3C_IMPORT_ROUTE = "/w3c/credentials/import-request"

W3C_SIGNING_ACTION = "signing"
W3C_IMPORT_ACTION = "import"

W3C_PURPOSE_ISSUER_VC_JWT = "issuer_vc_jwt"
W3C_PURPOSE_HOLDER_ADMIT = "holder_w3c_admit"
W3C_PURPOSE_HOLDER_VP_JWT = "holder_vp_jwt"
W3C_DEFAULT_SIGNING_PURPOSES = {
    W3C_PURPOSE_ISSUER_VC_JWT,
    W3C_PURPOSE_HOLDER_ADMIT,
}

W3C_DEDUPE_IN_FLIGHT = "in_flight"
W3C_DEDUPE_SUBMITTED = "submitted"
W3C_DEDUPE_IMPORTED = "imported"
W3C_DEDUPE_COMPLETE = "complete"
W3C_DEDUPE_FAILED = "failed"
W3C_DEDUPE_REJECTED = "rejected"
W3C_DEDUPE_BLOCKED = "blocked"
W3C_DEDUPE_TERMINAL_RETENTION_SECONDS = 10 * 60
W3C_DEDUPE_IN_FLIGHT_RETENTION_SECONDS = 10 * 60
W3C_TERMINAL_DEDUPE_STATUSES = {
    W3C_DEDUPE_COMPLETE,
    W3C_DEDUPE_FAILED,
    W3C_DEDUPE_REJECTED,
    W3C_DEDUPE_BLOCKED,
}

W3C_REQUEST_COMPLETE = "complete"
W3C_REQUEST_FAILED = "failed"
W3C_IMPORT_PENDING = "pending"
W3C_IMPORT_IMPORTED = "imported"
W3C_IMPORT_FAILED = "failed"
W3C_IMPORT_BLOCKED_NATIVE_VRD = "blocked_native_vrd"
W3C_IMPORT_EXPIRED = "expired"


class W3C:
    """Client helper for KERIA W3C issuer, holder, and presentation routes."""

    def __init__(self, client):
        self.client = client

    def startIssuance(self, name, sourceCredentialSaid):
        """Start QVI-side W3C issuance for a native VRD credential SAID."""
        return self.client.post(
            f"/identifiers/{name}/w3c/credentials",
            json={"sourceCredentialSaid": sourceCredentialSaid},
        ).json()

    def credential(self, name, credentialId):
        """Fetch one issuer issuance or held W3C credential view."""
        return self.client.get(
            f"/identifiers/{name}/w3c/credentials/{credentialId}"
        ).json()

    def credentials(self, name):
        """List held W3C credential views for one holder identifier."""
        return self.client.get(f"/identifiers/{name}/w3c/credentials").json()[
            "credentials"
        ]

    def retryIssuance(self, name, credentialId):
        """Retry one recoverable W3C issuance failure."""
        return self.client.post(
            f"/identifiers/{name}/w3c/credentials/{credentialId}/retry",
            json={},
        ).json()

    def redeliverIssuance(self, name, credentialId):
        """Redeliver one finalized W3C issuance artifact."""
        return self.client.post(
            f"/identifiers/{name}/w3c/credentials/{credentialId}/redeliver",
            json={},
        ).json()

    def backfillIssuances(self, name):
        """Ask KERIA to backfill eligible W3C issuances for one identifier."""
        return self.client.post(
            f"/identifiers/{name}/w3c/credentials/backfill",
            json={},
        ).json()

    def signingRequests(self, name=None, includeComplete=False, purpose=None):
        """List W3C signing requests, optionally across all local identifiers."""
        names = [name] if name is not None else self._managedNames()
        requests = []
        params = {"includeComplete": "true"} if includeComplete else None
        for aid_name in names:
            res = self.client.get(
                f"/identifiers/{aid_name}/w3c/signing-requests",
                params=params,
            )
            requests.extend(res.json()["requests"])
        if purpose is not None:
            requests = [
                request for request in requests if request.get("purpose") == purpose
            ]
        return requests

    def submitSignature(self, request, signature):
        """Submit one edge signature for a W3C signing request."""
        name = request["name"]
        request_id = request.get("requestId") or request["d"]
        return self.client.post(
            f"/identifiers/{name}/w3c/signing-requests/{request_id}/signatures",
            json={"signature": signature},
        ).json()

    def importRequests(self, name=None, includeComplete=False):
        """List holder W3C import requests, optionally across all identifiers."""
        names = [name] if name is not None else self._managedNames()
        requests = []
        params = {"includeComplete": "true"} if includeComplete else None
        for aid_name in names:
            res = self.client.get(
                f"/identifiers/{aid_name}/w3c/credentials/import-requests",
                params=params,
            )
            requests.extend(res.json()["requests"])
        return requests

    def importCredential(self, name, importRequestId):
        """Import a portable W3C credential through KERIA's canonical path."""
        return self.client.post(
            f"/identifiers/{name}/w3c/credentials/import",
            json={"importRequestId": importRequestId},
        ).json()

    def verifierContacts(self, name):
        """List runtime W3C verifier contacts for one holder."""
        return self.client.get(
            f"/identifiers/{name}/w3c/verifier-contacts"
        ).json()["contacts"]

    def createVerifierContact(self, name, descriptor):
        """Create or update a runtime W3C verifier contact."""
        return self.client.post(
            f"/identifiers/{name}/w3c/verifier-contacts",
            json=descriptor,
        ).json()

    def verifierContact(self, name, contactId):
        """Fetch one runtime W3C verifier contact."""
        return self.client.get(
            f"/identifiers/{name}/w3c/verifier-contacts/{contactId}"
        ).json()

    def presentTxs(self, name):
        """List holder W3C presentation transactions."""
        return self.client.get(f"/identifiers/{name}/w3c/present-txs").json()[
            "presentTxs"
        ]

    def startPresentTx(self, name, requestDescriptor):
        """Hand a runtime verifier request descriptor to KERIA."""
        return self.client.post(
            f"/identifiers/{name}/w3c/present-txs",
            json=requestDescriptor,
        ).json()

    def presentTx(self, name, presentTxId):
        """Fetch one holder W3C presentation transaction."""
        return self.client.get(
            f"/identifiers/{name}/w3c/present-txs/{presentTxId}"
        ).json()

    def submitPresentTxSignature(self, name, presentTxId, signature=None, vpJwt=None):
        """Submit holder presentation signature material to KERIA."""
        body = {}
        if signature is not None:
            body["signature"] = signature
        if vpJwt is not None:
            body["vpJwt"] = vpJwt
        return self.client.post(
            f"/identifiers/{name}/w3c/present-txs/{presentTxId}/signatures",
            json=body,
        ).json()

    def _managedNames(self):
        return [aid["name"] for aid in self.client.identifiers().list()["aids"]]


@dataclass
class W3CAutomationRecord:
    """Local W3C automation dedupe state for one durable KERIA request."""

    id: str
    aid: str
    name: str
    action: str
    status: str
    updated: str
    purpose: str | None = None
    error: str | None = None


class MemoryW3CAutomationStore:
    """In-memory W3C request dedupe store."""

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


class W3CAutomationBaser(dbing.LMDBer):
    """LMDBer rooted at the SignifyPy W3C automation home."""

    HeadDirPath = "~"
    TailDirPath = ".keri/sigpy"
    AltTailDirPath = ".keri/sigpy"
    TempPrefix = "sigpy_w3c_"

    def reopen(self, **kwa):
        opened = super().reopen(**kwa)
        self.records = koming.Komer(
            db=self, subkey="automationDedupe.", schema=W3CAutomationRecord
        )
        return opened


class LmdbW3CAutomationStore:
    """Persistent W3C automation dedupe store under ``~/.keri/sigpy/w3c``."""

    def __init__(
        self,
        name="w3c",
        headDirPath=None,
        reopen=True,
        clear=False,
        temp=False,
    ):
        self.db = W3CAutomationBaser(
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


class W3CEdgeAutomator:
    """Deduped W3C edge automation over signed SSE and durable polling."""

    def __init__(
        self,
        client,
        store=None,
        now=None,
        terminalRetentionSeconds=None,
        inFlightRetentionSeconds=None,
        signingPolicy=None,
        importPolicy=None,
    ):
        self.client = client
        self.w3c = W3C(client)
        self.store = store if store is not None else LmdbW3CAutomationStore()
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
        self.signingPolicy = (
            signingPolicy if signingPolicy is not None else defaultSigningPolicy
        )
        self.importPolicy = importPolicy if importPolicy is not None else defaultImportPolicy

    def handleEnvelope(self, envelope):
        """Verify and handle one W3C request from the signed SSE stream."""
        route = envelope.get("rpy", {}).get("r")
        if route not in {W3C_SIGN_ROUTE, W3C_IMPORT_ROUTE}:
            return {
                "outcome": "rejected",
                "error": f"unsupported W3C signal route {route}",
            }

        verified = self.client.signals().verifyReplyEnvelope(envelope, route=route)
        if not verified:
            return {
                "outcome": "rejected",
                "error": f"W3C signal envelope failed verification for {route}",
            }

        payload = envelope.get("rpy", {}).get("a")
        if route == W3C_SIGN_ROUTE:
            return self.handleSigningRequest(payload, source="sse")
        return self.handleImportRequest(payload, source="sse")

    def handleSigningRequest(self, request, source="polling"):
        """Sign one policy-valid KERIA W3C request once."""
        request_id = (request or {}).get("d") or (request or {}).get("requestId")
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

        self._putRecord(request, W3C_SIGNING_ACTION, W3C_DEDUPE_IN_FLIGHT)
        ownership_error = self._localSigningOwnershipError(request)
        if ownership_error is not None:
            record = self._putRecord(
                request, W3C_SIGNING_ACTION, W3C_DEDUPE_REJECTED, ownership_error
            )
            return self._outcome("rejected", request_id, source, record, ownership_error)

        policy_error = self._signingPolicyError(request)
        if policy_error is not None:
            record = self._putRecord(
                request, W3C_SIGNING_ACTION, W3C_DEDUPE_REJECTED, policy_error
            )
            return self._outcome("rejected", request_id, source, record, policy_error)

        try:
            signature = self._signRequest(request)
            self.w3c.submitSignature(request, signature)
        except Exception as ex:
            record = self._putRecord(
                request, W3C_SIGNING_ACTION, W3C_DEDUPE_FAILED, str(ex)
            )
            return self._outcome("failed", request_id, source, record, str(ex))

        record = self._putRecord(request, W3C_SIGNING_ACTION, W3C_DEDUPE_SUBMITTED)
        return self._outcome("submitted", request_id, source, record)

    def handleImportRequest(self, request, source="polling"):
        """Import one policy-valid holder W3C credential request once."""
        request_id = (request or {}).get("d") or (request or {}).get("importRequestId")
        if not request_id:
            return {
                "outcome": "rejected",
                "source": source,
                "error": "W3C import request is missing request SAID",
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

        self._putRecord(request, W3C_IMPORT_ACTION, W3C_DEDUPE_IN_FLIGHT)
        ownership_error = self._localImportOwnershipError(request)
        if ownership_error is not None:
            record = self._putRecord(
                request, W3C_IMPORT_ACTION, W3C_DEDUPE_REJECTED, ownership_error
            )
            return self._outcome("rejected", request_id, source, record, ownership_error)

        state = request.get("state")
        if state == W3C_IMPORT_BLOCKED_NATIVE_VRD:
            error = request.get("error") or "W3C import is blocked by missing native VRD state"
            record = self._putRecord(
                request, W3C_IMPORT_ACTION, W3C_DEDUPE_BLOCKED, error
            )
            return self._outcome("blocked", request_id, source, record, error)
        if state not in {None, W3C_IMPORT_PENDING}:
            error = f"W3C import request is {state}"
            record = self._putRecord(
                request, W3C_IMPORT_ACTION, W3C_DEDUPE_REJECTED, error
            )
            return self._outcome("rejected", request_id, source, record, error)

        policy_error = self._importPolicyError(request)
        if policy_error is not None:
            record = self._putRecord(
                request, W3C_IMPORT_ACTION, W3C_DEDUPE_REJECTED, policy_error
            )
            return self._outcome("rejected", request_id, source, record, policy_error)

        try:
            self.w3c.importCredential(request["holderName"], request_id)
        except Exception as ex:
            record = self._putRecord(
                request, W3C_IMPORT_ACTION, W3C_DEDUPE_FAILED, str(ex)
            )
            return self._outcome("failed", request_id, source, record, str(ex))

        record = self._putRecord(request, W3C_IMPORT_ACTION, W3C_DEDUPE_IMPORTED)
        return self._outcome("imported", request_id, source, record)

    def pollOnce(self, name=None):
        """Fetch pending W3C import and signing requests and handle each once."""
        outcomes = [
            self.handleImportRequest(request, source="polling")
            for request in self.w3c.importRequests(name=name)
        ]
        outcomes.extend(
            self.handleSigningRequest(request, source="polling")
            for request in self.w3c.signingRequests(name=name)
        )
        return outcomes

    def reconcile(self, name=None):
        """Update local dedupe records from KERIA durable request state."""
        self.store.purgeTerminal(self.terminalRetentionSeconds, self.now())
        records = []
        for request in self.w3c.signingRequests(name=name, includeComplete=True):
            if request.get("state") == W3C_REQUEST_COMPLETE:
                records.append(
                    self._putRecord(
                        request, W3C_SIGNING_ACTION, W3C_DEDUPE_COMPLETE
                    )
                )
            elif request.get("state") == W3C_REQUEST_FAILED:
                records.append(
                    self._putRecord(
                        request,
                        W3C_SIGNING_ACTION,
                        W3C_DEDUPE_FAILED,
                        request.get("error") or "KERIA reported W3C signing failure",
                    )
                )

        for request in self.w3c.importRequests(name=name, includeComplete=True):
            if request.get("state") == W3C_IMPORT_IMPORTED:
                records.append(
                    self._putRecord(request, W3C_IMPORT_ACTION, W3C_DEDUPE_COMPLETE)
                )
            elif request.get("state") in {W3C_IMPORT_FAILED, W3C_IMPORT_EXPIRED}:
                records.append(
                    self._putRecord(
                        request,
                        W3C_IMPORT_ACTION,
                        W3C_DEDUPE_FAILED,
                        request.get("error") or "KERIA reported W3C import failure",
                    )
                )
            elif request.get("state") == W3C_IMPORT_BLOCKED_NATIVE_VRD:
                records.append(
                    self._putRecord(
                        request,
                        W3C_IMPORT_ACTION,
                        W3C_DEDUPE_BLOCKED,
                        request.get("error") or "W3C import is blocked",
                    )
                )
        return records

    @staticmethod
    def _now():
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _outcome(outcome, request_id, source, record, error=None):
        result = {
            "outcome": outcome,
            "requestId": request_id,
            "source": source,
            "record": record,
        }
        if error is not None:
            result["error"] = error
        return result

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
            W3C_DEDUPE_IMPORTED,
            W3C_DEDUPE_COMPLETE,
            W3C_DEDUPE_FAILED,
            W3C_DEDUPE_REJECTED,
            W3C_DEDUPE_BLOCKED,
        }

    def _localSigningOwnershipError(self, request):
        name = request.get("name")
        aid = request.get("aid")
        return self._localOwnershipError(name, aid, "signing", request)

    def _localImportOwnershipError(self, request):
        name = request.get("holderName")
        aid = request.get("holderAid")
        return self._localOwnershipError(name, aid, "import", request)

    def _localOwnershipError(self, name, aid, action, request):
        try:
            hab = self.client.identifiers().get(name)
        except Exception as ex:
            return (
                f"W3C {action} request {request.get('d')} targets {aid}, "
                f"but local identifier {name} is unavailable: {ex}"
            )
        if hab.get("prefix") != aid:
            return (
                f"W3C {action} request {request.get('d')} targets {aid}, "
                f"but local identifier {name} is {hab.get('prefix')}"
            )
        return None

    def _signingPolicyError(self, request):
        approved = self.signingPolicy(request)
        if approved is True:
            return None
        if isinstance(approved, str):
            return approved
        return f"W3C signing purpose {request.get('purpose')} was not approved"

    def _importPolicyError(self, request):
        approved = self.importPolicy(request)
        if approved is True:
            return None
        if isinstance(approved, str):
            return approved
        return "W3C import request was not approved"

    def _signRequest(self, request):
        encoding = request.get("encoding", "base64url")
        if encoding != "base64url":
            raise ValueError(f"unsupported W3C signing request encoding {encoding}")
        hab = self.client.identifiers().get(request["name"])
        keeper = self.client.manager.get(aid=hab)
        signing_input = b64url_decode(request["signingInputB64"])
        sigs = keeper.sign(ser=signing_input, indexed=False)
        signature = sigs[0]
        return getattr(signature, "qb64", signature)

    def _putRecord(self, request, action, status, error=None):
        request_id = request.get("d") or request.get("requestId") or request.get("importRequestId")
        name = request.get("name") or request.get("holderName")
        aid = request.get("aid") or request.get("holderAid")
        record = W3CAutomationRecord(
            id=request_id,
            aid=aid,
            name=name,
            action=action,
            purpose=request.get("purpose"),
            status=status,
            updated=self.now(),
            error=error,
        )
        self.store.put(record)
        return record


def defaultSigningPolicy(request):
    """Approve non-presentation W3C signing requests by default."""
    return request.get("purpose") in W3C_DEFAULT_SIGNING_PURPOSES


def defaultImportPolicy(request):
    """Approve KERIA-validated pending import requests by default."""
    return request.get("state") in {None, W3C_IMPORT_PENDING}


def b64url_decode(value):
    """Decode an unpadded base64url string."""
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)
