# -*- encoding: utf-8 -*-
"""
SIGNIFY W3C projection helper tests.
"""

import pytest
from mockito import expect, mock, verifyNoUnwantedInteractions, unstub

from signify.app.w3cing import (
    W3C,
    W3CProjectionAutoApprover,
    MemoryW3CDedupeStore,
    W3CDedupeRecord,
    W3C_DEDUPE_COMPLETE,
    W3C_DEDUPE_FAILED,
    W3C_DEDUPE_IN_FLIGHT,
    W3C_DEDUPE_IN_FLIGHT_RETENTION_SECONDS,
    W3C_DEDUPE_REJECTED,
    W3C_DEDUPE_SUBMITTED,
    W3C_DEDUPE_TERMINAL_RETENTION_SECONDS,
    W3C_KIND_JWT,
    W3C_KIND_PROOF,
    W3C_SIGN_ROUTE,
    b64url_decode,
)


def request_fixture(**overrides):
    request = {
        "d": "request-id",
        "agent": "agent-aid",
        "aid": "managed-aid",
        "name": "aid1",
        "kind": W3C_KIND_PROOF,
        "signingInputB64": "cGF5bG9hZA",
        "state": "pending",
        "dt": "2021-06-27T21:26:21.233257+00:00",
    }
    request.update(overrides)
    return request


def envelope_fixture(request=None):
    return {
        "rpy": {
            "r": W3C_SIGN_ROUTE,
            "a": request if request is not None else request_fixture(),
        },
        "sigs": ["signature"],
    }


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def json(self):
        return self.payload


class FakeKeeper:
    def __init__(self, signature="edge-signature"):
        self.signature = signature
        self.calls = []

    def sign(self, ser, indexed=False):
        self.calls.append((ser, indexed))
        return [self.signature]


class FakeManager:
    def __init__(self, keeper=None):
        self.keeper = keeper if keeper is not None else FakeKeeper()
        self.calls = []

    def get(self, aid):
        self.calls.append(aid)
        return self.keeper


class FakeClient:
    def __init__(
        self,
        requests=None,
        verify=True,
        prefix="managed-aid",
        submit_error=None,
        identifier_error=None,
    ):
        self.requests_payload = requests if requests is not None else []
        self.verify = verify
        self.prefix = prefix
        self.submit_error = submit_error
        self.identifier_error = identifier_error
        self.manager = FakeManager()
        self.calls = []

    def signals(self):
        return self

    def verifyReplyEnvelope(self, _envelope, route=None):
        self.calls.append(("verify", route))
        return self.verify

    def identifiers(self):
        return self

    def get(self, *args, **kwargs):
        if args and args[0].startswith("/identifiers/"):
            self.calls.append(("requests", args, kwargs))
            return FakeResponse({"requests": self.requests_payload})

        name = args[0]
        if self.identifier_error is not None:
            raise self.identifier_error
        self.calls.append(("identifier", name))
        return {"prefix": self.prefix}

    def post(self, *args, **kwargs):
        if self.submit_error is not None:
            raise self.submit_error
        self.calls.append(("post", args, kwargs))
        return FakeResponse({"accepted": True})


def test_w3c_verifiers(make_mock_response):
    client = mock(strict=True)
    response = make_mock_response({"json": lambda: {"verifiers": ["verifier-aid"]}})
    expect(client, times=1).get("/w3c/verifiers").thenReturn(response)

    result = W3C(client).verifiers()

    assert result == ["verifier-aid"]
    verifyNoUnwantedInteractions()
    unstub()


def test_w3c_project(make_mock_response):
    client = mock(strict=True)
    response = make_mock_response({"json": lambda: {"sessionId": "session-id"}})
    expect(client, times=1).post(
        "/identifiers/aid1/w3c/projections",
        json={"credentialSaid": "credential-said", "verifierId": "verifier-aid"},
    ).thenReturn(response)

    result = W3C(client).project("aid1", "credential-said", "verifier-aid")

    assert result == {"sessionId": "session-id"}
    verifyNoUnwantedInteractions()
    unstub()


def test_w3c_projection(make_mock_response):
    client = mock(strict=True)
    response = make_mock_response({"json": lambda: {"state": "ready"}})
    expect(client, times=1).get(
        "/identifiers/aid1/w3c/projections/session-id"
    ).thenReturn(response)

    result = W3C(client).projection("aid1", "session-id")

    assert result == {"state": "ready"}
    verifyNoUnwantedInteractions()
    unstub()


def test_w3c_requests_for_identifier(make_mock_response):
    client = mock(strict=True)
    response = make_mock_response({"json": lambda: {"requests": [{"d": "request-id"}]}})
    expect(client, times=1).get(
        "/identifiers/aid1/w3c/signing-requests",
        params={"includeComplete": "true"},
    ).thenReturn(response)

    result = W3C(client).requests(name="aid1", includeComplete=True)

    assert result == [{"d": "request-id"}]
    verifyNoUnwantedInteractions()
    unstub()


def test_w3c_requests_for_all_managed_identifiers(make_mock_response):
    client = mock(strict=True)
    identifiers = mock(strict=True)
    response1 = make_mock_response({"json": lambda: {"requests": [{"d": "one"}]}})
    response2 = make_mock_response({"json": lambda: {"requests": [{"d": "two"}]}})
    expect(client, times=1).identifiers().thenReturn(identifiers)
    expect(identifiers, times=1).list().thenReturn(
        {"aids": [{"name": "aid1"}, {"name": "aid2"}]}
    )
    expect(client, times=1).get(
        "/identifiers/aid1/w3c/signing-requests", params=None
    ).thenReturn(response1)
    expect(client, times=1).get(
        "/identifiers/aid2/w3c/signing-requests", params=None
    ).thenReturn(response2)

    result = W3C(client).requests()

    assert result == [{"d": "one"}, {"d": "two"}]
    verifyNoUnwantedInteractions()
    unstub()


def test_w3c_submit_signature(make_mock_response):
    client = mock(strict=True)
    response = make_mock_response({"json": lambda: {"state": "complete"}})
    expect(client, times=1).post(
        "/identifiers/aid1/w3c/signing-requests/request-id/signatures",
        json={"signature": "edge-signature"},
    ).thenReturn(response)

    result = W3C(client).submitSignature(request_fixture(), "edge-signature")

    assert result == {"state": "complete"}
    verifyNoUnwantedInteractions()
    unstub()


def test_auto_approver_signs_and_submits_sse_envelope_once():
    client = FakeClient()
    approver = W3CProjectionAutoApprover(
        client, store=MemoryW3CDedupeStore(), now=lambda: "now"
    )

    first = approver.handleEnvelope(envelope_fixture())
    second = approver.handleEnvelope(envelope_fixture())

    assert first["outcome"] == "submitted"
    assert second["outcome"] == "skipped"
    assert second["record"].status == W3C_DEDUPE_SUBMITTED
    assert client.manager.keeper.calls == [(b"payload", False)]
    assert [call for call in client.calls if call[0] == "post"] == [
        (
            "post",
            ("/identifiers/aid1/w3c/signing-requests/request-id/signatures",),
            {"json": {"signature": "edge-signature"}},
        )
    ]


def test_auto_approver_rejects_unverified_sse_envelope():
    client = FakeClient(verify=False)

    result = W3CProjectionAutoApprover(
        client, store=MemoryW3CDedupeStore()
    ).handleEnvelope(envelope_fixture())

    assert result["outcome"] == "rejected"
    assert [call[0] for call in client.calls].count("post") == 0


def test_auto_approver_rejects_mismatched_local_aid():
    client = FakeClient(prefix="other-aid")

    result = W3CProjectionAutoApprover(
        client, store=MemoryW3CDedupeStore()
    ).handleRequest(request_fixture())

    assert result["outcome"] == "rejected"
    assert result["record"].status == W3C_DEDUPE_REJECTED
    assert [call[0] for call in client.calls].count("post") == 0


def test_auto_approver_rejects_unavailable_local_identifier():
    client = FakeClient(identifier_error=ValueError("not found"))

    result = W3CProjectionAutoApprover(
        client, store=MemoryW3CDedupeStore()
    ).handleRequest(request_fixture())

    assert result["outcome"] == "rejected"
    assert result["record"].status == W3C_DEDUPE_REJECTED
    assert "unavailable: not found" in result["error"]
    assert [call[0] for call in client.calls].count("post") == 0


def test_auto_approver_marks_unsupported_kind_failed():
    client = FakeClient()

    result = W3CProjectionAutoApprover(
        client, store=MemoryW3CDedupeStore()
    ).handleRequest(request_fixture(kind="unsupported"))

    assert result["outcome"] == "failed"
    assert result["record"].status == W3C_DEDUPE_FAILED
    assert "unsupported W3C signing request kind unsupported" in result["error"]


def test_auto_approver_retries_stale_in_flight_records_after_active_window():
    store = MemoryW3CDedupeStore()
    store.put(
        W3CDedupeRecord(
            id="request-id",
            aid="managed-aid",
            kind=W3C_KIND_JWT,
            status=W3C_DEDUPE_IN_FLIGHT,
            updated="2021-06-27T21:00:00+00:00",
        )
    )
    client = FakeClient()

    result = W3CProjectionAutoApprover(
        client,
        store=store,
        now=lambda: "2021-06-27T21:10:00+00:00",
        inFlightRetentionSeconds=W3C_DEDUPE_IN_FLIGHT_RETENTION_SECONDS,
    ).handleRequest(request_fixture(kind=W3C_KIND_JWT))

    assert result["outcome"] == "submitted"
    assert [call[0] for call in client.calls].count("post") == 1


def test_auto_approver_reconciles_completion_only_from_keria_state():
    request = request_fixture(state=W3C_DEDUPE_COMPLETE)
    pending = request_fixture(d="pending-id", state="pending")
    client = FakeClient(requests=[request, pending])
    store = MemoryW3CDedupeStore()
    approver = W3CProjectionAutoApprover(client, store=store)

    approver.handleRequest(request_fixture())
    records = approver.reconcile(name="aid1")

    assert len(records) == 1
    assert store.get("request-id").status == W3C_DEDUPE_COMPLETE
    assert store.get("pending-id") is None


def test_memory_dedupe_store_purges_old_terminal_records_only():
    store = MemoryW3CDedupeStore()
    store.put(
        W3CDedupeRecord(
            id="old-complete",
            aid="managed-aid",
            kind=W3C_KIND_PROOF,
            status=W3C_DEDUPE_COMPLETE,
            updated="2021-06-27T21:00:00+00:00",
        )
    )
    store.put(
        W3CDedupeRecord(
            id="recent-complete",
            aid="managed-aid",
            kind=W3C_KIND_PROOF,
            status=W3C_DEDUPE_COMPLETE,
            updated="2021-06-27T21:09:30+00:00",
        )
    )
    store.put(
        W3CDedupeRecord(
            id="old-submitted",
            aid="managed-aid",
            kind=W3C_KIND_PROOF,
            status=W3C_DEDUPE_SUBMITTED,
            updated="2021-06-27T21:00:00+00:00",
        )
    )
    store.put(
        W3CDedupeRecord(
            id="old-rejected",
            aid="managed-aid",
            kind=W3C_KIND_PROOF,
            status=W3C_DEDUPE_REJECTED,
            updated="2021-06-27T21:00:00+00:00",
        )
    )

    deleted = store.purgeTerminal(
        W3C_DEDUPE_TERMINAL_RETENTION_SECONDS,
        now="2021-06-27T21:10:00+00:00",
    )

    assert deleted == 2
    assert store.get("old-complete") is None
    assert store.get("old-rejected") is None
    assert store.get("recent-complete").status == W3C_DEDUPE_COMPLETE
    assert store.get("old-submitted").status == W3C_DEDUPE_SUBMITTED


@pytest.mark.parametrize(
    "value,decoded",
    [
        ("cGF5bG9hZA", b"payload"),
        ("cGF5bG9hZA==", b"payload"),
    ],
)
def test_b64url_decode_accepts_unpadded_and_padded_values(value, decoded):
    assert b64url_decode(value) == decoded
