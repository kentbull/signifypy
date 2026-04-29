# -*- encoding: utf-8 -*-
"""
SIGNIFY did:webs helper tests.
"""

import pytest
from mockito import expect, mock, verifyNoUnwantedInteractions, unstub

from signify.app.didwebing import (
    DWS_ACT_CRT_REG,
    DWS_ACT_ISS_DA,
    DWS_DEDUPE_COMPLETE,
    DWS_DEDUPE_FAILED,
    DWS_DEDUPE_IN_FLIGHT,
    DWS_DEDUPE_IN_FLIGHT_RETENTION_SECONDS,
    DWS_DEDUPE_REJECTED,
    DWS_DEDUPE_SUBMITTED,
    DWS_DEDUPE_TERMINAL_RETENTION_SECONDS,
    DWS_SIGN_ROUTE,
    DidWebsDedupeRecord,
    LmdbDidWebsDedupeStore,
    DidWebsAutoApprover,
    DidWebs,
    MemoryDidWebsDedupeStore,
)


def request_fixture(**overrides):
    request = {
        "d": "request-id",
        "type": "didwebs.registry.create",
        "action": DWS_ACT_CRT_REG,
        "agent": "agent-aid",
        "aid": "managed-aid",
        "name": "aid1",
        "did": "did:webs:example:aid",
        "registryName": "registry",
        "schema": "schema",
        "credentialData": {},
        "rules": {},
        "didJsonUrl": "http://example/did.json",
        "keriCesrUrl": "http://example/keri.cesr",
        "dt": "2021-06-27T21:26:21.233257+00:00",
    }
    request.update(overrides)
    return request


def envelope_fixture(request=None):
    return {
        "rpy": {
            "r": DWS_SIGN_ROUTE,
            "a": request if request is not None else request_fixture(),
        },
        "sigs": ["signature"],
    }


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def json(self):
        return self.payload


class FakeClient:
    def __init__(
        self,
        requests=None,
        verify=True,
        prefix="managed-aid",
        approve_error=None,
        identifier_error=None,
    ):
        self.requests_payload = requests if requests is not None else []
        self.verify = verify
        self.prefix = prefix
        self.approve_error = approve_error
        self.identifier_error = identifier_error
        self.calls = []

    def signals(self):
        return self

    def verifyReplyEnvelope(self, _envelope, route=None):
        self.calls.append(("verify", route))
        return self.verify

    def identifiers(self):
        return self

    def registries(self):
        return self

    def credentials(self):
        return self

    def get(self, *args, **kwargs):
        if args and args[0] == "/didwebs/signing/requests":
            self.calls.append(("requests", args, kwargs))
            return FakeResponse({"requests": self.requests_payload})
        if args and args[0].startswith("/didwebs/signing/requests/"):
            self.calls.append(("request", args, kwargs))
            return FakeResponse(request_fixture())

        name = args[0]
        if self.identifier_error is not None:
            raise self.identifier_error
        self.calls.append(("identifier", name))
        return {"prefix": self.prefix}

    def create(self, name, registry_name):
        if self.approve_error is not None:
            raise self.approve_error
        self.calls.append(("registry", name, registry_name))
        return "registry-op"

    def issue(self, name, registry_name, credential_data, schema, rules=None):
        if self.approve_error is not None:
            raise self.approve_error
        self.calls.append(
            ("credential", name, registry_name, credential_data, schema, rules)
        )
        return "credential-op"


def test_didwebs_requests(make_mock_response):
    client = mock(strict=True)
    response = make_mock_response({"json": lambda: {"requests": [{"d": "request-id"}]}})
    expect(client, times=1).get(
        "/didwebs/signing/requests", params={"aid": "aid", "includeComplete": "true"}
    ).thenReturn(response)

    result = DidWebs(client).requests(aid="aid", includeComplete=True)

    assert result == [{"d": "request-id"}]
    verifyNoUnwantedInteractions()
    unstub()


def test_didwebs_request(make_mock_response):
    client = mock(strict=True)
    response = make_mock_response({"json": lambda: {"d": "request-id"}})
    expect(client, times=1).get("/didwebs/signing/requests/request-id").thenReturn(
        response
    )

    result = DidWebs(client).request("request-id")

    assert result == {"d": "request-id"}
    verifyNoUnwantedInteractions()
    unstub()


def test_didwebs_approve_registry_request():
    client = mock(strict=True)
    registries = mock(strict=True)
    response = mock()
    expect(client, times=1).registries().thenReturn(registries)
    expect(registries, times=1).create("aid1", "registry").thenReturn(response)

    result = DidWebs(client).approve(
        {
            "action": DWS_ACT_CRT_REG,
            "name": "aid1",
            "registryName": "registry",
        }
    )

    assert result is response
    verifyNoUnwantedInteractions()
    unstub()


def test_didwebs_approve_designated_alias_request():
    client = mock(strict=True)
    credentials = mock(strict=True)
    response = mock()
    expect(client, times=1).credentials().thenReturn(credentials)
    expect(credentials, times=1).issue(
        "aid1",
        "registry",
        {"ids": ["did:webs:example:aid"]},
        "schema",
        rules={"usageDisclaimer": {}},
    ).thenReturn(response)

    result = DidWebs(client).approve(
        {
            "action": DWS_ACT_ISS_DA,
            "name": "aid1",
            "registryName": "registry",
            "credentialData": {"ids": ["did:webs:example:aid"]},
            "schema": "schema",
            "rules": {"usageDisclaimer": {}},
        }
    )

    assert result is response
    verifyNoUnwantedInteractions()
    unstub()


def test_didwebs_approve_rejects_unknown_action():
    client = mock(strict=True)

    with pytest.raises(ValueError, match="unsupported did:webs signing request"):
        DidWebs(client).approve({"action": "unknown", "name": "aid1"})


def test_auto_approver_dedupes_duplicate_sse_envelopes():
    client = FakeClient()
    approver = DidWebsAutoApprover(
        client, store=MemoryDidWebsDedupeStore(), now=lambda: "now"
    )

    first = approver.handleEnvelope(envelope_fixture())
    second = approver.handleEnvelope(envelope_fixture())

    assert first["outcome"] == "submitted"
    assert second["outcome"] == "skipped"
    assert second["record"].status == DWS_DEDUPE_SUBMITTED
    assert [call[0] for call in client.calls].count("registry") == 1


def test_auto_approver_dedupes_same_request_from_sse_and_polling():
    request = request_fixture()
    client = FakeClient(requests=[request])
    approver = DidWebsAutoApprover(client, store=MemoryDidWebsDedupeStore())

    approver.handleEnvelope(envelope_fixture(request))
    results = approver.pollOnce()

    assert results[0]["outcome"] == "skipped"
    assert [call[0] for call in client.calls].count("registry") == 1


def test_auto_approver_uses_provided_store_across_instances():
    store = MemoryDidWebsDedupeStore()
    client = FakeClient()

    DidWebsAutoApprover(client, store=store).handleRequest(request_fixture())
    second = DidWebsAutoApprover(client, store=store).handleRequest(request_fixture())

    assert second["outcome"] == "skipped"
    assert [call[0] for call in client.calls].count("registry") == 1


def test_auto_approver_retries_stale_in_flight_records_after_active_window():
    store = MemoryDidWebsDedupeStore()
    store.put(
        DidWebsDedupeRecord(
            id="request-id",
            aid="managed-aid",
            action=DWS_ACT_CRT_REG,
            status=DWS_DEDUPE_IN_FLIGHT,
            updated="2021-06-27T21:00:00+00:00",
        )
    )
    client = FakeClient()

    result = DidWebsAutoApprover(
        client,
        store=store,
        now=lambda: "2021-06-27T21:10:00+00:00",
        inFlightRetentionSeconds=DWS_DEDUPE_IN_FLIGHT_RETENTION_SECONDS,
    ).handleRequest(request_fixture())

    assert result["outcome"] == "submitted"
    assert [call[0] for call in client.calls].count("registry") == 1


def test_auto_approver_rejects_unverified_sse_envelope():
    client = FakeClient(verify=False)

    result = DidWebsAutoApprover(
        client, store=MemoryDidWebsDedupeStore()
    ).handleEnvelope(envelope_fixture())

    assert result["outcome"] == "rejected"
    assert [call[0] for call in client.calls].count("registry") == 0


def test_auto_approver_rejects_mismatched_local_aid():
    client = FakeClient(prefix="other-aid")

    result = DidWebsAutoApprover(
        client, store=MemoryDidWebsDedupeStore()
    ).handleRequest(request_fixture())

    assert result["outcome"] == "rejected"
    assert result["record"].status == DWS_DEDUPE_REJECTED
    assert [call[0] for call in client.calls].count("registry") == 0


def test_auto_approver_rejects_unavailable_local_identifier():
    client = FakeClient(identifier_error=ValueError("not found"))

    result = DidWebsAutoApprover(
        client, store=MemoryDidWebsDedupeStore()
    ).handleRequest(request_fixture())

    assert result["outcome"] == "rejected"
    assert result["record"].status == DWS_DEDUPE_REJECTED
    assert "unavailable: not found" in result["error"]
    assert [call[0] for call in client.calls].count("registry") == 0


def test_auto_approver_marks_approval_error_failed_without_completing():
    client = FakeClient(approve_error=ValueError("boom"))

    result = DidWebsAutoApprover(
        client, store=MemoryDidWebsDedupeStore()
    ).handleRequest(request_fixture())

    assert result["outcome"] == "failed"
    assert result["record"].status == DWS_DEDUPE_FAILED
    assert result["record"].error == "boom"


def test_auto_approver_reconciles_completion_only_from_keria_state():
    request = request_fixture(state=DWS_DEDUPE_COMPLETE)
    pending = request_fixture(d="pending-id", state="pending")
    client = FakeClient(requests=[request, pending])
    store = MemoryDidWebsDedupeStore()
    approver = DidWebsAutoApprover(client, store=store)

    approver.handleRequest(request_fixture())
    records = approver.reconcile()

    assert len(records) == 1
    assert store.get("request-id").status == DWS_DEDUPE_COMPLETE
    assert store.get("pending-id") is None


def test_memory_dedupe_store_purges_old_terminal_records_only():
    store = MemoryDidWebsDedupeStore()
    store.put(
        DidWebsDedupeRecord(
            id="old-complete",
            aid="managed-aid",
            action=DWS_ACT_CRT_REG,
            status=DWS_DEDUPE_COMPLETE,
            updated="2021-06-27T21:00:00+00:00",
        )
    )
    store.put(
        DidWebsDedupeRecord(
            id="recent-complete",
            aid="managed-aid",
            action=DWS_ACT_CRT_REG,
            status=DWS_DEDUPE_COMPLETE,
            updated="2021-06-27T21:09:30+00:00",
        )
    )
    store.put(
        DidWebsDedupeRecord(
            id="old-submitted",
            aid="managed-aid",
            action=DWS_ACT_CRT_REG,
            status=DWS_DEDUPE_SUBMITTED,
            updated="2021-06-27T21:00:00+00:00",
        )
    )
    store.put(
        DidWebsDedupeRecord(
            id="old-rejected",
            aid="managed-aid",
            action=DWS_ACT_CRT_REG,
            status=DWS_DEDUPE_REJECTED,
            updated="2021-06-27T21:00:00+00:00",
        )
    )

    deleted = store.purgeTerminal(
        DWS_DEDUPE_TERMINAL_RETENTION_SECONDS,
        now="2021-06-27T21:10:00+00:00",
    )

    assert deleted == 2
    assert store.get("old-complete") is None
    assert store.get("old-rejected") is None
    assert store.get("recent-complete").status == DWS_DEDUPE_COMPLETE
    assert store.get("old-submitted").status == DWS_DEDUPE_SUBMITTED


def test_lmdb_dedupe_store_persists_records_across_reopen(tmp_path):
    store = LmdbDidWebsDedupeStore(headDirPath=str(tmp_path), name="didwebs-test")
    store.put(
        DidWebsDedupeRecord(
            id="request-id",
            aid="managed-aid",
            action=DWS_ACT_CRT_REG,
            status=DWS_DEDUPE_SUBMITTED,
            updated="2021-06-27T21:00:00+00:00",
        )
    )
    store.close()

    reopened = LmdbDidWebsDedupeStore(headDirPath=str(tmp_path), name="didwebs-test")
    try:
        assert reopened.get("request-id").status == DWS_DEDUPE_SUBMITTED
    finally:
        reopened.close(clear=True)


def test_lmdb_dedupe_store_purges_terminal_records(tmp_path):
    store = LmdbDidWebsDedupeStore(headDirPath=str(tmp_path), name="didwebs-test")
    try:
        store.put(
            DidWebsDedupeRecord(
                id="old-failed",
                aid="managed-aid",
                action=DWS_ACT_CRT_REG,
                status=DWS_DEDUPE_FAILED,
                updated="2021-06-27T21:00:00+00:00",
            )
        )
        store.put(
            DidWebsDedupeRecord(
                id="old-submitted",
                aid="managed-aid",
                action=DWS_ACT_CRT_REG,
                status=DWS_DEDUPE_SUBMITTED,
                updated="2021-06-27T21:00:00+00:00",
            )
        )

        deleted = store.purgeTerminal(
            DWS_DEDUPE_TERMINAL_RETENTION_SECONDS,
            now="2021-06-27T21:10:00+00:00",
        )

        assert deleted == 1
        assert store.get("old-failed") is None
        assert store.get("old-submitted").status == DWS_DEDUPE_SUBMITTED
    finally:
        store.close(clear=True)
