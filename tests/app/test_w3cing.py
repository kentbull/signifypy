# -*- encoding: utf-8 -*-
"""SignifyPy W3C holder workflow helper tests."""

import pytest

from signify.app.w3cing import (
    MemoryW3CAutomationStore,
    W3C,
    W3CAutomationRecord,
    W3C_DEDUPE_BLOCKED,
    W3C_DEDUPE_COMPLETE,
    W3C_DEDUPE_FAILED,
    W3C_DEDUPE_IMPORTED,
    W3C_DEDUPE_IN_FLIGHT,
    W3C_DEDUPE_IN_FLIGHT_RETENTION_SECONDS,
    W3C_DEDUPE_REJECTED,
    W3C_DEDUPE_SUBMITTED,
    W3C_DEDUPE_TERMINAL_RETENTION_SECONDS,
    W3C_IMPORT_PENDING,
    W3C_IMPORT_ROUTE,
    W3C_PURPOSE_HOLDER_VP_JWT,
    W3C_PURPOSE_ISSUER_VC_JWT,
    W3C_SIGN_ROUTE,
    W3CEdgeAutomator,
    b64url_decode,
)


def signing_request_fixture(**overrides):
    request = {
        "d": "signing-id",
        "requestId": "signing-id",
        "name": "qvi",
        "aid": "Eqvi",
        "purpose": W3C_PURPOSE_ISSUER_VC_JWT,
        "related": "issuance-id",
        "signingInputB64": "cGF5bG9hZA",
        "encoding": "base64url",
        "verificationMethod": "did:webs:example.com:dws:Eqvi#Dkey",
        "state": "pending",
    }
    request.update(overrides)
    return request


def import_request_fixture(**overrides):
    request = {
        "d": "import-id",
        "importRequestId": "import-id",
        "holderName": "le",
        "holderAid": "Ele",
        "holderDid": "did:webs:example.com:dws:Ele",
        "issuerAid": "Eqvi",
        "issuerDid": "did:webs:example.com:dws:Eqvi",
        "sourceCredentialSaid": "credential-said",
        "schemaSaid": "schema-said",
        "grantSaid": "grant-said",
        "issuanceId": "issuance-id",
        "statusUrl": "http://status.example/w3c/vc/status/credential-said",
        "profile": "gleif-vrd-isomer-v1",
        "state": W3C_IMPORT_PENDING,
    }
    request.update(overrides)
    return request


def envelope_fixture(route, payload):
    return {"rpy": {"r": route, "a": payload}, "sigs": ["agent-signature"]}


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


class FakeIdentifiers:
    def __init__(self, prefixes):
        self.prefixes = prefixes
        self.calls = []

    def list(self):
        self.calls.append(("list",))
        return {"aids": [{"name": name} for name in self.prefixes.keys()]}

    def get(self, name):
        self.calls.append(("get", name))
        if name not in self.prefixes:
            raise ValueError("not found")
        return {"name": name, "prefix": self.prefixes[name]}


class FakeClient:
    def __init__(self, responses=None, verify=True, prefixes=None):
        self.responses = responses if responses is not None else {}
        self.verify = verify
        self.identifiers_resource = FakeIdentifiers(prefixes or {"qvi": "Eqvi", "le": "Ele"})
        self.manager = FakeManager()
        self.calls = []

    def signals(self):
        return self

    def verifyReplyEnvelope(self, _envelope, route=None):
        self.calls.append(("verify", route))
        return self.verify

    def identifiers(self):
        return self.identifiers_resource

    def get(self, path, **kwargs):
        self.calls.append(("get", path, kwargs))
        payload = self.responses.get(("get", path), {})
        return FakeResponse(payload)

    def post(self, path, **kwargs):
        self.calls.append(("post", path, kwargs))
        payload = self.responses.get(("post", path), {"accepted": True})
        return FakeResponse(payload)


def test_w3c_api_uses_holder_workflow_routes():
    client = FakeClient(
        responses={
            ("post", "/identifiers/qvi/w3c/credentials"): {"issuanceId": "issuance-id"},
            ("get", "/identifiers/le/w3c/credentials"): {"credentials": [{"credentialId": "held-id"}]},
            ("get", "/identifiers/le/w3c/credentials/held-id"): {"credentialId": "held-id"},
            ("get", "/identifiers/le/w3c/verifier-contacts"): {"contacts": []},
            ("get", "/identifiers/le/w3c/present-txs"): {"presentTxs": []},
        }
    )
    w3c = W3C(client)

    assert w3c.startIssuance("qvi", "credential-said") == {"issuanceId": "issuance-id"}
    assert w3c.credentials("le") == [{"credentialId": "held-id"}]
    assert w3c.credential("le", "held-id") == {"credentialId": "held-id"}
    assert w3c.importCredential("le", "import-id") == {"accepted": True}
    assert w3c.verifierContacts("le") == []
    assert w3c.createVerifierContact("le", {"origin": "https://verifier.example"}) == {"accepted": True}
    assert w3c.presentTxs("le") == []
    assert w3c.startPresentTx("le", {"aud": "https://verifier.example"}) == {"accepted": True}
    assert w3c.submitPresentTxSignature("le", "tx-id", signature="holder-signature") == {"accepted": True}

    assert ("post", "/identifiers/qvi/w3c/credentials", {"json": {"sourceCredentialSaid": "credential-said"}}) in client.calls
    assert ("post", "/identifiers/le/w3c/credentials/import", {"json": {"importRequestId": "import-id"}}) in client.calls
    assert (
        "post",
        "/identifiers/le/w3c/present-txs/tx-id/signatures",
        {"json": {"signature": "holder-signature"}},
    ) in client.calls


def test_w3c_polls_all_local_identifiers_and_filters_signing_purpose():
    issuer = signing_request_fixture(d="issuer-request", requestId="issuer-request")
    holder = signing_request_fixture(
        d="holder-request",
        requestId="holder-request",
        name="le",
        aid="Ele",
        purpose=W3C_PURPOSE_HOLDER_VP_JWT,
    )
    client = FakeClient(
        responses={
            ("get", "/identifiers/qvi/w3c/signing-requests"): {"requests": [issuer]},
            ("get", "/identifiers/le/w3c/signing-requests"): {"requests": [holder]},
            ("get", "/identifiers/qvi/w3c/credentials/import-requests"): {"requests": []},
            ("get", "/identifiers/le/w3c/credentials/import-requests"): {"requests": [import_request_fixture()]},
        }
    )

    requests = W3C(client).signingRequests(purpose=W3C_PURPOSE_HOLDER_VP_JWT)
    imports = W3C(client).importRequests()

    assert requests == [holder]
    assert imports == [import_request_fixture()]


def test_edge_automator_signs_verified_signing_request_once():
    client = FakeClient()
    automator = W3CEdgeAutomator(
        client,
        store=MemoryW3CAutomationStore(),
        now=lambda: "2026-06-01T00:00:00+00:00",
    )

    envelope = envelope_fixture(W3C_SIGN_ROUTE, signing_request_fixture())
    first = automator.handleEnvelope(envelope)
    second = automator.handleEnvelope(envelope)

    assert first["outcome"] == "submitted"
    assert first["record"].status == W3C_DEDUPE_SUBMITTED
    assert second["outcome"] == "skipped"
    assert client.manager.keeper.calls == [(b"payload", False)]
    assert [call for call in client.calls if call[0] == "post"] == [
        (
            "post",
            "/identifiers/qvi/w3c/signing-requests/signing-id/signatures",
            {"json": {"signature": "edge-signature"}},
        )
    ]


def test_edge_automator_rejects_unverified_envelope():
    client = FakeClient(verify=False)

    result = W3CEdgeAutomator(
        client, store=MemoryW3CAutomationStore()
    ).handleEnvelope(envelope_fixture(W3C_SIGN_ROUTE, signing_request_fixture()))

    assert result["outcome"] == "rejected"
    assert [call[0] for call in client.calls].count("post") == 0


def test_edge_automator_rejects_holder_vp_without_explicit_policy():
    client = FakeClient(prefixes={"le": "Ele"})
    request = signing_request_fixture(
        name="le",
        aid="Ele",
        purpose=W3C_PURPOSE_HOLDER_VP_JWT,
    )

    result = W3CEdgeAutomator(
        client, store=MemoryW3CAutomationStore()
    ).handleSigningRequest(request)

    assert result["outcome"] == "rejected"
    assert result["record"].status == W3C_DEDUPE_REJECTED
    assert "not approved" in result["error"]
    assert [call[0] for call in client.calls].count("post") == 0


def test_edge_automator_can_sign_holder_vp_with_explicit_policy():
    client = FakeClient(prefixes={"le": "Ele"})
    request = signing_request_fixture(
        name="le",
        aid="Ele",
        purpose=W3C_PURPOSE_HOLDER_VP_JWT,
    )

    result = W3CEdgeAutomator(
        client,
        store=MemoryW3CAutomationStore(),
        signingPolicy=lambda _request: True,
    ).handleSigningRequest(request)

    assert result["outcome"] == "submitted"
    assert [call for call in client.calls if call[0] == "post"] == [
        (
            "post",
            "/identifiers/le/w3c/signing-requests/signing-id/signatures",
            {"json": {"signature": "edge-signature"}},
        )
    ]


def test_edge_automator_imports_verified_import_request_once():
    client = FakeClient(prefixes={"le": "Ele"})
    automator = W3CEdgeAutomator(client, store=MemoryW3CAutomationStore())
    envelope = envelope_fixture(W3C_IMPORT_ROUTE, import_request_fixture())

    first = automator.handleEnvelope(envelope)
    second = automator.handleEnvelope(envelope)

    assert first["outcome"] == "imported"
    assert first["record"].status == W3C_DEDUPE_IMPORTED
    assert second["outcome"] == "skipped"
    assert [call for call in client.calls if call[0] == "post"] == [
        (
            "post",
            "/identifiers/le/w3c/credentials/import",
            {"json": {"importRequestId": "import-id"}},
        )
    ]


def test_edge_automator_blocks_import_when_native_vrd_missing():
    client = FakeClient(prefixes={"le": "Ele"})
    request = import_request_fixture(
        state="blocked_native_vrd",
        error="matching holder-local native VRD ACDC is missing",
    )

    result = W3CEdgeAutomator(
        client, store=MemoryW3CAutomationStore()
    ).handleImportRequest(request)

    assert result["outcome"] == "blocked"
    assert result["record"].status == W3C_DEDUPE_BLOCKED
    assert "native VRD" in result["error"]
    assert [call[0] for call in client.calls].count("post") == 0


def test_edge_automator_rejects_mismatched_local_aid():
    client = FakeClient(prefixes={"le": "Eother"})

    result = W3CEdgeAutomator(
        client, store=MemoryW3CAutomationStore()
    ).handleImportRequest(import_request_fixture())

    assert result["outcome"] == "rejected"
    assert result["record"].status == W3C_DEDUPE_REJECTED
    assert "targets Ele" in result["error"]
    assert [call[0] for call in client.calls].count("post") == 0


def test_edge_automator_poll_once_handles_imports_before_signing():
    client = FakeClient(
        responses={
            ("get", "/identifiers/qvi/w3c/credentials/import-requests"): {"requests": []},
            ("get", "/identifiers/le/w3c/credentials/import-requests"): {"requests": [import_request_fixture()]},
            ("get", "/identifiers/qvi/w3c/signing-requests"): {"requests": [signing_request_fixture()]},
            ("get", "/identifiers/le/w3c/signing-requests"): {"requests": []},
        }
    )

    results = W3CEdgeAutomator(
        client, store=MemoryW3CAutomationStore()
    ).pollOnce()

    assert [result["outcome"] for result in results] == ["imported", "submitted"]
    assert [call[1] for call in client.calls if call[0] == "post"] == [
        "/identifiers/le/w3c/credentials/import",
        "/identifiers/qvi/w3c/signing-requests/signing-id/signatures",
    ]


def test_edge_automator_reconciles_terminal_keria_states():
    signing = signing_request_fixture(state="complete")
    blocked = import_request_fixture(
        state="blocked_native_vrd",
        error="native VRD missing",
    )
    client = FakeClient(
        responses={
            ("get", "/identifiers/qvi/w3c/signing-requests"): {"requests": [signing]},
            ("get", "/identifiers/le/w3c/signing-requests"): {"requests": []},
            ("get", "/identifiers/qvi/w3c/credentials/import-requests"): {"requests": []},
            ("get", "/identifiers/le/w3c/credentials/import-requests"): {"requests": [blocked]},
        }
    )

    records = W3CEdgeAutomator(
        client, store=MemoryW3CAutomationStore()
    ).reconcile()

    assert [record.status for record in records] == [W3C_DEDUPE_COMPLETE, W3C_DEDUPE_BLOCKED]


def test_memory_dedupe_store_purges_old_terminal_records_only():
    store = MemoryW3CAutomationStore()
    store.put(
        W3CAutomationRecord(
            id="old-complete",
            aid="Eqvi",
            name="qvi",
            action="signing",
            purpose=W3C_PURPOSE_ISSUER_VC_JWT,
            status=W3C_DEDUPE_COMPLETE,
            updated="2026-06-01T00:00:00+00:00",
        )
    )
    store.put(
        W3CAutomationRecord(
            id="recent-complete",
            aid="Eqvi",
            name="qvi",
            action="signing",
            purpose=W3C_PURPOSE_ISSUER_VC_JWT,
            status=W3C_DEDUPE_COMPLETE,
            updated="2026-06-01T00:09:30+00:00",
        )
    )
    store.put(
        W3CAutomationRecord(
            id="old-submitted",
            aid="Eqvi",
            name="qvi",
            action="signing",
            purpose=W3C_PURPOSE_ISSUER_VC_JWT,
            status=W3C_DEDUPE_SUBMITTED,
            updated="2026-06-01T00:00:00+00:00",
        )
    )
    store.put(
        W3CAutomationRecord(
            id="old-rejected",
            aid="Ele",
            name="le",
            action="import",
            status=W3C_DEDUPE_REJECTED,
            updated="2026-06-01T00:00:00+00:00",
        )
    )

    deleted = store.purgeTerminal(
        W3C_DEDUPE_TERMINAL_RETENTION_SECONDS,
        now="2026-06-01T00:10:00+00:00",
    )

    assert deleted == 2
    assert store.get("old-complete") is None
    assert store.get("old-rejected") is None
    assert store.get("recent-complete").status == W3C_DEDUPE_COMPLETE
    assert store.get("old-submitted").status == W3C_DEDUPE_SUBMITTED


def test_edge_automator_retries_stale_in_flight_records_after_active_window():
    store = MemoryW3CAutomationStore()
    store.put(
        W3CAutomationRecord(
            id="signing-id",
            aid="Eqvi",
            name="qvi",
            action="signing",
            purpose=W3C_PURPOSE_ISSUER_VC_JWT,
            status=W3C_DEDUPE_IN_FLIGHT,
            updated="2026-06-01T00:00:00+00:00",
        )
    )
    client = FakeClient()

    result = W3CEdgeAutomator(
        client,
        store=store,
        now=lambda: "2026-06-01T00:10:00+00:00",
        inFlightRetentionSeconds=W3C_DEDUPE_IN_FLIGHT_RETENTION_SECONDS,
    ).handleSigningRequest(signing_request_fixture())

    assert result["outcome"] == "submitted"
    assert [call[0] for call in client.calls].count("post") == 1


@pytest.mark.parametrize(
    "value,decoded",
    [
        ("cGF5bG9hZA", b"payload"),
        ("cGF5bG9hZA==", b"payload"),
    ],
)
def test_b64url_decode_accepts_unpadded_and_padded_values(value, decoded):
    assert b64url_decode(value) == decoded
