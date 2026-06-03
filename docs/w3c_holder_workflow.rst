W3C Holder Workflow
===================

``signify.app.w3cing`` provides the SignifyPy edge-client helpers for KERIA's
holder-centered W3C VRD workflow. It mirrors the SignifyTS W3C operation API so
browser and headless wallets follow the same architecture.

Ownership Model
---------------

KERIA owns durable issuance, import, held credential, verifier contact, and
presentation transaction state. SignifyPy owns local policy decisions, request
dedupe, and private-key signing. Verifier services own VC/VP acceptance.

KERIA must not sign VC-JWT or VP-JWT token material. It stages signing inputs
and verifies submitted signatures. SignifyPy signs only locally owned,
policy-approved request bytes through the local keeper.

API Surface
-----------

``W3C`` wraps the KERIA W3C routes for:

- QVI-side issuance from a native VRD credential,
- edge signing requests and signature submission,
- holder import requests and held W3C credential inventory,
- runtime verifier contacts,
- holder presentation transactions and VP signature submission.

The helper does not sign by itself. Pair it with ``W3CEdgeAutomator`` or an
explicit signing loop to advance queued KERIA requests.

Edge Automation
---------------

``W3CEdgeAutomator`` verifies signed KERIA SSE envelopes, polls durable KERIA
queues, checks local identifier ownership, applies signing/import policy, and
records dedupe state so each request SAID is handled once.

Use ``LmdbW3CAutomationStore`` for long-lived headless processes. Use
``MemoryW3CAutomationStore`` for tests, foreground flows, and short-lived
harness runs.

The default signing policy approves issuer VC-JWT and holder-admit requests.
It deliberately excludes holder VP-JWT requests. A holder presentation policy
must recheck the live presentation transaction, selected credential, holder
AID, audience, and nonce before approving a VP signature.

Headless E2E Role
-----------------

The ``headless-w3c-e2e`` harness uses SignifyPy as a browserless wallet. It
connects to live KERIA, drives QVI issuance, imports/admites the holder W3C
credential, starts holder presentation transactions, and validates against live
Python, Node, and Go verifier services.

Fake verifier callables, direct verifier library calls, and CLI-only commands
are not end-to-end acceptance evidence for this path.
