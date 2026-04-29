# Signifypy
Signify implementation in Python

[![Tests](https://github.com/WebOfTrust/signifypy/actions/workflows/test.yaml/badge.svg?branch=development)](https://github.com/WebOfTrust/signifypy/actions/workflows/test.yaml)
[![codecov](https://codecov.io/gh/WebOfTrust/signifypy/graph/badge.svg?token=E9VS4PNKTD)](https://codecov.io/gh/WebOfTrust/signifypy)
[![Documentation Status](https://readthedocs.org/projects/signifypy/badge/?version=latest)](https://signifypy.readthedocs.io/en/latest/?badge=latest)

## Signify - KERI Signing at the Edge

Of the five functions in a KERI agent, 

1. Key generation
2. Encrypted key storage
3. Event generation
4. Event signing
5. Event Validation

Signifypy provides key generation and event signing in a library to provide "signing at the edge".
It accomplishes this by using [libsodium](https://doc.libsodium.org/) to generate ed25519 key pairs for signing and x25519 key pairs for encrypting the
private keys, next public keys, and salts used to generate the private keys.  The encrypted private key and salts are then stored on a
remote cloud agent that never has access to the decryption keys.  New key pair sets (current and next) will be generated 
for inception and rotation events with only the public keys and blake3 hash of the next keys made available to the agent.

The communication protocol between a Signify client and [KERI](https://github.com/WebOfTrust/keri) agent will encode all cryptographic primitives as CESR base64
encoded strings for the initial implementation.  Support for binary CESR can be added in the future.

### Development

Install [uv](https://docs.astral.sh/uv/) first, then sync the local environment:

```bash
make sync
```

Run the fast test suite with:

```bash
make test
```

### Agent signaling

KERIA can publish transient server-sent events for the connected agent at
`GET /signals/stream`. SignifyPy exposes this generic channel through
`client.signals()`.

The signaling API is deliberately separate from topic APIs:

- `client.signals().stream()` opens the authenticated SSE stream.
- `client.signals().verifyReplyEnvelope(envelope, route=...)` verifies that the
  SSE payload is a KERI `rpy` envelope signed by the connected KERIA agent AID.
- Topic resources own durable fallback and approval behavior. For did:webs,
  use `client.didwebs().requests()`, `client.didwebs().request(id)`, and
  `client.didwebs().approve(request)`.

SSE delivery is not durable. A client that is offline or disconnected must poll
the relevant topic endpoint. For did:webs publication, the durable fallback is
`/didwebs/signing/requests`.

### Packaging

```bash
make build
```

### Installation

#### From PyPi

`pip install signifypy`

#### Local

```bash
make sync
```

#### Local Editable Install In An Existing Python Environment

If you already have a Python environment selected and want an editable install
inside that environment, `uv` still supports that flow directly:

```bash
uv pip install -e .
```
