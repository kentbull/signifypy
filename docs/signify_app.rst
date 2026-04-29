Signify App API
===============

signify.app.aiding
------------------

.. automodule:: signify.app.aiding
    :members:

signify.app.clienting
---------------------

.. automodule:: signify.app.clienting
    :members:

signify.app.challenging
-----------------------

.. automodule:: signify.app.challenging
    :members:

signify.app.contacting
----------------------

.. automodule:: signify.app.contacting
    :members:

signify.app.coring
------------------

.. automodule:: signify.app.coring
    :members:

signify.app.credentialing
-------------------------

``signify.app.credentialing`` intentionally keeps three adjacent public
surfaces together:

- ``Registries`` owns registry lifecycle and serialization helpers.
- ``Credentials`` owns stored credential reads plus issue/revoke operations.
- ``Ipex`` owns conversation and presentation exchange methods layered on top
  of peer ``exn`` transport.

Read the class and method docstrings in this section as the detailed reference
contract for that split.

.. automodule:: signify.app.credentialing
    :members:

signify.app.delegating
----------------------

.. automodule:: signify.app.delegating
   :members:

signify.app.signaling
---------------------

``signify.app.signaling`` is the generic KERIA agent signaling API for
SignifyPy. It is deliberately separate from topic helpers such as did:webs.

Ownership boundary:

- ``AgentSignals`` opens the authenticated ``GET /signals/stream`` SSE stream.
- ``AgentSignals`` verifies KERIA agent-signed KERI ``rpy`` envelopes.
- Topic modules interpret event names, expected reply routes, and payloads.
- Topic modules also own durable polling fallback because SSE delivery is
  transient.

For did:webs publication, a live event should be verified with
``client.signals().verifyReplyEnvelope(envelope, route=DIDWEBS_SIGNING_ROUTE)``
before auto-approval. A disconnected client should recover through
``client.didwebs().requests()``.

.. automodule:: signify.app.signaling
   :members:

signify.app.didwebing
---------------------

``signify.app.didwebing`` owns did:webs publication request polling and
approval. It does not own SSE transport. KERIA coordinates publication for
managed AIDs, but the Signify edge client remains the signer for registry
creation and designated-alias ACDC issuance.

.. automodule:: signify.app.didwebing
   :members:

signify.app.exchanging
----------------------

.. automodule:: signify.app.exchanging
   :members:

signify.app.ending
------------------

.. automodule:: signify.app.ending
    :members:

signify.app.escrowing
---------------------

.. automodule:: signify.app.escrowing
    :members:

signify.app.grouping
--------------------

.. automodule:: signify.app.grouping
    :members:

signify.app.schemas
-------------------

.. automodule:: signify.app.schemas
    :members:

signify.app.notifying
---------------------

.. automodule:: signify.app.notifying
    :members:
