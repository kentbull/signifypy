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

signify.app.didwebing
---------------------

``signify.app.didwebing`` exposes only the thin KERIA did:webs setup and
readiness reads. Registry creation, designated-alias issuance, and other
did:webs setup orchestration live in the ``signifypy-did-webs`` package from
``w3c-crosswalk``. Live KERIA notification transport is exposed separately
through ``client.signals()``.

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
