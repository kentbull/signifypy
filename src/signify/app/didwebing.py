# -*- encoding: utf-8 -*-
"""Thin did:webs setup and readiness helpers for SignifyPy."""


class DidWebs:
    """Client helper for KERIA did:webs setup descriptors."""

    def __init__(self, client):
        """Create a did:webs resource wrapper bound to one Signify client."""
        self.client = client

    def setup(self, name):
        """Return KERIA setup state and edge-call arguments for one identifier."""
        res = self.client.get(f"/identifiers/{name}/dws/setup")
        return res.json()

    def readiness(self, name):
        """Return compact KERIA did:webs readiness for one identifier."""
        return self.client.identifiers().dws(name)
