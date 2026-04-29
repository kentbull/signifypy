# -*- encoding: utf-8 -*-
"""Generic KERIA agent signaling helpers.

KERIA's ``/signals/stream`` endpoint is a transport for transient, agent-scoped
events. Topic modules such as did:webs use that transport, but they do not own
it. Keep this module route-agnostic so later workflows can reuse the same SSE
channel and KERI ``rpy`` envelope verification without importing did:webs code.

The stream is intentionally not durable. A consumer that misses an SSE event
must recover through the topic's polling endpoint. For did:webs publication,
that fallback is ``/didwebs/signing/requests``.
"""

from keri import kering
from keri.core import indexing, serdering


class AgentSignals:
    """Generic signed event stream for one connected KERIA agent.

    ``AgentSignals`` owns only the transport and envelope-authentication
    contract:

    * ``stream`` opens KERIA's authenticated ``/signals/stream`` SSE endpoint.
    * ``verifyReplyEnvelope`` verifies that a received KERI ``rpy`` envelope was
      signed by the connected KERIA agent AID.

    Topic-specific code is responsible for interpreting event names, routes,
    and payloads after this generic verification step.
    """

    def __init__(self, client):
        self.client = client

    def stream(self):
        """Open the authenticated generic agent SSE stream.

        Native browser ``EventSource`` cannot attach the Signify authentication
        headers required by KERIA admin routes. Signify clients therefore use an
        authenticated HTTP stream and parse SSE frames themselves.
        """
        return self.client.stream(
            "/signals/stream",
            headers={"Accept": "text/event-stream"},
        )

    def verifyReplyEnvelope(self, envelope, route=None):
        """Verify one KERIA agent-signed KERI ``rpy`` envelope.

        Parameters:
            envelope (dict): A mapping with ``rpy`` and ``sigs`` keys as emitted
                by KERIA's signaling layer.
            route (str | None): Optional expected KERI reply route. Topic
                modules pass their own route, for example
                ``/didwebs/signing/request``.

        Returns:
            bool: ``True`` only when the envelope route matches, the payload
            names the connected KERIA agent, and the first signature verifies
            against the connected agent's current verifier.
        """
        if self.client.agent is None:
            raise kering.ConfigurationError("client must be connected before verification")

        rserder = serdering.SerderKERI(sad=envelope["rpy"])
        if route is not None and rserder.ked.get("r") != route:
            return False
        data = rserder.ked.get("a", {})
        if data.get("agent") != self.client.agent.pre:
            return False

        sigs = envelope.get("sigs") or []
        if not sigs:
            return False

        siger = indexing.Siger(qb64=sigs[0])
        return self.client.agent.verfer.verify(sig=siger.raw, ser=rserder.raw)
