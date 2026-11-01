"""Live compatibility coverage for the default Signify authentication mode."""

from __future__ import annotations

from urllib.parse import urlsplit

import pytest

from signify.app.clienting import SignifyAuth
from tests.integration.helpers import alias, create_identifier


pytestmark = pytest.mark.integration

SIGNED_HEADER_NAMES = {
    "signature",
    "signature-input",
    "signify-resource",
    "signify-timestamp",
}


def test_default_signed_header_transport_remains_compatible_with_keria(client_factory):
    """Prove an unchanged client still uses signed HTTP paths against KERIA.

    KERIA also supports ESSR-protected requests, which use ``POST /`` as a
    wrapper.  The default SignifyPy client must continue to send ordinary
    signed-header requests and verify KERIA's signed-header responses.
    """
    client = client_factory()

    assert isinstance(client.session.auth, SignifyAuth)

    responses = []
    response_hooks = client.session.hooks.get("response", [])
    if callable(response_hooks):
        response_hooks = [response_hooks]

    def capture_response(response, *args, **kwargs):
        responses.append(response)
        return response

    # Preserve the existing authentication hook ahead of the capture hook.
    # An invalid KERIA response signature therefore fails before capture.
    client.session.hooks["response"] = [*response_hooks, capture_response]

    listed = client.identifiers().list()
    name = alias("signed-header-compat")
    created = create_identifier(
        client,
        name,
        wits=[],
        add_end_role=False,
    )

    assert listed["aids"] == []
    assert created["name"] == name
    assert created["prefix"]

    get_response = next(
        response
        for response in responses
        if response.request.method == "GET"
        and urlsplit(response.request.url).path == "/identifiers"
    )
    post_response = next(
        response
        for response in responses
        if response.request.method == "POST"
        and urlsplit(response.request.url).path == "/identifiers"
    )

    for response in (get_response, post_response):
        request_header_names = {name.lower() for name in response.request.headers}
        response_header_names = {name.lower() for name in response.headers}

        assert SIGNED_HEADER_NAMES <= request_header_names
        assert SIGNED_HEADER_NAMES <= response_header_names
        assert "signify-receiver" not in request_header_names
        assert urlsplit(response.request.url).path != "/"

    assert post_response.request.body
    assert all(
        urlsplit(response.request.url).path != "/"
        for response in responses
        if "Signature" in response.request.headers
    )
