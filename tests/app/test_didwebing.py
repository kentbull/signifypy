# -*- encoding: utf-8 -*-
"""SIGNIFY did:webs setup helper tests."""

import signify.app.didwebing as didwebing
from mockito import expect, mock, verifyNoUnwantedInteractions, unstub

from signify.app.didwebing import DidWebs


def test_didwebs_setup_fetches_setup_descriptor(make_mock_response):
    client = mock(strict=True)
    response = make_mock_response({"json": lambda: {"ready": False}})
    expect(client, times=1).get("/identifiers/aid1/dws/setup").thenReturn(response)

    result = DidWebs(client).setup("aid1")

    assert result == {"ready": False}
    verifyNoUnwantedInteractions()
    unstub()


def test_didwebs_readiness_delegates_to_identifiers():
    identifiers = mock(strict=True)
    client = mock(strict=True)
    payload = {
        "dws": "did:webs:example:dws:Eaid",
        "didJsonUrl": "https://example/dws/Eaid/did.json",
        "keriCesrUrl": "https://example/dws/Eaid/keri.cesr",
    }
    expect(client, times=1).identifiers().thenReturn(identifiers)
    expect(identifiers, times=1).dws("aid1").thenReturn(payload)

    result = DidWebs(client).readiness("aid1")

    assert result == payload
    verifyNoUnwantedInteractions()
    unstub()


def test_didwebing_does_not_export_old_request_approval_api():
    removed = [
        "DWS_" + "SIGN_ROUTE",
        "DWS_ACT_CRT_REG",
        "DWS_ACT_ISS_DA",
        "DidWebsAuto" + "Approver",
        "DidWebsDe" + "dupeRecord",
        "MemoryDidWebsDe" + "dupeStore",
        "LmdbDidWebsDe" + "dupeStore",
    ]

    assert all(not hasattr(didwebing, name) for name in removed)
    assert not hasattr(DidWebs, "requests")
    assert not hasattr(DidWebs, "request")
    assert not hasattr(DidWebs, "approve")
