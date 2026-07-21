"""Regression coverage for presenting untargeted ACDCs through IPEX."""

from __future__ import annotations

import pytest

from .constants import TEST_WITNESS_AIDS, UNTARGETED_ATTESTATION_SCHEMA_SAID
from .helpers import (
    alias,
    create_identifier,
    create_registry,
    resolve_agent_oobi,
    resolve_schema_oobi,
    send_credential_grant,
    submit_admit,
    wait_for_credential,
    wait_for_notification,
    wait_for_operation,
)


pytestmark = pytest.mark.integration


def test_untargeted_acdc_grant_delivers_artifacts_to_disclosee(client_factory):
    """Present an ACDC without an issuee to an independently addressed disclosee.

    The disclosee intentionally does not resolve the issuer's OOBI first.  An
    IPEX Grant is responsible for delivering the issuer KEL and the credential
    artifacts needed to validate the embedded untargeted attestation.
    """
    issuer_client = client_factory()
    disclosee_client = client_factory()
    issuer_name = alias("untargeted-issuer")
    disclosee_name = alias("untargeted-disclosee")
    registry_name = alias("untargeted-registry")

    issuer = create_identifier(issuer_client, issuer_name, wits=TEST_WITNESS_AIDS)
    disclosee = create_identifier(disclosee_client, disclosee_name, wits=TEST_WITNESS_AIDS)

    # The issuer must know where to send the Grant.  Do not resolve the reverse
    # direction: successful presentation must bootstrap the disclosee with the
    # issuer artifacts carried by the Grant workflow.
    resolve_agent_oobi(disclosee_client, disclosee_name, issuer_client)
    resolve_schema_oobi(issuer_client, UNTARGETED_ATTESTATION_SCHEMA_SAID)
    resolve_schema_oobi(disclosee_client, UNTARGETED_ATTESTATION_SCHEMA_SAID)

    create_registry(issuer_client, issuer_name, registry_name)
    issued = issuer_client.credentials().issue(
        issuer_name,
        registry_name,
        data={"claim": "An issuer-authored observation addressed to whom it may concern."},
        schema=UNTARGETED_ATTESTATION_SCHEMA_SAID,
        recipient=None,
        edges={},
        rules={},
    )
    wait_for_operation(issuer_client, issued.op())

    assert issued.acdc.sad["i"] == issuer["prefix"]
    assert "i" not in issued.acdc.sad["a"]

    send_credential_grant(
        issuer_client,
        issuer_name=issuer_name,
        recipient=disclosee["prefix"],
        creder=issued.acdc,
        iserder=issued.iss,
        anc=issued.anc,
        sigs=issued.sigs,
    )

    grant_note = wait_for_notification(
        disclosee_client,
        "/exn/ipex/grant",
        timeout=30.0,
    )
    submit_admit(
        disclosee_client,
        holder_name=disclosee_name,
        issuer_prefix=issuer["prefix"],
        notification=grant_note,
    )
    received = wait_for_credential(disclosee_client, issued.acdc.said)

    assert received["sad"]["d"] == issued.acdc.said
    assert received["sad"]["i"] == issuer["prefix"]
    assert "i" not in received["sad"]["a"]
