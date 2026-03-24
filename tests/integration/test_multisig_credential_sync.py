"""Live integration coverage for targeted multisig credential-history sync."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from keri.core import eventing, serdering
from keri.core import signing as csigning
from keri.help import helping
from requests import HTTPError

from .constants import SCHEMA_OOBI, TEST_WITNESS_AIDS
from .helpers import (
    accept_multisig_rotation,
    alias,
    assert_multisig_members,
    create_identifier,
    create_multisig_group_n,
    create_multisig_registry,
    exchange_agent_oobis,
    exchange_agent_oobis_among,
    expected_multisig_agent_eids,
    expose_multisig_agent_oobi_n,
    get_end_roles,
    issue_multisig_credential,
    query_key_state,
    resolve_oobi,
    revoke_multisig_credential,
    wait_for_contact_alias,
    wait_for_issued_credential,
    wait_for_multisig_credential_state_convergence,
    wait_for_multisig_registry_convergence,
    wait_for_multisig_request,
    wait_for_notification,
    wait_for_operation,
    rotate_identifier,
)
from .test_multisig_join import _wait_for_group_sequence, _wait_for_registry_listing


pytestmark = pytest.mark.integration


def _messagize(serder, sigs):
    """Encode a serder plus signatures into the attachment form peers expect."""
    sigers = [csigning.Siger(qb64=sig) for sig in sigs]
    return eventing.messagize(serder=serder, sigers=sigers)


def _late_join_group_with_preexisting_registry(client_factory):
    client1 = client_factory()
    client2 = client_factory()
    client3 = client_factory()
    name_member1 = alias("member-1")
    name_member2 = alias("member-2")
    name_member3 = alias("member-3")
    group_name = alias("joinable-group")
    registry_name = alias("registry")

    member1 = create_identifier(client1, name_member1, wits=TEST_WITNESS_AIDS)
    member2 = create_identifier(client2, name_member2, wits=TEST_WITNESS_AIDS)
    participants_ab = [(client1, name_member1), (client2, name_member2)]
    exchange_agent_oobis_among(participants_ab)
    groups = create_multisig_group_n(participants_ab, group_name, wits=TEST_WITNESS_AIDS)
    group_agent_eids = expected_multisig_agent_eids(client1, group_name)
    group_agent_oobi = expose_multisig_agent_oobi_n(participants_ab, group_name)
    group_oobi = group_agent_oobi.split("/agent/")[0]

    registry_op1, _ = create_multisig_registry(
        client1,
        local_member_name=name_member1,
        group_name=group_name,
        other_member_prefixes=[member2["prefix"]],
        registry_name=registry_name,
        is_initiator=True,
    )
    registry_op2, _ = create_multisig_registry(
        client2,
        local_member_name=name_member2,
        group_name=group_name,
        other_member_prefixes=[member1["prefix"]],
        registry_name=registry_name,
    )
    wait_for_operation(client1, registry_op1)
    wait_for_operation(client2, registry_op2)
    registry1, registry2 = wait_for_multisig_registry_convergence(
        client1,
        client2,
        group_name=group_name,
        registry_name=registry_name,
    )
    regk = registry1["regk"]
    assert registry2["regk"] == regk
    _wait_for_registry_listing(client1, group_name, regk=regk)
    _wait_for_registry_listing(client2, group_name, regk=regk)

    resolve_oobi(client1, SCHEMA_OOBI, alias="schema")
    resolve_oobi(client2, SCHEMA_OOBI, alias="schema")

    issue_timestamp = helping.nowIso8601()
    creder1, _, _, _, issue_operation1, _ = issue_multisig_credential(
        client1,
        local_member_name=name_member1,
        group_name=group_name,
        other_member_prefixes=[member2["prefix"]],
        registry_name=registry_name,
        recipient=member2["prefix"],
        data={"LEI": "5493001KJTIIGC8Y1R17"},
        timestamp=issue_timestamp,
        is_initiator=True,
    )
    _, issue_request2 = wait_for_multisig_request(client2, "/multisig/iss")
    creder2, _, _, _, issue_operation2, issue_request2 = issue_multisig_credential(
        client2,
        local_member_name=name_member2,
        group_name=group_name,
        other_member_prefixes=[member1["prefix"]],
        registry_name=registry_name,
        recipient=member2["prefix"],
        data={"LEI": "5493001KJTIIGC8Y1R17"},
        timestamp=issue_timestamp,
        request=issue_request2,
    )
    wait_for_operation(client1, issue_operation1)
    wait_for_operation(client2, issue_operation2)
    wait_for_issued_credential(client1, groups[0]["prefix"], creder1.said)
    wait_for_issued_credential(client2, groups[0]["prefix"], creder1.said)
    assert creder1.said == creder2.said

    member3 = create_identifier(client3, name_member3, wits=TEST_WITNESS_AIDS)
    exchange_agent_oobis(client1, name_member1, client3, name_member3)
    exchange_agent_oobis(client2, name_member2, client3, name_member3)
    resolve_oobi(client3, group_oobi, alias=group_name)
    contact = wait_for_contact_alias(client3, group_name)
    assert contact["alias"] == group_name
    assert contact["id"] == groups[0]["prefix"]

    member1 = rotate_identifier(client1, name_member1)
    member2 = rotate_identifier(client2, name_member2)
    member2_state_for_member1 = query_key_state(client1, member2["prefix"], sn=member2["state"]["s"])
    member3_state_for_member1 = query_key_state(client1, member3["prefix"], sn=member3["state"]["s"])
    member1_state_for_member2 = query_key_state(client2, member1["prefix"], sn=member1["state"]["s"])
    member3_state_for_member2 = query_key_state(client2, member3["prefix"], sn=member3["state"]["s"])
    query_key_state(client3, member1["prefix"], sn=member1["state"]["s"])
    query_key_state(client3, member2["prefix"], sn=member2["state"]["s"])
    first_states = [member1["state"], member2_state_for_member1]
    first_rstates = [member1["state"], member2_state_for_member1, member3_state_for_member1]
    rot1, sigs1, _ = client1.identifiers().rotate(
        group_name,
        states=first_states,
        rstates=first_rstates,
    )
    client1.exchanges().send(
        name_member1,
        group_name,
        sender=member1,
        route="/multisig/rot",
        payload=dict(
            gid=rot1.pre,
            smids=[state["i"] for state in first_states],
            rmids=[state["i"] for state in first_rstates],
        ),
        embeds=dict(rot=_messagize(rot1, sigs1)),
        recipients=[member2["prefix"], member3["prefix"]],
    )
    first_accept_operation = accept_multisig_rotation(
        client2,
        member_name=name_member2,
        group_name=group_name,
        participant_states={
            member1["prefix"]: member1_state_for_member2,
            member2["prefix"]: member2["state"],
            member3["prefix"]: member3_state_for_member2,
        },
    )
    wait_for_notification(client3, "/multisig/rot")
    wait_for_operation(client2, first_accept_operation)
    query_key_state(client3, groups[0]["prefix"], sn="2")

    member1 = rotate_identifier(client1, name_member1)
    member2 = rotate_identifier(client2, name_member2)
    member3 = rotate_identifier(client3, name_member3)
    member2_state_for_member1 = query_key_state(client1, member2["prefix"], sn=member2["state"]["s"])
    member3_state_for_member1 = query_key_state(client1, member3["prefix"], sn=member3["state"]["s"])
    member1_state_for_member2 = query_key_state(client2, member1["prefix"], sn=member1["state"]["s"])
    member3_state_for_member2 = query_key_state(client2, member3["prefix"], sn=member3["state"]["s"])
    query_key_state(client3, member1["prefix"], sn=member1["state"]["s"])
    query_key_state(client3, member2["prefix"], sn=member2["state"]["s"])
    second_states = [member1["state"], member2_state_for_member1, member3_state_for_member1]
    rot2, sigs2, _ = client1.identifiers().rotate(
        group_name,
        states=second_states,
        rstates=second_states,
    )
    client1.exchanges().send(
        name_member1,
        "multisig",
        sender=member1,
        route="/multisig/rot",
        payload=dict(
            gid=rot2.pre,
            smids=[state["i"] for state in second_states],
            rmids=[state["i"] for state in second_states],
        ),
        embeds=dict(rot=_messagize(rot2, sigs2)),
        recipients=[member2["prefix"], member3["prefix"]],
    )

    second_accept_operation = accept_multisig_rotation(
        client2,
        member_name=name_member2,
        group_name=group_name,
        participant_states={
            member1["prefix"]: member1_state_for_member2,
            member2["prefix"]: member2["state"],
            member3["prefix"]: member3_state_for_member2,
        },
    )
    join_note = wait_for_notification(client3, "/multisig/rot")
    join_request = client3.groups().get_request(join_note["a"]["d"])
    join_exn = join_request[0]["exn"]
    join_rot = serdering.SerderKERI(sad=join_exn["e"]["rot"])
    query_key_state(client3, groups[0]["prefix"], sn=join_rot.ked["s"])
    join_keeper = client3.manager.get(
        aid={
            "prefix": join_exn["a"]["gid"],
            "group": {
                "mhab": member3,
                "keys": join_rot.ked["k"],
                "ndigs": join_rot.ked["n"],
            },
        }
    )
    join_sigs = join_keeper.sign(ser=join_rot.raw)
    join_operation = client3.groups().join(
        name=group_name,
        rot=join_rot,
        sigs=join_sigs,
        gid=join_exn["a"]["gid"],
        smids=join_exn["a"]["smids"],
        rmids=join_exn["a"]["rmids"],
    )
    wait_for_operation(client2, second_accept_operation)
    wait_for_operation(client3, join_operation)

    assert_multisig_members(
        client3,
        group_name,
        count=3,
        signing_aids=[member1["prefix"], member2["prefix"], member3["prefix"]],
        rotation_aids=[member1["prefix"], member2["prefix"], member3["prefix"]],
    )
    multisig3 = _wait_for_group_sequence(client3, group_name, sn=join_rot.ked["s"])
    assert multisig3["prefix"] == groups[0]["prefix"]
    end_roles3 = get_end_roles(client3, group_name, role="agent")
    visible_eids = {end_role.get("eid") for end_role in end_roles3 if end_role.get("eid")}
    assert group_agent_eids <= visible_eids
    assert client3.registries().list(group_name) == []

    return SimpleNamespace(
        client1=client1,
        client2=client2,
        client3=client3,
        name_member1=name_member1,
        name_member2=name_member2,
        name_member3=name_member3,
        group_name=group_name,
        registry_name=registry_name,
        member1=member1,
        member2=member2,
        member3=member3,
        group_prefix=groups[0]["prefix"],
        group_sn=join_rot.ked["s"],
        regk=regk,
        prejoin_credential_said=creder1.said,
    )


def test_multisig_late_join_member_syncs_preexisting_credential_for_revocation(client_factory):
    scenario = _late_join_group_with_preexisting_registry(client_factory)

    regsync_operation = scenario.client3.registries().sync(
        scenario.group_name,
        source=scenario.member1["prefix"],
    )
    wait_for_operation(scenario.client3, regsync_operation)
    registries3 = _wait_for_registry_listing(
        scenario.client3,
        scenario.group_name,
        regk=scenario.regk,
    )
    assert len(registries3) == 1
    assert registries3[0]["regk"] == scenario.regk

    revoke_timestamp = helping.nowIso8601()
    revoke_serder1, revoke_anc1, _, revoke_operation1, _ = revoke_multisig_credential(
        scenario.client1,
        local_member_name=scenario.name_member1,
        group_name=scenario.group_name,
        other_member_prefixes=[scenario.member3["prefix"]],
        credential_said=scenario.prejoin_credential_said,
        timestamp=revoke_timestamp,
        is_initiator=True,
    )
    _, revoke_request3 = wait_for_multisig_request(scenario.client3, "/multisig/rev")
    assert revoke_request3[0]["exn"]["e"]["rev"]["dt"] == revoke_timestamp

    with pytest.raises(HTTPError) as err:
        scenario.client3.delete(
            f"/identifiers/{scenario.group_name}/credentials/{scenario.prejoin_credential_said}",
            body=dict(rev=revoke_request3[0]["exn"]["e"]["rev"]),
        )
    assert err.value.response.status_code == 409
    assert "credentials().sync" in err.value.response.json()["description"]

    credsync_operation = scenario.client3.credentials().sync(
        scenario.group_name,
        [scenario.prejoin_credential_said],
        source=scenario.member1["prefix"],
    )
    credsync_result = wait_for_operation(scenario.client3, credsync_operation)
    assert "response" in credsync_result, credsync_result
    assert credsync_result["response"] == {
        "pre": scenario.group_prefix,
        "source": scenario.member1["prefix"],
        "synced": [scenario.prejoin_credential_said],
    }

    imported = scenario.client3.credentials().get(scenario.prejoin_credential_said)
    assert imported["sad"]["d"] == scenario.prejoin_credential_said

    revoke_serder3, revoke_anc3, _, revoke_operation3, revoke_request3 = revoke_multisig_credential(
        scenario.client3,
        local_member_name=scenario.name_member3,
        group_name=scenario.group_name,
        other_member_prefixes=[scenario.member1["prefix"]],
        credential_said=scenario.prejoin_credential_said,
        timestamp=revoke_timestamp,
        request=revoke_request3,
    )
    wait_for_operation(scenario.client1, revoke_operation1)
    wait_for_operation(scenario.client3, revoke_operation3)
    revoke_state1, revoke_state3 = wait_for_multisig_credential_state_convergence(
        scenario.client1,
        scenario.client3,
        registry_said=scenario.regk,
        credential_said=scenario.prejoin_credential_said,
        expected_et="rev",
    )

    assert revoke_serder1.ked["dt"] == revoke_timestamp
    assert revoke_request3[0]["exn"]["e"]["rev"] == revoke_serder1.ked
    assert revoke_request3[0]["exn"]["e"]["anc"] == revoke_anc1.ked
    assert revoke_serder3.ked["dt"] == revoke_timestamp
    assert revoke_serder3.ked == revoke_serder1.ked
    assert revoke_anc3.ked == revoke_anc1.ked
    assert revoke_state1["et"] == "rev"
    assert revoke_state3["et"] == "rev"
