"""Live multisig join and expansion coverage beyond the 2-of-2 happy path."""

from __future__ import annotations

import time

import pytest
from keri.core import eventing, serdering
from keri.core import signing as csigning

from .constants import TEST_WITNESS_AIDS
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
    query_key_state,
    resolve_oobi,
    rotate_identifier,
    wait_for_multisig_registry_convergence,
    wait_for_notification,
    wait_for_operation,
    rotate_multisig_group_n,
    wait_for_contact_alias,
)


pytestmark = pytest.mark.integration


def _messagize(serder, sigs):
    """Encode a serder plus signatures into the attachment form peers expect."""
    sigers = [csigning.Siger(qb64=sig) for sig in sigs]
    return eventing.messagize(serder=serder, sigers=sigers)


def _wait_for_registry_listing(client, group_name: str, *, regk: str, timeout: float = 20.0) -> list[dict]:
    """Poll registry listing until the expected registry becomes visible."""
    deadline = time.time() + timeout
    last_registries = None
    while time.time() < deadline:
        registries = client.registries().list(group_name)
        last_registries = registries
        if any(registry.get("regk") == regk for registry in registries):
            return registries
        time.sleep(0.5)

    raise TimeoutError(
        f"timed out waiting for registry {regk} in {group_name}; "
        f"last_registries={last_registries!r}"
    )


def _wait_for_group_sequence(
    client,
    group_name: str,
    *,
    sn: str,
    timeout: float = 20.0,
) -> dict:
    """Poll a group habitat until it reaches the expected sequence number."""
    deadline = time.time() + timeout
    last_group = None
    while time.time() < deadline:
        group = client.identifiers().get(group_name)
        last_group = group
        if group["state"]["s"] == sn:
            return group
        time.sleep(0.5)

    raise TimeoutError(
        f"timed out waiting for group sequence {sn} on {group_name}; "
        f"last_group={last_group!r}"
    )


def test_multisig_join_lifecycle_4_of_4(client_factory):
    # This replaces the old create/join quartet scripts with one isolated live
    # scenario: create four member AIDs, exchange the exact agent OOBIs they
    # need to coordinate, incept one 4-of-4 group, publish the group agent
    # OOBI, and then rotate the whole group after every member rotates.
    clients = [client_factory() for _ in range(5)]
    member_clients = clients[:4]
    observer = clients[4]
    member_names = [alias(f"member-{index + 1}") for index in range(4)]
    group_name = alias("quadlet")
    participants = list(zip(member_clients, member_names))

    member_habs = [
        create_identifier(client, member_name, wits=TEST_WITNESS_AIDS)
        for client, member_name in participants
    ]
    exchange_agent_oobis_among(participants)
    groups = create_multisig_group_n(
        participants,
        group_name,
        wits=TEST_WITNESS_AIDS,
    )

    expected_prefixes = [member["prefix"] for member in member_habs]
    members = assert_multisig_members(
        member_clients[0],
        group_name,
        count=4,
        signing_aids=expected_prefixes,
        rotation_aids=expected_prefixes,
    )
    assert len({group["prefix"] for group in groups}) == 1
    assert all(group["name"] == group_name for group in groups)
    assert all(group["state"]["b"] == TEST_WITNESS_AIDS for group in groups)
    assert len(members["signing"]) == 4

    group_oobi = expose_multisig_agent_oobi_n(participants, group_name)
    resolve_oobi(observer, group_oobi, alias=group_name)
    contact = wait_for_contact_alias(observer, group_name)

    created_digest = groups[0]["state"]["d"]
    rotated_groups = rotate_multisig_group_n(participants, group_name)

    assert contact["alias"] == group_name
    assert contact["id"] == groups[0]["prefix"]
    assert int(rotated_groups[0]["state"]["s"], 16) == 1
    assert len({group["state"]["s"] for group in rotated_groups}) == 1
    assert len({group["state"]["d"] for group in rotated_groups}) == 1
    assert rotated_groups[0]["state"]["d"] != created_digest


@pytest.mark.xfail(
    strict=True,
    reason="KERIA does not yet hydrate preexisting multisig registries for late-joined members",
)
def test_multisig_late_join_member_sees_preexisting_registry(client_factory):
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
    assert "/agent/" in group_agent_oobi
    group_oobi = group_agent_oobi.split("/agent/")[0]

    operation_a, _ = create_multisig_registry(
        client1,
        local_member_name=name_member1,
        group_name=group_name,
        other_member_prefixes=[member2["prefix"]],
        registry_name=registry_name,
        is_initiator=True,
    )
    operation_b, _ = create_multisig_registry(
        client2,
        local_member_name=name_member2,
        group_name=group_name,
        other_member_prefixes=[member1["prefix"]],
        registry_name=registry_name,
    )
    wait_for_operation(client1, operation_a)
    wait_for_operation(client2, operation_b)
    registry1, registry2 = wait_for_multisig_registry_convergence(
        client1,
        client2,
        group_name=group_name,
        registry_name=registry_name,
    )
    regk = registry1["regk"]
    assert registry2["regk"] == regk

    registries1 = _wait_for_registry_listing(client1, group_name, regk=regk)
    registries2 = _wait_for_registry_listing(client2, group_name, regk=regk)
    assert len(registries1) == 1
    assert len(registries2) == 1
    assert registries1[0]["name"] == registry_name
    assert registries2[0]["name"] == registry_name
    assert registries1[0]["regk"] == regk
    assert registries2[0]["regk"] == regk

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
    multisig3 = _wait_for_group_sequence(
        client3,
        group_name,
        sn="3",
    )
    assert multisig3["prefix"] == groups[0]["prefix"]
    assert len(multisig3["state"]["k"]) == 3
    assert len(multisig3["state"]["n"]) == 3
    assert multisig3["state"]["k"] == [
        member1["state"]["k"][0],
        member2["state"]["k"][0],
        member3["state"]["k"][0],
    ]
    assert multisig3["state"]["n"] == [
        member1["state"]["n"][0],
        member2["state"]["n"][0],
        member3["state"]["n"][0],
    ]
    end_roles3 = get_end_roles(client3, group_name, role="agent")
    visible_eids = {end_role.get("eid") for end_role in end_roles3 if end_role.get("eid")}
    assert group_agent_eids <= visible_eids

    registries1 = _wait_for_registry_listing(client1, group_name, regk=regk)
    registries2 = _wait_for_registry_listing(client2, group_name, regk=regk)
    # Expected xfail boundary: member C has enough KEL/group state to join, but
    # the preexisting registry still is not hydrated into C's local registry list.
    registries3 = _wait_for_registry_listing(client3, group_name, regk=regk)
    assert len(registries1) == 1
    assert len(registries2) == 1
    assert len(registries3) == 1
    assert registries3[0]["name"] == registry_name
