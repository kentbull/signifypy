"""Live SignifyPy proof for the bounded KERIA multisig-add spike."""

from __future__ import annotations

import base64
import os

import pytest
import requests
from requests import HTTPError

from keri import core, kering
from keri.app.keeping import Algos
from keri.core import eventing

from .constants import QVI_SCHEMA_SAID
from .helpers import (
    alias,
    create_identifier,
    create_multisig_registry,
    exchange_agent_oobis_among,
    get_states,
    issue_multisig_credential,
    poll_until,
    resolve_schema_oobi,
    wait_for_end_role,
    wait_for_multisig_credential_state_convergence,
    wait_for_multisig_registry_convergence,
    wait_for_multisig_request,
    wait_for_operation,
)


missing_spike = os.getenv("SIGNIFYPY_MULTISIG_ADD_SPIKE") != "1"
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        missing_spike,
        reason="requires the pinned multisig-add spike worktrees",
    ),
]


def _messagize(serder, sigs, *, seal=None):
    return bytes(
        eventing.messagize(
            serder=serder,
            sigers=[core.Siger(qb64=sig) for sig in sigs],
            seal=seal,
        )
    )


def _put_cesr(live_stack, destination, raw):
    response = requests.put(
        f"{live_stack['keria_agent_url'].rstrip('/')}/",
        data=bytes(raw),
        headers={
            "Content-Type": "application/octet-stream",
            "CESR-DESTINATION": destination,
        },
        timeout=30,
    )
    response.raise_for_status()
    assert response.status_code == 204


def _wait_state(client, pre, said):
    return poll_until(
        lambda: get_states(client, [pre])[0],
        ready=lambda state: state["d"] == said,
        timeout=60,
        interval=0.25,
        describe=f"key state {pre}:{said}",
        retry_exceptions=(HTTPError,),
    )


def _create_precommitted_group(
    client_a,
    member_a_name,
    client_b,
    member_b_name,
    member_c,
    group_name,
):
    member_a = client_a.identifiers().get(member_a_name)
    member_b = client_b.identifiers().get(member_b_name)
    smids = [member_a["prefix"], member_b["prefix"]]
    rmids = [*smids, member_c["prefix"]]

    states_a = get_states(client_a, smids)
    rstates_a = get_states(client_a, rmids)
    icp_a, sigs_a, operation_a = client_a.identifiers().create(
        group_name,
        algo=Algos.group,
        mhab=member_a,
        isith=2,
        nsith=3,
        toad=0,
        wits=[],
        states=states_a,
        rstates=rstates_a,
    )
    client_a.exchanges().send(
        member_a_name,
        "multisig",
        sender=member_a,
        route="/multisig/icp",
        payload={"gid": icp_a.pre, "smids": smids, "rmids": rmids},
        embeds={"icp": _messagize(icp_a, sigs_a)},
        recipients=[member_b["prefix"]],
    )

    _, request = wait_for_multisig_request(client_b, "/multisig/icp")
    proposal = request[0]["exn"]
    icp = proposal["e"]["icp"]
    states_b = get_states(client_b, proposal["a"]["smids"])
    rstates_b = get_states(client_b, proposal["a"]["rmids"])
    icp_b, sigs_b, operation_b = client_b.identifiers().create(
        group_name,
        algo=Algos.group,
        mhab=member_b,
        isith=icp["kt"],
        nsith=icp["nt"],
        toad=int(icp["bt"]),
        wits=icp["b"],
        states=states_b,
        rstates=rstates_b,
    )
    assert icp_b.raw == icp_a.raw
    client_b.exchanges().send(
        member_b_name,
        "multisig",
        sender=member_b,
        route="/multisig/icp",
        payload={"gid": icp_b.pre, "smids": smids, "rmids": rmids},
        embeds={"icp": _messagize(icp_b, sigs_b)},
        recipients=[member_a["prefix"]],
    )

    wait_for_operation(client_a, operation_a)
    wait_for_operation(client_b, operation_b)
    group_a = client_a.identifiers().get(group_name)
    group_b = client_b.identifiers().get(group_name)
    assert group_a["prefix"] == group_b["prefix"]
    return group_a, group_b, smids, rmids


def _publish_endpoint(
    client_a,
    member_a_name,
    client_b,
    member_b_name,
    group_name,
    live_stack,
):
    member_a = client_a.identifiers().get(member_a_name)
    member_b = client_b.identifiers().get(member_b_name)
    group_a = client_a.identifiers().get(group_name)
    stamp = group_a["state"]["dt"]

    rpy_a, sigs_a, operation_a = client_a.identifiers().addEndRole(
        group_name,
        role=kering.Roles.controller,
        eid=member_a["prefix"],
        stamp=stamp,
    )
    seal = eventing.SealEvent(
        i=group_a["prefix"],
        s=group_a["state"]["ee"]["s"],
        d=group_a["state"]["ee"]["d"],
    )
    client_a.exchanges().send(
        member_a_name,
        "multisig",
        sender=member_a,
        route="/multisig/rpy",
        payload={"gid": group_a["prefix"]},
        embeds={"rpy": _messagize(rpy_a, sigs_a, seal=seal)},
        recipients=[member_b["prefix"]],
    )

    wait_for_multisig_request(client_b, "/multisig/rpy")
    rpy_b, sigs_b, operation_b = client_b.identifiers().addEndRole(
        group_name,
        role=kering.Roles.controller,
        eid=member_a["prefix"],
        stamp=stamp,
    )
    assert rpy_b.raw == rpy_a.raw
    client_b.exchanges().send(
        member_b_name,
        "multisig",
        sender=member_b,
        route="/multisig/rpy",
        payload={"gid": group_a["prefix"]},
        embeds={"rpy": _messagize(rpy_b, sigs_b, seal=seal)},
        recipients=[member_a["prefix"]],
    )
    wait_for_operation(client_a, operation_a)
    wait_for_operation(client_b, operation_b)
    wait_for_end_role(
        client_a,
        group_name,
        eid=member_a["prefix"],
        role=kering.Roles.controller,
    )
    wait_for_end_role(
        client_b,
        group_name,
        eid=member_a["prefix"],
        role=kering.Roles.controller,
    )

    loc, loc_sigs, loc_operation = client_a.identifiers().addLocScheme(
        member_a_name,
        live_stack["keria_agent_url"],
        eid=member_a["prefix"],
        scheme=kering.Schemes.http,
        stamp=stamp,
    )
    wait_for_operation(client_a, loc_operation)
    member_seal = eventing.SealEvent(
        i=member_a["prefix"],
        s=member_a["state"]["ee"]["s"],
        d=member_a["state"]["ee"]["d"],
    )
    _put_cesr(
        live_stack,
        member_b["prefix"],
        _messagize(loc, loc_sigs, seal=member_seal),
    )
    poll_until(
        lambda: client_b.get(f"/locschemes/{member_a['prefix']}").json(),
        ready=lambda schemes: any(
            item["scheme"] == kering.Schemes.http for item in schemes
        ),
        timeout=60,
        interval=0.25,
        describe=f"member location {member_a['prefix']} on source B",
        retry_exceptions=(HTTPError,),
    )


def _rotate_member(client, name):
    serder, sigs, operation = client.identifiers().rotate(name, toad=0)
    wait_for_operation(client, operation)
    return client.identifiers().get(name), serder, sigs


def _prepare(client, group_name, body):
    response = client.post(
        f"/identifiers/{group_name}/multisig/add",
        json=body,
    )
    assert response.status_code == 202
    return response.json()


def _approval(client, group, prepared):
    raw = base64.urlsafe_b64decode(
        prepared["signable"] + ("=" * (-len(prepared["signable"]) % 4))
    )
    return client.manager.get(aid=group).sign(raw)[0]


def _deliver(client, target, prepared, approvals, live_stack):
    manifest = prepared["manifest"]
    payload = {
        "op": "deliver",
        "gid": manifest["gid"],
        "target": manifest["target"],
        "manifest": manifest["d"],
        "catalog": prepared["signable"],
        "approvals": approvals,
    }
    exn, sigs, atc = client.exchanges().createExchangeMessage(
        target,
        "/multisig/add",
        payload,
        {},
        recipient=target["prefix"],
    )
    assert atc == ""
    seal = eventing.SealEvent(
        i=target["prefix"],
        s=target["state"]["ee"]["s"],
        d=target["state"]["ee"]["d"],
    )
    _put_cesr(live_stack, target["prefix"], _messagize(exn, sigs, seal=seal))


def _wait_sync(client, operation, status):
    return poll_until(
        lambda: client.operations().get(operation),
        ready=lambda op: op.get("metadata", {}).get("status") == status,
        timeout=90,
        interval=0.25,
        describe=f"{operation} status {status}",
        retry_exceptions=(HTTPError,),
    )


def test_multisig_add_reaches_core_converged_with_signifypy(
    isolated_client_factory,
    isolated_live_stack,
):
    client_a = isolated_client_factory()
    client_b = isolated_client_factory()
    client_c = isolated_client_factory()
    client_h = isolated_client_factory()

    member_a_name = alias("member-a")
    member_b_name = alias("member-b")
    member_c_name = alias("member-c")
    holder_name = alias("holder")
    group_name = alias("group")
    registry_name = alias("registry")

    member_a = create_identifier(client_a, member_a_name, wits=[])
    member_b = create_identifier(client_b, member_b_name, wits=[])
    member_c = create_identifier(client_c, member_c_name, wits=[])
    holder = create_identifier(client_h, holder_name, wits=[])
    exchange_agent_oobis_among(
        [
            (client_a, member_a_name),
            (client_b, member_b_name),
            (client_c, member_c_name),
            (client_h, holder_name),
        ]
    )

    group_a, group_b, smids, rmids = _create_precommitted_group(
        client_a,
        member_a_name,
        client_b,
        member_b_name,
        member_c,
        group_name,
    )
    _publish_endpoint(
        client_a,
        member_a_name,
        client_b,
        member_b_name,
        group_name,
        isolated_live_stack,
    )
    resolve_schema_oobi(client_a, QVI_SCHEMA_SAID)
    resolve_schema_oobi(client_b, QVI_SCHEMA_SAID)

    registry_operation_a, _ = create_multisig_registry(
        client_a,
        local_member_name=member_a_name,
        group_name=group_name,
        other_member_prefixes=[member_b["prefix"]],
        registry_name=registry_name,
        is_initiator=True,
    )
    registry_operation_b, _ = create_multisig_registry(
        client_b,
        local_member_name=member_b_name,
        group_name=group_name,
        other_member_prefixes=[member_a["prefix"]],
        registry_name=registry_name,
    )
    wait_for_operation(client_a, registry_operation_a)
    wait_for_operation(client_b, registry_operation_b)
    registry_a, registry_b = wait_for_multisig_registry_convergence(
        client_a,
        client_b,
        group_name=group_name,
        registry_name=registry_name,
    )
    assert registry_a["regk"] == registry_b["regk"]

    issued_a = issue_multisig_credential(
        client_a,
        local_member_name=member_a_name,
        group_name=group_name,
        other_member_prefixes=[member_b["prefix"]],
        registry_name=registry_name,
        recipient=holder["prefix"],
        data={"LEI": "5493001KJTIIGC8Y1R17"},
        is_initiator=True,
    )
    issued_b = issue_multisig_credential(
        client_b,
        local_member_name=member_b_name,
        group_name=group_name,
        other_member_prefixes=[member_a["prefix"]],
        registry_name=registry_name,
        recipient=holder["prefix"],
        data={"LEI": "5493001KJTIIGC8Y1R17"},
    )
    creder_a, _, _, _, credential_operation_a, _ = issued_a
    creder_b, _, _, _, credential_operation_b, _ = issued_b
    assert creder_a.raw == creder_b.raw
    wait_for_operation(client_a, credential_operation_a)
    wait_for_operation(client_b, credential_operation_b)
    wait_for_multisig_credential_state_convergence(
        client_a,
        client_b,
        registry_said=registry_a["regk"],
        credential_said=creder_a.said,
        expected_et="iss",
    )
    assert client_c.keyStates().get(group_a["prefix"]) == []
    with pytest.raises(HTTPError):
        client_c.credentials().get(creder_a.said)

    member_a, rotation_a, sigs_a = _rotate_member(client_a, member_a_name)
    member_b, rotation_b, sigs_b = _rotate_member(client_b, member_b_name)
    member_c, rotation_c, sigs_c = _rotate_member(client_c, member_c_name)
    _put_cesr(
        isolated_live_stack,
        member_b["prefix"],
        _messagize(rotation_a, sigs_a),
    )
    _put_cesr(
        isolated_live_stack,
        member_a["prefix"],
        _messagize(rotation_b, sigs_b),
    )
    for destination in (member_a["prefix"], member_b["prefix"]):
        _put_cesr(
            isolated_live_stack,
            destination,
            _messagize(rotation_c, sigs_c),
        )
    _wait_state(client_a, member_b["prefix"], rotation_b.said)
    _wait_state(client_a, member_c["prefix"], rotation_c.said)
    _wait_state(client_b, member_a["prefix"], rotation_a.said)
    _wait_state(client_b, member_c["prefix"], rotation_c.said)

    states_a = get_states(client_a, rmids)
    states_b = get_states(client_b, rmids)
    group_state = client_a.identifiers().get(group_name)["state"]
    adding_rotation = eventing.rotate(
        pre=group_a["prefix"],
        keys=[state["k"][0] for state in states_a],
        dig=group_state["d"],
        sn=int(group_state["s"], 16) + 1,
        isith="3",
        ndigs=[state["n"][0] for state in states_a],
        nsith="3",
        toad=0,
        wits=[],
        cuts=[],
        adds=[],
    )
    body = {
        "rot": adding_rotation.ked,
        "target": member_c["prefix"],
        "smids": rmids,
        "rmids": rmids,
        "registry": registry_a["regk"],
        "credential": creder_a.said,
        "schema": QVI_SCHEMA_SAID,
        "endpoint": {
            "cid": group_a["prefix"],
            "role": kering.Roles.controller,
            "eid": member_a["prefix"],
        },
        "location": {
            "eid": member_a["prefix"],
            "scheme": kering.Schemes.http,
        },
    }
    prepared_a = _prepare(client_a, group_name, body)
    prepared_b = _prepare(client_b, group_name, body)
    assert prepared_a["signable"] == prepared_b["signable"]
    assert prepared_a["manifest"]["smids"] == rmids
    assert smids == rmids[:-1]

    approvals = [
        _approval(client_a, group_a, prepared_a),
        _approval(client_b, group_b, prepared_b),
    ]
    _deliver(
        client_c,
        member_c,
        prepared_a,
        approvals,
        isolated_live_stack,
    )
    _wait_sync(client_c, prepared_a["operation"], "state-verified")

    keeper_a = client_a.manager.get(aid=group_a)
    keeper_b = client_b.manager.get(aid=group_b)
    keeper_a.mhab = member_a
    keeper_b.mhab = member_b
    keeper_a.rotate(states=states_a, rstates=states_a)
    keeper_b.rotate(states=states_b, rstates=states_b)
    group_sigs = [
        keeper_a.sign(adding_rotation.raw, rotated=True)[0],
        keeper_b.sign(adding_rotation.raw, rotated=True)[0],
        client_c.manager.get(aid=member_c).sign(
            adding_rotation.raw,
            indexed=True,
            indices=[2],
            ondices=[2],
        )[0],
    ]
    _put_cesr(
        isolated_live_stack,
        member_c["prefix"],
        _messagize(adding_rotation, group_sigs),
    )
    operation = _wait_sync(
        client_c,
        prepared_a["operation"],
        "core-converged",
    )
    assert operation["done"] is False

    group_state_c = get_states(client_c, [group_a["prefix"]])[0]
    credential_c = client_c.credentials().get(creder_a.said)
    credential_state_c = client_c.credentials().state(
        registry_a["regk"],
        creder_a.said,
    )
    schema_c = client_c.schemas().get(QVI_SCHEMA_SAID)
    end_roles_c = client_c.endroles().list(
        aid=group_a["prefix"],
        role=kering.Roles.controller,
    )
    locations_c = client_c.get(f"/locschemes/{member_a['prefix']}").json()

    assert group_state_c["d"] == adding_rotation.said
    assert credential_c["sad"]["d"] == creder_a.said
    assert credential_state_c["et"] == "iss"
    assert schema_c["$id"] == QVI_SCHEMA_SAID
    assert any(role["eid"] == member_a["prefix"] for role in end_roles_c)
    assert any(item["scheme"] == kering.Schemes.http for item in locations_c)
