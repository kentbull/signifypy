# -*- encoding: utf-8 -*-
"""Minimal SignifyPy proof for the experimental multisig-add core."""

import base64
import importlib.util

import pytest
import requests
import responses

from keri import core
from keri.app.keeping import Algos
from keri.core import coring, eventing

from signify.app.clienting import SignifyClient
from signify.core import keeping


if importlib.util.find_spec("keri.syncing") is not None:
    from keri import syncing
else:
    syncing = None

pytestmark = pytest.mark.skipif(
    syncing is None,
    reason="requires the experimental KERIpy multisig-add spike",
)


FIXED_DT = "2026-07-22T12:00:00.000000+00:00"


def _encode(raw):
    return base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode("utf-8")


def _decode(text):
    return base64.urlsafe_b64decode(text + ("=" * (-len(text) % 4)))


def _messagize(serder, sigs):
    return bytes(eventing.messagize(
        serder=serder,
        sigers=[core.Siger(qb64=sig) for sig in sigs],
        pipelined=True,
    ))


def _member(manager, *, name, pidx, bran):
    keeper = manager.new(Algos.salty, pidx=pidx, bran=bran)
    keys, ndigs = keeper.incept(transferable=True)
    icp = eventing.incept(
        keys=keys,
        isith="1",
        ndigs=ndigs,
        nsith="1",
        toad="0",
        wits=[],
        cnfg=[],
        data=[],
    )
    old_hab = {
        "name": name,
        "prefix": icp.pre,
        "state": {**icp.ked, "ee": {"s": icp.ked["s"], "d": icp.said}},
        "salty": keeper.params(),
    }
    icp_msg = _messagize(icp, keeper.sign(icp.raw))

    keys, ndigs = keeper.rotate(
        ncodes=keeper.ncodes,
        transferable=True,
    )
    rot = eventing.rotate(
        pre=icp.pre,
        keys=keys,
        dig=icp.said,
        sn=1,
        isith="1",
        ndigs=ndigs,
        nsith="1",
        toad="0",
        wits=[],
        cuts=[],
        adds=[],
    )
    rot_sigs = keeper.sign(
        rot.raw,
        indexed=True,
        indices=[0],
        ondices=[0],
    )
    current_hab = {
        "name": name,
        "prefix": icp.pre,
        "state": {**rot.ked, "ee": {"s": rot.ked["s"], "d": rot.said}},
        "salty": keeper.params(),
    }
    return {
        "old_hab": old_hab,
        "current_hab": current_hab,
        "icp": icp,
        "icp_msg": icp_msg,
        "rot": rot,
        "rot_msg": _messagize(rot, rot_sigs),
    }


def _prepared_catalog(client):
    members = [
        _member(
            client.manager,
            name=name,
            pidx=pidx,
            bran=bran,
        )
        for name, pidx, bran in (
            ("a", 0, "0123456789abcdefghijk"),
            ("b", 1, "123456789abcdefghijkl"),
            ("target", 2, "23456789abcdefghijklm"),
        )
    ]
    a, b, target = members

    adding_keys = [member["rot"].verfers[0].qb64 for member in members]
    group_ndigs = [
        coring.Diger(ser=coring.Verfer(qb64=key).qb64b).qb64
        for key in adding_keys
    ]
    group_icp = eventing.incept(
        keys=[a["icp"].verfers[0].qb64, b["icp"].verfers[0].qb64],
        isith="2",
        ndigs=group_ndigs,
        nsith="3",
        toad="0",
        wits=[],
        cnfg=[],
        data=[],
    )
    group_sigs = [
        client.manager.get(a["old_hab"]).sign(
            group_icp.raw, indexed=True, indices=[0], ondices=[None]
        )[0],
        client.manager.get(b["old_hab"]).sign(
            group_icp.raw, indexed=True, indices=[1], ondices=[None]
        )[0],
    ]
    group_msg = _messagize(group_icp, group_sigs)

    adding_rotation = eventing.rotate(
        pre=group_icp.pre,
        keys=adding_keys,
        dig=group_icp.said,
        sn=1,
        isith="3",
        ndigs=[member["rot"].ndigers[0].qb64 for member in members],
        nsith="3",
        toad="0",
        wits=[],
        cuts=[],
        adds=[],
    )
    frames = [
        *(syncing.Frame.from_raw("kel", member["icp_msg"]) for member in members),
        syncing.Frame.from_raw("kel", group_msg),
        *(syncing.Frame.from_raw("kel", member["rot_msg"]) for member in members),
    ]
    mids = [member["icp"].pre for member in members]
    catalog = syncing.build_catalog(
        gid=group_icp.pre,
        target=target["icp"].pre,
        smids=mids,
        rmids=mids,
        rotation=adding_rotation.raw,
        frames=frames,
    )
    prepared = {
        "manifest": catalog.manifest,
        "signable": _encode(catalog.raw),
        "operation": f"multisig.add.{catalog.said}",
    }
    groups = [
        {
            "prefix": group_icp.pre,
            "state": {
                **group_icp.ked,
                "ee": {"s": group_icp.ked["s"], "d": group_icp.said},
            },
            "group": {
                "mhab": member["old_hab"],
                "keys": group_icp.ked["k"],
                "ndigs": group_icp.ked["n"],
            },
        }
        for member in (a, b)
    ]
    return prepared, catalog, groups, target


def _approve(client, group, prepared):
    signable = _decode(prepared["signable"])
    return client.manager.get(group).sign(signable)[0]


def _delivery(client, target, prepared, approvals):
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
        target["current_hab"],
        syncing.Route,
        payload,
        {},
        recipient=manifest["target"],
        dt=FIXED_DT,
    )
    assert atc == ""
    state = target["current_hab"]["state"]
    seal = eventing.SealEvent(
        i=manifest["target"],
        s=state["ee"]["s"],
        d=state["ee"]["d"],
    )
    raw = bytes(eventing.messagize(
        serder=exn,
        sigers=[core.Siger(qb64=sig) for sig in sigs],
        seal=seal,
    ))
    return exn, raw


def _put(agent_url, target, raw):
    response = requests.put(
        f"{agent_url.rstrip('/')}/",
        data=raw,
        headers={
            "Content-Type": "application/octet-stream",
            "CESR-DESTINATION": target,
        },
    )
    response.raise_for_status()
    return response


def test_signifypy_builds_target_signed_delivery():
    client = SignifyClient(passcode="abcdefghijklmnop01234")
    client.mgr = keeping.Manager(salter=client.ctrl.salter)
    prepared, _, groups, target = _prepared_catalog(client)

    approvals = [_approve(client, group, prepared) for group in groups]
    assert len(set(approvals)) == 2

    exn, raw = _delivery(client, target, prepared, approvals)
    repeated_exn, repeated_raw = _delivery(client, target, prepared, approvals)
    assert repeated_exn.said == exn.said
    assert repeated_raw == raw
    assert exn.ked["i"] == prepared["manifest"]["target"]
    assert exn.ked["rp"] == prepared["manifest"]["target"]


@responses.activate
def test_direct_put_preserves_target_signed_delivery_bytes():
    raw = b'{"v":"KERI10JSON000000_"}-signed-delivery'
    target = "E" + ("A" * 43)
    url = "http://127.0.0.1:3902/"
    responses.put(url, status=204)

    response = _put(url, target, raw)

    assert response.status_code == 204
    request = responses.calls[0].request
    assert request.body == raw
    assert request.headers["Content-Type"] == "application/octet-stream"
    assert request.headers["CESR-DESTINATION"] == target
