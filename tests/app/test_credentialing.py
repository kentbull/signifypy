# -*- encoding: utf-8 -*-
"""
SIGNIFY
signify.app.test_credentialing module

Testing credentialing with unit tests
"""
import pytest
import requests
from keri.app.keeping import Algos
from keri.core import eventing, coring
from keri.peer import exchanging
from keri.vdr import eventing as veventing
from mockito import mock, verify, expect, ANY

from signify.app import credentialing
from signify.app.clienting import SignifyClient
from signify.core import keeping as signify_keeping


JOIN_PASSCODE = "abcdefghijklmnop01234"
JOIN_PEER_PASSCODE = "zyxwvutsrqponmlkjih12"
JOIN_RECIPIENT_PASSCODE = "01234abcdefghijklmnop"
JOIN_BASE = "http://keria.example"
JOIN_GROUP_NAME = "group"
JOIN_LOCAL_MEMBER_NAME = "local"
JOIN_PEER_MEMBER_NAME = "peer"
JOIN_RECIPIENT_NAME = "recipient"
JOIN_DATE = "2026-01-01T00:00:00.000000+00:00"


def _hab_state(serder):
    ked = serder.ked
    return {
        "vn": [1, 0],
        "i": serder.pre,
        "s": ked["s"],
        "d": serder.said,
        "ee": ked,
        "kt": ked["kt"],
        "k": ked["k"],
        "nt": ked["nt"],
        "n": ked["n"],
        "bt": ked["bt"],
        "b": ked["b"],
        "p": ked.get("p", ""),
        "f": "",
        "dt": JOIN_DATE,
        "et": ked["t"],
        "c": ked.get("c", []),
        "di": ked.get("di", ""),
    }


def _member_hab(client, name, bran):
    keeper = client.manager.new(Algos.salty, 0, bran=bran)
    keys, ndigs = keeper.incept(transferable=True)
    serder = eventing.incept(
        keys=keys,
        isith="1",
        nsith="1",
        ndigs=ndigs,
        code=coring.MtrDex.Blake3_256,
        wits=[],
        toad="0",
        cnfg=[],
        data=[],
    )
    return {
        "name": name,
        "prefix": serder.pre,
        Algos.salty: keeper.params(),
        "transferable": True,
        "state": _hab_state(serder),
        "windexes": [],
    }


def _group_hab(client, name, member, peer):
    states = [member["state"], peer["state"]]
    keeper = client.manager.new(
        Algos.group,
        0,
        mhab=member,
        states=states,
        rstates=states,
    )
    keys, ndigs = keeper.incept()
    serder = eventing.incept(
        keys=keys,
        isith="1",
        nsith="1",
        ndigs=ndigs,
        code=coring.MtrDex.Blake3_256,
        wits=[],
        toad="0",
        cnfg=[],
        data=[],
    )
    return {
        "name": name,
        "prefix": serder.pre,
        Algos.group: keeper.params(),
        "transferable": True,
        "state": _hab_state(serder),
        "windexes": [],
    }


def _mock_response(make_mock_response, payload):
    return make_mock_response({"ok": True, "status_code": 200, "json": lambda: payload})


def _inner_ipex(route="/ipex/apply", *, sender, recipient):
    payload = {"m": ""}
    if route == "/ipex/apply":
        payload |= {"s": "schema-said", "a": {}}

    serder, _ = exchanging.exchange(
        route=route,
        payload=payload,
        sender=sender,
        recipient=recipient,
        date=JOIN_DATE,
    )
    return serder


def _outer_exchange(inner, *, gid, route="/multisig/exn", proposal_atc="ABCDEFGH"):
    return {
        "exn": {
            "r": route,
            "a": {"gid": gid},
            "e": {"exn": inner.ked},
        },
        "pathed": {"exn": proposal_atc},
    }


def _join_harness(
    make_mock_response,
    *,
    route="/ipex/apply",
    proposal_atc="ABCDEFGH",
    exchange_factory=None,
    members_factory=None,
    expect_posts=True,
):
    client = SignifyClient(passcode=JOIN_PASSCODE, url=JOIN_BASE)
    client.base = JOIN_BASE
    client.session = mock(spec=requests.Session, strict=True)
    client.mgr = signify_keeping.Manager(salter=client.ctrl.salter)

    member = _member_hab(client, JOIN_LOCAL_MEMBER_NAME, JOIN_PASSCODE)
    peer = _member_hab(client, JOIN_PEER_MEMBER_NAME, JOIN_PEER_PASSCODE)
    recipient = _member_hab(client, JOIN_RECIPIENT_NAME, JOIN_RECIPIENT_PASSCODE)
    group = _group_hab(client, JOIN_GROUP_NAME, member, peer)
    inner = _inner_ipex(route, sender=group["prefix"], recipient=recipient["prefix"])
    habitats = dict(group=group, member=member, peer=peer, recipient=recipient)
    exchange = (
        exchange_factory(habitats, inner)
        if exchange_factory is not None
        else _outer_exchange(inner, gid=group["prefix"], proposal_atc=proposal_atc)
    )
    members = (
        members_factory(habitats)
        if members_factory is not None
        else {
            "signing": [{"aid": member["prefix"]}, {"aid": peer["prefix"]}],
            "rotation": [{"aid": member["prefix"]}, {"aid": peer["prefix"]}],
        }
    )
    posts = []

    expect(client.session, times=1).get(f"{JOIN_BASE}/identifiers/{JOIN_GROUP_NAME}").thenReturn(
        _mock_response(make_mock_response, group)
    )
    expect(client.session, times=1).get(f"{JOIN_BASE}/exchanges/outer-said").thenReturn(
        _mock_response(make_mock_response, exchange)
    )
    expect(client.session, times=1).get(f"{JOIN_BASE}/identifiers/{JOIN_GROUP_NAME}/members").thenReturn(
        _mock_response(make_mock_response, members)
    )

    if expect_posts:
        endpoint = credentialing.Ipex._ipex_join_path(route)

        def capture_post(url, json):
            posts.append({"path": url.removeprefix(JOIN_BASE), "json": json})
            return _mock_response(make_mock_response, {"name": "exchange.op", "done": False})

        expect(
            client.session,
            times=1,
        ).post(f"{JOIN_BASE}/identifiers/{JOIN_GROUP_NAME}/ipex/{endpoint}", json=ANY).thenAnswer(capture_post)
        expect(
            client.session,
            times=1,
        ).post(f"{JOIN_BASE}/identifiers/{JOIN_LOCAL_MEMBER_NAME}/exchanges", json=ANY).thenAnswer(capture_post)

    return client, habitats, inner, posts


def test_registries_legacy_create_returns_registry_result(make_mock_client_with_manager, make_mock_response):
    mock_client, mock_manager = make_mock_client_with_manager()
    from signify.core import keeping
    mock_response = make_mock_response({})
    mock_hab = {'prefix': 'ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose',
                'name': 'aid1', 'state': {'s': '1', 'd': "ABCDEFG"}}
    regName = "reg1"

    mock_keeper = mock({'algo': 'salty', 'params': lambda: {'keeper': 'params'}}, spec=keeping.SaltyKeeper, strict=True)
    expect(mock_manager, times=2).get(aid=mock_hab).thenReturn(mock_keeper)
    expect(mock_keeper, times=1).sign(ser=ANY()).thenReturn(['a signature'])
    expect(mock_client, times=1).post(path="/identifiers/aid1/registries", json=ANY()).thenReturn(mock_response)

    from signify.app.credentialing import Registries

    registries = Registries(client=mock_client)
    result = registries.create(mock_hab, regName)

    assert isinstance(result, credentialing.RegistryResult)
    assert result.regser.pre
    assert result.serder.pre == mock_hab["prefix"]
    assert result.sigs == ['a signature']
    assert result.response == mock_response


def test_registries_name_create_returns_registry_result(make_mock_client_with_manager, make_mock_response):
    mock_client, mock_manager = make_mock_client_with_manager()

    from signify.app.aiding import Identifiers
    mock_ids = mock(spec=Identifiers, strict=True)
    from signify.core import keeping

    mock_response = make_mock_response({})
    mock_hab = {'prefix': 'ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose',
                'name': 'aid1', 'state': {'s': '1', 'd': "ABCDEFG"}}
    regName = "reg1"

    expect(mock_client, times=1).identifiers().thenReturn(mock_ids)
    expect(mock_ids, times=1).get("aid1").thenReturn(mock_hab)
    mock_keeper = mock({'algo': 'salty', 'params': lambda: {'keeper': 'params'}}, spec=keeping.SaltyKeeper, strict=True)
    expect(mock_manager, times=2).get(aid=mock_hab).thenReturn(mock_keeper)
    expect(mock_keeper, times=1).sign(ser=ANY()).thenReturn(['a signature'])
    expect(mock_client, times=1).post(path="/identifiers/aid1/registries", json=ANY()).thenReturn(mock_response)

    result = credentialing.Registries(client=mock_client).create(
        "aid1",
        regName,
        nonce="A_NONCE",
    )

    assert isinstance(result, credentialing.RegistryResult)
    assert result.regser.pre
    assert result.serder.pre == mock_hab["prefix"]
    assert result.sigs == ['a signature']
    assert result.response == mock_response


def test_registries_name_create_establishment_only_not_implemented(make_mock_client_with_manager):
    mock_client, _ = make_mock_client_with_manager()

    from signify.app.aiding import Identifiers
    mock_ids = mock(spec=Identifiers, strict=True)
    expect(mock_client, times=1).identifiers().thenReturn(mock_ids)
    expect(mock_ids, times=1).get("aid1").thenReturn({
        "prefix": "EPREFIX",
        "name": "aid1",
        "state": {"s": "1", "d": "ABCDEFG", "c": ["EO"]},
    })

    with pytest.raises(NotImplementedError, match="establishment only not implemented"):
        credentialing.Registries(client=mock_client).create("aid1", "reg1")


def test_registries_list_get_rename_and_serialize(make_mock_client_with_manager, make_mock_response):
    mock_client, _ = make_mock_client_with_manager()
    mock_response = make_mock_response({'json': lambda: {}})
    mock_hab = {'prefix': 'ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose',
                'name': 'aid1', 'state': {'s': '1', 'd': "ABCDEFG"}}
    regName = "reg1"

    registries = credentialing.Registries(client=mock_client)

    expect(mock_client, times=1).get("/identifiers/aid1/registries").thenReturn(mock_response)
    registries.list(name="aid1")

    expect(mock_client, times=1).get("/identifiers/aid1/registries/reg1").thenReturn(mock_response)
    registries.get(name="aid1", registryName=regName)

    (expect(mock_client, times=1).put(path="/identifiers/aid1/registries/reg1", json={'name': 'test'})
     .thenReturn(mock_response))
    registries.rename(mock_hab, regName, "test")

    (expect(mock_client, times=1).put(path="/identifiers/aid1/registries/reg1", json={'name': 'again'})
     .thenReturn(mock_response))
    registries.rename("aid1", regName, "again")

    pre = "ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose"
    dig = "EOgQvKz8ziRn7FdR_ebwK9BkaVOnGeXQOJ87N6hMLrK0"
    nonce = "ACb_3pGwW3uIjtOg4zRQ66I-SggMcmoyju_uCzuSvgG4"
    serder = veventing.incept(pre=pre, nonce=nonce)
    anc = eventing.interact(pre=pre, dig=dig)

    msg = credentialing.Registries.serialize(serder, anc)
    assert msg == (b'{"v":"KERI10JSON00010f_","t":"vcp","d":"EGaypC6sODRFyIuhdFzzFmBU'
                   b'4Xe5SNprALGbltnyHYSz","i":"EGaypC6sODRFyIuhdFzzFmBU4Xe5SNprALGbl'
                   b'tnyHYSz","ii":"ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose","s"'
                   b':"0","c":[],"bt":"0","b":[],"n":"ACb_3pGwW3uIjtOg4zRQ66I-SggMcmo'
                   b'yju_uCzuSvgG4"}-VAS-GAB0AAAAAAAAAAAAAAAAAAAAAABENns5-voIbnRMADUO'
                   b'so7HDiQ9ZS_AfU8BfgGLHEW54H1')


def test_registry_result_op(make_mock_response):
    mock_response = make_mock_response({"json": lambda: {}})
    expect(mock_response, times=1).json().thenReturn({"done": True})

    result = credentialing.RegistryResult(
        regser="regser",
        serder="serder",
        sigs=["a signature"],
        response=mock_response,
    )

    assert result.regser == "regser"
    assert result.serder == "serder"
    assert result.sigs == ["a signature"]
    assert result.op() == {"done": True}


def test_registries_createFromEvents_returns_registry_result(make_mock_client_with_manager, make_mock_response):
    mock_client, mock_manager = make_mock_client_with_manager()

    from signify.core import keeping
    mock_hab = {'prefix': 'ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose',
                'name': 'aid1', 'state': {'s': '1', 'd': "ABCDEFG"}}
    mock_keeper = mock({'algo': 'salty', 'params': lambda: {'keeper': 'params'}}, spec=keeping.SaltyKeeper, strict=True)
    expect(mock_manager, times=1).get(aid=mock_hab).thenReturn(mock_keeper)

    mock_response = make_mock_response({})
    expect(mock_client, times=1).post(path="/identifiers/aid1/registries", json=ANY()).thenReturn(mock_response)

    vcp = veventing.incept(pre=mock_hab["prefix"], nonce="A_NONCE")
    ixn = eventing.interact(pre=mock_hab["prefix"], dig="ABCDEFG")

    result = credentialing.Registries(client=mock_client).createFromEvents(
        hab=mock_hab,
        name="aid1",
        registryName="reg1",
        vcp=vcp.ked,
        ixn=ixn.ked,
        sigs=["a signature"],
    )

    assert isinstance(result, credentialing.RegistryResult)
    assert result.regser.said == vcp.said
    assert result.serder.said == ixn.said
    assert result.sigs == ["a signature"]
    assert result.response == mock_response


def test_registries_create_from_events_compat_returns_json(make_mock_client_with_manager, make_mock_response):
    mock_client, mock_manager = make_mock_client_with_manager()

    from signify.core import keeping
    mock_hab = {'prefix': 'ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose',
                'name': 'aid1', 'state': {'s': '1', 'd': "ABCDEFG"}}
    mock_keeper = mock({'algo': 'salty', 'params': lambda: {'keeper': 'params'}}, spec=keeping.SaltyKeeper, strict=True)
    expect(mock_manager, times=1).get(aid=mock_hab).thenReturn(mock_keeper)

    mock_response = make_mock_response({})
    expect(mock_client, times=1).post(path="/identifiers/aid1/registries", json=ANY()).thenReturn(mock_response)
    expect(mock_response, times=1).json().thenReturn({"done": True})

    vcp = veventing.incept(pre=mock_hab["prefix"], nonce="A_NONCE")
    ixn = eventing.interact(pre=mock_hab["prefix"], dig="ABCDEFG")

    result = credentialing.Registries(client=mock_client).create_from_events(
        hab=mock_hab,
        registryName="reg1",
        vcp=vcp.ked,
        ixn=ixn.ked,
        sigs=["a signature"],
    )

    assert result == {"done": True}


def test_registries_create_uses_nb_trait_for_backerless_registry():
    """Backerless registry inception must use the VDR `NB` trait code.

    This looks small, but it is the difference between a true no-backer
    registry and a backer-capable one. When the wrong trait code is used, the
    live stack silently issues `bis/brv` events instead of `iss/rev`, and
    later revoke coverage fails for the wrong reason.
    """

    class DummyResponse:
        def json(self):
            return {}

    class DummyKeeper:
        algo = "salty"

        @staticmethod
        def params():
            return {"keeper": "params"}

        @staticmethod
        def sign(ser):
            return ["a signature"]

    class DummyManager:
        @staticmethod
        def get(aid):
            return DummyKeeper()

    class DummyClient:
        def __init__(self):
            self.manager = DummyManager()
            self.last_post = None

        def post(self, path, json):
            self.last_post = (path, json)
            return DummyResponse()

    hab = {
        "prefix": "ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose",
        "name": "aid1",
        "state": {"s": "1", "d": "ABCDEFG"},
    }

    client = DummyClient()
    credentialing.Registries(client=client).create(hab, "reg1")

    assert client.last_post is not None
    path, body = client.last_post
    assert path == "/identifiers/aid1/registries"
    assert body["vcp"]["c"] == ["NB"]

def test_credentials_list(make_mock_response):
    from signify.app.clienting import SignifyClient
    mock_client = mock(spec=SignifyClient, strict=True)

    mock_response = make_mock_response({'json': lambda: {}})
    expect(mock_client, times=1).post('/credentials/query',
                                      json={'filter': {'genre': 'horror'},
                                            'sort': ['updside down'], 'skip': 10, 'limit': 10}).thenReturn(mock_response)

    from signify.app.credentialing import Credentials
    Credentials(client=mock_client).list(filter={'genre': 'horror'}, sort=['updside down'], skip=10,
                                         limit=10)  # type: ignore

    verify(mock_response, times=1).json()


def test_credentials_get_json(make_mock_response):
    from signify.app.clienting import SignifyClient
    mock_client = mock(spec=SignifyClient, strict=True)

    payload = {'sad': {'d': 'a_said'}}
    mock_response = make_mock_response({'json': lambda: payload})
    expect(mock_client, times=1).get('/credentials/a_said',
                                     headers={'accept': 'application/json'}).thenReturn(mock_response)

    from signify.app.credentialing import Credentials
    out = Credentials(client=mock_client).get('a_said')  # type: ignore

    assert out == payload


def test_credentials_get_cesr(make_mock_response):
    from signify.app.clienting import SignifyClient
    mock_client = mock(spec=SignifyClient, strict=True)

    mock_response = make_mock_response({'content': b'things I found'})
    expect(mock_client, times=1).get('/credentials/a_said',
                                     headers={'accept': 'application/json+cesr'}).thenReturn(mock_response)

    from signify.app.credentialing import Credentials
    out = Credentials(client=mock_client).get('a_said', includeCESR=True)  # type: ignore

    assert out == b'things I found'


def test_credentials_export(make_mock_response):
    from signify.app.clienting import SignifyClient
    mock_client = mock(spec=SignifyClient, strict=True)

    mock_response = make_mock_response({'content': b'things I found'})
    expect(mock_client, times=1).get('/credentials/a_said',
                                     headers={'accept': 'application/json+cesr'}).thenReturn(mock_response)

    from signify.app.credentialing import Credentials
    out = Credentials(client=mock_client).export('a_said')  # type: ignore

    assert out == b'things I found'


def test_credentials_delete(make_mock_response):
    from signify.app.clienting import SignifyClient
    mock_client = mock(spec=SignifyClient, strict=True)

    mock_response = make_mock_response({})
    expect(mock_client, times=1).delete('/credentials/a_said').thenReturn(mock_response)

    from signify.app.credentialing import Credentials
    out = Credentials(client=mock_client).delete('a_said')  # type: ignore

    assert out is None


def test_credentials_state(make_mock_response):
    from signify.app.clienting import SignifyClient
    mock_client = mock(spec=SignifyClient, strict=True)

    payload = {'et': 'iss', 's': '0'}
    mock_response = make_mock_response({'json': lambda: payload})
    expect(mock_client, times=1).get('/registries/registry_said/credential_said').thenReturn(mock_response)

    from signify.app.credentialing import Credentials
    out = Credentials(client=mock_client).state('registry_said', 'credential_said')  # type: ignore

    assert out == payload


def test_credential_issue_result_op_and_iterable(make_mock_response):
    mock_response = make_mock_response({"json": lambda: {"done": True}})
    expect(mock_response, times=2).json().thenReturn({"done": True})

    result = credentialing.CredentialIssueResult(
        acdc="acdc",
        iss="iss",
        anc="anc",
        sigs=["a signature"],
        response=mock_response,
    )

    assert result.acdc == "acdc"
    assert result.iss == "iss"
    assert result.anc == "anc"
    assert result.sigs == ["a signature"]
    assert result.op() == {"done": True}
    assert tuple(result) == ("acdc", "iss", "anc", ["a signature"], {"done": True})


def test_credential_revoke_result_op_and_iterable(make_mock_response):
    mock_response = make_mock_response({"json": lambda: {"done": True}})
    expect(mock_response, times=2).json().thenReturn({"done": True})

    result = credentialing.CredentialRevokeResult(
        rev="rev",
        anc="anc",
        sigs=["a signature"],
        response=mock_response,
    )

    assert result.rev == "rev"
    assert result.anc == "anc"
    assert result.sigs == ["a signature"]
    assert result.op() == {"done": True}
    assert tuple(result) == ("rev", "anc", ["a signature"], {"done": True})


def test_credentials_issue(make_mock_client_with_manager, make_mock_response):
    mock_client, mock_manager = make_mock_client_with_manager()

    from signify.app.aiding import Identifiers
    from signify.app.credentialing import Registries
    from signify.core import keeping

    mock_ids = mock(spec=Identifiers, strict=True)
    mock_regs = mock(spec=Registries, strict=True)
    mock_hab = {'prefix': 'ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose', 'name': 'aid1',
                'state': {'s': '1', 'd': "ABCDEFG"}}
    mock_registry = {'regk': "EKRg7i8jS4O6BYUYiQG7X8YiMYdDXdw28tJRhFndCdGF",
                     'pre': 'EHpwssa6tmD2U5W7-aogym-r1NobKBNXydP4MmaebA4O', 'state': {'c': ['NB']}}
    data = dict(dt="2023-09-27T16:27:14.376928+00:00", LEI="ABC1234567890AD4456")
    schema = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
    recp = "ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose"

    expect(mock_client, times=1).identifiers().thenReturn(mock_ids)
    expect(mock_ids, times=1).get("aid1").thenReturn(mock_hab)
    expect(mock_client, times=1).registries().thenReturn(mock_regs)
    expect(mock_regs, times=1).get("aid1", "reg1").thenReturn(mock_registry)

    mock_keeper = mock({'algo': 'salty', 'params': lambda: {'keeper': 'params'}}, spec=keeping.SaltyKeeper, strict=True)
    expect(mock_manager, times=2).get(aid=mock_hab).thenReturn(mock_keeper)
    expect(mock_keeper, times=1).sign(ser=ANY()).thenReturn(['a signature'])
    mock_response = make_mock_response({})
    expect(mock_response, times=2).json().thenReturn({'v': 'ACDC10JSON00014c_'})

    body = {'acdc': {'v': 'ACDC10JSON000196_', 'd': 'EK2xYrVkfJJHvlGhP79sfEPvQGmkFPPNAj-bjI5oHy7m',
                     'i': 'EHpwssa6tmD2U5W7-aogym-r1NobKBNXydP4MmaebA4O',
                     'ri': 'EKRg7i8jS4O6BYUYiQG7X8YiMYdDXdw28tJRhFndCdGF',
                     's': 'EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao',
                     'a': {'d': 'EHpwssa6tmD2U5W7-aogym-r1NobKBNXydP4MmaebA4O',
                           'i': 'ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose',
                           'dt': '2023-09-27T16:27:14.376928+00:00', 'LEI': 'ABC1234567890AD4456'}},
            'iss': {'v': 'KERI10JSON0000ed_', 't': 'iss', 'd': 'EE8yncw1LCyBVtZPtozAFi7qvGn9dRPwTbuq--ulOAtB',
                    'i': 'EK2xYrVkfJJHvlGhP79sfEPvQGmkFPPNAj-bjI5oHy7m', 's': '0',
                    'ri': 'EKRg7i8jS4O6BYUYiQG7X8YiMYdDXdw28tJRhFndCdGF', 'dt': '2023-09-27T16:27:14.376928+00:00'},
            'ixn': {'v': 'KERI10JSON000115_', 't': 'ixn', 'd': 'EC5KxyucpxnOpIpHe2QUPs9YeH1yGvkALg8NcWLYFe6a',
                    'i': 'ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose', 's': '2', 'p': 'ABCDEFG', 'a': [
                    {'i': 'EK2xYrVkfJJHvlGhP79sfEPvQGmkFPPNAj-bjI5oHy7m', 's': '0',
                     'd': 'EE8yncw1LCyBVtZPtozAFi7qvGn9dRPwTbuq--ulOAtB'}]}, 'sigs': ['a signature'],
            'salty': {'keeper': 'params'}}

    expect(mock_client, times=1).post("/identifiers/aid1/credentials", json=body).thenReturn(mock_response)

    result = credentialing.Credentials(client=mock_client).issue(
        "aid1",
        "reg1",
        data,
        schema,
        recipient=recp,
    )

    assert isinstance(result, credentialing.CredentialIssueResult)
    assert result.acdc.said == "EK2xYrVkfJJHvlGhP79sfEPvQGmkFPPNAj-bjI5oHy7m"
    assert result.iss.said == "EE8yncw1LCyBVtZPtozAFi7qvGn9dRPwTbuq--ulOAtB"
    assert result.anc.said == "EC5KxyucpxnOpIpHe2QUPs9YeH1yGvkALg8NcWLYFe6a"
    assert result.sigs == ['a signature']
    assert result.op() == {'v': 'ACDC10JSON00014c_'}
    assert tuple(result) == (
        result.acdc,
        result.iss,
        result.anc,
        ['a signature'],
        {'v': 'ACDC10JSON00014c_'},
    )

def test_credentials_create(make_mock_client_with_manager, make_mock_response):
    mock_client, mock_manager = make_mock_client_with_manager()

    from signify.core import keeping
    mock_hab = {'prefix': 'ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose', 'name': 'aid1',
                'state': {'s': '1', 'd': "ABCDEFG"}}
    mock_registry = {'regk': "EKRg7i8jS4O6BYUYiQG7X8YiMYdDXdw28tJRhFndCdGF",
                     'pre': 'EHpwssa6tmD2U5W7-aogym-r1NobKBNXydP4MmaebA4O', 'state': {'c': ['NB']}}
    data = dict(dt="2023-09-27T16:27:14.376928+00:00", LEI="ABC1234567890AD4456")
    schema = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
    recp = "ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose"

    mock_keeper = mock({'algo': 'salty', 'params': lambda: {'keeper': 'params'}}, spec=keeping.SaltyKeeper, strict=True)
    expect(mock_manager, times=2).get(aid=mock_hab).thenReturn(mock_keeper)
    expect(mock_keeper, times=1).sign(ser=ANY()).thenReturn(['a signature'])
    mock_response = make_mock_response({})
    expect(mock_response, times=1).json().thenReturn({'v': 'ACDC10JSON00014c_'})

    sad = {'v': 'ACDC10JSON00014c_', 'd': '',
           'i': 'ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose',
           'ri': 'a_regk', 's': 'EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao',
           'a': {'d': 'EHpwssa6tmD2U5W7-aogym-r1NobKBNXydP4MmaebA4O',
                 'i': 'ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose',
                 'dt': '2023-09-27T16:27:14.376928+00:00', 'LEI': 'ABC1234567890AD4456'}}

    _, sad = coring.Saider.saidify(sad)

    body = {'acdc': {'v': 'ACDC10JSON000196_', 'd': 'EK2xYrVkfJJHvlGhP79sfEPvQGmkFPPNAj-bjI5oHy7m',
                     'i': 'EHpwssa6tmD2U5W7-aogym-r1NobKBNXydP4MmaebA4O',
                     'ri': 'EKRg7i8jS4O6BYUYiQG7X8YiMYdDXdw28tJRhFndCdGF',
                     's': 'EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao',
                     'a': {'d': 'EHpwssa6tmD2U5W7-aogym-r1NobKBNXydP4MmaebA4O',
                           'i': 'ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose',
                           'dt': '2023-09-27T16:27:14.376928+00:00', 'LEI': 'ABC1234567890AD4456'}},
            'iss': {'v': 'KERI10JSON0000ed_', 't': 'iss', 'd': 'EE8yncw1LCyBVtZPtozAFi7qvGn9dRPwTbuq--ulOAtB',
                    'i': 'EK2xYrVkfJJHvlGhP79sfEPvQGmkFPPNAj-bjI5oHy7m', 's': '0',
                    'ri': 'EKRg7i8jS4O6BYUYiQG7X8YiMYdDXdw28tJRhFndCdGF', 'dt': '2023-09-27T16:27:14.376928+00:00'},
            'ixn': {'v': 'KERI10JSON000115_', 't': 'ixn', 'd': 'EC5KxyucpxnOpIpHe2QUPs9YeH1yGvkALg8NcWLYFe6a',
                    'i': 'ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose', 's': '2', 'p': 'ABCDEFG', 'a': [
                    {'i': 'EK2xYrVkfJJHvlGhP79sfEPvQGmkFPPNAj-bjI5oHy7m', 's': '0',
                     'd': 'EE8yncw1LCyBVtZPtozAFi7qvGn9dRPwTbuq--ulOAtB'}]}, 'sigs': ['a signature'],
            'salty': {'keeper': 'params'}}

    expect(mock_client, times=1).post(f"/identifiers/aid1/credentials", json=body).thenReturn(mock_response)

    from signify.app.credentialing import Credentials
    creder, iss, ixn, sigs, op = Credentials(client=mock_client).create(mock_hab, mock_registry, data, schema, recp)

    assert creder.said == "EK2xYrVkfJJHvlGhP79sfEPvQGmkFPPNAj-bjI5oHy7m"
    assert iss.said == "EE8yncw1LCyBVtZPtozAFi7qvGn9dRPwTbuq--ulOAtB"
    assert ixn.said == "EC5KxyucpxnOpIpHe2QUPs9YeH1yGvkALg8NcWLYFe6a"
    assert op == {'v': 'ACDC10JSON00014c_'}


def test_credentials_revoke_uses_ri_and_returns_result(make_mock_response):
    credential_said = "EMwcsEMUEruPXVwPCW7zmqmN8m0I3CihxolBm-RDrsJo"
    registry_said = "EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df"
    status_said = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK"

    class DummyKeeper:
        algo = "salty"

        @staticmethod
        def params():
            return {"keeper": "params"}

        @staticmethod
        def sign(ser):
            return ["a signature"]

    class DummyManager:
        @staticmethod
        def get(aid):
            return DummyKeeper()

    class DummyIdentifiers:
        @staticmethod
        def get(name):
            assert name == "aid1"
            return {"prefix": "ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose", "name": "aid1",
                    "state": {"s": "1", "d": "ABCDEFG"}}

    class DummyResponse:
        @staticmethod
        def json():
            return {"done": True}

    class DummyClient:
        def __init__(self):
            self.manager = DummyManager()
            self.last_delete = None

        @staticmethod
        def identifiers():
            return DummyIdentifiers()

        @staticmethod
        def get(path, headers=None):
            assert path == f"/credentials/{credential_said}"
            assert headers == {"accept": "application/json"}
            return make_mock_response({
                "json": lambda: {
                    "sad": {"d": credential_said, "ri": registry_said},
                    "status": {"d": status_said},
                }
            })

        def delete(self, path, body=None):
            self.last_delete = (path, body)
            return DummyResponse()

    client = DummyClient()
    result = credentialing.Credentials(client=client).revoke(
        "aid1",
        credential_said,
        timestamp="2023-09-27T16:27:14.376928+00:00",
    )

    assert isinstance(result, credentialing.CredentialRevokeResult)
    assert result.rev.ked["t"] == "rev"
    assert result.rev.ked["ri"] == registry_said
    assert result.rev.ked["i"] == credential_said
    assert result.rev.ked["dt"] == "2023-09-27T16:27:14.376928+00:00"
    assert result.anc.ked["t"] == "ixn"
    assert result.sigs == ["a signature"]
    assert result.op() == {"done": True}
    assert tuple(result) == (result.rev, result.anc, ["a signature"], {"done": True})
    assert client.last_delete[0] == f"/identifiers/aid1/credentials/{credential_said}"
    assert client.last_delete[1]["rev"]["ri"] == registry_said
    assert client.last_delete[1]["rev"]["i"] == credential_said
    assert client.last_delete[1]["ixn"]["t"] == "ixn"
    assert client.last_delete[1]["sigs"] == ["a signature"]
    assert client.last_delete[1]["salty"] == {"keeper": "params"}


def test_credentials_revoke_falls_back_to_rd(make_mock_response):
    credential_said = "EMwcsEMUEruPXVwPCW7zmqmN8m0I3CihxolBm-RDrsJo"
    registry_said = "EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df"
    status_said = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK"

    class DummyKeeper:
        algo = "salty"

        @staticmethod
        def params():
            return {"keeper": "params"}

        @staticmethod
        def sign(ser):
            return ["a signature"]

    class DummyManager:
        @staticmethod
        def get(aid):
            return DummyKeeper()

    class DummyIdentifiers:
        @staticmethod
        def get(name):
            return {"prefix": "ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose", "name": name,
                    "state": {"s": "1", "d": "ABCDEFG"}}

    class DummyResponse:
        @staticmethod
        def json():
            return {"done": True}

    class DummyClient:
        def __init__(self):
            self.manager = DummyManager()
            self.last_delete = None

        @staticmethod
        def identifiers():
            return DummyIdentifiers()

        @staticmethod
        def get(path, headers=None):
            return make_mock_response({
                "json": lambda: {
                    "sad": {"d": credential_said, "rd": registry_said},
                    "status": {"d": status_said},
                }
            })

        def delete(self, path, body=None):
            self.last_delete = (path, body)
            return DummyResponse()

    client = DummyClient()
    result = credentialing.Credentials(client=client).revoke(
        "aid1",
        credential_said,
        timestamp="2023-09-27T16:27:14.376928+00:00",
    )

    assert result.rev.ked["ri"] == registry_said
    assert client.last_delete[1]["rev"]["ri"] == registry_said

def test_ipex_grant():
    from signify.app.clienting import SignifyClient
    mock_client = mock(spec=SignifyClient, strict=True)

    from signify.app.exchanging import Exchanges
    mock_excs = mock(spec=Exchanges, strict=True)

    dt = "2023-09-25T16:01:37.000000+00:00"
    mock_hab = {'prefix': 'a_prefix', 'name': 'aid1', 'state': {'s': '1', 'd': "ABCDEFG"}}
    mock_acdc = b"ACDC"
    mock_iss = b"ISS"
    mock_anc = b"ANC"
    mock_agree = mock({'said': 'EAGREE123'}, strict=True)
    mock_grant = {}
    mock_gsigs = []
    mock_atc = ""
    expect(mock_client, times=1).exchanges().thenReturn(mock_excs)
    expect(mock_excs).createExchangeMessage(sender=mock_hab, route="/ipex/grant",
                                            payload={'m': 'this is a test',
                                                     'i': 'ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose'},
                                            embeds={'acdc': b'ACDC', 'iss': b'ISS', 'anc': b'ANC'},
                                            recipient='ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose',
                                            dt=dt,
                                            datetime=None,
                                            dig='EAGREE123').thenReturn((mock_grant, mock_gsigs, mock_atc))

    ipex = credentialing.Ipex(mock_client)
    recp = "ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose"

    grant, gsigs, atc = ipex.grant(hab=mock_hab, recp=recp, message="this is a test", acdc=mock_acdc, iss=mock_iss,
                                   anc=mock_anc, agree=mock_agree, dt=dt)

    assert grant == mock_grant
    assert gsigs == mock_gsigs
    assert atc == mock_atc


def test_ipex_apply():
    from signify.app.clienting import SignifyClient
    from signify.app.aiding import Identifiers
    from signify.app.exchanging import Exchanges

    mock_client = mock(spec=SignifyClient, strict=True)
    mock_ids = mock(spec=Identifiers, strict=True)
    mock_excs = mock(spec=Exchanges, strict=True)

    dt = "2023-09-25T16:01:37.000000+00:00"
    mock_hab = {"prefix": "a_prefix", "name": "aid1", "state": {"s": "1", "d": "ABCDEFG"}}
    mock_apply = {}
    mock_sigs = []
    mock_atc = ""

    expect(mock_client, times=1).identifiers().thenReturn(mock_ids)
    expect(mock_ids, times=1).get("aid1").thenReturn(mock_hab)
    expect(mock_client, times=1).exchanges().thenReturn(mock_excs)
    expect(mock_excs, times=1).createExchangeMessage(
        sender=mock_hab,
        route="/ipex/apply",
        payload={"m": "please share", "s": "ESCHEMA", "a": {"LEI": "5493001KJTIIGC8Y1R17"}},
        embeds={},
        recipient="ERECIPIENT",
        dt=dt,
        datetime=None,
    ).thenReturn((mock_apply, mock_sigs, mock_atc))

    apply, sigs, atc = credentialing.Ipex(mock_client).apply(
        "aid1",
        "ERECIPIENT",
        "ESCHEMA",
        message="please share",
        attributes={"LEI": "5493001KJTIIGC8Y1R17"},
        dt=dt,
    )

    assert apply == mock_apply
    assert sigs == mock_sigs
    assert atc == mock_atc


def test_ipex_offer():
    from signify.app.clienting import SignifyClient
    from signify.app.aiding import Identifiers
    from signify.app.exchanging import Exchanges

    class DummyAcdc:
        raw = b'{"v":"ACDC10JSON000000_"}'

    mock_client = mock(spec=SignifyClient, strict=True)
    mock_ids = mock(spec=Identifiers, strict=True)
    mock_excs = mock(spec=Exchanges, strict=True)

    dt = "2023-09-25T16:01:37.000000+00:00"
    mock_hab = {"prefix": "a_prefix", "name": "aid1", "state": {"s": "1", "d": "ABCDEFG"}}
    mock_offer = {}
    mock_sigs = []
    mock_atc = ""

    expect(mock_client, times=1).identifiers().thenReturn(mock_ids)
    expect(mock_ids, times=1).get("aid1").thenReturn(mock_hab)
    expect(mock_client, times=1).exchanges().thenReturn(mock_excs)
    expect(mock_excs, times=1).createExchangeMessage(
        sender=mock_hab,
        route="/ipex/offer",
        payload={"m": "this matches"},
        embeds={"acdc": DummyAcdc.raw},
        recipient="ERECIPIENT",
        dig="EAPPLYSAID",
        dt=dt,
        datetime=None,
    ).thenReturn((mock_offer, mock_sigs, mock_atc))

    offer, sigs, atc = credentialing.Ipex(mock_client).offer(
        "aid1",
        "ERECIPIENT",
        DummyAcdc(),
        message="this matches",
        applySaid="EAPPLYSAID",
        dt=dt,
    )

    assert offer == mock_offer
    assert sigs == mock_sigs
    assert atc == mock_atc


def test_ipex_agree():
    from signify.app.clienting import SignifyClient
    from signify.app.aiding import Identifiers
    from signify.app.exchanging import Exchanges

    mock_client = mock(spec=SignifyClient, strict=True)
    mock_ids = mock(spec=Identifiers, strict=True)
    mock_excs = mock(spec=Exchanges, strict=True)

    dt = "2023-09-25T16:01:37.000000+00:00"
    mock_hab = {"prefix": "a_prefix", "name": "aid1", "state": {"s": "1", "d": "ABCDEFG"}}
    mock_agree = {}
    mock_sigs = []
    mock_atc = ""

    expect(mock_client, times=1).identifiers().thenReturn(mock_ids)
    expect(mock_ids, times=1).get("aid1").thenReturn(mock_hab)
    expect(mock_client, times=1).exchanges().thenReturn(mock_excs)
    expect(mock_excs, times=1).createExchangeMessage(
        sender=mock_hab,
        route="/ipex/agree",
        payload={"m": "agreed"},
        embeds={},
        recipient="ERECIPIENT",
        dig="EOFFERSAID",
        dt=dt,
        datetime=None,
    ).thenReturn((mock_agree, mock_sigs, mock_atc))

    agree, sigs, atc = credentialing.Ipex(mock_client).agree(
        "aid1",
        "ERECIPIENT",
        "EOFFERSAID",
        message="agreed",
        dt=dt,
    )

    assert agree == mock_agree
    assert sigs == mock_sigs
    assert atc == mock_atc


def test_ipex_name_grant():
    from signify.app.clienting import SignifyClient
    from signify.app.aiding import Identifiers
    from signify.app.exchanging import Exchanges

    class DummyAcdc:
        raw = b"ACDC"

    class DummyEvt:
        raw = b"KERI"

    mock_client = mock(spec=SignifyClient, strict=True)
    mock_ids = mock(spec=Identifiers, strict=True)
    mock_excs = mock(spec=Exchanges, strict=True)

    dt = "2023-09-25T16:01:37.000000+00:00"
    mock_hab = {"prefix": "a_prefix", "name": "aid1", "state": {"s": "1", "d": "ABCDEFG"}}
    mock_grant = {}
    mock_sigs = []
    mock_atc = ""

    expect(mock_client, times=1).identifiers().thenReturn(mock_ids)
    expect(mock_ids, times=1).get("aid1").thenReturn(mock_hab)
    expect(mock_client, times=1).exchanges().thenReturn(mock_excs)
    expect(mock_excs, times=1).createExchangeMessage(
        sender=mock_hab,
        route="/ipex/grant",
        payload={"m": "present", "i": "ERECIPIENT"},
        embeds={"acdc": b"ACDCattach-acdc", "iss": b"KERIattach-iss", "anc": b"KERIattach-anc"},
        recipient="ERECIPIENT",
        dt=dt,
        datetime=None,
        dig="EAGREE123",
    ).thenReturn((mock_grant, mock_sigs, mock_atc))

    grant, sigs, atc = credentialing.Ipex(mock_client).grant(
        name="aid1",
        recipient="ERECIPIENT",
        message="present",
        acdc=DummyAcdc(),
        iss=DummyEvt(),
        anc=DummyEvt(),
        acdcAttachment="attach-acdc",
        issAttachment="attach-iss",
        ancAttachment="attach-anc",
        agreeSaid="EAGREE123",
        dt=dt,
    )

    assert grant == mock_grant
    assert sigs == mock_sigs
    assert atc == mock_atc


def test_ipex_name_admit():
    from signify.app.clienting import SignifyClient
    from signify.app.aiding import Identifiers
    from signify.app.exchanging import Exchanges

    mock_client = mock(spec=SignifyClient, strict=True)
    mock_ids = mock(spec=Identifiers, strict=True)
    mock_excs = mock(spec=Exchanges, strict=True)

    dt = "2023-09-25T16:01:37.000000+00:00"
    mock_hab = {"prefix": "a_prefix", "name": "aid1", "state": {"s": "1", "d": "ABCDEFG"}}
    mock_admit = {}
    mock_sigs = []
    mock_atc = ""

    expect(mock_client, times=1).identifiers().thenReturn(mock_ids)
    expect(mock_ids, times=1).get("aid1").thenReturn(mock_hab)
    expect(mock_client, times=1).exchanges().thenReturn(mock_excs)
    expect(mock_excs, times=1).createExchangeMessage(
        sender=mock_hab,
        route="/ipex/admit",
        payload={"m": ""},
        embeds=None,
        recipient="ERECIPIENT",
        dt=dt,
        datetime=None,
        dig="EGRANT123",
    ).thenReturn((mock_admit, mock_sigs, mock_atc))

    admit, sigs, atc = credentialing.Ipex(mock_client).admit(
        name="aid1",
        recipient="ERECIPIENT",
        grantSaid="EGRANT123",
        dt=dt,
    )

    assert admit == mock_admit
    assert sigs == mock_sigs
    assert atc == mock_atc

def test_ipex_admit():
    from signify.app.clienting import SignifyClient
    mock_client = mock(spec=SignifyClient, strict=True)

    from signify.app.exchanging import Exchanges
    mock_excs = mock(spec=Exchanges, strict=True)

    grant, _ = exchanging.exchange("/admit/grant", payload={}, sender="EEE")

    dt = "2023-09-25T16:01:37.000000+00:00"
    mock_hab = {'prefix': 'a_prefix', 'name': 'aid1', 'state': {'s': '1', 'd': "ABCDEFG"}}
    mock_admit = {}
    mock_gsigs = []
    mock_atc = ""
    expect(mock_client, times=1).exchanges().thenReturn(mock_excs)
    expect(mock_excs).createExchangeMessage(sender=mock_hab, route="/ipex/admit",
                                            payload={'m': 'this is a test'},
                                            embeds=None,
                                            recipient='ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose',
                                            dt=dt,
                                            datetime=None,
                                            dig=grant.said).thenReturn((mock_admit, mock_gsigs, mock_atc))

    ipex = credentialing.Ipex(mock_client)  # type: ignore
    grant, gsigs, atc = ipex.admit(
        hab=mock_hab,
        message="this is a test",
        dt=dt,
        grant=grant.said,
        recp="ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose",
    )

    assert grant == mock_admit
    assert gsigs == mock_gsigs
    assert atc == mock_atc


def test_submit_apply():
    from signify.app.clienting import SignifyClient
    from requests import Response

    mock_client = mock(spec=SignifyClient, strict=True)
    mock_rep = mock(spec=Response, strict=True)

    expect(mock_rep).json().thenReturn(dict(b='c'))

    mock_apply = mock({'ked': dict(a='b')})
    mock_sigs = []
    recp = ["ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose"]

    ipex = credentialing.Ipex(mock_client)  # type: ignore
    body = {'exn': {'a': 'b'}, 'sigs': [], 'rec': ['ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose']}
    expect(mock_client, times=1).post(f"/identifiers/aid1/ipex/apply", json=body).thenReturn(mock_rep)
    rep = ipex.submitApply("aid1", exn=mock_apply, sigs=mock_sigs, recp=recp)

    assert rep == dict(b='c')



def test_submit_admit():
    from signify.app.clienting import SignifyClient
    mock_client = mock(spec=SignifyClient, strict=True)

    from requests import Response
    mock_rep = mock(spec=Response, strict=True)

    expect(mock_rep).json().thenReturn(dict(b='c'))

    mock_admit = mock({'ked': dict(a='b')})
    mock_gsigs = []
    mock_end = ""
    recp = ["ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose"]

    ipex = credentialing.Ipex(mock_client)  # type: ignore
    body = {'exn': {'a': 'b'}, 'sigs': [], 'atc': '', 'rec': ['ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose']}
    expect(mock_client, times=1).post(f"/identifiers/aid1/ipex/admit", json=body).thenReturn(mock_rep)
    rep = ipex.submitAdmit("aid1", exn=mock_admit, sigs=mock_gsigs, atc=mock_end, recp=recp)

    assert rep == dict(b='c')


def test_submit_offer():
    from signify.app.clienting import SignifyClient
    from requests import Response

    mock_client = mock(spec=SignifyClient, strict=True)
    mock_rep = mock(spec=Response, strict=True)

    expect(mock_rep).json().thenReturn(dict(b='c'))

    mock_offer = mock({'ked': dict(a='b')})
    mock_sigs = []
    mock_end = ""
    recp = ["ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose"]

    ipex = credentialing.Ipex(mock_client)  # type: ignore
    body = {'exn': {'a': 'b'}, 'sigs': [], 'atc': '', 'rec': ['ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose']}
    expect(mock_client, times=1).post(f"/identifiers/aid1/ipex/offer", json=body).thenReturn(mock_rep)
    rep = ipex.submitOffer("aid1", exn=mock_offer, sigs=mock_sigs, atc=mock_end, recp=recp)

    assert rep == dict(b='c')


def test_submit_agree():
    from signify.app.clienting import SignifyClient
    from requests import Response

    mock_client = mock(spec=SignifyClient, strict=True)
    mock_rep = mock(spec=Response, strict=True)

    expect(mock_rep).json().thenReturn(dict(b='c'))

    mock_agree = mock({'ked': dict(a='b')})
    mock_sigs = []
    recp = ["ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose"]

    ipex = credentialing.Ipex(mock_client)  # type: ignore
    body = {'exn': {'a': 'b'}, 'sigs': [], 'rec': ['ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose']}
    expect(mock_client, times=1).post(f"/identifiers/aid1/ipex/agree", json=body).thenReturn(mock_rep)
    rep = ipex.submitAgree("aid1", exn=mock_agree, sigs=mock_sigs, recp=recp)

    assert rep == dict(b='c')


def test_submit_grant():
    from signify.app.clienting import SignifyClient
    mock_client = mock(spec=SignifyClient, strict=True)

    from requests import Response
    mock_rep = mock(spec=Response, strict=True)

    expect(mock_rep).json().thenReturn(dict(b='c'))

    mock_admit = mock({'ked': dict(a='b')})
    mock_gsigs = []
    mock_end = ""
    recp = ["ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose"]

    ipex = credentialing.Ipex(mock_client)  # type: ignore
    body = {'exn': {'a': 'b'}, 'sigs': [], 'atc': '', 'rec': ['ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose']}
    expect(mock_client, times=1).post(f"/identifiers/aid1/ipex/grant", json=body).thenReturn(mock_rep)
    rep = ipex.submitGrant("aid1", exn=mock_admit, sigs=mock_gsigs, atc=mock_end, recp=recp)

    assert rep == dict(b='c')


def test_ipex_join_apply_posts_multisig_exn_with_original_proposal_attachment(make_mock_response):
    client, habitats, inner, posts = _join_harness(make_mock_response, proposal_atc="PROPATC8")

    result = credentialing.Ipex(client).join("group", "outer-said")

    assert result == {"name": "exchange.op", "done": False}
    assert len(posts) == 2
    post = posts[0]
    assert post["path"] == "/identifiers/group/ipex/apply"
    body = post["json"]
    assert body["rec"] == [habitats["recipient"]["prefix"]]
    assert body["exn"]["r"] == "/multisig/exn"
    assert body["exn"]["a"]["gid"] == habitats["group"]["prefix"]
    assert body["exn"]["e"]["exn"]["d"] == inner.said
    assert body["exn"]["e"]["exn"]["r"] == "/ipex/apply"
    assert "PROPATC8" in body["atc"]
    assert body["sigs"]

    peer_post = posts[1]
    assert peer_post["path"] == "/identifiers/local/exchanges"
    assert peer_post["json"]["rec"] == [habitats["peer"]["prefix"]]
    assert peer_post["json"]["exn"]["r"] == "/multisig/exn"
    assert peer_post["json"]["exn"]["e"]["exn"]["d"] == inner.said
    assert "PROPATC8" in peer_post["json"]["atc"]
    assert peer_post["json"]["sigs"]


@pytest.mark.parametrize(
    "route,endpoint",
    [
        ("/ipex/apply", "apply"),
        ("/ipex/offer", "offer"),
        ("/ipex/agree", "agree"),
        ("/ipex/grant", "grant"),
        ("/ipex/admit", "admit"),
    ],
)
def test_ipex_join_dispatches_supported_ipex_routes(route, endpoint, make_mock_response):
    client, _, _, posts = _join_harness(make_mock_response, route=route)

    credentialing.Ipex(client).join("group", "outer-said")

    assert posts[0]["path"] == f"/identifiers/group/ipex/{endpoint}"


@pytest.mark.parametrize(
    "exchange,match",
    [
        (
            lambda habitats, inner: _outer_exchange(
                inner,
                gid=habitats["group"]["prefix"],
                route="/ipex/apply",
            ),
            "expected /multisig/exn",
        ),
        (
            lambda habitats, inner: _outer_exchange(inner, gid=habitats["peer"]["prefix"]),
            "does not match group",
        ),
        (
            lambda habitats, inner: {
                "exn": {
                    "r": "/multisig/exn",
                    "a": {"gid": habitats["group"]["prefix"]},
                    "e": {},
                },
                "pathed": {},
            },
            "missing embedded exn",
        ),
        (
            lambda habitats, inner: {
                "exn": {
                    "r": "/multisig/exn",
                    "a": {"gid": habitats["group"]["prefix"]},
                    "e": {"exn": {**inner.ked, "i": habitats["peer"]["prefix"]}},
                },
                "pathed": {},
            },
            "does not match group",
        ),
        (
            lambda habitats, inner: {
                "exn": {
                    "r": "/multisig/exn",
                    "a": {"gid": habitats["group"]["prefix"]},
                    "e": {"exn": {**inner.ked, "a": {"m": ""}}},
                },
                "pathed": {},
            },
            "missing recipient",
        ),
        (
            lambda habitats, inner: _outer_exchange(
                _inner_ipex(
                    "/ipex/spurn",
                    sender=habitats["group"]["prefix"],
                    recipient=habitats["recipient"]["prefix"],
                ),
                gid=habitats["group"]["prefix"],
            ),
            "unsupported embedded IPEX route",
        ),
    ],
)
def test_ipex_join_rejects_invalid_multisig_ipex_proposals(exchange, match, make_mock_response):
    def exchange_factory(habitats, inner):
        return exchange(habitats, inner)

    client, _, _, posts = _join_harness(
        make_mock_response,
        exchange_factory=exchange_factory,
        expect_posts=False,
    )

    with pytest.raises(ValueError, match=match):
        credentialing.Ipex(client).join("group", "outer-said")

    assert posts == []


def test_ipex_join_requires_peer_signing_members(make_mock_response):
    client, _, _, posts = _join_harness(
        make_mock_response,
        members_factory=lambda habitats: {"signing": [{"aid": habitats["member"]["prefix"]}], "rotation": []},
        expect_posts=False,
    )

    with pytest.raises(ValueError, match="no peer signing members"):
        credentialing.Ipex(client).join("group", "outer-said")

    assert posts == []
