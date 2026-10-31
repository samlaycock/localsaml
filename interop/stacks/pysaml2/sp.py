"""A pysaml2 service provider for the localsaml interop harness.

Reads one JSON command per line on stdin and writes one JSON result per line on stdout, so
run.mjs can play the browser while pysaml2 builds requests and validates what localsaml sends.
Signing, verification and decryption go through the xmlsec1 binary, independently of the
JavaScript libraries the harness also uses.
"""

import json
import os
import re
import sys
import tempfile
import traceback
from html import unescape

from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT, BINDING_SOAP
from saml2.pack import make_soap_enveloped_saml_thingy
from saml2.response import AttributeResponse
from saml2.client import Saml2Client
from saml2.config import SPConfig
from saml2.saml import NameID
from saml2.xmldsig import DIGEST_SHA256, SIG_RSA_SHA256

TMP = tempfile.mkdtemp()


def files(sp):
    key, cert = os.path.join(TMP, "sp.key"), os.path.join(TMP, "sp.crt")
    with open(key, "w") as f:
        f.write(sp["key"])
    with open(cert, "w") as f:
        f.write(sp["cert"])
    return key, cert


def client(c):
    sp = c["sp"]
    key, cert = files(sp)
    conf = SPConfig()
    conf.load({
        "entityid": sp["entity_id"],
        "xmlsec_binary": "/usr/bin/xmlsec1",
        "key_file": key,
        "cert_file": cert,
        "encryption_keypairs": [{"key_file": key, "cert_file": cert}],
        "metadata": {"inline": [c["idp_metadata"]]},
        "allow_unknown_attributes": True,
        "accepted_time_diff": 5,
        "signing_algorithm": SIG_RSA_SHA256,
        "digest_algorithm": DIGEST_SHA256,
        "service": {
            "sp": {
                "endpoints": {
                    "assertion_consumer_service": [(sp["acs"], BINDING_HTTP_POST)],
                    "single_logout_service": [(sp["slo"], BINDING_HTTP_REDIRECT)],
                },
                "allow_unsolicited": True,
                "authn_requests_signed": bool(c.get("sign")),
                "logout_requests_signed": True,
                "want_assertions_signed": bool(c.get("want_assertions_signed")),
                "want_response_signed": bool(c.get("want_response_signed")),
                "name_id_format": [sp.get("name_id_format")] if sp.get("name_id_format") else [],
            }
        },
    })
    return Saml2Client(config=conf), list(conf.metadata.identity_providers())[0]


def post_form(html):
    fields = dict((k, unescape(v)) for k, v in re.findall(r'name="(SAMLRequest|SAMLResponse|RelayState)" value="([^"]*)"', html))
    action = unescape(re.search(r'action="([^"]*)"', html).group(1))
    return {"action": action, "form": fields}


def location(info):
    return dict(info["headers"])["Location"]


def run(c):
    sp, idp = client(c)
    op = c["op"]
    sigalg = SIG_RSA_SHA256 if c.get("sign") else None
    if op == "login":
        binding = BINDING_HTTP_POST if c.get("binding") == "post" else BINDING_HTTP_REDIRECT
        req_id, info = sp.prepare_for_authenticate(
            entityid=idp,
            relay_state=c.get("relay_state", ""),
            binding=binding,
            sign=bool(c.get("sign")),
            sigalg=sigalg,
            digest_alg=DIGEST_SHA256 if c.get("sign") else None,
            nameid_format=c["sp"].get("name_id_format"),
        )
        if binding == BINDING_HTTP_POST:
            return {"id": req_id, **post_form(info["data"])}
        return {"id": req_id, "url": location(info)}
    if op == "parse_response":
        outstanding = {i: "/" for i in c.get("request_ids") or []}
        resp = sp.parse_authn_request_response(c["saml_response"], BINDING_HTTP_POST, outstanding=outstanding)
        if resp is None:
            raise Exception("pysaml2 returned no response")
        if resp.assertion is None:
            # pysaml2 logs and drops Responses it won't accept (e.g. a wrong Destination).
            raise Exception("pysaml2 accepted no assertion from the Response")
        attrs = {}
        for statement in resp.assertion.attribute_statement:
            for a in statement.attribute:
                attrs.setdefault(a.name, []).extend(v.text or "" for v in a.attribute_value)
        authn = resp.assertion.authn_statement
        return {
            "name_id": resp.name_id.text,
            "name_id_format": resp.name_id.format,
            "attributes": attrs,
            "session_index": authn[0].session_index if authn else None,
        }
    if op == "logout":
        name_id = NameID(text=c["name_id"], format=c.get("name_id_format"))
        destination = sp.metadata.single_logout_service(idp, BINDING_HTTP_REDIRECT, "idpsso")[0]["location"]
        req_id, request = sp.create_logout_request(
            destination, idp, name_id=name_id, session_indexes=[c["session_index"]] if c.get("session_index") else None
        )
        info = sp.apply_binding(BINDING_HTTP_REDIRECT, str(request), destination, c.get("relay_state", ""), sign=True, sigalg=SIG_RSA_SHA256)
        return {"id": req_id, "url": location(info)}
    if op == "attribute_query":
        # A signed AttributeQuery in a SOAP envelope, for the harness to POST to the AttributeService.
        destination = sp.metadata.attribute_service(idp, BINDING_SOAP)[0]["location"]
        attributes = {n: None for n in c.get("attributes") or []}
        req_id, request = sp.create_attribute_query(
            destination, name_id=NameID(text=c["name_id"], format=c.get("name_id_format")),
            attribute=attributes or None, sign=True, sign_alg=SIG_RSA_SHA256, digest_alg=DIGEST_SHA256,
        )
        return {"id": req_id, "destination": destination, "envelope": make_soap_enveloped_saml_thingy(request)}
    if op == "parse_attribute_response":
        # pysaml2's SOAP unwrapping re-serializes the Response with its own prefixes (ns0:…),
        # which breaks any Exclusive C14N signature made with other prefixes. The harness passes
        # the Response exactly as it was in the envelope (base64, as the POST binding carries it).
        # This is parse_attribute_query_response with its SOAP-binding settings (asynchop=False:
        # InResponseTo is checked below) but the POST binding's unravelling.
        resp = sp._parse_response(
            c["saml_response"], AttributeResponse, "attribute_consuming_service", BINDING_HTTP_POST,
            entity_id=sp.config.entityid, attribute_converters=sp.config.attribute_converters, asynchop=False,
        )
        if resp is None or resp.assertion is None:
            raise Exception("pysaml2 accepted no assertion from the attribute query Response")
        if resp.in_response_to != c["id"]:
            raise Exception(f"InResponseTo {resp.in_response_to}, expected {c['id']}")
        attrs = {}
        for statement in resp.assertion.attribute_statement:
            for a in statement.attribute:
                attrs.setdefault(a.name, []).extend(v.text or "" for v in a.attribute_value)
        return {"name_id": resp.assertion.subject.name_id.text, "attributes": attrs}
    if op == "parse_logout_response":
        resp = sp.parse_logout_request_response(c["saml_response"], BINDING_HTTP_REDIRECT)
        if resp is None:
            raise Exception("pysaml2 returned no logout response")
        status = resp.response.status.status_code.value
        if not status.endswith(":Success"):
            raise Exception(f"status {status}")
        return {"in_response_to": resp.response.in_response_to, "status": status}
    if op == "handle_logout_request":
        # A LogoutRequest from localsaml (Redirect binding), propagating another SP's logout.
        # pysaml2 decides whether a Redirect-binding request needs a query signature from its *IdP*
        # setting want_authn_requests_signed, even when it acts as an SP; without it, it doesn't
        # check the signature at all.
        if c.get("require_signature", True):
            sp.config.setattr("idp", "want_authn_requests_signed", True)
        req = sp.parse_logout_request(
            c["saml_request"],
            BINDING_HTTP_REDIRECT,
            relay_state=c.get("relay_state"),
            sigalg=c.get("sigalg"),
            signature=c.get("signature"),
        )
        if req is None:
            raise Exception("pysaml2 returned no logout request")
        msg = req.message
        if msg.issuer.text.strip() != idp:
            raise Exception(f"Issuer {msg.issuer.text}")
        if msg.destination != c["sp"]["slo"]:
            raise Exception(f"Destination {msg.destination}")
        if msg.name_id is None or msg.name_id.text != c["name_id"]:
            raise Exception(f"NameID {msg.name_id and msg.name_id.text}, expected {c['name_id']}")
        indexes = [s.text for s in msg.session_index or []]
        if c.get("session_index") and c["session_index"] not in indexes:
            raise Exception(f"SessionIndex {indexes}, expected {c['session_index']}")
        response = sp.create_logout_response(msg, [BINDING_HTTP_REDIRECT], sign=False)
        rinfo = sp.response_args(msg, [BINDING_HTTP_REDIRECT])
        info = sp.apply_binding(
            rinfo["binding"], str(response), rinfo["destination"], c.get("relay_state"),
            response=True, sign=True, sigalg=SIG_RSA_SHA256,
        )
        return {"id": msg.id, "name_id": msg.name_id.text, "session_index": indexes, "url": location(info)}
    raise Exception(f"unknown op {op}")


for line in sys.stdin:
    try:
        result = run(json.loads(line))
        result["ok"] = True
    except Exception as e:  # report every failure to the harness
        result = {"ok": False, "error": f"{type(e).__name__}: {e}"[:600], "trace": traceback.format_exc()[-1500:]}
    sys.stdout.write(json.dumps(result) + "\n")
    sys.stdout.flush()
