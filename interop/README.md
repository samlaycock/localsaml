# Interop harness

SAML has no equivalent of the OpenID Foundation conformance suite, so localsaml is tested against the service-provider implementations apps actually use. `run.mjs` builds localsaml, starts it on port 9411 with a throwaway key and data directory, and plays service providers built on five SAML stacks, against the root issuer and every template issuer (`/p/<id>`).

The stacks were chosen so that signatures, canonicalization and decryption are checked by independent XML-security implementations, not just one:

| Stack | XML signatures and encryption | How it runs |
|---|---|---|
| [`@node-saml/node-saml`](https://github.com/node-saml/node-saml) 5.2 (behind passport-saml) | xml-crypto, xml-encryption | in-process |
| [`samlify`](https://github.com/tngan/samlify) 2.15 | xml-crypto, @authenio/xml-encryption | in-process |
| [pysaml2](https://github.com/IdentityPython/pysaml2) 7.5.5 | the `xmlsec1` binary (libxmlsec1 1.2.37, libxml2) | Docker: [`stacks/pysaml2`](stacks/pysaml2) |
| [crewjam/saml](https://github.com/crewjam/saml) 0.5.1 | goxmldsig (Go) | Docker: [`stacks/crewjam`](stacks/crewjam) |
| [Shibboleth SP](https://shibboleth.atlassian.net/wiki/spaces/SP3) 3.4.1 (Apache mod_shib + shibd) | OpenSAML C++, xml-security-c | Docker: [`stacks/shibboleth`](stacks/shibboleth) |

node-saml and samlify share xml-crypto, so the other three are what make the results independent.

```sh
cd interop
npm ci
node run.mjs                 # everything (about 40 seconds once the images are built)
node run.mjs --only okta     # one issuer: root, generic, entra, adfs, okta, ...
node run.mjs --stacks node,shibboleth   # some stacks: node, pysaml2, crewjam, shibboleth
node run.mjs --no-build      # use the existing target/debug/localsaml
node run.mjs --binary ../target/release/localsaml
node run.mjs --require-stacks           # fail instead of skipping the Docker stacks (CI)
node run.mjs --port 9511 --shibboleth-port 9512   # other ports (e.g. next to another run)
node run.mjs --image-tag mybranch       # tag the stacks' images localsaml-interop-<stack>:mybranch
node run.mjs --no-image-build           # use the stacks' images as they are (CI builds them)
node run.mjs --verbose       # stack traces and the server log for failures
```

It needs Node.js 20+, `openssl` (to make the service providers' key and certificate) and a Rust toolchain unless you pass `--binary` or `--no-build`. pysaml2, crewjam and Shibboleth SP need Docker; their images (`localsaml-interop-<stack>:latest`, or `--image-tag`) are built from `stacks/` at the start of each run, which is quick once Docker has cached the layers. Without Docker those stacks are skipped (and reported as skipped), unless `--require-stacks` is given. localsaml listens on port 9411 (`--port`) and Shibboleth SP is published on port 9412 (`--shibboleth-port`). To run beside another checkout's run, give both ports and an `--image-tag`, so neither run rebuilds the other's images. It exits non-zero if any check fails.

In CI (the `interop` job in `.github/workflows/ci.yml`), the three images are built with `docker/build-push-action` and the GitHub Actions cache (one cache scope per image) and loaded into Docker; the harness then runs with `--no-image-build --require-stacks`.

## What it checks

For each issuer and stack, with the stack's signature checks set to match the template (e.g. Entra ID signs only the assertion, Keycloak only the response):

- **SP-initiated login.** Over the Redirect and POST bindings, with signed and unsigned AuthnRequests. Logins are finished with `dev_attributes`, `dev_user` (a `[[users]]` entry in the generated `localsaml.toml`) and the login form (`POST /login` with `preset` and `identity`). The stacks validate the Response, including `InResponseTo`. The NameID, NameID format and attributes (single and multi-valued) are checked.
- **localsaml verifies the stacks' signatures.** The harness's service providers are declared with their certificate, so localsaml really checks the signed AuthnRequests from xmlsec1, goxmldsig and OpenSAML (query signatures and enveloped XML signatures). A pysaml2 or crewjam request changed after signing must be refused with "Invalid AuthnRequest signature". The Shibboleth SP is declared with `want_authn_requests_signed`, so its logins only work if its signatures verify.
- **ECP.** The harness is the enhanced client: it gets a signed PAOS AuthnRequest from Shibboleth SP's session initiator, relays it to localsaml's SOAP SingleSignOnService with HTTP Basic credentials, checks that the `ecp:Response` header names the `responseConsumerURL` Shibboleth gave, and relays the Response (with Shibboleth's `ecp:RelayState`) back to Shibboleth's PAOS ACS, which must create a session. (mod_shib declines ECP on a protected path under Apache 2.4, so the harness starts at `/Shibboleth.sso/Login`.)
- **HTTP-Artifact.** Shibboleth SP asks for its Response by artifact (its HTTP-Artifact ACS, from its own metadata), then resolves the artifact itself with a signed ArtifactResolve over SOAP to localsaml's ArtifactResolutionService (from its container, at `host.docker.internal`; on Linux localsaml listens on all interfaces for it). It must accept the signed ArtifactResponse and create a session, and a replayed artifact must fail. The harness lets Shibboleth resolve over plain HTTP (`requireConfidentiality="false"`), so the ArtifactResponse's signature is what it trusts.
- **Attribute queries.** pysaml2 builds and signs an `AttributeQuery` for the declared user (all attributes, then just one), the harness POSTs it to localsaml's AttributeService, and pysaml2 validates the answer: signatures, InResponseTo, the subject and the attributes. pysaml2's own SOAP unwrapping re-serializes the Response with its own prefixes, which breaks any Exclusive C14N signature made with other prefixes, so the harness hands pysaml2 the Response exactly as it was in the envelope.
- **Encrypted NameIDs.** pysaml2 and Shibboleth SP must decrypt an `EncryptedID` minted with `encrypt_name_id` to the NameID localsaml says it issued. node-saml, samlify and crewjam/saml accept a Response with an EncryptedID but don't decrypt it, so they aren't checked. Encrypted attributes aren't checked by any stack: pysaml2 7.5's EncryptedAttribute decryption is broken (it passes an object where xmlsec1 needs text), and OpenSAML C++ rejects an AttributeStatement holding only EncryptedAttributes (its schema validator requires a plain Attribute); localsaml's own tests decrypt them.
- **Encrypted assertions.** RSA-OAEP key transport with AES-256-GCM and AES-128-CBC (node-saml, samlify, pysaml2), AES-128-GCM and AES-256-CBC (crewjam), and AES-256-GCM (Shibboleth SP).
- **IdP-initiated SSO.** `/sso/initiate?sp=…`, an unsolicited Response with RelayState.
- **Single logout.** Each stack does an SP-initiated logout and validates localsaml's signed LogoutResponse: Redirect binding for node-saml, samlify, pysaml2 and Shibboleth SP, POST binding for crewjam. Shibboleth SP's logout must end its own session too. Google Workspace advertises no SLO.
- **IdP-propagated single logout.** Two service providers share one browser session (the harness's cookie jar): node-saml logs out, localsaml sends the other SP a signed LogoutRequest, collects its LogoutResponse, and only then answers node-saml. node-saml must get a signed LogoutResponse with status `Success` and no `PartialLogout` second-level status, with its RelayState back, and localsaml's session cookie must be gone. The other SP is each of:
  - **samlify** (Redirect binding), which parses the LogoutRequest and answers.
  - **pysaml2** (Redirect binding). pysaml2 verifies the query signature; the harness checks the Issuer, Destination, NameID and SessionIndex against what it got in its assertion, and pysaml2 answers with a LogoutResponse signed in the query string.
  - **crewjam/saml** (POST binding, `slo_binding = "post"`). The enveloped signature is verified with goxmldsig against the IdP metadata's signing certificates, the same checks are made, and crewjam answers with a signed, POSTed LogoutResponse.
  - **Shibboleth SP** (Redirect binding, through the browser). Shibboleth requires a verified signature on a LogoutRequest; it must end its session (its Session handler shows none afterwards) and redirect a LogoutResponse back to localsaml.

  A LogoutRequest changed after signing (RelayState for the Redirect binding, IssueInstant in crewjam's XML) must be rejected by pysaml2, crewjam and Shibboleth SP for its signature, and Shibboleth's session must survive it. A pysaml2, crewjam or Shibboleth SP LogoutResponse changed after signing must make localsaml answer node-saml with `PartialLogout`, so the `Success` above means localsaml verified the other SP's answer.
- **Defects are rejected.** Responses minted with `/dev/api/response?tamper=…` (bad signature, untrusted certificate, wrong audience, issuer, recipient or destination, expired, not yet valid, unsigned, SHA-1) and with an error status must be rejected. For Shibboleth SP they're posted straight to its ACS, and must not create a session. An untouched minted Response must be accepted.
- **Key rotation.** After `POST /dev/api/rotate-keys`, the metadata lists the new and the old certificate. For every stack, Responses issued before and after the rotation verify against it, and an SP pinned to the old certificate rejects the new ones (samlify only checks the post-rotation Response). pysaml2 and crewjam are given the refreshed or the old metadata per call. Shibboleth SP still has the old metadata loaded when the rotation happens, so it is the pinned SP first: a post-rotation Response is posted and must be rejected for its signature. Then the harness replaces its metadata file (the `MetadataProvider`s have `reloadChanges="true"`), and a pre-rotation and a fresh post-rotation Response must be accepted. Shibboleth remembers Response IDs it has seen, even rejected ones, so no Response is posted to it twice. The rotation runs once, after every other check, on the root issuer (or the one `--only` names), because it changes the signing key under every issuer.
- Registering a service provider over `POST /dev/api/service-providers`.

The service providers the harness plays are declared in the generated `localsaml.toml`, with their certificate, ACS and SLO URLs. Some of them have `encrypt_assertions` set. The Shibboleth SP's `shibboleth2.xml` and `attribute-map.xml` are generated too, trusting the metadata of every issuer being tested; see `shibConfig` in `run.mjs`.

## How the Docker stacks are driven

pysaml2 and crewjam run as long-lived helpers ([`stacks/pysaml2/sp.py`](stacks/pysaml2/sp.py), [`stacks/crewjam/main.go`](stacks/crewjam/main.go)) that read one JSON command per line on stdin (`login`, `parse_response`, `logout`, `parse_logout_response`, `handle_logout_request`) and answer on stdout. They keep no state between commands; each one carries the IdP metadata and the SP's settings. The harness plays the browser: it follows the redirects and posts the forms, and asks the helper to build requests and validate what localsaml sent back. They need no network access.

Shibboleth SP runs as a real web server (Apache's `ServerName` is set from the `SHIB_URL` the harness passes, so it matches `--shibboleth-port`). The harness, as the browser, starts logins at `/Shibboleth.sso/Login` (Redirect binding) and `/Shibboleth.sso/LoginPost` (POST binding), finishes them at localsaml, posts the Response to Shibboleth's ACS, and reads the result from Shibboleth's Session handler (`/Shibboleth.sso/Session`, as JSON). The container only needs the generated configuration; it never calls localsaml itself.

## Library behaviour worth knowing

These aren't localsaml bugs, but apps using these libraries will run into them too:

- **samlify** refuses to sign AuthnRequests unless the IdP metadata says `WantAuthnRequestsSigned="true"`. It requires that flag to match the SP's `AuthnRequestsSigned`. localsaml's metadata says `false`, though it verifies signed requests from service providers it has a certificate for. The harness sets the flag in the metadata it gives samlify.
- **samlify** signs POST-binding AuthnRequests at its default signature location, `Response/Issuer`, when the SP sets `wantMessageSigned`, and fails because an AuthnRequest has no such element. Set `signatureConfig.location` to `AuthnRequest/Issuer`.
- **samlify**'s Redirect-binding parsers take the decoded query (as a web framework parses it) plus the raw `octetString` that was signed. `parseLogoutRequest` only checks the signature if `wantLogoutRequestSigned` is set.
- **node-saml 5** only logs (`NODE_DEBUG=node-saml`) a `Recipient` or `Destination` that isn't the ACS URL; it doesn't reject it. So those defects aren't checked against node-saml.
- **pysaml2** doesn't check `SubjectConfirmationData/@Recipient`, so that defect isn't checked against it. It drops a Response with the wrong `Destination` by returning no assertion rather than raising.
- **node-saml and Shibboleth SP** accept RSA-SHA1 signatures by default. samlify rejects them when `allowedSignatureAlgorithms` excludes SHA-1.
- **crewjam/saml** can't decrypt AES-256-GCM (it has AES-128-GCM and AES-CBC). localsaml's default encryption algorithm is AES-256-GCM, so a crewjam SP needs `encryption_algorithm = "aes128-gcm"`, including for templates that encrypt by default (Shibboleth).
- **crewjam/saml** only validates a LogoutResponse with an embedded XML signature, even over the Redirect binding, where the SAML bindings spec puts the signature in the query string. localsaml signs Redirect-binding messages in the query, so crewjam SPs use the POST binding for logout (`slo_binding = "post"`).
- **crewjam/saml** has no API for a service provider to validate a LogoutRequest from the IdP (only LogoutResponses), so the harness's crewjam helper checks one itself, as crewjam checks LogoutResponses: an enveloped goxmldsig signature by a signing certificate in the IdP metadata. crewjam also only signs the LogoutResponse it makes (and other messages) when `SignatureMethod` is set.
- **pysaml2** only checks the query signature of a Redirect-binding LogoutRequest an SP receives if its *IdP-side* setting `want_authn_requests_signed` is on (it reads that setting for every incoming request, even as an SP). Otherwise a LogoutRequest whose RelayState or query was changed after signing is accepted. The harness's pysaml2 helper sets it (`config.setattr("idp", "want_authn_requests_signed", True)`). pysaml2 also re-encodes the query parameters to rebuild the signed string, rather than using the raw query.
- **crewjam/saml** asks for transient NameIDs unless `AuthnNameIDFormat` is set, and its `ParseResponse` expects the request's form to be parsed already (its middleware does that).
- **Shibboleth SP** only keeps attributes named in `attribute-map.xml`, matched by name and `NameFormat`. Attributes without a `NameFormat` (Entra ID, AD FS) match rules with the `unspecified` format.
- **Shibboleth SP** remembers the ID of every Response posted to it, rejected or not, and refuses it a second time. It reads local metadata files once unless the `MetadataProvider` has `reloadChanges="true"`.
- `@authenio/samlify-node-xmllint` (samlify's schema validator) adds event listeners on every validation, so the harness raises Node's listener limit.
