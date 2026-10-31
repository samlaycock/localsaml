# localsaml

[![CI](https://github.com/samlaycock/localsaml/actions/workflows/ci.yml/badge.svg)](https://github.com/samlaycock/localsaml/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/samlaycock/localsaml)](https://github.com/samlaycock/localsaml/releases)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)

A local SAML 2.0 identity provider for offline development and testing. It's a single Rust binary (or Docker image) with no external services, and it can pretend to be Microsoft Entra ID, Okta, AD FS, Google Workspace and seven other identity providers. It's the SAML sibling of [localoidc](https://github.com/samlaycock/localoidc).

- **An attribute editor instead of a password prompt.** At login you pick an identity provider to emulate and set exactly what goes into the assertion: the NameID and every attribute.
- **Identity provider templates.** It reproduces the attribute names, NameID formats, signing behaviour, XML style and endpoint paths of Entra ID, AD FS, Okta, Google Workspace, OneLogin, Auth0, Keycloak, PingFederate, JumpCloud and Shibboleth. Your app sees the same shapes it will see in production.
- **The whole protocol.** It supports the HTTP-Redirect and HTTP-POST bindings, signed AuthnRequests, signed responses and assertions, encrypted assertions, IdP-initiated SSO, ForceAuthn and IsPassive, NameID policies, and single logout across several service providers.
- **See every message.** The request inspector at `/dev/requests` decodes every AuthnRequest, Response and logout message into readable XML. It also shows the exact reason anything was rejected, like a SAML tracer that's always on.
- **A built-in test SP.** `/sp` starts logins and validates the Response the way a strict service provider would, so you can try everything before your app exists.
- **Mint responses without a login.** You can do it from a web page (`/dev`) or a JSON API (`/dev/api/response`), and post them straight to your ACS.
- **Built for automated tests.** Sign in from Playwright or Cypress with a single query parameter, or turn on auto-login. [Fault injection](#injecting-faults) returns SAML error statuses and deliberately broken responses (bad signatures, wrong audience, expired, replayed). A [shifted clock](#shifting-the-clock) tests your skew handling, and [declared users](#declared-users) give a team and its CI the same named identities.

> [!WARNING]
> localsaml is for development and testing only. It accepts any service provider by default, lets anyone sign in or mint assertions as any identity, and serves unauthenticated endpoints for minting responses and rotating keys. Its signing key is not a secret, and its dev API answers cross-origin requests, so any page you visit while it runs could mint assertions or change its settings. Never expose it to the internet or trust it to protect real data.

## Contents

- [Installation](#installation)
- [Quick start](#quick-start)
- [Endpoints and protocol support](#endpoints-and-protocol-support)
- [Identity provider templates](#identity-provider-templates)
- [The test SP](#the-test-sp)
- [Minting responses for development and tests](#minting-responses-for-development-and-tests)
- [Single logout](#single-logout)
- [Inspecting requests](#inspecting-requests)
- [Configuration](#configuration)
- [Interop testing](#interop-testing)
- [Contributing](#contributing)
- [License](#license)

## Installation

**Docker** (linux/amd64 and linux/arm64):

```sh
docker run --rm -p 9401:9401 -v localsaml:/data ghcr.io/samlaycock/localsaml
```

The image is tagged `:<version>`, `:<major>.<minor>` (and `:<major>` from 1.0) and `:latest`. It runs as a non-root user and keeps its state in the `/data` volume. Pass flags after the image name, e.g. `docker run … ghcr.io/samlaycock/localsaml --auto-login`.

**From source** (needs a recent stable Rust toolchain):

```sh
cargo install --git https://github.com/samlaycock/localsaml --locked
localsaml
```

Or clone the repository and run `cargo run --release`.

localsaml listens on port 9401, so it can run next to localoidc (9400).

## Quick start

Start localsaml with either command above. It serves http://localhost:9401.

Most service provider libraries can be configured from the identity provider's metadata, at `http://localhost:9401/metadata`. If yours wants the settings one by one:

| Setting | Value |
|---|---|
| IdP entity ID / issuer | `http://localhost:9401/metadata` |
| SSO URL (Redirect and POST bindings) | `http://localhost:9401/sso` |
| SLO URL (Redirect and POST bindings) | `http://localhost:9401/slo` |
| Signing certificate | `http://localhost:9401/certificate.pem`, or the SHA-1/SHA-256 fingerprint shown on the home page |

For example, with [`@node-saml/passport-saml`](https://github.com/node-saml/passport-saml):

```js
new SamlStrategy({
  entryPoint: "http://localhost:9401/sso",
  logoutUrl: "http://localhost:9401/slo",
  idpCert: await (await fetch("http://localhost:9401/certificate.pem")).text(),
  issuer: "http://localhost:3000/saml/metadata",  // your SP's entity ID: anything
  callbackUrl: "http://localhost:3000/saml/acs",
}, verify, verify);
```

Any service provider entity ID and ACS URL is accepted unless you [declare service providers](#service-providers). When your app redirects to the login page, pick a template, adjust the attributes and sign in. The Response is posted back to your ACS URL.

To try a login before your app exists, open http://localhost:9401/sp ([the test SP](#the-test-sp)). To get a signed Response without a browser:

```sh
curl -s 'http://localhost:9401/dev/api/response?sp=http://localhost:3000/saml/metadata&acs_url=http://localhost:3000/saml/acs&email=me@example.com' | jq -r .saml_response
```

To make localsaml look like a specific identity provider, use that template's issuer, for example `http://localhost:9401/p/okta/metadata`. See [Identity provider templates](#identity-provider-templates).

## Endpoints and protocol support

| What | Where |
|---|---|
| Metadata | `/metadata` (`?signed=true` for signed metadata) |
| Single sign-on (HTTP-Redirect, HTTP-POST; SOAP for ECP) | `/sso` |
| Single logout (HTTP-Redirect, HTTP-POST, SOAP) | `/slo` |
| Artifact resolution (SOAP) | `/artifact` |
| Attribute queries (SOAP) | `/attribute` |
| IdP-initiated SSO (non-standard) | `/sso/initiate?sp=<entity ID>[&RelayState=…][&acs=…]` |
| IdP-initiated logout (non-standard) | `/slo/initiate[?sid=…][&return_to=…]` |
| Signing certificate | `/certificate.pem` |
| Test SP (non-standard) | `/sp`, metadata `/sp/metadata` |
| Assertion generator UI (non-standard) | `/dev` |
| Response API (non-standard) | `/dev/api/response` (GET/POST) |
| Service providers (non-standard) | `/dev/api/service-providers` (GET/POST/DELETE) |
| Templates (non-standard) | `/dev/api/presets` |
| Declared users (non-standard) | `/dev/api/users` |
| Certificate and key rotation (non-standard) | `/dev/api/certificate`, `POST /dev/api/rotate-keys` |
| Clock offset (non-standard) | `/dev/api/clock` (GET/POST) |
| Sessions (non-standard) | `/dev/api/sessions` (GET), `/dev/api/sessions/{sid}` (DELETE) |
| Fault injection (non-standard) | `/dev/api/faults` (GET/POST/DELETE), `/dev/api/faults/{id}` (DELETE) |
| Request inspector (non-standard) | `/dev/requests`, `/dev/api/requests` (GET/DELETE) |
| Health check | `/health` |

Every template issuer serves the same endpoints under `/p/<template>`, plus that provider's own paths (see below). `/sso` and `/slo` accept any SAML message, so a template whose real SSO endpoint also handles logout (Entra ID, AD FS, Keycloak) works the same way.

### Supported protocol features

- **Bindings:** AuthnRequests and logout messages over HTTP-Redirect (DEFLATE, with query-string signatures) and HTTP-POST (with enveloped XML signatures). Responses are sent with HTTP-POST, or with [HTTP-Artifact](#http-artifact) when the AuthnRequest's `ProtocolBinding` asks for it.
- **AuthnRequests:** `AssertionConsumerServiceURL` or `AssertionConsumerServiceIndex`, `ForceAuthn`, `IsPassive` (a `NoPassive` status without a session), `NameIDPolicy/@Format` and `SPNameQualifier`, `RequestedAuthnContext` (the first requested class is used), `ProviderName`, and `Subject/NameID`: it pre-fills the login page and the assertion is always about that subject (Profiles 4.1.4.1). `login_hint` in the query pre-fills it too, as it does with Entra ID. `Scoping`: localsaml never proxies, so an `IDPList` that doesn't name it gets a `NoSupportedIDP` error Response; `RequesterID`s are shown on the login page. A request whose `Destination` isn't where it was sent is discarded with a `Requester` error Response (Core 3.2.1). A stale `IssueInstant` or RelayState over 80 bytes is reported on the login page and in the inspector, not rejected. ACS, SLO and return URLs must be http(s). A request that can't be answered with a SAML error Response (no service provider or ACS to trust) gets an error page with HTTP 400, its title in the `x-localsaml-error` header.
- **Request signatures:** when a service provider has a certificate (declared, or from its metadata), its signed requests are verified and an invalid signature is rejected. `want_authn_requests_signed` (or `AuthnRequestsSigned="true"` in its metadata) rejects unsigned AuthnRequests, and `want_logout_signed` unsigned logout messages (SAML Profiles 4.4.4.2 requires them signed; it's off by default so SPs that don't sign logout still work). Without a certificate, signatures are noted but not checked. RSA (SHA-1/256/512) and DSA (SHA-1/256) signatures are verified, including the DER-encoded DSA signatures Java stacks put in Redirect binding query strings. A query string with a SAML parameter twice is refused, so the message that's verified is always the one that's processed.
- **Responses:** RSA-SHA256 by default (RSA-SHA512 and RSA-SHA1 too), with Exclusive XML Canonicalization and the certificate in `KeyInfo`. Whether the Response, the Assertion or both are signed follows the template, and can be overridden per service provider. Bearer subject confirmation, `Conditions` with an `AudienceRestriction`, an `AuthnStatement` with a `SessionIndex`, and an `AttributeStatement`.
- **Encrypted assertions:** `EncryptedAssertion` with AES-256-GCM (default), AES-128-GCM, AES-256-CBC or AES-128-CBC, and RSA-OAEP key transport, for service providers with an encryption certificate.
- **Encrypted NameIDs:** an `EncryptedID` instead of the NameID (with the key inside the EncryptedData, so service providers that decrypt it on its own can), for service providers with `encrypt_name_id = true` or whose AuthnRequest asks for `NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted"` (`InvalidNameIDPolicy` if there's no encryption certificate). LogoutRequests to them carry an `EncryptedID` too, and LogoutRequests with one, encrypted for localsaml's certificate, are decrypted.
- **Encrypted attributes:** with `encrypt_attributes = true`, each attribute is sent as an `EncryptedAttribute`. Few service providers handle them: Shibboleth SP (OpenSAML C++) rejects an AttributeStatement that holds only EncryptedAttributes, and pysaml2 7.5 fails to decrypt them, so check yours does before relying on it.
- **NameIDs:** the template's format by default, or the one `NameIDPolicy` asks for. Email-address NameIDs follow the email attribute. Persistent NameIDs are pairwise (stable per user and service provider, like Entra ID's and Shibboleth's), and transient ones are new each session. You can also type any NameID in the login form.
- **Sessions:** a cookie per issuer. With `--silent-sso` a second service provider gets an assertion without seeing the login page, like a production IdP. Otherwise the login page offers the active session as a one-click option, so you can still change identities. `ForceAuthn` always shows the login page and restarts the `AuthnInstant`.
- **IdP-initiated SSO:** unsolicited Responses (no `InResponseTo`) to a service provider's default ACS URL, with a `RelayState`. The template aliases work too, e.g. Shibboleth's `/idp/profile/SAML2/Unsolicited/SSO?providerId=…` and PingFederate's `/idp/startSSO.ping?PartnerSpId=…`.
- **ECP:** enhanced clients (Profiles 4.2) relay a service provider's PAOS AuthnRequest to `/sso` in a SOAP envelope, with HTTP Basic credentials: a declared user's id, email or NameID, or any other login, which pre-fills the template's identity like a login hint. Any password is accepted, and a missing `Authorization` header gets a 401 asking for one. The AuthnRequest is checked like any other, and the Response comes back in a SOAP envelope with an `ecp:Response` header naming the ACS. Errors that would be pages in a browser are SOAP faults. Declare an SP's PAOS ACSs with `acs_ecp_urls` (they're read from its metadata too).
- **Attribute queries:** localsaml is also an attribute authority (`AttributeAuthorityDescriptor` in the metadata). A service provider POSTs an `AttributeQuery` in a SOAP envelope to `/attribute` and gets a Response with an assertion about the NameID it asked about: the attributes of the session in which it was given that NameID, or of the declared user with it, filtered to the attributes (and values) the query names. The assertion is signed (and encrypted, like that SP's assertions), with a sender-vouches `SubjectConfirmation` for that SP and no `AuthnStatement`. An unknown NameID gets `UnknownPrincipal`. A signed query is verified against the SP's certificate. The test SP has a **Query attributes** button.
- **[Single logout](#single-logout):** SP-initiated and IdP-initiated. Every other service provider in the session is sent a signed LogoutRequest in turn, then the initiator gets a LogoutResponse (`PartialLogout` if some didn't answer `Success`).

**Not implemented:** IdP proxying, and AuthnRequests sent by artifact. A request asking for any other response binding gets an HTTP-POST Response, with a warning.

### HTTP-Artifact

- An AuthnRequest with `ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"` gets its Response by artifact: the browser is redirected to the ACS with `SAMLart` (and `RelayState`), and the service provider resolves it with a SOAP `ArtifactResolve` to `/artifact` (the `ArtifactResolutionService` in the metadata). The answer is a signed `ArtifactResponse` carrying the Response, which is signed and encrypted as usual.
- Artifacts are type 0x0004, with this issuer's SourceID. Each resolves once, within 5 minutes, and only for the service provider it was issued for; otherwise the `ArtifactResponse` is empty. A signed `ArtifactResolve` is verified against the service provider's certificate; an unsigned one is accepted.
- Service providers whose default ACS in their metadata is HTTP-Artifact, or that set `response_binding = "artifact"`, get artifacts without asking, including for IdP-initiated logins (`/sso/initiate?…&binding=artifact` for any one).
- The test SP offers HTTP-Artifact as a response binding, and `POST /dev/api/response` with `"binding": "artifact"` returns an artifact to resolve.

## Identity provider templates

There are two ways to use the templates:

1. **Pick one at login.** On the root issuer, the login page has a template picker that switches the attribute names and NameID. The Response follows the template you pick.
2. **Use a template issuer.** Every template is also served as its own identity provider at `/p/<template>`, e.g. `http://localhost:9401/p/entra/metadata`. It has its own entity ID (shaped like the real one), metadata, and that provider's endpoint paths. The template also controls the XML: prefixes, ID format, `NameFormat`, `xsi:type` and statement order.

To make a template the default on the root issuer, use `--default-preset <id>`. A declared service provider can also name a `preset` for its logins on the root issuer.

| Template | NameID | Attributes | Signs | Paths under `/p/<template>` |
|---|---|---|---|---|
| `generic` | emailAddress (email) | `email`, `firstName`, `lastName`, `displayName`, `uid`, `groups`, `roles`, … | Response + assertion | – |
| `entra` | emailAddress (UPN) | WS-Fed claim URIs: `…/claims/name`, `…/emailaddress`, `…/givenname`, `objectidentifier`, `tenantid`, `role`, `groups`, `authnmethodsreferences`. No `NameFormat`, default namespace, `_<uuid>` IDs | Assertion | `/{tenant}/saml2`, `/{tenant}/federationmetadata/2007-06/federationmetadata.xml` |
| `adfs` | emailAddress | `…/claims/upn`, `…/emailaddress`, `http://schemas.xmlsoap.org/claims/Group`, `windowsaccountname`, `primarysid`. Default namespace | Assertion | `/adfs/ls/`, `/FederationMetadata/2007-06/FederationMetadata.xml` |
| `okta` | unspecified (email) | `email`, `firstName`, `lastName`, `groups`, with `xs:string` values and an `entity` Issuer format. `saml2:` prefixes, `id…` IDs; encrypts with AES-256-CBC, with the `EncryptedKey` beside the `EncryptedData` (a `ds:RetrievalMethod`) | Response + assertion | `/app/{app}/{id}/sso/saml`, `/app/{app}/{id}/slo/saml`, `/app/{id}/sso/saml/metadata` |
| `google` | unspecified (primary email) | `email`, `firstName`, `lastName`, `groups` (group names, `xs:anyType`), before the AuthnStatement | Assertion | `/o/saml2/idp` (no single logout) |
| `onelogin` | emailAddress | `User.email`, `User.FirstName`, `User.LastName`, `memberOf` (every parameter is sent, empty if the user has no value), `SessionNotOnOrAfter`, `pfx…` Response and `A…` assertion IDs | Response | `/trust/saml2/http-{redirect,post}/sso/{id}`, `/trust/saml2/http-redirect/slo/{id}`, `/saml/metadata/{id}` |
| `auth0` | unspecified (`auth0\|…` user ID) | WS-Fed URIs plus `http://schemas.auth0.com/…` (`email_verified` and `isSocial` as `xs:boolean`, `identities/default/connection`, …), `uri` NameFormat, default-namespace signature | Assertion | `/samlp/{client_id}`, `/samlp/{client_id}/logout`, `/samlp/metadata/{client_id}` |
| `keycloak` | unspecified (username) | `Role` (role list mapper: one Attribute per role, a new user's effective roles), plus the commonly added X.500 mappers `urn:oid:…` with FriendlyNames, `dsig:` prefix, `ID_…` IDs | Response (document) | `/realms/{realm}/protocol/saml`, `/realms/{realm}/protocol/saml/descriptor`, `/realms/{realm}/protocol/saml/clients/{name}` (IdP-initiated, for an SP declared with `idp_initiated_name`) |
| `pingfederate` | unspecified | LDAP names: `mail`, `givenName`, `sn`, `memberOf` (DNs); entity ID `localhost:default:entityId` | Response | `/idp/SSO.saml2`, `/idp/SLO.saml2`, `/idp/startSSO.ping`, `/pf/federation_metadata.ping` |
| `jumpcloud` | unspecified (email) | `email`, `firstname`, `lastname`, `memberOf` with `unspecified` NameFormat, before the AuthnStatement; entity ID `JumpCloud` with an `entity` Issuer format, 40-character IDs | Response (newer apps' default; older ones sign the assertion) | `/saml2/{app}` |
| `shibboleth` | transient | eduPerson and `urn:oid:` attributes with FriendlyNames (`eduPersonPrincipalName`, `mail`, `eduPersonScopedAffiliation`, `subject-id`, `pairwise-id`, …), `uri` NameFormat | Response; encrypts the assertion (AES-128-GCM) when the SP has a certificate | `/idp/profile/SAML2/{Redirect,POST}/SSO`, `/idp/profile/SAML2/Unsolicited/SSO`, `/idp/profile/SAML2/{Redirect,POST}/SLO`, `/idp/shibboleth` |

The SessionIndex follows the provider too: the assertion ID for Entra ID, AD FS, Google and Keycloak, the AuthnRequest ID for Okta, and a per-session value otherwise. AD FS and Keycloak confirm the subject for 5 minutes, unlike their assertion lifetimes. `{…}` path segments accept any value, so the URL from a real tenant's configuration works once you swap the host. The metadata advertises the template's own SSO and SLO paths. The templates follow each provider's defaults and most common setup. Real deployments let administrators rename attributes and change signing, so declare a service provider with `sign_response`, `sign_assertion` or custom attributes to match yours. `GET /dev/api/presets` lists all the templates.

## The test SP

http://localhost:9401/sp is a service provider built into localsaml, so you can try logins without an app. It's the SAML version of localoidc's `/callback`.

- It starts SP-initiated logins with the Redirect or POST binding, signed or not. You can set ForceAuthn, IsPassive, a NameIDPolicy, a requested AuthnContext and a RelayState. It can also start an IdP-initiated login.
- It validates the Response the way a strict service provider would, and lists every check. That covers status, Destination, InResponseTo, issuer, signatures (against every certificate in the metadata), decryption, Recipient, NotBefore/NotOnOrAfter against real time (allowing 60 seconds of skew), audience, and replays. Then it shows the NameID, the attributes and the XML.
- It does SP-initiated single logout, and answers LogoutRequests when another service provider starts one.

Each template issuer has its own test SP (`/p/<template>/sp`), which sends its requests to that template's SSO path. The test SP shares localsaml's key pair, so its signed requests verify and it can decrypt the Shibboleth template's encrypted assertions.

## Minting responses for development and tests

**Web page:** open `http://localhost:9401/dev` (or `/p/<template>/dev`). Build an identity, choose who the Response is for and how it's signed or encrypted, and add any [defects](#injecting-faults). Then post it to the ACS in a new tab, or copy it. The page also shows a curl command that posts it, and the equivalent API call.

**JSON API:**

```sh
# Quick GET: unknown query params become attributes (a JSON array for several values).
curl -s 'http://localhost:9401/dev/api/response?sp=http://localhost:3000/saml/metadata&acs_url=http://localhost:3000/saml/acs&email=me@example.com&groups=["admins","users"]'

# Just the base64 SAMLResponse (or format=xml for the document), ready to post to your ACS in a test.
curl -s 'http://localhost:9401/dev/api/response?sp=…&acs_url=…&format=base64'

# Full POST. `attributes` are merged over the template defaults; a null value removes one.
curl -s -X POST http://localhost:9401/dev/api/response -H 'content-type: application/json' -d '{
  "preset": "entra",
  "sp": "http://localhost:3000/saml/metadata",
  "acs_url": "http://localhost:3000/saml/acs",
  "in_response_to": "_abc123",
  "relay_state": "/dashboard",
  "attributes": { "http://schemas.microsoft.com/ws/2008/06/identity/claims/role": ["Admin"] },
  "sign_response": true,
  "expires_in": 120
}'
```

The response has `saml_response` (base64), `xml`, `pretty`, `acs_url`, `relay_state`, `name_id`, `attributes`, the IDs, what was signed and encrypted, and a ready-made `curl` command. Other options are `user`, `audience`, `name_id`, `name_id_format`, `defaults: false` (start from no attributes), `sign_assertion`, `signature_algorithm`, `encrypt`, `encryption_algorithm`, `authn_context`, `session_index`, `tamper` (a list of [defects](#injecting-faults)), `status`/`status_message` (an error Response), `encrypt_name_id`, `encrypt_attributes` and `binding: "artifact"` (also returns an `artifact` to [resolve](#http-artifact), and its ACS `url`). Without `sp`, the Response is for the test SP.

### Declared users

Declare named users in `localsaml.toml` so a team, its tests and CI all sign in as the same people:

```toml
[[users]]
id = "alice"                   # used by dev_user and the dev API
label = "Alice (admin)"        # optional, shown on the login page
preset = "okta"                # optional, otherwise the issuer's default template
attributes = { email = "alice@acme.dev", groups = ["Everyone", "Admins"] }
# name_id = "alice@acme.dev"   # default: derived like the template's
# name_id_format = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
# defaults = false             # don't merge over the template's default attributes
```

- Users appear at the top of the login and `/dev` pages for one-click sign-in.
- Identifiers like Entra's object ID, AD FS's SID or Auth0's user ID are made unique per user (stable across restarts) unless you set them.
- `?dev_user=alice` on an SSO request signs in as Alice straight away. `dev_attributes` are merged on top.
- With `--auto-login`, a login hint (the AuthnRequest's `Subject`, or `login_hint`) matching a user's `id`, NameID or email signs in as that user.
- `POST /dev/api/response` accepts `"user": "alice"` (or `?user=alice` on GET). `GET /dev/api/users` lists the users as the issuer would issue them.

### Automating browser logins (Playwright, Cypress, …)

Service providers build the SSO URL themselves, so these go on the redirect to localsaml. With Playwright, rewrite it in a route handler. Or set them once with `--auto-login`.

- `dev_user=<id>` signs in as a [declared user](#declared-users) immediately.
- `dev_attributes=<JSON or base64url JSON>` signs in immediately with the template defaults merged with those attributes. `dev_preset=<id>` picks the template and `dev_name_id` sets the NameID.
- `--auto-login` signs every request in with the template defaults, or as the declared user a login hint names. An existing session is reused unless the request has ForceAuthn, and passive (`IsPassive`) requests are signed in too.
- `--silent-sso` reuses sessions without the login page but still shows it for new logins.

```js
// Playwright: sign in as Alice whenever the app sends the browser to localsaml.
await page.route("http://localhost:9401/sso?**", (route) =>
  route.continue({ url: route.request().url() + "&dev_user=alice" }));
```

### Rotating the signing key

`POST /dev/api/rotate-keys`, or the **Rotate signing key** button on `/dev`, generates a new key and certificate. Use it to test how your app handles an IdP certificate rollover.

- The keyring is shared by all issuers, and new responses are signed with the new key straight away.
- The previous two certificates stay in the metadata, so service providers that refresh metadata keep working until a third rotation retires them. Service providers configured with a pinned certificate or fingerprint stop accepting responses, as they would in production.

```sh
curl -s -X POST http://localhost:9401/dev/api/rotate-keys | jq .certificate.sha256_fingerprint
```

### Shifting the clock

localsaml can run its clock ahead of (or behind) real time. Your app's clock isn't affected, so this simulates an identity provider whose clock is off:

- Move it forward a few minutes and assertions arrive "not yet valid" (`NotBefore` and `IssueInstant` in the future). Move it back and they arrive already expired. That tests your app's clock-skew allowance.
- localsaml's own sessions, pending logins and logouts expire by the shifted clock. Move it forward a day and the next login can't reuse a session.

```sh
curl -s -X POST http://localhost:9401/dev/api/clock -H 'content-type: application/json' -d '{"advance": "10m"}'
# {"now":…,"offset":600,"offset_text":"+10m","real_now":…}
curl -s -X POST http://localhost:9401/dev/api/clock -H 'content-type: application/json' -d '{"reset": true}'
```

- `POST /dev/api/clock` takes exactly one of `offset` (set it), `advance` (move it; negative moves back) or `reset: true`. Durations are seconds or text such as `90s`, `15m`, `2h`, `31d` or `1d12h`. `GET /dev/api/clock` shows the current state.
- The `/dev` page has the same controls. While the clock is shifted, every page shows a warning banner.
- `--clock-offset <duration>` (`LOCALSAML_CLOCK_OFFSET`) sets an offset at startup. The offset isn't saved, so a restart always goes back to real time.

### Injecting faults

Make the next logins fail on purpose, carry a deliberately defective Response, or respond slowly. Use it to test that your app handles a misbehaving identity provider and rejects what it should. Your app doesn't need to change anything.

```sh
# The next login gets a Response with status Responder/AuthnFailed
curl -s -X POST http://localhost:9401/dev/api/faults -H 'content-type: application/json' \
  -d '{"endpoint": "sso", "status": "AuthnFailed"}'

# The next login gets an expired assertion for the wrong audience: your app must reject it
curl -s -X POST http://localhost:9401/dev/api/faults -H 'content-type: application/json' \
  -d '{"endpoint": "sso", "tamper": ["expired", "wrong_audience"]}'

# Metadata answers 503 until the fault is removed
curl -s -X POST http://localhost:9401/dev/api/faults -H 'content-type: application/json' \
  -d '{"endpoint": "metadata", "always": true}'

curl -s -X DELETE http://localhost:9401/dev/api/faults   # remove them all
```

- `endpoint` is `sso` (SP- and IdP-initiated logins), `slo` or `metadata`. Template paths count too, e.g. Okta's `/app/…/sso/saml` is `sso`. Narrow a fault with `issuer` (`root` or a template id) and `sp` (an entity ID).
- `status` is a SAML status: a second-level code such as `AuthnFailed`, `NoPassive`, `RequestDenied`, `UnknownPrincipal`, `NoAuthnContext`, `InvalidNameIDPolicy` or `UnsupportedBinding` (sent under its usual top-level code), a top-level code (`Responder`, `Requester`), or a full status URN. `status_message` adds a `StatusMessage`. An SSO fault without anything else answers `Responder`. The error Response goes to the service provider's ACS like a real one, and an SLO fault answers the LogoutRequest with that status.
- `tamper` puts defects in an otherwise successful Response:

  | `tamper` | What your app should do |
  |---|---|
  | `unsigned` | reject: nothing is signed |
  | `bad_signature` | reject: the NameID was changed after signing |
  | `wrong_cert` | reject: signed by a certificate that isn't in the metadata |
  | `sha1` | reject if it requires SHA-256: signed with RSA-SHA1 |
  | `expired` | reject: the assertion expired an hour ago |
  | `not_yet_valid` | reject: valid from an hour from now |
  | `wrong_audience` | reject: the Audience is another service provider |
  | `wrong_issuer` | reject: the Issuer is another identity provider |
  | `wrong_destination` | reject: the Response's Destination is another URL |
  | `wrong_recipient` | reject: the SubjectConfirmationData Recipient is another URL |
  | `wrong_in_response_to` | reject: InResponseTo doesn't match the AuthnRequest |
  | `replay` | reject: the previous Response for this SP, sent again unchanged |

- Metadata faults answer with `http_status` (default 503). `delay_ms` (up to 30000) waits before answering, and on its own just makes the request slow.
- A fault affects the next matching request, or the next `count` of them, or every one with `always: true` until it's removed.
- For a one-off, add `dev_status=<status>` (and optionally `dev_status_message`) or `dev_tamper=<defect,…>` to the SSO request.
- `GET /dev/api/faults` lists the armed faults and `DELETE /dev/api/faults/{id}` removes one. The `/dev` page has the same controls, and every page shows a warning banner while faults are armed. Faults live in memory, so a restart clears them.

## Single logout

- **SP-initiated:** a service provider sends a LogoutRequest to `/slo` (or the template's path). localsaml ends the session, then sends a signed LogoutRequest to every other service provider that got an assertion during it. These go one at a time over front-channel redirects (or POSTs), each with the NameID and SessionIndex that service provider received. When they've all answered, the initiator gets its LogoutResponse: `Success`, with a `PartialLogout` second-level status if some didn't log out.
- **IdP-initiated:** `/slo/initiate` logs out the browser's session (or `?sid=…`), notifies every service provider the same way, and shows who was logged out (or redirects to `return_to`). The `/dev` page lists sessions with a **Single logout** button.
- Service providers need an SLO URL to be notified, either declared (`slo_url`, `slo_binding`) or from their metadata. Others are skipped and listed as "not notified". An undeclared service provider that starts a logout has no SLO URL to answer to either, so its logout ends on an error page after the session is ended; declare it to get a LogoutResponse.
- **Back-channel (SOAP binding):** service providers with a SOAP SingleLogoutService (`slo_soap_url`, or from their metadata) and no front-channel one are logged out with a signed LogoutRequest POSTed to them while the browser waits. Service providers can also send localsaml a LogoutRequest over SOAP (POST a SOAP envelope to `/slo`): it ends the session that SessionIndex or NameID names, logs the other service providers out back-channel, and answers with a signed LogoutResponse.
- `DELETE /dev/api/sessions/{sid}` (**End (back-channel)** on `/dev`) ends a session as if the user had logged out elsewhere: service providers with a SOAP endpoint get a LogoutRequest, like localoidc's back-channel logout, and the answer lists each delivery. The others can't be told without the browser.
- Back-channel calls show up in the [request inspector](#inspecting-requests) as outgoing requests, with what was sent and answered.
- A LogoutRequest for a session that's already gone still gets `Success`. The Google Workspace template doesn't do single logout, like the real one.

## Inspecting requests

Open `http://localhost:9401/dev/requests` (linked as **Requests** in the top bar) to see the last 500 requests to every issuer, newest first. New requests appear as they arrive.

- Each row shows the endpoint, the service provider, the SAML messages it carried and the outcome. Examples: `Response → http://localhost:3000/saml/acs`, `LogoutRequest → …`, `page: Sign in`, or the error (`NoPassive`, `Invalid AuthnRequest signature`, …). Failures are marked in red.
- Click a row to see its parameters, and every SAML message it received or sent, decoded (inflated, base64-decoded) and indented with a copy button. Encrypted assertions are shown decrypted too. Failures show why, for example `Unregistered AssertionConsumerServiceURL — 'http://localhost:3000/acs' isn't one of My App's ACS URLs`.
- Filter by service provider or to errors only. Metadata, localsaml's own `/dev` tools and the test SP are hidden unless you ask for them.
- The list is kept in memory, so a restart clears it.

Tests can use the same data to check what an app actually sent:

```sh
curl -s -X DELETE http://localhost:9401/dev/api/requests      # start from a clean slate
# ... run the login flow ...
curl -s 'http://localhost:9401/dev/api/requests?sp=http://localhost:3000/saml/metadata' \
  | jq '.entries[] | .messages[] | select(.direction == "received") | .xml' -r
```

`GET /dev/api/requests` returns `{"entries": [...], "latest_id": …, "capacity": 500}` and accepts `sp`, `errors=true`, `limit` and `after=<id>` (only newer entries). Clearing doesn't reset ids, so polling with `after` never misses a request.

## Configuration

Settings come from CLI flags, `LOCALSAML_*` environment variables, or a `localsaml.toml` in the working directory (or `--config <path>`). Flags and environment variables win over the file. See [`localsaml.example.toml`](localsaml.example.toml) for every setting and `localsaml --help` for the flags.

### Service providers

Undeclared service providers are accepted with whatever their AuthnRequest says, unless `strict_service_providers = true`. Declared ones get more:

```toml
[[service_providers]]
entity_id = "http://localhost:3000/saml/metadata"
acs_urls = ["http://localhost:3000/saml/acs"]   # enforced; the first is the default
slo_url = "http://localhost:3000/saml/slo"      # notified on single logout
slo_soap_url = "http://localhost:3000/saml/soap" # or back-channel, over SOAP
# acs_artifact_urls = ["http://localhost:3000/saml/artifact"]  # HTTP-Artifact ACSs
# acs_ecp_urls = ["http://localhost:3000/saml/ecp"]            # PAOS ACSs (ECP)
# response_binding = "artifact"                 # post (default) or artifact
certificate = """-----BEGIN CERTIFICATE-----
…
-----END CERTIFICATE-----"""                     # verifies signed requests, encrypts assertions
encrypt_assertions = true
# encrypt_name_id = true                        # EncryptedID instead of NameID
# encrypt_attributes = true                     # EncryptedAttributes (few SPs accept them)
sign_response = true                            # override the template
```

- Settings can come from the service provider's metadata instead. Use `metadata_url` (fetched at startup, and again on the service provider's first request if it wasn't up yet), `metadata_file` or inline `metadata`. Explicit settings win. The metadata provides the entity ID, HTTP-POST, HTTP-Artifact and PAOS ACS URLs and their indexes (and the default ACS's binding), the SLO endpoint and binding, signing and encryption certificates, `AuthnRequestsSigned`, `WantAssertionsSigned` and the NameID format.
- `POST /dev/api/service-providers` registers one at runtime, from metadata XML (the request body) or JSON with the same fields as above, including `metadata_url`. Registered service providers are saved in the state database. `GET` lists them all, `DELETE ?entity_id=…` removes one and `DELETE` without it removes every registered one. The `/dev` page has the same controls.

Named identities go in `[[users]]`. See [Declared users](#declared-users).

### State

- All state lives in `~/.localsaml/` (`--data-dir`): the signing key and certificate in `signing-key.pem` and `signing-cert.pem`, retired ones in `retired-keys/`, and everything else in the SQLite database `state.db`.
- The database holds sessions, pending logins, logouts in progress, unresolved artifacts and registered service providers, so a restart loses nothing. Expired rows are purged every minute.
- The certificate is self-signed and valid for ten years. Delete `state.db` to start fresh. `--ephemeral-keys` generates a new key and certificate on every start (your service providers will need the new one).

### Docker

- In the image the state lives in `/data` (`LOCALSAML_DATA_DIR`), and the server binds `0.0.0.0` (`LOCALSAML_HOST`).
- Mount a config file with `-v ./localsaml.toml:/localsaml.toml -e LOCALSAML_CONFIG=/localsaml.toml`.
- The base URL must be one the browser can reach, because SAML logins happen in the browser. If other containers fetch metadata from a different hostname, give them the metadata as a file, or use `--dynamic-base-url` to derive URLs from each request's `Host` header.

## Interop testing

There's no maintained, official conformance suite for SAML identity providers like the OpenID Foundation's for OIDC, so localsaml is tested two ways:

- **Interop with independent service providers** (`interop/`). The harness drives localsaml with SP libraries built on different XML-security stacks: [`@node-saml/node-saml`](https://github.com/node-saml/node-saml) and [samlify](https://github.com/tngan/samlify) (xml-crypto), [pysaml2](https://github.com/IdentityPython/pysaml2) (xmlsec1), [crewjam/saml](https://github.com/crewjam/saml) (goxmldsig) and the [Shibboleth SP](https://shibboleth.atlassian.net/wiki/spaces/SP3) (OpenSAML C++). For every template it covers both bindings, signed requests that localsaml must verify, encrypted assertions, IdP-initiated SSO, single logout and key rotation, and checks that tampered responses are rejected. See [`interop/README.md`](interop/README.md).
- **The [SAML Conformance Test Kit](https://github.com/codice/saml-conformance)** (`interop/codice/`), a black-box test kit for identity providers that checks the MUSTs of the SAML 2.0 Core, Bindings and Profiles specifications for Web Browser SSO and single logout. It's no longer maintained (its last release is from 2019), so it runs from its published Docker image with a few workarounds. Every test passes except the few listed, with reasons, in [`expected-failures.tsv`](interop/codice/expected-failures.tsv). See [`interop/codice/README.md`](interop/codice/README.md).

Both run in CI.

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to build, test and release.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
