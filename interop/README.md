# Interop harness

SAML has no equivalent of the OpenID Foundation conformance suite, so localsaml is tested against the service-provider libraries apps actually use. `run.mjs` builds localsaml, starts it on port 9411 with a throwaway key and data directory, and plays service providers built with [`@node-saml/node-saml`](https://github.com/node-saml/node-saml) (behind passport-saml) and [`samlify`](https://github.com/tngan/samlify), against the root issuer and every template issuer (`/p/<id>`).

```sh
cd interop
npm ci
node run.mjs                 # everything (about 10 seconds after the build)
node run.mjs --only okta     # one issuer: root, generic, entra, adfs, okta, ...
node run.mjs --no-build      # use the existing target/debug/localsaml
node run.mjs --binary ../target/release/localsaml
node run.mjs --verbose       # stack traces and the server log for failures
```

It needs Node.js 20+, `openssl` (to make the service providers' key and certificate) and a Rust toolchain unless you pass `--binary` or `--no-build`. It exits non-zero if any check fails.

## What it checks

For each issuer, with the libraries' signature checks set to match the template (e.g. Entra ID signs only the assertion, Keycloak only the response):

- **SP-initiated login.** node-saml over the Redirect binding, signed and unsigned. samlify over the Redirect and POST bindings, signed (query signature and enveloped XML signature) and unsigned. Logins are finished with `dev_attributes`, `dev_user` (a `[[users]]` entry in the generated `localsaml.toml`) and the login form (`POST /login` with `preset` and `identity`). The libraries validate the Response, including `InResponseTo`. The NameID, NameID format and attributes are checked.
- **Encrypted assertions.** AES-256-GCM and AES-128-CBC with RSA-OAEP key transport, decrypted by both libraries.
- **IdP-initiated SSO.** `/sso/initiate?sp=…`, an unsolicited Response with RelayState.
- **Single logout.** node-saml and samlify each do an SP-initiated logout and validate the signed LogoutResponse. Then two service providers share a session: node-saml logs out, localsaml sends samlify a LogoutRequest, samlify answers, and only then does node-saml get its LogoutResponse. Google Workspace advertises no SLO.
- **Defects are rejected.** Responses minted with `/dev/api/response?tamper=…` (bad signature, untrusted certificate, wrong audience, issuer, recipient or destination, expired, not yet valid, unsigned, SHA-1) and with an error status must be rejected by the libraries. An untouched minted Response must be accepted.
- **Key rotation.** After `POST /dev/api/rotate-keys`, the metadata lists the new and the old certificate. Responses issued before and after the rotation verify against it, and a library pinned to the old certificate rejects the new ones.
- Registering a service provider over `POST /dev/api/service-providers`.

The service providers the harness plays are declared in the generated `localsaml.toml`, with their certificate, ACS and SLO URLs. Some of them have `encrypt_assertions` set.

## Library behaviour worth knowing

These aren't localsaml bugs, but apps using these libraries will run into them too:

- **samlify** refuses to sign AuthnRequests unless the IdP metadata says `WantAuthnRequestsSigned="true"`. It requires that flag to match the SP's `AuthnRequestsSigned`. localsaml's metadata says `false`, though it verifies signed requests from service providers it has a certificate for. The harness sets the flag in the metadata it gives samlify.
- **samlify** signs POST-binding AuthnRequests at its default signature location, `Response/Issuer`, when the SP sets `wantMessageSigned`, and fails because an AuthnRequest has no such element. Set `signatureConfig.location` to `AuthnRequest/Issuer`.
- **samlify**'s Redirect-binding parsers take the decoded query (as a web framework parses it) plus the raw `octetString` that was signed. `parseLogoutRequest` only checks the signature if `wantLogoutRequestSigned` is set.
- **node-saml 5** only logs (`NODE_DEBUG=node-saml`) a `Recipient` or `Destination` that isn't the ACS URL; it doesn't reject it. So those defects are only checked against samlify.
- **Both** accept RSA-SHA1 signatures by default. samlify rejects them when `allowedSignatureAlgorithms` excludes SHA-1. node-saml has no option for that.
- `@authenio/samlify-node-xmllint` (samlify's schema validator) adds event listeners on every validation, so the harness raises Node's listener limit.
