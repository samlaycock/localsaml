# localsaml

## 0.2.0

### Minor Changes

- [#2](https://github.com/samlaycock/localsaml/pull/2) [`d3cb0f0`](https://github.com/samlaycock/localsaml/commit/d3cb0f01d86460c3041195aaba8c361ff3c71129) Thanks [@samlaycock](https://github.com/samlaycock)! - The web UI is rebuilt as a React app with shadcn/ui components. Everything works as before (the attribute editor at sign-in, reviewing a Response before it's sent, the assertion generator with its service provider, certificate, clock, fault and session tools, the test SP and the request inspector), with a few changes:
  
  - The overview, assertion generator, test SP and request inspector switch without reloading, and the request inspector's filters are kept in the URL.
  - Registering service providers and changing the clock, faults, sessions or signing key update the page in place instead of reloading it.
  - There's a light, dark and system theme switch.
  - The login form still works without JavaScript (the interop harness and the conformance kit post it unchanged), signing in with the template's default identity.
  - `GET /dev/api/info` returns what the web UI shows about an identity provider, and `GET /dev/api/test-sp` the test SP's settings and session. `GET /dev/api/faults` now includes each fault's `summary`.

## 0.1.0

### Minor Changes

- [`fe984e2`](https://github.com/samlaycock/localsaml/commit/fe984e2128fce9d987f1b8e0c2a3068e14ac23d4) Thanks [@samlaycock](https://github.com/samlaycock)! - First release of localsaml, a local SAML 2.0 identity provider for offline development, published as a Docker image (`ghcr.io/samlaycock/localsaml`) for linux/amd64 and linux/arm64. Signing in shows a short wizard (template, attributes, subject) instead of a password prompt, with saved identities for one-click sign-in. Templates reproduce the attribute names, NameIDs, signing behaviour, XML style and endpoint paths of Microsoft Entra ID, AD FS, Okta, Google Workspace, OneLogin, Auth0, Keycloak, PingFederate, JumpCloud and Shibboleth. It supports the HTTP-Redirect, HTTP-POST and HTTP-Artifact bindings (with SOAP artifact resolution), ECP, signed requests and responses, encrypted assertions, NameIDs and attributes, IdP-initiated SSO, and single logout over the front channel and back-channel (SOAP), attribute queries (SOAP), and adds a built-in test SP, an assertion generator, a request inspector that decodes every SAML message, fault injection (error statuses and deliberately defective responses), a shifted clock and signing key rotation. It follows the SAML 2.0 specification by default (ACS URLs verified, logout messages and artifact resolutions authenticated, no HTTP error codes for SAML failures), with a lenient mode for quick experiments.
