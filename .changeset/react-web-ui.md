---
"localsaml": minor
---

The web UI is rebuilt as a React app with shadcn/ui components. Everything works as before (the attribute editor at sign-in, reviewing a Response before it's sent, the assertion generator with its service provider, certificate, clock, fault and session tools, the test SP and the request inspector), with a few changes:

- The overview, assertion generator, test SP and request inspector switch without reloading, and the request inspector's filters are kept in the URL.
- Registering service providers and changing the clock, faults, sessions or signing key update the page in place instead of reloading it.
- There's a light, dark and system theme switch.
- The login form still works without JavaScript (the interop harness and the conformance kit post it unchanged), signing in with the template's default identity.
- `GET /dev/api/info` returns what the web UI shows about an identity provider, and `GET /dev/api/test-sp` the test SP's settings and session. `GET /dev/api/faults` now includes each fault's `summary`.
