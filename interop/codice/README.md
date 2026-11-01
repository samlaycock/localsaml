# SAML Conformance Test Kit

[codice/saml-conformance](https://github.com/codice/saml-conformance) is the closest SAML has to the OpenID Foundation's conformance suite. It's a black-box test kit for identity providers that checks the `MUST`s of the SAML 2.0 Core, Bindings and Profiles specifications for Web Browser SSO and Single Logout, over the HTTP-Redirect and HTTP-POST bindings. Its last release is from January 2019, so it's used here through its published Docker image (`codice/samlconf`, linux/amd64), with a few workarounds.

```sh
./run.sh                 # build localsaml and run every test (needs Docker and a Rust toolchain)
BINARY=../../target/release/localsaml ./run.sh
LENIENT=1 ./run.sh       # the kit's -l mode: error pages may use HTTP 4xx/5xx (the bindings forbid that)
```

A run takes about 15 seconds once localsaml is built (the kit runs under amd64 emulation on Apple silicon). `run.sh` exits non-zero if a test fails that isn't listed in [`expected-failures.tsv`](expected-failures.tsv). It also lists expected failures that passed, so the list can be kept up to date. Everything it produces is in `.work/`: `results.log` (every test with its real result and reason), `localsaml.log` and the kit's section report in `out/report.txt`.

## How it's wired up

- **The kit's service providers.** The kit plays two service providers, described by its own metadata ([`samlconf-sp-metadata.xml`](samlconf-sp-metadata.xml), copied from the image). [`localsaml.toml`](localsaml.toml) declares them.
- **Logging in.** The kit needs a plugin that performs the login. [`plugin/`](plugin) submits localsaml's login form unchanged, which signs in with the template's default identity, and hands back the page that posts the Response. Its requests go through the kit's global HTTP session, so localsaml's session cookie is kept between the logins and logouts of a test, as in a browser.
- **Silent SSO.** The kit expects a second service provider's login in the same session to complete without a login page, as a production IdP's would. So `silent_sso` is on.
- **Compiling.** The plugin and runner are compiled inside the kit's image (JDK 8) against the kit's own libraries, so the kit's dead Gradle build (Gradle 4.9, a retired repository) isn't needed.

## Workarounds for the kit

- **Its runner reports every test as passing.** The kit's `samlconf` only marks a test failed if the test recorded one of its own compliance exceptions. A test that dies with any other exception, such as a parse error or an unexpected binding, is printed as `SUCCESSFUL`, and the section report then shows everything as `SKIPPED`. [`runner/`](runner) runs the same test classes with the same settings and reports JUnit's actual result for each test.
- **Its schema validation always fails.** The validator only lets itself read `file:` URLs, but in the kit's distribution the XSDs are inside a jar. Every message with a signature then fails with "Cannot resolve the name 'ds:Signature'". On top of that, the XML-DSig and XML-Enc XSDs load their DTD from www.w3.org, which often refuses automated clients, so the failures were also intermittent. `run.sh` extracts the XSDs in front of the classpath and points the DTD at an empty local file.

## Results

28 tests run. 8 are DDF-specific or disabled in the kit itself and are skipped.

| Mode | Passed | Failed |
|---|---|---|
| strict (`./run.sh`) | 23 | 5 (all expected) |
| lenient (`LENIENT=1 ./run.sh`) | 23 | 5 |

All of SSO over both bindings, with and without RelayState and ACS URLs, passes, and so do the Destination checks (a request whose `Destination` isn't where it was received gets a `Requester` error) and the `Subject` checks (an AuthnRequest naming a subject the user didn't sign in as gets an error Response, Profiles 4.1.4.1). So does single logout from one service provider and from two (propagation, RelayState, and an SP that fails to log out). The expected failures, with reasons, are in [`expected-failures.tsv`](expected-failures.tsv):

- **The kit expects what no IdP can do, or what the spec asks of the sender (5 tests).**
  - It wants a SAML error Response to an AuthnRequest that's empty or can't be decoded, so has no service provider or ACS to send it to. localsaml shows an error page, with HTTP 200 because Bindings 3.4.6/3.5.6 say SAML failures MUST NOT use HTTP error codes (the `x-localsaml-error` header tells scripts it's an error). The kit's lenient mode only accepts such a page with an HTTP error code, so it fails these in both modes.
  - It wants RelayState over 80 bytes rejected; that limit is a rule for the sender. localsaml accepts it and warns on the login page.

### DSA signatures

The kit's second service provider signs with DSA (DSA-SHA1 and DSA-SHA256), and puts DER-encoded signatures in Redirect binding query strings, as Java's `java.security.Signature` produces them (XML-DSig itself uses raw `r||s`). localsaml verifies both encodings, so that SP is declared from its metadata with its certificate, and "Bindings 3.4.4.1: Redirect AuthnRequest Using DSA1 Signature Algorithm" and the multi-SP logout tests verify its signatures for real.
