# Contributing to localsaml

Thanks for helping out. Bug reports, template fixes (an identity provider whose real responses look different from ours) and new features are all welcome. For anything large, please open an issue first so we can agree on the approach.

## Development

You need a recent stable Rust toolchain. Node.js and Docker are needed for the interop and conformance tests, and Node.js for changesets.

```sh
cargo run                        # serve on http://localhost:9401
cargo test                       # unit tests and integration tests for every flow
cargo clippy --all-targets -- -D warnings
cargo fmt
docker build -t localsaml .      # the release image
```

CI runs `cargo fmt --check`, clippy with `-D warnings`, `cargo test`, the interop tests and the SAML Conformance Test Kit on every pull request.

- The login and assertion generator pages share `assets/app.js` and `assets/app.css`. Both are compiled into the binary, so rebuild after changing them.
- Identity provider templates (attribute names, NameIDs, signing, XML style and endpoint paths) live in `src/presets.rs`. Their endpoint paths are mounted by `src/routes/providers.rs`.
- XML signatures and canonicalization are in `src/xml.rs` and `src/dsig.rs`, and encryption is in `src/xmlenc.rs`. They only need to handle what SAML uses, but must agree byte for byte with other implementations, so change them carefully and run the interop tests.

If you change protocol behaviour or anything that touches the XML, run the [interop tests](interop/README.md) (`cd interop && npm ci && npm test`) and the [conformance kit](interop/codice/README.md) (`interop/codice/run.sh`) as well. If a conformance test starts or stops failing, update `interop/codice/expected-failures.tsv` with the reason.

## Changesets

Every pull request needs a changeset: a short Markdown file under `.changeset/` that says what changed and whether it's a `patch`, `minor` or `major` change. It becomes the changelog entry.

```sh
npm ci
npm run changeset                # describe a change users will notice
npm run changeset -- --empty     # for CI, tests, docs and other invisible changes
```

CI fails if a pull request has no changeset.

## Releases

Releases are managed with [changesets](https://github.com/changesets/changesets). `package.json` holds the version, and `npm run version` copies it into `Cargo.toml` and `Cargo.lock`.

1. Changesets land on `main` with their pull requests.
2. The release workflow keeps a "Release <version>" pull request open. It applies the pending changesets: the version bump and `CHANGELOG.md`. CI runs on it, including a Docker build check.
3. Merging that pull request does the release:
   - builds the image natively for amd64 and arm64;
   - pushes `ghcr.io/samlaycock/localsaml:<version>`, `:<major>.<minor>` (and `:<major>` from 1.0) and `:latest`;
   - tags `v<version>` and creates the GitHub release from the changelog.

## License

By contributing, you agree that your contributions will be dual licensed under the MIT and Apache-2.0 licenses, as described in the [README](README.md#license).
