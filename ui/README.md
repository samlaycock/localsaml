# localsaml web UI

A React single-page app built with stock [shadcn/ui](https://ui.shadcn.com) components. The
Rust server compiles `dist/` into the binary. Every issuer serves it (the root issuer at `/`, a
template's at `/p/<template>`), and its files are at `/assets/`.

## Working on it

```sh
cargo run                 # localsaml on http://localhost:9401
cd ui
bun install
bun run dev               # the dev tools with hot reload; the API calls and the SAML
                          # endpoints go to localhost:9401 (LOCALSAML_URL=http://… for another)
bun run check             # format check, lint and type check
bun run fix               # format, and apply lint fixes
bun run build             # write dist/: commit it with your change
```

The login, review and sign-out pages come from the server (it decides when to show them), so with
`bun run dev` they're the built app. Debug builds of localsaml read `dist/` from disk, so after
`bun run build` a reload shows the change without rebuilding the binary.

The project is managed by [Vite+](https://viteplus.dev): the scripts call its `vp` command,
which brings Vite, Oxfmt (formatting), Oxlint (linting) and tsrs (type checking). With the
[global `vp`](https://viteplus.dev/guide/global-cli) installed, `vp dev`, `vp check` and
`vp build` work directly.

`dist/` is committed so `cargo install --git` and `cargo build` work without Node. CI fails if
it doesn't match the source.

## Conventions

These are shared by the local\* tools (localforce, localflake, localoidc, localmail and
localsaml), so their UIs look and work alike.

- **Stack.** Vite+, React, React Router in data mode (`createBrowserRouter`), Tailwind CSS
  v4 and shadcn/ui, set up with `shadcn init` (the `base-nova` style on Base UI, neutral base
  colour, lucide icons). The Geist font and the icons are bundled, so the UI works offline.
- **Vite+ does the checking.** `vite.config.ts` holds the `lint` and `fmt` settings: Oxlint's
  correctness rules plus the React plugin (hooks and React Compiler rules), type-aware rules
  and type checking, and shadcn's code style for Oxfmt. There's no ESLint, Prettier or `tsc`.
- **Stock components only.** `src/components/ui/` holds components from the public shadcn
  registry, added with `bunx shadcn@latest add <name>` and never edited. Formatting and lint
  skip them. `bun run stock-diff` shows any difference from the registry.
- **One accent colour per product.** `src/index.css` is shadcn's stock theme, as `shadcn init`
  wrote it. `src/theme.css` sets the product's accent (`--primary`, `--ring`, `--chart-1`,
  `--sidebar-primary`) and is the only product-specific styling. Style with theme tokens
  (`bg-muted`, `text-primary`, `border`), not palette colours. (The templates' colours are
  data: they mark which provider an identity looks like.)
- **App components compose stock ones.** `src/components/` has the header, the attribute
  editor, the XML block and the like, built from stock components and Tailwind classes. The XML
  block highlights with theme colours: element names take the accent, attributes are muted.
- **Custom rendering happens on the server.** Content the stock components can't show is
  rendered by the server and shown in an iframe (localmail's email bodies, for example).

## How localsaml's app is put together

- **The dev tools are routes.** The overview (`/`), the assertion generator (`/dev`), the test
  SP (`/sp`) and the request inspector (`/dev/requests`) load their data from the `/dev/api/*`
  endpoints. `GET /dev/api/info` has what every page needs: the identity provider, its
  endpoints, certificate, clock and armed faults for the warning banners. A change calls the
  API, then revalidates, so the page and the banners update.
- **The server decides the protocol's pages.** For sign-in, reviewing a Response, picking a
  service provider for IdP-initiated login, signing out, the test SP's verdicts and errors,
  `src/html.rs` sends the app's page with a description of what to show
  (`<script id="lo-page">`), which `src/routes/protocol.tsx` renders. The same script carries the
  issuer's path prefix, which the router uses as its basename.
- **Those pages work without JavaScript.** The server also puts a plain HTML version in
  `<div id="root">`, which the app replaces when it starts. The login page's is a real form
  (`<form method="post" action="…" id="lo-form">` with a hidden `req` field) that signs in with
  the template's default identity: the interop harness and the SAML conformance kit post it.
- **Sign-in and the test SP use real form posts.** The attribute editor fills the login form's
  hidden fields (`preset`, `identity`), and the server answers with the page that posts the
  Response to the ACS, as it would for any login. The test SP's forms go to its own endpoints.
- **Identities are kept in the browser.** Saved identities, the last one used and the "review
  before sending" choice are in `localStorage` under the keys the previous UI used
  (`localsaml.identities`, `localsaml.last`, `localsaml.review`), so they carry over.
