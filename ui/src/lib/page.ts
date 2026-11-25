// What the server put in the page: the identity provider it's for and, on the protocol's pages
// (sign-in, review, sign-out, the test SP's verdicts, errors), which of them to show.

import type { ProtocolView } from "@/lib/types"

type PageData = { entityId: string; prefix: string; view: ProtocolView | null }

function read(): PageData {
  try {
    const el = document.getElementById("lo-page")
    if (el?.textContent) return JSON.parse(el.textContent) as PageData
  } catch {
    // Fall through: work it out from the address.
  }
  // `bun run dev` serves the page without the server's data.
  const prefix = /^\/p\/[^/]+/.exec(location.pathname)?.[0] ?? ""
  return { entityId: "", prefix, view: null }
}

export const page = read()

/** The issuer's path prefix: "" for the root issuer, `/p/<template>` for a template's. */
export const prefix = page.prefix

/** The location the server rendered, whose protocol view the app shows. */
export const initialPath = location.pathname
