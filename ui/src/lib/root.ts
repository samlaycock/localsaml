import { useRouteLoaderData } from "react-router"

import { api } from "@/lib/api"
import type { Info } from "@/lib/types"

/** This issuer's details, for the header, the warning banners and the dev tools. */
export const rootLoader = () => api<Info>("/dev/api/info")

export const useInfo = () => useRouteLoaderData("root") as Info
