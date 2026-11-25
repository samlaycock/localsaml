import { StrictMode } from "react"
import { createRoot } from "react-dom/client"
import { createBrowserRouter } from "react-router"
import { RouterProvider } from "react-router/dom"

import "./index.css"
import "./theme.css"
import { ThemeProvider } from "@/components/theme-provider"
import { prefix } from "@/lib/page"
import { rootLoader } from "@/lib/root"
import { DevPage, devLoader } from "@/routes/dev"
import { Home } from "@/routes/home"
import { ProtocolPage } from "@/routes/protocol"
import { Requests } from "@/routes/requests"
import { Loading, Root, RouteError } from "@/routes/root"
import { TestSpPage, testSpLoader } from "@/routes/test-sp"

const router = createBrowserRouter(
  [
    {
      id: "root",
      path: "/",
      loader: rootLoader,
      Component: Root,
      ErrorBoundary: RouteError,
      HydrateFallback: Loading,
      children: [
        { index: true, Component: Home, handle: { title: "Home" } },
        {
          path: "dev",
          loader: devLoader,
          Component: DevPage,
          ErrorBoundary: RouteError,
          handle: { title: "Assertion generator" },
        },
        {
          path: "dev/requests",
          Component: Requests,
          handle: { title: "Requests" },
        },
        {
          path: "sp",
          loader: testSpLoader,
          Component: TestSpPage,
          ErrorBoundary: RouteError,
          handle: { title: "Test SP" },
        },
        // The protocol's pages (sign-in, review, sign-out, errors), which the server describes.
        { path: "*", Component: ProtocolPage },
      ],
    },
  ],
  // Every issuer serves the app: the root one at `/`, a template's at `/p/<template>`.
  { basename: prefix || "/" }
)

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ThemeProvider storageKey="localsaml.theme">
      <RouterProvider router={router} />
    </ThemeProvider>
  </StrictMode>
)
