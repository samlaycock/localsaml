import * as React from "react"
import { useLocation, useNavigationType, useSearchParams } from "react-router"

const NONE: string[] = []

/**
 * A text input bound to a URL parameter. It updates the URL once typing pauses, and follows
 * the URL on back and forward. `reset` names parameters to drop when it changes, such as a page
 * offset (pass a constant: a new array each render restarts the wait).
 */
export function useUrlInput(name: string, reset = NONE) {
  const [params, setParams] = useSearchParams()
  const location = useLocation()
  const navigationType = useNavigationType()
  const fromUrl = params.get(name) ?? ""
  const [value, setValue] = React.useState(fromUrl)
  const [syncedKey, setSyncedKey] = React.useState(location.key)
  if (navigationType === "POP" && location.key !== syncedKey) {
    setSyncedKey(location.key)
    setValue(fromUrl)
  }

  React.useEffect(() => {
    if (value.trim() === fromUrl.trim()) return
    const timer = setTimeout(() => {
      setParams(
        (current) => {
          const next = new URLSearchParams(current)
          if (value.trim()) next.set(name, value.trim())
          else next.delete(name)
          for (const r of reset) next.delete(r)
          return next
        },
        { replace: true }
      )
    }, 200)
    return () => clearTimeout(timer)
  }, [value, fromUrl, name, reset, setParams])

  return [value, setValue] as const
}
