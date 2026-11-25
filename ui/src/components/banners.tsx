import { ClockIcon, TriangleAlertIcon } from "lucide-react"
import { Link } from "react-router"

import { Alert, AlertDescription } from "@/components/ui/alert"
import { useInfo } from "@/lib/root"

/** Warnings shown on every page: a shifted clock and armed faults change everything. */
export function Banners() {
  const { clock, faults_armed: faults } = useInfo()
  if (!clock.offset && !faults) return null
  return (
    <div className="flex flex-col gap-2 border-b px-4 py-2">
      {clock.offset !== 0 && (
        <Alert role="status">
          <ClockIcon />
          <AlertDescription>
            <span>
              The localsaml clock is{" "}
              <b className="font-semibold text-foreground">
                {clock.offset_text}
              </b>{" "}
              {clock.offset > 0 ? "ahead of" : "behind"} real time. Assertion
              timestamps and expiry checks use the shifted time.{" "}
              <Link to="/dev#clock">Change or reset it</Link>
            </span>
          </AlertDescription>
        </Alert>
      )}
      {faults > 0 && (
        <Alert variant="destructive" role="status">
          <TriangleAlertIcon />
          <AlertDescription>
            <span>
              <b className="font-semibold">
                {faults === 1 ? "1 fault is" : `${faults} faults are`} armed
              </b>
              : matching requests will fail or slow down on purpose.{" "}
              <Link to="/dev#faults">Manage faults</Link>
            </span>
          </AlertDescription>
        </Alert>
      )}
    </div>
  )
}
