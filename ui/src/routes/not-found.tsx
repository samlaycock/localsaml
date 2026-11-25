import { SearchXIcon } from "lucide-react"
import { Link } from "react-router"

import { buttonVariants } from "@/components/ui/button"
import {
  Empty,
  EmptyContent,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"

export function NotFound() {
  return (
    <Empty className="h-full">
      <EmptyHeader>
        <EmptyMedia variant="icon">
          <SearchXIcon />
        </EmptyMedia>
        <EmptyTitle>There's no page here</EmptyTitle>
        <EmptyDescription>
          The link may be from another version.
        </EmptyDescription>
      </EmptyHeader>
      <EmptyContent>
        <Link to="/" className={buttonVariants({ variant: "outline" })}>
          Go to the overview
        </Link>
      </EmptyContent>
    </Empty>
  )
}
