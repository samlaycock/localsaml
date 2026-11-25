import { FileCodeIcon, LogInIcon } from "lucide-react"
import { Link } from "react-router"

import { CodeBlock } from "@/components/code-block"
import { CopyButton } from "@/components/copy-button"
import { PresetDot } from "@/components/identity-editor"
import { buttonVariants } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import {
  Item,
  ItemContent,
  ItemDescription,
  ItemTitle,
} from "@/components/ui/item"
import { Table, TableBody, TableCell, TableRow } from "@/components/ui/table"
import { prefix } from "@/lib/page"
import { useInfo } from "@/lib/root"
import { cn } from "@/lib/utils"

/** The identity provider: where to point a service provider, its endpoints, and the templates. */
export function Home() {
  const info = useInfo()
  const dev =
    info.endpoints.find((e) => e.url.endsWith("/dev/api/response"))?.url ??
    `${prefix}/dev/api/response`
  const cert = info.certificate
  return (
    <div className="mx-auto flex max-w-5xl flex-col gap-6 p-6">
      <Card>
        <CardHeader>
          <CardDescription>Local SAML identity provider</CardDescription>
          <CardTitle className="flex flex-wrap items-center gap-x-2 text-2xl">
            Entity ID
            <span className="font-mono text-primary">{info.entity_id}</span>
            <CopyButton text={info.entity_id} variant="ghost" />
          </CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <p className="max-w-3xl text-sm text-muted-foreground">
            Point your service provider at the metadata URL{" "}
            <code>{info.metadata_url}</code>.{" "}
            {info.lenient ? (
              "Lenient mode: any service provider is accepted, with the ACS URL from its AuthnRequest."
            ) : (
              <>
                It answers the service providers it knows: declared in{" "}
                <code>localsaml.toml</code>, registered on the assertion
                generator page, or serving their metadata at their entity ID.
                (The SAML specification requires an identity provider to verify
                ACS URLs; <code>--lenient</code> accepts any.)
              </>
            )}{" "}
            Signing in shows an attribute editor instead of a password prompt.
          </p>
          <div className="flex gap-2">
            <Link to="/sp" className={buttonVariants()}>
              <LogInIcon data-icon="inline-start" />
              Try a login
            </Link>
            <Link to="/dev" className={buttonVariants({ variant: "outline" })}>
              <FileCodeIcon data-icon="inline-start" />
              Open assertion generator
            </Link>
          </div>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Endpoints</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableBody>
              {info.endpoints.map((e) => (
                <TableRow key={e.label}>
                  <TableCell className="w-72 whitespace-normal text-muted-foreground">
                    {e.label}
                  </TableCell>
                  <TableCell className="font-mono text-xs break-all whitespace-normal">
                    {e.url}
                  </TableCell>
                  <TableCell className="w-20 text-right">
                    <CopyButton text={e.url} variant="ghost" />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Signing certificate</CardTitle>
          <CardDescription>
            The same key signs for every issuer. Download it as{" "}
            <a
              href={`${prefix}/certificate.pem`}
              className="underline underline-offset-4"
            >
              PEM
            </a>{" "}
            for service providers that want the certificate rather than
            metadata.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-2 text-sm">
            {[
              ["SHA-1 fingerprint", cert.sha1_fingerprint],
              ["SHA-256 fingerprint", cert.sha256_fingerprint],
              ["Valid until", cert.not_after],
            ].map(([term, value]) => (
              <div key={term} className="contents">
                <dt className="text-muted-foreground">{term}</dt>
                <dd className="font-mono text-xs break-all">{value}</dd>
              </div>
            ))}
          </dl>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Quick start</CardTitle>
        </CardHeader>
        <CardContent>
          <CodeBlock
            title="Mint a Response with curl, for a service provider localsaml knows (declared, registered or discovered)"
            code={`curl -s '${dev}?sp=http://localhost:3000/saml/metadata&email=me@example.com' | jq .
curl -s -X POST ${dev} -H 'content-type: application/json' \\
  -d '{"preset":"okta","sp":"http://localhost:3000/saml/metadata","attributes":{"groups":["admins"]}}'`}
          />
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Templates</CardTitle>
          <CardDescription>
            Each template is also served as its own identity provider, with that
            provider's attribute names, NameID, signing behaviour, XML style and
            endpoint paths.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
          {info.issuers.map((t) => {
            const current = t.entity_id === info.entity_id
            return (
              <Item
                key={t.entity_id}
                variant="outline"
                size="sm"
                className={cn(current && "border-primary/40 bg-primary/5")}
                render={
                  <a
                    href={`${t.prefix}/`}
                    aria-current={current ? "page" : undefined}
                  />
                }
              >
                <ItemContent className="min-w-0">
                  <ItemTitle>
                    <PresetDot color={t.color} />
                    {t.name}
                  </ItemTitle>
                  <ItemDescription className="text-xs">
                    {t.description}
                  </ItemDescription>
                  <code className="truncate font-mono text-xs text-muted-foreground">
                    {t.entity_id}
                  </code>
                </ItemContent>
              </Item>
            )
          })}
        </CardContent>
      </Card>
    </div>
  )
}
