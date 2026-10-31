// Prints the release notes for a version: its CHANGELOG.md section, plus
// how to run the image. Usage: node scripts/release-notes.mjs 1.2.3
import { readFileSync } from "node:fs";

const version = process.argv[2];
if (!version) throw new Error("usage: release-notes.mjs <version>");

const lines = readFileSync("CHANGELOG.md", "utf8").split("\n");
const start = lines.findIndex((line) => line.trim() === `## ${version}`);
if (start === -1) throw new Error(`CHANGELOG.md has no section for ${version}`);
const end = lines.findIndex((line, i) => i > start && line.startsWith("## "));
const section = lines.slice(start + 1, end === -1 ? undefined : end).join("\n").trim();

const image = `ghcr.io/${process.env.GITHUB_REPOSITORY ?? "samlaycock/localsaml"}`;
console.log(`${section}

## Docker image

\`\`\`sh
docker run --rm -p 9401:9401 -v localsaml:/data ${image}:${version}
\`\`\`
`);
