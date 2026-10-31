# Changesets

Every pull request that changes localsaml's behaviour needs a changeset: a short
Markdown file saying what changed and whether that's a `patch`, `minor` or
`major` change. Create one with:

```sh
npm run changeset
```

For changes users won't notice (CI, tests, docs), add an empty one with
`npm run changeset -- --empty`.

When changesets land on `main`, a "Release <version>" pull request collects them
into the next version and its changelog. Merging that pull request publishes
the Docker image and the GitHub release. See "Releases" in the README.
