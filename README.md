# totem-releases
Official Totem desktop installers and signed updates. Application source remains private.

## Desktop release verification

`checks/desktop-release-checks.mjs` re-derives a release's trust from its public
bytes instead of trusting the approval inputs. For a published tag it checks that
`latest.json`, the per-platform manifests, `SHA256SUMS`, the build receipts and
the served installers all describe the same build, and that every updater
signature verifies against the key pinned in `checks/updater-pubkey.txt`.

```sh
node checks/desktop-release-checks.mjs --tag v0.9.31
node checks/desktop-release-checks.mjs --tag v0.9.31 --require-trusted
node --test checks/desktop-release-checks.test.mjs
```

`--require-trusted` is the distribution gate: it additionally demands Developer
ID signing, a notarized macOS build, an Authenticode-signed Windows installer whose
version resource carries Company/Product/FileVersion, and per-platform build
receipts that bind their native build to the served bytes. It refuses signatures
whose trusted comment names another file, and it lists every blocker in one run.
The build-side steps are in `docs/desktop-signing-runbook.md`. Without it the command accepts an unsigned preview but prints
every deviation as a warning.

`--asset-base` points the same checks at a local directory served over HTTP, so a
candidate can be verified before it is published.

The pinned key must be the key compiled into the shipped app; rotating it without
shipping the new key in the app breaks updates for every existing install.
