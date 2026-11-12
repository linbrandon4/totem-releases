# Desktop release runbook: signing, notarization, receipts

State this document assumes (verified 2026-11-11 against the published v0.9.31):
the updater feed is `github.com/linbrandon4/totem-releases`, updater signatures
already verify against the pinned key `ce539f4122c5c0ba`, the macOS bundle is
ad-hoc signed with hardened runtime and is not notarized, the Windows installer
has no Authenticode table and no `CompanyName` resource, and both platforms
publish the same build receipt.

Everything below is the build-side counterpart to
`checks/desktop-release-checks.mjs --require-trusted`. A successor release passes
only when both agree.

## 1. Windows: publisher identity and version metadata

Two separate things make Windows show a warning, and both must be fixed:

| Symptom | Cause | Fix |
| --- | --- | --- |
| "Windows protected your PC" / unknown publisher | no Authenticode signature (certificate table size 0) | sign the installer with an OV/EV code-signing certificate |
| Empty Company / Product version in Properties | installer has `ProductName` and `FileVersion` but no `CompanyName` | set the publisher in the bundler config |

In the Tauri config (`src-tauri/tauri.conf.json`) set the publisher and the
descriptive strings the version resource is built from:

```json
{
  "bundle": {
    "publisher": "Totem Labs, Inc.",
    "copyright": "Copyright (c) Totem Labs, Inc.",
    "shortDescription": "Totem desktop",
    "windows": {
      "nsis": { "displayName": "Totem" }
    }
  }
}
```

`bundle.publisher` is what the NSIS version resource emits as `CompanyName`; the
version comes from the top-level `version`. Rebuild, then confirm with the same
inspector the release check uses:

```sh
node checks/desktop-release-checks.mjs --tag v0.9.32 --asset-base http://127.0.0.1:8099/v0.9.32
# {"check":"windows installer metadata","versionInfo":{"CompanyName":"Totem Labs, Inc.",...}}
```

Sign, after the installer bytes are final (signing invalidates any earlier hash):

```powershell
signtool sign /fd sha256 /td sha256 /tr http://timestamp.digicert.com `
  /f C:\secrets\totem-codesign.pfx /p $env:TOTEM_CSC_PASSWORD `
  Totem-Windows-x64.exe
signtool verify /pa /all Totem-Windows-x64.exe
```

With an HSM or Azure Trusted Signing, use that provider's signing tool and keep
the timestamp step. EV certificates get SmartScreen reputation immediately; OV
certificates accumulate it, so early downloads still show a prompt until Microsoft
has seen enough installs. Defender scanning is a separate claim and must be
evidenced separately.

## 2. macOS: Developer ID, hardened runtime, notarization, staple

Sign every nested binary before the bundle, with the hardened runtime and a
timestamp, then verify the result:

```sh
codesign --force --options runtime --timestamp \
  --entitlements apps/desktop/entitlements.mac.plist \
  --sign "Developer ID Application: Totem Labs, Inc. (TEAMID1234)" \
  Totem.app/Contents/MacOS/totem-desktop
codesign --force --options runtime --timestamp \
  --sign "Developer ID Application: Totem Labs, Inc. (TEAMID1234)" Totem.app
codesign --verify --strict --verbose=2 Totem.app
spctl -a -vv --type execute Totem.app    # expect: accepted, source=Notarized Developer ID
```

Notarize the DMG (the website installer) and staple it so first launch works
offline:

```sh
xcrun notarytool store-credentials totem-notary \
  --apple-id "$APPLE_ID" --team-id "$APPLE_TEAM_ID" --password "$APPLE_APP_PASSWORD"
xcrun notarytool submit Totem-Mac-Apple-Silicon.dmg --keychain-profile totem-notary --wait
xcrun stapler staple Totem-Mac-Apple-Silicon.dmg
xcrun stapler validate Totem-Mac-Apple-Silicon.dmg
```

Order matters for the updater payload: sign the app, create the archive from the
signed bundle, and sign the archive last, so the trusted comment names the asset
that is actually published:

```sh
tar -czf Totem-Mac-Apple-Silicon.app.tar.gz Totem.app
node_modules/.bin/tauri signer sign -f "$TAURI_SIGNING_PRIVATE_KEY" \
  -p "$TAURI_SIGNING_PRIVATE_KEY_PASSWORD" Totem-Mac-Apple-Silicon.app.tar.gz
sha256sum Totem-Mac-Apple-Silicon.app.tar.gz > SHA256SUMS
```

v0.9.24 shipped a signature whose trusted comment named `Totem.app.tar.gz`, which
is why the verifier warns on it and fails it under `--require-trusted`.

**Do not rotate the updater key in the same release that adds signing.** The key
must match the one compiled into the app the user already has, or every existing
install loses the ability to verify updates.

## 3. Per-platform build receipts

`mac-build-receipt.json` and `windows-build-receipt.json` in v0.9.31 are
byte-identical and contain only renderer/source digests, so they prove nothing
about either native build. A trusted release needs them to differ and to bind the
native build to the served bytes:

```json
{
  "version": "0.9.32",
  "sourceCommit": "<40 hex>",
  "platform": "windows-x86_64",
  "checks": ["nsis-build", "signtool-verify", "clean-install"],
  "build": {
    "host": "windows-builder-2024",
    "artifactSha256": "<sha256 of the published installer>",
    "signing": { "status": "Signed", "publisher": "Totem Labs, Inc." }
  }
}
```

macOS uses `"platform": "darwin-aarch64"` and
`"signing": { "status": "DeveloperID", "teamId": "TEAMID1234", "notarized": true }`.
The verifier rejects a receipt whose `platform` does not match its artifact, whose
`build.artifactSha256` differs from the served bytes, whose `build.signing.status`
is not `Signed` (Windows) or `DeveloperID` (macOS), or that is identical to the
other platform's receipt.

## 4. Approval

Publish the successor as a new tag — never replace a published asset — then:

1. `release-approval` workflow, `distribution: trusted`, with the source commit,
   version and the sha256 of the published `latest.json`. The job verifies the
   manifest, runs the gate, and records the artifact digests plus the report hash.
2. Physical checks the workflow cannot do: clean install on macOS and Windows,
   an actual update from an installed earlier build, launch, retained login/data,
   Explorer publisher and icon, SmartScreen prompt behaviour.
3. Only then repoint the website download link at the successor.
