// Verifies a published Totem desktop release from its public artifacts only.
//
// Covers the gaps that let an unverifiable release ship: updater signatures that
// do not match the pinned key, hashes that disagree between latest.json,
// the per-platform manifests, SHA256SUMS and the bytes actually served, and
// platform manifests or build receipts that describe a different build than the
// one the updater will install.
//
// Usage:
//   node checks/desktop-release-checks.mjs --tag v0.9.31 [--require-trusted]
//   node checks/desktop-release-checks.mjs --tag v0.9.31 --asset-base http://127.0.0.1:8099/v0.9.31
//
// Exit code 0 means every blocking check passed. --require-trusted additionally
// demands Developer ID + notarized macOS artifacts and Authenticode-signed
// Windows artifacts, and is what a distribution release must satisfy.

import assert from "node:assert/strict";
import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import { createWriteStream } from "node:fs";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const args = new Map();
for (let i = 2; i < process.argv.length; i += 1) {
  const arg = process.argv[i];
  if (!arg.startsWith("--")) continue;
  const next = process.argv[i + 1];
  if (next === undefined || next.startsWith("--")) args.set(arg.slice(2), true);
  else {
    args.set(arg.slice(2), next);
    i += 1;
  }
}

const repository = args.get("repository") ?? "linbrandon4/totem-releases";
const tag = args.get("tag");
const requireTrusted = args.get("require-trusted") === true;
const assetBase =
  args.get("asset-base") ??
  `https://github.com/${repository}/releases/download/${tag}`;
assert.match(String(tag), /^v\d+\.\d+\.\d+$/, "--tag must look like v0.9.31");
assert.doesNotMatch(String(assetBase), /[?#]/, "--asset-base must not carry a query");

const MAX_BYTES = 200 * 1024 * 1024;
const sha256 = (buffer) => createHash("sha256").update(buffer).digest("hex");

// --- pinned updater key -----------------------------------------------------

const pinned = (await readFile(join(here, "updater-pubkey.txt"), "utf8")).trim();
const pinnedLines = pinned.split("\n");
assert.match(pinnedLines[0], /^untrusted comment: minisign public key: [0-9A-F]{16}$/);
const pinnedKey = Buffer.from(pinnedLines[1], "base64");
assert.equal(pinnedKey.length, 42, "pinned public key must be 42 bytes");
assert.equal(pinnedKey.subarray(0, 2).toString(), "Ed", "pinned key must be Ed25519");
const pinnedKeyId = pinnedKey.subarray(2, 10).toString("hex");
const publicKey = createPublicKey({
  key: Buffer.concat([
    Buffer.from("302a300506032b6570032100", "hex"),
    pinnedKey.subarray(10),
  ]),
  format: "der",
  type: "spki",
});

// --- helpers ----------------------------------------------------------------

const results = [];
const warnings = [];
function record(name, detail = {}) {
  results.push({ check: name, passed: true, ...detail });
  console.log(JSON.stringify({ check: name, passed: true, ...detail }));
}
function fail(name, message) {
  results.push({ check: name, passed: false, error: message });
  throw new Error(`${name}: ${message}`);
}
async function fetchOk(url) {
  const response = await fetch(url, { redirect: "follow" });
  if (response.status !== 200) throw new Error(`GET ${url} -> ${response.status}`);
  const length = Number(response.headers.get("content-length") ?? "0");
  if (length > MAX_BYTES) throw new Error(`GET ${url} -> ${length} bytes exceeds cap`);
  return Buffer.from(await response.arrayBuffer());
}
async function fetchToFile(url, path) {
  const response = await fetch(url, { redirect: "follow" });
  if (response.status !== 200) throw new Error(`GET ${url} -> ${response.status}`);
  if (!response.body) throw new Error(`GET ${url} -> empty body`);
  await pipeline(Readable.fromWeb(response.body), createWriteStream(path));
  return (await stat(path)).size;
}
function parseSignatureBox(base64) {
  const text = Buffer.from(base64, "base64").toString("utf8");
  const lines = text.trimEnd().split("\n");
  if (lines.length !== 4 || lines[3].length === 0) {
    throw new Error(`signature box has ${lines.length} lines, expected 4`);
  }
  if (!lines[0].startsWith("untrusted comment: ")) throw new Error("missing untrusted comment");
  if (!lines[2].startsWith("trusted comment: ")) throw new Error("missing trusted comment");
  const payload = Buffer.from(lines[1], "base64");
  if (payload.length !== 74) throw new Error(`signature payload is ${payload.length} bytes, expected 74`);
  const algorithm = payload.subarray(0, 2).toString();
  if (algorithm !== "ED" && algorithm !== "Ed") throw new Error(`unsupported signature algorithm ${algorithm}`);
  const keyId = payload.subarray(2, 10).toString("hex");
  const signature = payload.subarray(10);
  const trustedComment = lines[2].slice("trusted comment: ".length);
  const globalSignature = Buffer.from(lines[3], "base64");
  if (globalSignature.length !== 64) {
    throw new Error(`global signature is ${globalSignature.length} bytes, expected 64`);
  }
  return { algorithm, keyId, signature, trustedComment, globalSignature };
}
function verifyMinisign(name, data, base64, expectedFile, requireFilename = false) {
  let box;
  try {
    box = parseSignatureBox(base64);
  } catch (error) {
    return fail(name, `malformed signature box: ${error.message}`);
  }
  if (box.keyId !== pinnedKeyId) {
    fail(name, `signed with key ${box.keyId}, feed pins ${pinnedKeyId}`);
  }
  const message =
    box.algorithm === "ED" ? createHash("blake2b512").update(data).digest() : data;
  if (!cryptoVerify(null, message, publicKey, box.signature)) {
    fail(name, "signature does not verify over the served bytes");
  }
  const globalMessage = Buffer.concat([box.signature, Buffer.from(box.trustedComment, "utf8")]);
  if (!cryptoVerify(null, globalMessage, publicKey, box.globalSignature)) {
    fail(name, "trusted comment signature does not verify");
  }
  // tauri's signer writes tab-separated fields and the asset basename; a
  // signature that names another file or version is a mislabeled artifact.
  const fields = new Map(
    box.trustedComment
      .split(/\t| (?=\w+:)/)
      .map((part) => part.split(/:(.*)/s).slice(0, 2))
      .filter(([key, value]) => key && value !== undefined && value !== "")
      .map(([key, value]) => [key.trim(), value.trim()]),
  );
  if (fields.has("file") && fields.get("file") !== expectedFile) {
    const message = `signature names ${fields.get("file")}, artifact is ${expectedFile}`;
    if (requireFilename) fail(name, message);
    warnings.push(`${name}: ${message}`);
    console.log(JSON.stringify({ warning: warnings.at(-1) }));
  }
  if (fields.has("version") && fields.get("version") !== version) {
    fail(name, `signature names version ${fields.get("version")}, release is ${version}`);
  }
  record(name, {
    keyId: box.keyId,
    file: fields.get("file") ?? null,
    version: fields.get("version") ?? null,
  });
  return fields;
}

// --- manifests --------------------------------------------------------------

const latest = JSON.parse(await fetchOk(`${assetBase}/latest.json`).then((b) => b.toString("utf8")));
const version = tag.slice(1);
if (latest.version !== version) fail("latest.json version", `${latest.version} != ${version}`);
if (!Number.isFinite(Date.parse(latest.pub_date))) fail("latest.json pub_date", "not a timestamp");
if (!/^[a-f0-9]{40}$/.test(latest.sourceCommit ?? "")) {
  fail("latest.json sourceCommit", "missing or malformed");
}
record("latest.json manifest", { version, pubDate: latest.pub_date, sourceCommit: latest.sourceCommit });

const platforms = latest.platforms ?? {};
for (const target of ["darwin-aarch64", "windows-x86_64"]) {
  if (!platforms[target]) fail(`latest.json platforms.${target}`, "missing");
}
for (const [target, entry] of Object.entries(platforms)) {
  if (!entry.signature || !entry.url) fail(`latest.json platforms.${target}`, "needs signature and url");
  const url = new URL(entry.url);
  const expected = `/linbrandon4/totem-releases/releases/download/${tag}/`;
  if (url.protocol !== "https:" || url.host !== "github.com" || !url.pathname.startsWith(expected)) {
    fail(`latest.json platforms.${target}.url`, `${entry.url} is outside the pinned release path`);
  }
}

const work = await mkdtemp(join(tmpdir(), "totem-desktop-check-"));
try {
  const files = new Map();
  for (const [target, entry] of Object.entries(platforms)) {
    const name = decodeURIComponent(new URL(entry.url).pathname.split("/").pop());
    const path = join(work, name);
    const bytes = await fetchToFile(`${assetBase}/${encodeURIComponent(name)}`, path);
    const digest = sha256(await readFile(path));
    files.set(target, { name, path, bytes, digest });
    const sigAsset = await fetchOk(`${assetBase}/${encodeURIComponent(`${name}.sig`)}`)
      .then((b) => b.toString("utf8").trim())
      .catch(() => null);
    if (sigAsset !== null && sigAsset !== entry.signature.trim()) {
      fail(`signature asset ${name}.sig`, "does not match latest.json");
    }
    verifyMinisign(
      `updater signature ${target}`,
      await readFile(path),
      entry.signature,
      name,
      requireTrusted,
    );
    record(`artifact ${name}`, { bytes, sha256: digest, sigAssetMatchesInline: sigAsset !== null });
  }

  // SHA256SUMS and the per-platform manifests must agree with the served bytes.
  const sumsText = await fetchOk(`${assetBase}/SHA256SUMS`)
    .then((b) => b.toString("utf8"))
    .catch(() => null);
  if (sumsText === null) {
    if (requireTrusted) fail("SHA256SUMS", "missing from a trusted release");
    warnings.push("SHA256SUMS is not published for this release");
    console.log(JSON.stringify({ warning: warnings.at(-1) }));
  }
  const sums = new Map(
    (sumsText ?? "")
      .split("\n")
      .filter(Boolean)
      .map((line) => {
        const [digest, name] = line.trim().split(/\s+/);
        return [name.replace(/^\*/, ""), digest];
      }),
  );
  if (sumsText !== null && sums.size === 0) fail("SHA256SUMS", "empty");
  for (const { name, digest } of files.values()) {
    if (sumsText === null) break;
    if (!sums.has(name)) fail("SHA256SUMS", `${name} is not listed`);
    if (sums.get(name) !== digest) fail("SHA256SUMS", `${name} digest does not match served bytes`);
  }
  if (sumsText !== null) record("SHA256SUMS", { entries: sums.size });

  const manifestFiles = new Map([
    ["darwin-aarch64", ["darwin-aarch64.json", "mac-build-receipt.json"]],
    ["windows-x86_64", ["windows-x86_64.json", "windows-build-receipt.json"]],
  ]);
  const receipts = [];
  for (const [target, [manifestName, receiptName]] of manifestFiles) {
    const manifest = JSON.parse(
      await fetchOk(`${assetBase}/${manifestName}`).then((b) => b.toString("utf8")),
    );
    const served = files.get(target);
    if (manifest.target !== target) fail(manifestName, `target is ${manifest.target}`);
    if (manifest.version !== version) fail(manifestName, `version ${manifest.version} != ${version}`);
    if (manifest.sourceCommit !== latest.sourceCommit) {
      fail(manifestName, `sourceCommit ${manifest.sourceCommit} != ${latest.sourceCommit}`);
    }
    if (manifest.sha256 !== served.digest) fail(manifestName, "sha256 does not match served bytes");
    if (manifest.installerSha256 === undefined) fail(manifestName, "missing installerSha256");
    const installerName = manifest.installer ?? served.name;
    const installer = decodeURIComponent(installerName);
    const installerPath = join(work, installer);
    await fetchToFile(`${assetBase}/${encodeURIComponent(installer)}`, installerPath);
    const installerDigest = sha256(await readFile(installerPath));
    if (installerDigest !== manifest.installerSha256) {
      fail(manifestName, "installerSha256 does not match served installer");
    }
    if (sumsText !== null && (!sums.has(installer) || sums.get(installer) !== installerDigest)) {
      fail("SHA256SUMS", `${installer} digest does not match served installer`);
    }
    if (manifest.signature !== platforms[target].signature) {
      fail(manifestName, "signature differs from latest.json");
    }
    record(manifestName, {
      target,
      version: manifest.version,
      installer,
      installerSha256: installerDigest,
      publisherSignature: manifest.publisherSignature ?? null,
    });

    const receiptText = await fetchOk(`${assetBase}/${receiptName}`)
      .then((b) => b.toString("utf8"))
      .catch(() => null);
    if (receiptText === null) {
      if (requireTrusted) fail(receiptName, "missing from a trusted release");
      warnings.push(`${receiptName} is not published for this release`);
      console.log(JSON.stringify({ warning: warnings.at(-1) }));
      continue;
    }
    const receipt = JSON.parse(receiptText);
    if (receipt.version !== version) fail(receiptName, `version ${receipt.version} != ${version}`);
    if (receipt.sourceCommit !== latest.sourceCommit) {
      fail(receiptName, `sourceCommit ${receipt.sourceCommit} != ${latest.sourceCommit}`);
    }
    receipts.push({
      name: receiptName,
      target,
      platform: receipt.platform ?? null,
      checks: receipt.checks ?? null,
      digest: sha256(Buffer.from(JSON.stringify(receipt))),
    });
    record(receiptName, {
      version: receipt.version,
      sourceCommit: receipt.sourceCommit,
      platform: receipt.platform ?? null,
    });
  }
  // A receipt that only carries source and renderer digests is identical on both
  // platforms; that is allowed for an unsigned preview but proves nothing about
  // the native build, so it is reported and enforced under --require-trusted.
  if (receipts.length === 2 && receipts[0].digest === receipts[1].digest) {
    warnings.push(
      "macOS and Windows build receipts are byte-identical and record no platform-specific build evidence",
    );
    console.log(JSON.stringify({ warning: warnings.at(-1) }));
  }

  if (requireTrusted) {
    const mac = JSON.parse(await fetchOk(`${assetBase}/darwin-aarch64.json`).then((b) => b.toString("utf8")));
    const win = JSON.parse(await fetchOk(`${assetBase}/windows-x86_64.json`).then((b) => b.toString("utf8")));
    if (mac.publisherSignature?.status !== "DeveloperID") {
      fail("trusted distribution macOS", `publisher status is ${mac.publisherSignature?.status}`);
    }
    if (mac.publisherSignature?.notarized !== true) fail("trusted distribution macOS", "not notarized");
    if (!/^[A-Z0-9]{10}$/.test(mac.publisherSignature?.teamId ?? "")) {
      fail("trusted distribution macOS", "missing Apple team id");
    }
    if (win.publisherSignature?.status !== "Signed" || !win.publisherSignature?.publisher) {
      fail("trusted distribution Windows", `publisher status is ${win.publisherSignature?.status}`);
    }
    for (const receipt of receipts) {
      if (receipt.platform !== receipt.target) {
        fail("trusted distribution receipts", `${receipt.name} does not record platform ${receipt.target}`);
      }
      if (!Array.isArray(receipt.checks) || receipt.checks.length === 0) {
        fail("trusted distribution receipts", `${receipt.name} records no native build checks`);
      }
    }
    record("trusted distribution gate", { mac: mac.publisherSignature, windows: win.publisherSignature });
  }

  const report = {
    repository,
    tag,
    version,
    sourceCommit: latest.sourceCommit,
    requireTrusted,
    assetBase,
    passed: results.every((result) => result.passed),
    warnings,
    results,
  };
  if (typeof args.get("report") === "string") {
    await import("node:fs/promises").then(({ writeFile }) =>
      writeFile(args.get("report"), JSON.stringify(report, null, 2) + "\n"),
    );
  }
  console.log(JSON.stringify({ release: tag, passed: report.passed }));
} finally {
  await rm(work, { recursive: true, force: true });
}
