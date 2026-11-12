// Regression tests for checks/desktop-release-checks.mjs. The verifier is only
// trustworthy if a tampered release actually fails it, so every case here serves
// a mutated copy of a real published release over loopback HTTP and asserts the
// verifier rejects it.
//
//   node --test checks/desktop-release-checks.test.mjs
//
// The real release assets are fetched once into a cache directory; set
// TOTEM_DESKTOP_FIXTURES to reuse an existing cache.

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { createServer } from "node:http";
import { existsSync } from "node:fs";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const checker = join(here, "desktop-release-checks.mjs");
const tag = "v0.9.31";
const releaseBase = `https://github.com/linbrandon4/totem-releases/releases/download/${tag}`;

const fixtures = [
  "latest.json",
  "SHA256SUMS",
  "darwin-aarch64.json",
  "windows-x86_64.json",
  "mac-build-receipt.json",
  "windows-build-receipt.json",
  "Totem-Mac-Apple-Silicon.app.tar.gz",
  "Totem-Mac-Apple-Silicon.app.tar.gz.sig",
  "Totem-Mac-Apple-Silicon.dmg",
  "Totem-Windows-x64.exe",
  "Totem-Windows-x64.exe.sig",
];

const cacheDir =
  process.env.TOTEM_DESKTOP_FIXTURES ?? join(tmpdir(), `totem-desktop-fixtures-${tag}`);
const openServers = [];

async function ensureFixtures() {
  await mkdir(cacheDir, { recursive: true });
  for (const name of fixtures) {
    const path = join(cacheDir, name);
    if (existsSync(path)) continue;
    const response = await fetch(`${releaseBase}/${encodeURIComponent(name)}`);
    assert.equal(response.status, 200, `fixture ${name}`);
    await writeFile(path, Buffer.from(await response.arrayBuffer()));
  }
}

function serve(directory) {
  const server = createServer(async (request, response) => {
    const name = decodeURIComponent(new URL(request.url, "http://127.0.0.1").pathname.slice(1));
    if (!name || name.includes("/") || name.includes("..")) {
      response.writeHead(404).end();
      return;
    }
    try {
      const body = await readFile(join(directory, name));
      response.writeHead(200, { "content-length": body.length }).end(body);
    } catch {
      response.writeHead(404).end();
    }
  });
  openServers.push(server);
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve(`http://127.0.0.1:${server.address().port}`));
  });
}

const execFileAsync = promisify(execFile);

// The fixture server lives in this process, so the child must run asynchronously
// or the event loop cannot answer its requests.
async function run(base, extra = []) {
  const args = [checker, "--tag", tag, "--asset-base", base, ...extra];
  try {
    const { stdout, stderr } = await execFileAsync(process.execPath, args, {
      encoding: "utf8",
      maxBuffer: 32 * 1024 * 1024,
    });
    return { status: 0, output: `${stdout}${stderr}` };
  } catch (error) {
    return { status: error.code ?? 1, output: `${error.stdout ?? ""}${error.stderr ?? ""}` };
  }
}

// Each case gets a private copy of the cached release so mutations cannot leak.
async function withRelease(mutate, assertion) {
  const directory = await mkdtemp(join(tmpdir(), "totem-desktop-case-"));
  await cp(cacheDir, directory, { recursive: true });
  if (mutate) await mutate(directory);
  openServers.length = 0;
  const base = await serve(directory);
  try {
    await assertion(await run(base), base);
  } finally {
    for (const server of openServers) server.close();
    await rm(directory, { recursive: true, force: true });
  }
}

async function expectFailure(mutate, message, extra = []) {
  await withRelease(mutate, async (result, base) => {
    if (extra.length > 0) result = await run(base, extra);
    assert.equal(result.status, 1, `expected failure, got ${result.status}\n${result.output}`);
    assert.match(result.output, message);
  });
}

async function patchJson(directory, name, change) {
  const path = join(directory, name);
  const value = JSON.parse(await readFile(path, "utf8"));
  change(value);
  await writeFile(path, JSON.stringify(value, null, 2));
}

const mutating = (name, change) => (directory) => patchJson(directory, name, change);

before(ensureFixtures);

after(async () => {
  for (const server of openServers) server.close();
});

test("the published release passes", async () => {
  await withRelease(null, async (result) => {
    assert.equal(result.status, 0, result.output.slice(-2000));
    assert.match(result.output, new RegExp(`"release":"${tag}","passed":true`));
  });
});

test("a flipped byte in the served installer fails signature verification", async () => {
  await expectFailure(
    async (directory) => {
      const path = join(directory, "Totem-Windows-x64.exe");
      const body = await readFile(path);
      body[Math.floor(body.length / 2)] ^= 0xff;
      await writeFile(path, body);
    },
    /does not verify over the served bytes/,
  );
});

test("a feed advertising another version fails", async () => {
  await expectFailure(
    mutating("latest.json", (manifest) => {
      manifest.version = "0.9.30";
    }),
    /latest\.json version: 0\.9\.30 != 0\.9\.31/,
  );
});

test("a SHA256SUMS digest that disagrees with the served bytes fails", async () => {
  await expectFailure(
    async (directory) => {
      const path = join(directory, "SHA256SUMS");
      const lines = (await readFile(path, "utf8")).trimEnd().split("\n");
      lines[0] = `${"0".repeat(64)}  Totem-Mac-Apple-Silicon.app.tar.gz`;
      await writeFile(path, `${lines.join("\n")}\n`);
    },
    /SHA256SUMS: [^:]*digest does not match served bytes/,
  );
});

test("signatures swapped between platforms fail", async () => {
  await expectFailure(
    mutating("latest.json", (manifest) => {
      const mac = manifest.platforms["darwin-aarch64"].signature;
      manifest.platforms["darwin-aarch64"].signature = manifest.platforms["windows-x86_64"].signature;
      manifest.platforms["windows-x86_64"].signature = mac;
    }),
    /(does not match latest\.json|does not verify over the served bytes)/,
  );
});

test("a platform manifest hash for different bytes fails", async () => {
  await expectFailure(
    mutating("darwin-aarch64.json", (manifest) => {
      manifest.sha256 = "1".repeat(64);
    }),
    /darwin-aarch64\.json: sha256 does not match served bytes/,
  );
});

test("a build receipt from another source commit fails", async () => {
  await expectFailure(
    mutating("windows-build-receipt.json", (receipt) => {
      receipt.sourceCommit = "2".repeat(40);
    }),
    /windows-build-receipt\.json: sourceCommit .* != /,
  );
});

test("a receipt claiming another platform is rejected", async () => {
  await expectFailure(
    mutating("mac-build-receipt.json", (receipt) => {
      receipt.platform = "windows-x86_64";
    }),
    /mac-build-receipt\.json does not record platform darwin-aarch64/,
    ["--require-trusted"],
  );
});

test("a receipt that does not bind the served artifact is rejected", async () => {
  await expectFailure(
    mutating("mac-build-receipt.json", (receipt) => {
      receipt.platform = "darwin-aarch64";
      receipt.checks = ["codesign-verify"];
      receipt.build = { host: "mac-builder", artifactSha256: "3".repeat(64), signing: { status: "DeveloperID" } };
    }),
    /mac-build-receipt\.json build digest does not match the served artifact/,
    ["--require-trusted"],
  );
});

test("an unsigned preview cannot satisfy --require-trusted", async () => {
  await withRelease(null, async (result, base) => {
    const trusted = await run(base, ["--require-trusted"]);
    assert.equal(trusted.status, 1, trusted.output.slice(-2000));
    assert.match(trusted.output, /publisher status is AdHoc/);
    assert.match(trusted.output, /installer has no CompanyName resource/);
    assert.match(trusted.output, /receipts are identical/);
  });
});
