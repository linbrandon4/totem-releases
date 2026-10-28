import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

// Tests only the public distributable, synthetic credentials and disposable user state.
const [packagePath, version] = process.argv.slice(2);
const root = await mkdtemp(join(homedir(), "totem-release-check-"));
const load = (name) => import(pathToFileURL(join(resolve(packagePath), "bin", name)));
const results = [];
const windows = process.platform === "win32";
const ps = (script) =>
  execFileSync(
    join(
      process.env.SystemRoot ?? process.env.SYSTEMROOT,
      "System32/WindowsPowerShell/v1.0/powershell.exe",
    ),
    [
      "-NoProfile",
      "-NonInteractive",
      "-EncodedCommand",
      Buffer.from("$ErrorActionPreference='Stop';" + script, "utf16le").toString("base64"),
    ],
    { encoding: "utf8", timeout: 20000, windowsHide: true },
  );
const literal = (path) =>
  `[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${Buffer.from(path).toString("base64")}'))`;
async function privateAcl(path) {
  if (!windows) return;
  ps(
    `$p=${literal(path)};$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User;$a=[Security.AccessControl.DirectorySecurity]::new();$a.SetOwner($sid);$a.SetAccessRuleProtection($true,$false);$a.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow'));Set-Acl -LiteralPath $p -AclObject $a`,
  );
}
async function fixture() {
  const path = await mkdtemp(join(root, "case-"));
  await privateAcl(path);
  const key = join(path, "key.json");
  await writeFile(key, JSON.stringify({ synthetic: true }), { mode: 0o600 });
  return { path, key };
}
async function check(name, run) {
  await run();
  results.push({ name, passed: true });
  console.log(JSON.stringify({ check: name, passed: true }));
}
try {
  await privateAcl(root);
  const pkg = JSON.parse(await readFile(join(packagePath, "package.json"), "utf8"));
  assert.equal(pkg.name, "totemlayer");
  assert.equal(pkg.version, version);
  const { assertWindowsPrivatePath } = await load("windows-private-path.mjs");
  const { privateDirectory, privateWrite, privateRead, ensureInstalledRuntime } = await load(
    "runtime-installation.mjs",
  );
  const { saveAgentProfile, readAgentProfile, readAgentCredential } =
    await load("agent-profile.mjs");
  await check("packaged CLI version and command aliases", async () => {
    const output = execFileSync(
      process.execPath,
      [join(packagePath, "bin/totem.mjs"), "--version"],
      { encoding: "utf8", timeout: 20000 },
    );
    assert.equal(output.trim(), version);
    assert.deepEqual(Object.keys(pkg.bin).sort(), ["agenttrust", "totem", "totemlayer"]);
  });
  await check("bundled complete guide pins the exact tested client", async () => {
    const { readReleaseSetupGuide } = await load("setup-guide.mjs");
    const primary = await readReleaseSetupGuide();
    const alternate = await readReleaseSetupGuide("alternate");
    assert.equal(primary.integrityVerified, true);
    assert.equal(primary.sha256, alternate.sha256);
    assert(primary.text.includes(`release **${version}**`));
    assert(primary.text.includes(`totemlayer-${version}.tgz`));
  });
  await check("private owned key and directory remain usable", async () => {
    const f = await fixture();
    await assertWindowsPrivatePath(f.key);
    await assertWindowsPrivatePath(f.path);
    await privateDirectory(join(f.path, "new-state"));
    await privateWrite(join(f.path, "new-state/state.json"), { synthetic: true });
    assert.deepEqual(await privateRead(join(f.path, "new-state/state.json")), { synthetic: true });
  });
  await check("real packaged profile writer and credential reader", async () => {
    const f = await fixture();
    const environment = { ...process.env, TOTEM_CONFIG_DIR: f.path };
    const token = "tn_test_" + "x".repeat(43);
    const saved = await saveAgentProfile(
      "fixture",
      {
        baseUrl: "http://127.0.0.1:9",
        agentId: "11111111-2222-4333-8444-555555555555",
        address: "fixture@fixture.totem",
        environment: "SANDBOX",
        provider: "codex",
        model: "synthetic-fixture-model",
        repositoryRoots: [],
      },
      token,
      { environment },
    );
    const read = await readAgentProfile("fixture", { environment });
    assert.equal(read.agentId, saved.agentId);
    assert.equal(await readAgentCredential(read), token);
  });
  if (windows) {
    await check("inherited Everyone read access is rejected before private read", async () => {
      const f = await fixture();
      ps(
        `$p=${literal(f.path)};$a=Get-Acl -LiteralPath $p;$a.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-1-0'),'Read','ContainerInherit,ObjectInherit','None','Allow'));Set-Acl -LiteralPath $p -AclObject $a`,
      );
      await assert.rejects(assertWindowsPrivatePath(f.key));
      await assert.rejects(privateRead(f.key));
    });
    await check("broad ancestor replacement grant is rejected", async () => {
      const f = await fixture();
      const child = join(f.path, "child");
      await mkdir(child);
      await privateAcl(child);
      const key = join(child, "key.json");
      await writeFile(key, "{}");
      ps(
        `$p=${literal(f.path)};$a=Get-Acl -LiteralPath $p;$a.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-1-0'),'DeleteSubdirectoriesAndFiles','Allow'));Set-Acl -LiteralPath $p -AclObject $a`,
      );
      await assert.rejects(assertWindowsPrivatePath(key));
    });
    await check("non-user file ownership is rejected", async () => {
      const f = await fixture();
      ps(
        `$p=${literal(f.key)};$a=Get-Acl -LiteralPath $p;$a.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'));Set-Acl -LiteralPath $p -AclObject $a`,
      );
      await assert.rejects(assertWindowsPrivatePath(f.key));
    });
    await check("junction traversal is rejected", async () => {
      const f = await fixture();
      const target = join(f.path, "target"),
        link = join(f.path, "junction");
      await mkdir(target);
      await writeFile(join(target, "key.json"), "{}");
      await symlink(target, link, "junction");
      await assert.rejects(assertWindowsPrivatePath(join(link, "key.json")));
    });
  }
  await check("default and opt-in package hooks create no background state", async () => {
    const { postinstallMain } = await load("installation.mjs");
    for (const option of [undefined, "0", "1"]) {
      const f = await fixture();
      const environment = { ...process.env, TOTEM_CONFIG_DIR: f.path };
      delete environment.CI;
      delete environment.TOTEM_AUTO_START;
      if (option !== undefined) environment.TOTEM_AUTO_START = option;
      const before = await readdir(f.path);
      assert.equal(await postinstallMain(environment, { stdout: { write() {} } }), 0);
      assert.deepEqual(await readdir(f.path), before);
    }
  });
  await check("explicit runtime preparation and cleanup", async () => {
    const f = await fixture();
    const environment = {
      ...process.env,
      TOTEM_CONFIG_DIR: f.path,
      TOTEM_AUTO_START: "0",
      TOTEM_AUTO_UPDATE: "0",
      CI: "1",
    };
    const runtime = await ensureInstalledRuntime(environment);
    assert.equal(runtime.version, version);
    assert.equal((await privateRead(join(f.path, "runtime/current.json"))).version, version);
    const native = JSON.parse(
      await readFile(
        join(
          runtime.root,
          "runtime-packages",
          version,
          "node_modules/totemlayer/bin/native/darwin-lifetime.json",
        ),
        "utf8",
      ),
    );
    const binary = await readFile(
      join(
        runtime.root,
        "runtime-packages",
        version,
        "node_modules/totemlayer/bin/native/darwin-lifetime",
      ),
    );
    assert.equal(createHash("sha256").update(binary).digest("hex"), native.binarySha256);
  });
  if (process.env.NATIVE_CODEX_CHECK === "1") {
    if (process.env.RUNTIME_ARCHIVE_URL && process.env.RUNTIME_MANIFEST_URL) {
      await check(
        "exact signed update extracts and protects state on the native platform",
        async () => {
          const f = await fixture();
          const { verifyUpdateManifest } = await load("runtime-update.mjs");
          const { extractRuntimeArchive } = await load("runtime-archive.mjs");
          for (const url of [process.env.RUNTIME_ARCHIVE_URL, process.env.RUNTIME_MANIFEST_URL])
            assert.match(
              url,
              /^https:\/\/github\.com\/linbrandon4\/totem-releases\/releases\/download\/cli-candidate-[\w.-]+\/[\w.-]+$/,
            );
          const response = await fetch(process.env.RUNTIME_MANIFEST_URL);
          assert.equal(response.status, 200);
          const manifest = verifyUpdateManifest(await response.json());
          assert.equal(manifest.version, version);
          assert.equal(manifest.sourceCommit, process.env.SOURCE_COMMIT);
          const download = await fetch(process.env.RUNTIME_ARCHIVE_URL);
          assert.equal(download.status, 200);
          const bytes = Buffer.from(await download.arrayBuffer());
          assert.equal(bytes.length, manifest.archive.size);
          assert.equal(createHash("sha256").update(bytes).digest("hex"), manifest.archive.sha256);
          await extractRuntimeArchive(bytes, f.path);
          const installed = join(f.path, "node_modules/totemlayer");
          for (const name of [
            "windows-private-path.mjs",
            "strict-codex-adapter.mjs",
            "setup-assets/manifest.json",
          ])
            assert.deepEqual(
              await readFile(join(installed, "bin", name)),
              await readFile(join(packagePath, "bin", name)),
            );
          execFileSync(process.execPath, [join(installed, "bin/update-health.mjs")], {
            encoding: "utf8",
            timeout: 30000,
            env: { ...process.env, TOTEM_CONFIG_DIR: f.path, TOTEM_AUTO_START: "0", CI: "1" },
          });
          const archived = await import(
            pathToFileURL(join(installed, "bin/runtime-installation.mjs"))
          );
          const state = join(f.path, "verified-state.json");
          await archived.privateWrite(state, { synthetic: true });
          assert.deepEqual(await archived.privateRead(state), { synthetic: true });
        },
      );
    }
    await check("native Codex current session and selected model readback", async () => {
      const f = await fixture();
      const environment = {
        ...process.env,
        CODEX_HOME: join(f.path, "codex"),
        TOTEM_CONFIG_DIR: join(f.path, "totem"),
      };
      for (const key of [
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "TOTEM_NETWORK_API_KEY",
        "TOTEM_NETWORK_API_KEY_FILE",
        "CODEX_THREAD_ID",
      ])
        delete environment[key];
      await mkdir(environment.CODEX_HOME, { mode: 0o700 });
      const config = join(environment.CODEX_HOME, "config.toml");
      await writeFile(config, 'model = "preserved-native-fixture-model"\n', { mode: 0o600 });
      const { connectCodexHarness } = await load("harness-bootstrap.mjs");
      const { createStrictCodexAdapter } = await load("strict-codex-adapter.mjs");
      let rpc = connectCodexHarness(environment),
        adapter;
      try {
        await rpc.initialize();
        const created = await rpc.request("thread/start", { cwd: f.path });
        assert.equal(created.model, "preserved-native-fixture-model");
        await rpc.request("thread/inject_items", {
          threadId: created.thread.id,
          items: [
            {
              type: "message",
              role: "user",
              content: [
                { type: "input_text", text: "Disposable release metadata fixture; no model turn." },
              ],
            },
          ],
        });
        await rpc.close();
        rpc = undefined;
        await writeFile(config, 'model = "different-default-fixture-model"\n', { mode: 0o600 });
        adapter = createStrictCodexAdapter(
          { baseUrl: "https://totemlayer.com", sessionId: created.thread.id, waitSeconds: 0 },
          { env: environment, write() {} },
        );
        const inspected = await adapter.inspect();
        assert.equal(inspected.host.model, created.model);
        assert.equal(inspected.host.sessionId, created.thread.id);
        assert.equal(inspected.host.modelVerified, true);
        assert.equal(inspected.connection, undefined);
        assert.match(inspected.host.policyDigest, /^[a-f0-9]{64}$/);
      } finally {
        await adapter?.close();
        await rpc?.close();
      }
    });
  }
  console.log(
    JSON.stringify({
      platform: process.platform,
      architecture: process.arch,
      node: process.version,
      version,
      passed: results.length,
      nativeWindowsChecks: windows ? 4 : 0,
      modelInvoked: false,
      connectionCreated: false,
    }),
  );
} finally {
  await rm(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
}
