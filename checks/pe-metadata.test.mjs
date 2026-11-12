import assert from "node:assert/strict";
import { test } from "node:test";
import { inspectPe, metadataProblems } from "./pe-metadata.mjs";

function peBuffer({ certificateSize = 0, strings = {} } = {}) {
  const header = Buffer.alloc(0x80 + 24 + 96 + 40);
  header.write("MZ", 0, "latin1");
  header.writeUInt32LE(0x80, 0x3c);
  header.write("PE\0\0", 0x80, "latin1");
  header.writeUInt16LE(0x8664, 0x84);
  const optional = 0x80 + 24;
  header.writeUInt16LE(0x10b, optional);
  const directories = optional + 96;
  header.writeUInt32LE(0, directories + 4 * 8);
  header.writeUInt32LE(certificateSize, directories + 4 * 8 + 4);
  let body = Buffer.alloc(0);
  for (const [key, value] of Object.entries(strings)) {
    body = Buffer.concat([
      body,
      Buffer.from(`${key}\0\0`, "utf16le"),
      Buffer.alloc(4),
      Buffer.from(`${value}\0`, "utf16le"),
    ]);
  }
  return Buffer.concat([header, body]);
}

test("an unsigned installer with no version resource reports every gap", () => {
  const report = inspectPe(peBuffer());
  assert.equal(report.authenticode, false);
  assert.deepEqual(metadataProblems(report), [
    "installer carries no Authenticode signature",
    "installer has no CompanyName resource",
    "installer has no ProductName resource",
    "installer has no FileVersion resource",
  ]);
});

test("a signed installer still needs company, product and version strings", () => {
  const report = inspectPe(peBuffer({ certificateSize: 512 }));
  assert.equal(report.authenticode, true);
  assert.deepEqual(metadataProblems(report), [
    "installer has no CompanyName resource",
    "installer has no ProductName resource",
    "installer has no FileVersion resource",
  ]);
});

test("version strings are read back from the resource", () => {
  const report = inspectPe(
    peBuffer({
      certificateSize: 512,
      strings: { CompanyName: "Totem Labs, Inc.", ProductName: "Totem", FileVersion: "0.9.32" },
    }),
  );
  assert.equal(report.versionInfo.CompanyName, "Totem Labs, Inc.");
  assert.equal(report.versionInfo.ProductName, "Totem");
  assert.equal(report.versionInfo.FileVersion, "0.9.32");
  assert.deepEqual(metadataProblems(report), []);
});

test("a non-PE buffer is not mistaken for an installer", () => {
  assert.equal(inspectPe(Buffer.from("not a windows binary")).format, "unknown");
});
