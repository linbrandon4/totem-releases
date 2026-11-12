// Windows installer metadata inspection used by desktop-release-checks.mjs.
//
// SmartScreen reads the Authenticode certificate table and Explorer reads the
// version resource, so an installer with neither shows an unknown publisher and
// an empty description even when the update payload itself is signed.

const VERSION_KEYS = ["CompanyName", "ProductName", "FileVersion", "ProductVersion"];

export function inspectPe(buffer) {
  if (buffer.length < 0x40 || buffer.toString("latin1", 0, 2) !== "MZ") return { format: "unknown" };
  const pe = buffer.readUInt32LE(0x3c);
  if (buffer.toString("latin1", pe, pe + 4) !== "PE\0\0") return { format: "unknown" };
  const machine = buffer.readUInt16LE(pe + 4);
  const optional = pe + 24;
  const magic = buffer.readUInt16LE(optional);
  // Data directory 4 is the certificate table; its size is the Authenticode blob.
  const directories = optional + (magic === 0x20b ? 112 : 96);
  const certificateRva = buffer.readUInt32LE(directories + 4 * 8);
  const certificateSize = buffer.readUInt32LE(directories + 4 * 8 + 4);
  const versionInfo = {};
  for (const key of VERSION_KEYS) {
    const marker = Buffer.from(`${key}\0\0`, "utf16le");
    const at = buffer.indexOf(marker);
    if (at < 0) {
      versionInfo[key] = null;
      continue;
    }
    // Values follow the key, zero-padded to a word boundary, as UTF-16LE.
    let cursor = at + marker.length;
    while (cursor < buffer.length && buffer[cursor] === 0) cursor += 1;
    let end = cursor;
    while (end + 1 < buffer.length && !(buffer[end] === 0 && buffer[end + 1] === 0)) end += 2;
    versionInfo[key] = buffer.toString("utf16le", cursor, end) || null;
  }
  return {
    format: "PE",
    machine: machine === 0x14c ? "x86" : machine === 0x8664 ? "x86_64" : `0x${machine.toString(16)}`,
    authenticode: certificateSize > 0,
    certificateRva,
    versionInfo,
  };
}

export function metadataProblems(report) {
  const problems = [];
  if (!report.authenticode) problems.push("installer carries no Authenticode signature");
  for (const key of ["CompanyName", "ProductName", "FileVersion"]) {
    if (!report.versionInfo?.[key]) problems.push(`installer has no ${key} resource`);
  }
  return problems;
}
