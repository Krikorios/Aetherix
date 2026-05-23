// Lightweight SHA-256 helper using SubtleCrypto. Used for content hashing in
// evidence payloads. The extension NEVER sends raw paste/upload bodies to the
// agent — only a hash plus signals derived locally.

export async function sha256Hex(input) {
  const data = typeof input === "string"
    ? new TextEncoder().encode(input)
    : input instanceof ArrayBuffer
      ? new Uint8Array(input)
      : input;
  const digest = await crypto.subtle.digest("SHA-256", data);
  const bytes = new Uint8Array(digest);
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return `sha256:${hex}`;
}
