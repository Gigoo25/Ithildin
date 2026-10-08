// Inline image and document bytes are not text. The text scanner cannot
// remove secrets from pixels or a PDF, and would corrupt them trying. These are
// the blocks proxy/src/redact.ts withholds (isOpaqueBlock); they reach here
// only when the user allowed them.
export function isImagePayload(
  value: string,
  key: string | undefined,
  parent?: Record<string, unknown>,
): boolean {
  if (
    (key === "image_url" || key === "url" || key === "file_data") &&
    /^data:[\w.+-]+\/[\w.+-]+;base64,/.test(value)
  ) {
    return true;
  }
  if (key !== "data" || !parent) return false;
  const mime = parent.media_type ?? parent.mimeType;
  return (
    typeof mime === "string" &&
    (parent.type === "base64" || (mime.startsWith("image/") && typeof parent.mimeType === "string"))
  );
}

// The media type beside those bytes is a wire enum the provider checks. A
// starved scan budget omits every string it has not vouched for, and an
// omitted "image/png" is a 400 on every request that carries the image
// (Claude Code then drops images one at a time, missing the cache on each
// retry). Only a value shaped like a MIME type passes; free text still scans.
export function isPayloadMediaType(
  value: string,
  key: string | undefined,
  parent?: Record<string, unknown>,
): boolean {
  if ((key !== "media_type" && key !== "mimeType") || !parent) return false;
  return (
    /^[\w.+-]+\/[\w.+-]+$/.test(value) &&
    typeof parent.data === "string" &&
    isImagePayload(parent.data, "data", parent)
  );
}
