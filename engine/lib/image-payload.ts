// Image bytes are not text. The text scanner cannot remove secrets from pixels.
export function isImagePayload(
  value: string,
  key: string | undefined,
  parent?: Record<string, unknown>,
): boolean {
  if ((key === "image_url" || key === "url") && /^data:image\/[\w.+-]+;base64,/.test(value)) {
    return true;
  }
  if (key !== "data" || !parent) return false;
  const mime = parent.media_type ?? parent.mimeType;
  return (
    typeof mime === "string" &&
    mime.startsWith("image/") &&
    (parent.type === "base64" || typeof parent.mimeType === "string")
  );
}
