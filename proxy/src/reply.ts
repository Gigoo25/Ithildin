// What the proxy's own answers share: the error shape, and a body read
// no further than a cap.

// Every error the proxy answers itself has this shape, which is Anthropic's,
// so an agent shows the message rather than a parse failure.
export function errorReply(
  status: number,
  message: string,
  headers: Record<string, string> = {},
): Response {
  return Response.json(
    { type: "error", error: { type: "ithildin_error", message: `ithildin: ${message}` } },
    { status, headers },
  );
}

// A body as text, read no further than the cap: a chunked body declares no
// length. Undefined when it runs over.
export async function readCapped(
  body: ReadableStream<Uint8Array> | null,
  max: number,
): Promise<string | undefined> {
  if (!body) return "";
  const chunks: Uint8Array[] = [];
  let size = 0;
  for await (const chunk of body) {
    size += chunk.byteLength;
    // Leaving the loop cancels the rest of the stream.
    if (size > max) return undefined;
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}
