// Test fixtures: the text layouts of common dump tools, byte for byte.

const hex = (byte: number) => byte.toString(16).padStart(2, "0");
const ascii = (byte: number) => (byte >= 0x20 && byte < 0x7f ? String.fromCharCode(byte) : ".");

export function xxd(bytes: Buffer): string {
  let out = "";
  for (let at = 0; at < bytes.length; at += 16) {
    const row = [...bytes.subarray(at, at + 16)];
    const groups: string[] = [];
    for (let i = 0; i < row.length; i += 2) groups.push(row.slice(i, i + 2).map(hex).join(""));
    out += `${at.toString(16).padStart(8, "0")}: ${groups.join(" ").padEnd(39)}  ${row.map(ascii).join("")}\n`;
  }
  return out;
}

export function hexdumpC(bytes: Buffer): string {
  let out = "";
  for (let at = 0; at < bytes.length; at += 16) {
    const row = [...bytes.subarray(at, at + 16)];
    const cells = row.map(hex);
    const left = cells.slice(0, 8).join(" ");
    const right = cells.slice(8).join(" ");
    out += `${at.toString(16).padStart(8, "0")}  ${`${left.padEnd(23)}  ${right}`.padEnd(48)}  |${row.map(ascii).join("")}|\n`;
  }
  return `${out}${bytes.length.toString(16).padStart(8, "0")}\n`;
}

// od -x: octal offsets, little-endian 16-bit words.
export function odX(bytes: Buffer): string {
  let out = "";
  for (let at = 0; at < bytes.length; at += 16) {
    const words: string[] = [];
    for (let i = at; i < Math.min(at + 16, bytes.length); i += 2) words.push(((bytes[i + 1] ?? 0) << 8 | bytes[i]!).toString(16).padStart(4, "0"));
    out += `${at.toString(8).padStart(7, "0")} ${words.join(" ")}\n`;
  }
  return `${out}${bytes.length.toString(8).padStart(7, "0")}\n`;
}

export function base64Wrapped(bytes: Buffer): string {
  return `${bytes.toString("base64").replace(/.{76}/g, "$&\n").replace(/\n$/, "")}\n`;
}

export function xxdPlain(bytes: Buffer): string {
  return `${bytes.toString("hex").replace(/.{60}/g, "$&\n").replace(/\n$/, "")}\n`;
}
