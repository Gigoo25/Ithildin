interface CookieRedaction {
  text: string;
  hits: number;
}

type ReplaceValue = (value: string) => string;
type IsSynthetic = (value: string) => boolean;

const SET_COOKIE_ATTRIBUTES = new Set([
  "domain",
  "expires",
  "httponly",
  "max-age",
  "partitioned",
  "path",
  "priority",
  "samesite",
  "secure",
]);

function redactSegment(
  segment: string,
  replaceValue: ReplaceValue,
  isSynthetic: IsSynthetic,
): CookieRedaction {
  const match = /^(\s*[^=;\s]+\s*=\s*)(.*?)(\s*)$/.exec(segment);
  const [, head = "", value = "", tail = ""] = match ?? [];
  if (!match || value.length === 0 || isSynthetic(value)) {
    return { text: segment, hits: 0 };
  }
  return {
    text: `${head}${replaceValue(value)}${tail}`,
    hits: 1,
  };
}

export function redactCookieValue(
  value: string,
  setCookie: boolean,
  replaceValue: ReplaceValue,
  isSynthetic: IsSynthetic,
  onEdit?: (start: number, end: number, replacementLength: number) => void,
): CookieRedaction {
  let hits = 0;
  let cookieSeen = false;
  let offset = 0;
  const parts = value.split(/(;)/).map((part) => {
    const start = offset;
    offset += part.length;
    if (part === ";") return part;
    const name = /^\s*([^=;\s]+)/.exec(part)?.[1]?.toLowerCase();
    if (!name) return part;
    if (setCookie && cookieSeen) return part;
    if (setCookie && SET_COOKIE_ATTRIBUTES.has(name)) return part;
    const result = redactSegment(part, replaceValue, isSynthetic);
    if (result.hits > 0) {
      cookieSeen = true;
      const match = /^(\s*[^=;\s]+\s*=\s*)(.*?)(\s*)$/.exec(part)!;
      onEdit?.(
        start + match[1]!.length,
        start + match[1]!.length + match[2]!.length,
        result.text.length - match[1]!.length - match[3]!.length,
      );
    }
    hits += result.hits;
    return result.text;
  });
  return { text: parts.join(""), hits };
}

export function redactCookieHeaders(
  text: string,
  replaceValue: ReplaceValue,
  isSynthetic: IsSynthetic,
  onEdit?: (start: number, end: number, replacementLength: number) => void,
): CookieRedaction {
  let hits = 0;
  const output = text.replace(
    /\b(set-cookie|cookie)(\s*:\s*)([^\r\n'"`]*)/gi,
    (_match, header: string, separator: string, value: string, offset: number) => {
      const result = redactCookieValue(
        value,
        header.toLowerCase() === "set-cookie",
        replaceValue,
        isSynthetic,
        (start, end, length) =>
          onEdit?.(
            offset + header.length + separator.length + start,
            offset + header.length + separator.length + end,
            length,
          ),
      );
      hits += result.hits;
      return `${header}${separator}${result.text}`;
    },
  );
  return { text: output, hits };
}

export function commandSendsCookies(command: string): boolean {
  if (!/\bcurl(?:\s|$)/i.test(command)) return false;
  return (
    /(?:^|\s)(?:-H|--header)(?:=|\s)+["']?\s*cookie\s*:/im.test(command) ||
    /(?:^|\s)--cookie(?:=|\s)/im.test(command) ||
    /(?:^|\s)-b(?:=|\s)/m.test(command)
  );
}
