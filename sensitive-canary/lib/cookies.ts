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
  if (!match || match[2].length === 0 || isSynthetic(match[2])) {
    return { text: segment, hits: 0 };
  }
  return {
    text: `${match[1]}${replaceValue(match[2])}${match[3]}`,
    hits: 1,
  };
}

export function redactCookieValue(
  value: string,
  setCookie: boolean,
  replaceValue: ReplaceValue,
  isSynthetic: IsSynthetic,
): CookieRedaction {
  let hits = 0;
  let cookieSeen = false;
  const parts = value.split(/(;)/).map((part) => {
    if (part === ";") return part;
    const name = /^\s*([^=;\s]+)/.exec(part)?.[1]?.toLowerCase();
    if (!name) return part;
    if (setCookie && cookieSeen) return part;
    if (setCookie && SET_COOKIE_ATTRIBUTES.has(name)) return part;
    const result = redactSegment(part, replaceValue, isSynthetic);
    if (result.hits > 0) cookieSeen = true;
    hits += result.hits;
    return result.text;
  });
  return { text: parts.join(""), hits };
}

export function redactCookieHeaders(
  text: string,
  replaceValue: ReplaceValue,
  isSynthetic: IsSynthetic,
): CookieRedaction {
  let hits = 0;
  const output = text.replace(
    /\b(set-cookie|cookie)(\s*:\s*)([^\r\n'"`]*)/gi,
    (_match, header: string, separator: string, value: string) => {
      const result = redactCookieValue(
        value,
        header.toLowerCase() === "set-cookie",
        replaceValue,
        isSynthetic,
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
