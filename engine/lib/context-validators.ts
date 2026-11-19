import { isNotSecretShaped, isPlaceholder } from "./shapes.ts";

// These rules name the field directly. Unlike an entropy heuristic, a literal
// password field can hold a short word or a PIN. References still hold nothing.
export function isLiteralPassword(value: string, match?: RegExpMatchArray): boolean {
  const quoted = /^["']$/.test(match?.[1] ?? "") || /"[ \t]*:[ \t]*"/.test(match?.[0] ?? "");
  // Bare words may describe the password or name a variable. Quoted values
  // can be words/passphrases; unquoted values need a mixed shape or a PIN.
  const shaped = quoted || /^\d+$/.test(value) || (/\p{L}/u.test(value) && /[^\p{L}]/u.test(value));
  return (
    shaped &&
    (quoted || !/[()[\]{}]/.test(value)) &&
    (!/\s/.test(value) || quoted) &&
    !/^--?[A-Za-z]/.test(value) &&
    value.length > 0 &&
    !isPlaceholder(value) &&
    (/^\d+$/.test(value) || !isNotSecretShaped(value)) &&
    !/^(?:password|passwd|pass|pwd|true|false|null|undefined)$/i.test(value) &&
    !/[\\`]|\$\{|\$[A-Za-z_]|\{\{|<[^>]*>/.test(value)
  );
}

// A token, secret or API key, unlike a password, is not a word someone chose:
// `"token": "string"` in an API schema and `apiKey: "Required"` describe one.
// No spaces either; a passphrase is the password rules' business. Four
// characters at least, and no `%s`/`{}` template: a format string is not a value.
export function isLiteralCredential(value: string): boolean {
  return (
    value.length >= 4 &&
    isLiteralPassword(value) &&
    !/\s|%[sd]|\{\}/.test(value) &&
    !/^(?:[a-z]+|[A-Z][a-z]+|[A-Z]+)$/.test(value)
  );
}

// In prose, an ordinary word after "password is" is usually a description.
// Keep the existing requirement for letters and digits, but not its length
// or entropy floor: a short mixed password is still a password.
export function isProsePassword(value: string): boolean {
  return isLiteralPassword(value) && /\p{L}/u.test(value) && /\d/.test(value);
}

export function isCustomerNumber(value: string): boolean {
  return (value.match(/[0-9０-９]/g)?.length ?? 0) >= 2;
}

// HMRC excludes these letters and prefixes from issued National Insurance
// numbers. Checking them avoids treating arbitrary spaced identifiers as PII.
export function isNationalInsurance(value: string): boolean {
  const compact = value.replace(/[ \t]/g, "");
  return (
    /^[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\d{6}[A-D]$/.test(compact) &&
    !/^(?:BG|GB|KN|NK|NT|TN|ZZ)/.test(compact)
  );
}

export function isInternationalPhone(value: string): boolean {
  const digits = value.replace(/\D/g, "");
  return digits.length >= 9 && digits.length <= 15 && !/^(\d)\1*$/.test(digits);
}

// A nearby access-key ID is context, not proof that every 40-character word is
// its secret. Digests and ordinary all-letter identifiers are common beside it.
export function isAwsSecret(value: string): boolean {
  return !/^[a-f0-9]{40}$/i.test(value) && /[A-Z]/.test(value) && /[a-z]/.test(value);
}
