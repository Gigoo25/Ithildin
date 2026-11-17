import { describe, expect, it } from "bun:test";
import { redactText } from "../core.ts";
import { CONTEXT_RULES } from "./context-rules.ts";
import {
  applyUserOverrides,
  compileRule,
  RULES,
  scan,
  scanWindows,
  SCAN_WINDOW_CHARS,
} from "./rules.ts";

function values(text: string, id: string): string[] {
  return scan(text)
    .filter((finding) => finding.ruleId === id)
    .map((finding) => finding.secretValue);
}

function detects(id: string, text: string, expected: string): void {
  expect(values(text, id)).toContain(expected);
  for (const finding of scan(text).filter((finding) => finding.ruleId === id)) {
    expect(text.slice(finding.start, finding.end)).toBe(finding.secretValue);
  }
}

describe("contextual built-in rules", () => {
  it("compiles and loads every rule with a unique id", () => {
    for (const config of CONTEXT_RULES) {
      expect(() => compileRule(config)).not.toThrow();
      expect(RULES.filter((rule) => rule.id === config.id)).toHaveLength(1);
    }
  });

  it("detects labelled birth dates in eight languages, without hiding labels", () => {
    for (const [label, date] of [
      ["DOB", "1985-03-12"],
      ["date_of_birth", "12/03/1985"],
      ["date of birth", "03/23/1985"],
      ["birthdate", "March 12, 1985"],
      ["D.O.B.", "12 March 1985"],
      ["生年月日", "1985年3月12日"],
      ["出生日期", "1985年3月12日"],
      ["생년월일", "1985년 3월 12일"],
      ["date de naissance", "12 mars 1985"],
      ["data di nascita", "12 marzo 1985"],
      ["Geburtsdatum", "12. März 1985"],
      ["fecha de nacimiento", "12 de marzo de 1985"],
      ["fecha de nacimiento", "12 de enero de 1985"],
      ["fecha de nacimiento", "12 de febrero de 1985"],
      ["fecha de nacimiento", "12 de abril de 1985"],
      ["data di nascita", "12 gennaio 1985"],
      ["date de naissance", "12 février 1985"],
    ]) {
      detects("pii-date-of-birth", `${label}: ${date}`, date!);
    }
    detects("pii-date-of-birth", '{"date_of_birth":"1985-03-12"}', "1985-03-12");
    detects("pii-date-of-birth", "DOB is 1985.3.12", "1985.3.12");
    detects("pii-date-of-birth", "生年月日は1985年3月12日", "1985年3月12日");
    for (const text of [
      "release date: 1985-03-12",
      "DOB: 1985-00-12",
      "DOB: 1985-03-00",
      "DOB: 1985-03-1234",
      "DOB: 1985-03-12-snapshot",
      "DOB: YYYY-MM-DD",
      "birthdate_format = ISO_8601",
      "生年月日は必須項目です。",
      "customer date of birth field accepts dates",
    ]) {
      expect(values(text, "pii-date-of-birth")).toEqual([]);
    }
  });

  it("detects customer and member numbers in eight languages", () => {
    for (const label of [
      "customer ID",
      "membership number",
      "account number",
      "会員番号",
      "顧客ID",
      "口座番号",
      "客户编号",
      "會員號碼",
      "고객번호",
      "회원 번호",
      "numéro de client",
      "numero cliente",
      "Kundennummer",
      "Mitgliedsnummer",
      "número de cliente",
    ]) {
      detects("pii-customer-number", `${label}: MBR-20419`, "MBR-20419");
    }
    detects("pii-customer-number", '{"customer_id":"ab_20419"}', "ab_20419");
    detects("pii-customer-number", "会員番号：ＡＢ１２３４５", "ＡＢ１２３４５");
    detects("pii-customer-number", "会員番号は12345", "12345");
    for (const text of [
      "customer ID: VARCHAR",
      "customer ID: CUSTOMER_ID",
      "customer ID: value1",
      "customer ID: $MEMBER_ID",
      "customer_id_format: MBR-20419",
      `customer ID: ${"A".repeat(40)}12`,
      "MBR-20419",
    ]) {
      expect(values(text, "pii-customer-number")).toEqual([]);
    }
  });

  it("detects complete numbered postal addresses in seven countries", () => {
    const cases = [
      ["jp", "東京都新宿区西新宿2丁目8番1号"],
      ["jp", "大阪府大阪市北区梅田1-2-3"],
      ["jp", "埼玉県さいたま市浦和区高砂3-15-1"],
      ["cn", "北京市朝阳区建国路88号"],
      ["cn", "广东省深圳市南山区科技路12号"],
      ["kr", "서울특별시 강남구 테헤란로 123"],
      ["kr", "경기도 성남시 분당구 판교역로 235"],
      ["fr", "18 rue des Lilas 75002 Paris"],
      ["fr", "12 bis avenue Victor Hugo, 75016 Paris"],
      ["it", "Via Garibaldi 18 20121 Milano"],
      ["it", "Piazza del Popolo, 12, 00187 Roma"],
      ["it", `${["Lar", "go"].join("")} del Teatro 18 00186 Roma`],
      ["de", "Hauptstraße 18, 10115 Berlin"],
      ["de", "Rosenweg 12a 10115 Berlin"],
      ["es", "Calle Mayor 18 28013 Madrid"],
      ["es", "Avenida de la Paz, 18, 28036 Madrid"],
    ];
    for (const [country, address] of cases) {
      detects(`pii-address-${country}`, `Ship to: ${address}.`, address!);
    }
    for (const [country, text] of [
      ["jp", "東京都新宿区にある公園は2025年に開園しました。"],
      ["jp", "東京都新宿区西新宿"],
      ["jp", "東京都新宿区の2025-01-01の予定"],
      ["cn", "北京市朝阳区有88个公园。"],
      ["cn", "北京市朝阳区建国路"],
      ["kr", "서울특별시 강남구 인구 123명"],
      ["fr", "18 rue des Lilas"],
      ["it", "Via Garibaldi 18"],
      ["de", "Hauptstraße 18"],
      ["es", "Calle Mayor 18"],
      ["fr", "release 2025 rue des Lilas"],
    ]) {
      expect(values(text!, `pii-address-${country}`)).toEqual([]);
    }
  });

  it("validates compact and spaced UK National Insurance numbers", () => {
    for (const number of ["AB 12 34 56 C", "AB123456C", "AB\t12\t34\t56\tC"]) {
      detects("pii-nino-uk", `NINO: ${number}`, number);
    }
    for (const number of [
      "DA 12 34 56 C",
      "AO 12 34 56 C",
      "BG 12 34 56 C",
      "GB 12 34 56 C",
      "ZZ 12 34 56 C",
      "AB 12 34 56 E",
      "XAB 12 34 56 C",
      "AB 12 34 56 CX",
    ]) {
      expect(values(number, "pii-nino-uk")).toEqual([]);
    }
  });

  it("detects Docker Hub tokens without relying on entropy or a field label", () => {
    const token = `dckr_pat_${"a".repeat(27)}`;
    detects("docker-hub-pat", `credential: ${token}`, token);
    for (const text of ["dckr_pat_short", `prefix_${token}`, `dckr_pat_${"a".repeat(257)}`]) {
      expect(values(text, "docker-hub-pat")).toEqual([]);
    }
  });

  it("detects an AWS secret beside its ID, not the key ID again", () => {
    const id = "AKIAQ7MR9VB2XK5NL8ST";
    const secret = "yJ8vR4mQ2xK9nL5sT7wB3zA6cD1fG0hP8uE4iO2a";
    for (const text of [
      `${id} ${secret}`,
      `${id}\t${secret}`,
      `AWS_ACCESS_KEY_ID=${id}\nAWS_SECRET_ACCESS_KEY=${secret}`,
      `AWS_ACCESS_KEY_ID=${id}\r\nAWS_SECRET_ACCESS_KEY=${secret}`,
      `{"id":"${id}","secret":"${secret}"}`,
    ]) {
      detects("aws-secret-near-key-id", text, secret);
    }
    for (const text of [
      `AKIAIOSFODNN7EXAMPLE ${secret}`,
      `${id}\n\n${secret}`,
      `${id} ${"a".repeat(40)}`,
      `${id} ${"ab1234ef".repeat(5)}`,
      `${id} ${secret}x`,
      `${id} ${secret}=`,
      `${id} ${" ".repeat(100)}${secret}`,
    ]) {
      expect(values(text, "aws-secret-near-key-id")).toEqual([]);
    }
  });

  it("detects short passwords in assignments and prose", () => {
    detects("password-assignment", "password=R7m!q2", "R7m!q2");
    detects("password-assignment", 'db_password="r7!"', "r7!");
    detects("password-assignment", "password: 1234", "1234");
    detects("password-assignment", "pwd='river cedar wren'", "river cedar wren");
    detects("password-prose-short", "my password is R7m!q2 for the site", "R7m!q2");
    detects("password-prose-short", "パスワードは R7m!q2", "R7m!q2");
    detects("password-prose-short", "パスワードはR7m!q2です。", "R7m!q2");
    detects("password-prose-short", "パスワード：「R7m!q2」", "R7m!q2");
    detects("password-prose-short", "password is R7m!q2.", "R7m!q2");
    for (const text of [
      "password is required.",
      "password is stored in the vault",
      "パスワードは必須です。",
      "password = process.env.PASSWORD",
      "password = password_value",
      "const password = passwordHash;",
      "password = getPassword()",
      "pwd = credentials[0]",
      "password = await getPassword()",
      "password = new Secret()",
      "password = policy",
      "password = PASSWORD_VALUE",
      "password = null",
      "password: ${DB_PASSWORD}",
      "pwd: {{ password }}",
      "password = <password>",
      "password_file = /etc/app/secret.txt",
    ]) {
      expect(values(text, "password-assignment")).toEqual([]);
      expect(values(text, "password-prose-short")).toEqual([]);
    }
  });

  it("detects short JSON password fields, including a numeric-string PIN", () => {
    for (const key of [
      "password",
      "passwd",
      "pwd",
      "db_password",
      "db.pwd",
      "db-pwd",
      "dbPassword",
      "PASSWORD",
    ]) {
      detects("password-json-key", JSON.stringify({ [key]: "R7m!q2" }), "R7m!q2");
    }
    detects("password-json-key", '{"pwd":"1234"}', "1234");
    detects("password-json-key", '{"pwd":"river cedar wren"}', "river cedar wren");
    for (const value of ["$PASSWORD", "${PASSWORD}", "<password>", "YOUR_PASSWORD", "null"]) {
      expect(values(JSON.stringify({ pwd: value }), "password-json-key")).toEqual([]);
    }
    expect(values('{"password_file":"/etc/app/secret.txt"}', "password-json-key")).toEqual([]);
    expect(values('{"pwd":"escaped\\nreference"}', "password-json-key")).toEqual([]);
    expect(values('{"compass":"R7m!q2"}', "password-json-key")).toEqual([]);
  });

  it("detects short CLI passwords but not unrelated -p flags", () => {
    for (const command of [
      "tool --password R7m!q2",
      "tool --password=R7m!q2",
      "tool --passwd 'R7m!q2'",
      'tool --pass="R7m!q2"',
    ]) {
      detects("password-cli-flag", command, "R7m!q2");
    }
    for (const command of [
      "mysql -p'R7m!q2'",
      'mysql --host example.com -u reporter -p"R7m!q2"',
      "mariadb -p'R7m!q2'",
    ]) {
      detects("mysql-password", command, "R7m!q2");
    }
    for (const command of [
      "mkdir -p'R7m!q2'",
      "mysql -p",
      "mysql -p'$DB_PASSWORD'",
      "mysql -p'<password>'",
      "mysql; mkdir -p'R7m!q2'",
    ]) {
      expect(values(command, "mysql-password")).toEqual([]);
    }
    for (const command of [
      "tool --password $PASSWORD",
      "tool --password <password>",
      "tool --password --verbose",
      "tool --password-file /etc/app/secret.txt",
      "tool --password YOUR_PASSWORD",
    ]) {
      expect(values(command, "password-cli-flag")).toEqual([]);
    }
  });

  it("detects netrc password lines and inline machine records", () => {
    for (const text of [
      "password R7m!q2",
      "machine example.com\nlogin reporter\npassword R7m!q2",
      "machine example.com login reporter password R7m!q2",
    ]) {
      detects("password-netrc", text, "R7m!q2");
    }
    for (const text of ["password policy requires 8 characters", "password $PASSWORD"]) {
      expect(values(text, "password-netrc")).toEqual([]);
    }
  });

  it("detects Redis passwords with and without ACL usernames", () => {
    for (const text of [
      "AUTH R7m!q2",
      "AUTH reporter R7m!q2",
      "redis-cli -a R7m!q2 ping",
      "redis-cli -h example.com -p 6379 -a 'R7m!q2' ping",
    ]) {
      detects("redis-auth", text, "R7m!q2");
    }
    detects("redis-auth", "AUTH 1234", "1234");
    detects("redis-auth", 'AUTH reporter "river cedar wren"', "river cedar wren");
    detects("redis-auth", 'redis-cli -a "river cedar wren" ping', "river cedar wren");
    for (const text of ["AUTH $PASSWORD", "redis-cli -a $PASSWORD", "redis-cli --help"]) {
      expect(values(text, "redis-auth")).toEqual([]);
    }
  });

  it("detects international phones with spaces, hyphens and parentheses", () => {
    for (const number of [
      "+351 912 345 678",
      "+351-912-345-678",
      "+44 (20) 7946 0827",
      "+1 (415) 867-2439",
      "+351912345678",
    ]) {
      detects("pii-phone-intl", `call ${number} now`, number);
    }
    for (const text of [
      "x + 100000000",
      "1e+351912345678",
      "a++351912345678",
      "+012 345 6789",
      "+111 111 1111",
      "+12 345",
      "+1234567890123456",
      "+123 456 789 012 3456",
    ]) {
      expect(values(text, "pii-phone-intl")).toEqual([]);
    }
  });

  it("keeps contextual rules overridable like the JSON defaults", () => {
    const original = CONTEXT_RULES.find((rule) => rule.id === "pii-date-of-birth")!;
    const changed = applyUserOverrides(RULES, [{ ...original, regex: "custom-dob" }]);
    expect(changed.find((rule) => rule.id === original.id)?.regex.source).toBe("custom-dob");
  });

  it("detects labelled values crossing scan-window boundaries", () => {
    // Match existing window-edge tests: a long blank run exercises unrelated
    // whitespace-heavy rules rather than this rule's boundary handling.
    const padding = `${"x".repeat(SCAN_WINDOW_CHARS - 5)} `;
    const text = `${padding}DOB: 1985-03-12`;
    const result = scanWindows(text);
    expect(result.trips).toEqual([]);
    const hit = result.findings.find((finding) => finding.ruleId === "pii-date-of-birth")!;
    expect(hit.secretValue).toBe("1985-03-12");
    expect(text.slice(hit.start, hit.end)).toBe(hit.secretValue);
  });

  it("keeps numeric customer IDs scoped to their labelled fields", () => {
    const out = redactText('{"customer_id":54321,"count":54321,"note":"54321"}').text;
    const parsed = JSON.parse(out);
    expect(parsed.customer_id).not.toBe(54321);
    expect(parsed.count).toBe(54321);
    expect(parsed.note).toBe("54321");
  });

  it("redacts actual values and respects per-category allowances", () => {
    const text = "DOB: 1985-03-12; customer ID: MBR-20419; pwd: R7m!q2";
    const masked = redactText(text).text;
    for (const value of ["1985-03-12", "MBR-20419", "R7m!q2"]) {
      expect(masked).not.toContain(value);
    }
    expect(masked).toContain("DOB:");
    const allowPii = redactText(text, new Set(["pii"])).text;
    expect(allowPii).toContain("1985-03-12");
    expect(allowPii).not.toContain("R7m!q2");
    const allowSecrets = redactText(text, new Set(["secret"])).text;
    expect(allowSecrets).not.toContain("1985-03-12");
    expect(allowSecrets).toContain("R7m!q2");
  });
});
