import { expect, it } from "bun:test";
import { redactCookieHeaders, redactCookieValue } from "./cookies.ts";

const replace = (value: string) => `R(${value})`;
const neverSynthetic = () => false;

it("leaves segments without a value alone", () => {
  expect(redactCookieValue("just-a-flag", false, replace, neverSynthetic).hits).toBe(0);
  expect(redactCookieValue("session=; theme=dark", false, replace, neverSynthetic).text).toContain(
    "session=;",
  );
});

it("leaves values already synthetic alone", () => {
  const result = redactCookieValue(
    "a=1",
    false,
    (value) => value,
    () => true,
  );
  expect(result.hits).toBe(0);
  expect(result.text).toBe("a=1");
});

it("redacts the cookie string under curl's flag, and leaves a jar path and -B alone", () => {
  const run = (text: string) => redactCookieHeaders(text, replace, neverSynthetic);
  expect(run("curl -b 'sid=9; tok=8' https://x.test").text).toBe(
    "curl -b 'sid=R(9); tok=R(8)' https://x.test",
  );
  expect(run('curl --cookie "sid=9" https://x.test').text).toContain("sid=R(9)");
  expect(run("curl --cookie=sid=9 https://x.test").text).toBe(
    "curl --cookie=sid=R(9) https://x.test",
  );
  expect(run("curl -b sid=9 -o out=1.txt").text).toBe("curl -b sid=R(9) -o out=1.txt");
  expect(run("curl -b cookies.txt https://x.test/?a=1").hits).toBe(0);
  expect(run("curl -B 'sid=9' https://x.test").hits).toBe(0);
  expect(run("grep -rb 'a=1' src").hits).toBe(0);
});

it("reports each edit where the value sits in the text it was given", () => {
  const text = "curl -b 'sid=9' -H 'Cookie: tok=8'";
  const edits: [number, number][] = [];
  redactCookieHeaders(text, replace, neverSynthetic, (start, end) => edits.push([start, end]));
  expect(edits.map(([start, end]) => text.slice(start, end))).toEqual(["9", "8"]);
});

it("redacts cookie headers", () => {
  const result = redactCookieHeaders("Cookie: a=1; b=2", replace, neverSynthetic);
  expect(result.hits).toBeGreaterThan(0);
  expect(result.text).toContain("a=R(");
});
