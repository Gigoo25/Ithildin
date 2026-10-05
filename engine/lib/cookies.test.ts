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

it("redacts cookie headers", () => {
  const result = redactCookieHeaders("Cookie: a=1; b=2", replace, neverSynthetic);
  expect(result.hits).toBeGreaterThan(0);
  expect(result.text).toContain("a=R(");
});
