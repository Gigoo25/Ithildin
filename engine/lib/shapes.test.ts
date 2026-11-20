import { expect, it } from "bun:test";
import { isPlaceholder } from "./shapes.ts";

// A connection string a compose file or quickstart ships is a placeholder, not
// a leak; one with real credentials is not.
it("reads a default service login in a connection string as a placeholder", () => {
  expect(isPlaceholder("postgres://postgres:postgres@db:5432/app")).toBe(true);
  expect(isPlaceholder("amqp://Guest:guest@rabbit/")).toBe(true);
  // Same word, but not a service account name.
  expect(isPlaceholder("postgres://alice:alice@db.zqxcorp.test/app")).toBe(false);
  // A service name with a different password.
  expect(isPlaceholder("postgres://postgres:hunter22@db.zqxcorp.test/app")).toBe(false);
});

it("reads an unexpanded reference in the credentials as a placeholder", () => {
  expect(isPlaceholder("postgres://app:${DB_PASSWORD}@db/app")).toBe(true);
  expect(isPlaceholder("redis://:$REDIS_PASS@cache:6379")).toBe(true);
});
