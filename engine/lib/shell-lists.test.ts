import { expect, it } from "bun:test";
import { gaps, topLevelParts } from "./shell-lists.ts";

const parts = (command: string) =>
  topLevelParts(command)?.map(([from, to]) => command.slice(from, to).trim());

it("splits on list separators and keeps pipelines and compounds whole", () => {
  expect(parts("a; b && c || d & e\nf")).toEqual(["a", "b", "c", "d", "e", "f"]);
  expect(parts("a 2>&1 | b |& c; d &>/dev/null")).toEqual(["a 2>&1 | b |& c", "d &>/dev/null"]);
  expect(parts("for x in 1; do a; b; done; c")).toEqual(["for x in 1; do a; b; done", "c"]);
  expect(parts("if a; then b; elif c; then d; else e; fi && f")).toEqual([
    "if a; then b; elif c; then d; else e; fi",
    "f",
  ]);
  expect(parts("while a; do b; done; { c; d; }; (e; f); g")).toEqual([
    "while a; do b; done",
    "{ c; d; }",
    "(e; f)",
    "g",
  ]);
  expect(parts("x=$(a; b); echo $((1+2)) done fi")).toEqual(["x=$(a; b)", "echo $((1+2)) done fi"]);
  expect(parts("! if a; then b; fi; c")).toEqual(["! if a; then b; fi", "c"]);
  expect(parts(";; a ;")).toEqual([";; a"]);
});

it("gives up on what it does not follow", () => {
  for (const command of [
    "echo `a`",
    "f() { a; }",
    "function f { a; }",
    "a)",
    "if a; then b",
    "fi",
    "(a",
  ])
    expect([command, topLevelParts(command)]).toEqual([command, undefined]);
});

it("returns the gaps between ranges", () => {
  expect(gaps([], 3)).toEqual([[0, 3]]);
  expect(
    gaps(
      [
        [4, 6],
        [0, 2],
        [1, 3],
      ],
      8,
    ),
  ).toEqual([
    [3, 4],
    [6, 8],
  ]);
  expect(gaps([[0, 8]], 8)).toEqual([]);
});
