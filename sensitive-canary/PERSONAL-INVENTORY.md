# Personal PII inventory

Names, handles, employers, home SSIDs, and ticket prefixes have no safe
generic shape — any word could be one. The answer is exact-match rules fed
with your real values, the same pattern as the fleet inventory in
`lib/rules.ts`. Those values must never enter this repo, so they live in an
untracked user config the engine already loads:

1. Copy `user-config.example.json` to `~/.config/sensitive-canary/config.json`
   (or anywhere and export `SENSITIVE_CANARY_CONFIG` pointing at it).
2. Replace every `EXAMPLE…` value with the real one. Keep each entry narrow:
   full names, exact handles, exact org/network names, and a pinned ticket
   prefix (`ACME-\d+`, never a bare `[A-Z]+-\d+` — that fires on CVEs).
3. `chmod 600` the copy. A non-file (FIFO, device, directory) is ignored
   with a stderr warning; malformed rules are skipped the same way.
4. Restart Pi (or start a new session). Type a value: expect an obvious
   `__CANARY_*__` token and the canary notice. `[allow-pii]` bypasses these
   like any other PII rule.

Notes:

- User rules with the same `id` as a built-in replace it (defaults and local
  rules share one override pass); new ids append. Prefer new ids
  (e.g. `pii-personal-*`) so updates never silently drop you.
- If an override drops a validator the built-in had, the built-in is kept
  and a stderr warning is printed.
- `secretGroup: 0` on the GitHub-URL rule synthesizes `github.com/you` as
  one unit instead of leaving a half-redacted URL behind.
- Validators by name (`public-ipv4`, …) are available via `"validate"`, and
  `contextWords` + `requireContext` work exactly as in the built-ins.
- The template's example values are inert: they match nothing you will
  type, so copying it verbatim changes nothing until you fill it in.
- The `inventory` list is the simpler alternative to hand-written regex:
  `{ "id": "nickname", "literal": "Your Exact Name", "match": "token" }`
  compiles to a `pii-inventory-nickname` rule. `match: "phrase"` matches
  the exact phrase including spaces; `caseSensitive: false` opts into
  case-insensitive matching. Token matching uses Unicode
  letter/number/underscore boundaries. Empty literals, duplicate ids, and
  wrongly typed fields are rejected with safe diagnostics (values never
  printed). Duplicate entries are rejected while the first valid entry is kept.
  Inventory entries only append — they never override built-ins. The existing
  500-entry ceiling remains; entries beyond it are not loaded and produce a
  warning. This is a capacity limit, not a fail-closed policy boundary.
- At session start the engine also compiles in-memory inventory rules from the
  process username, hostname (and its first label), home directory, and
  `git config user.name` / `user.email` when git is available. These
  never hit disk or the ledger. Generic names (`localhost`, `root`, distro
  defaults), example-template tokens, ephemeral `/tmp` homes, and values under
  three characters are skipped. File inventory still wins for employer names,
  family names, and SSIDs.
- Invalid regexes and unknown validators reject that definition without printing
  the supplied identifier, regex body, validator name or config contents. The
  last valid custom rule definition is retained. Import-time loading is covered
  by an isolated fresh-process test, not only pure helper tests.
