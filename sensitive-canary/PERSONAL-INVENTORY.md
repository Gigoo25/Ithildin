# Personal PII inventory

Names, handles, employers, home SSIDs, and ticket prefixes have no safe generic shape. Any word could be one of them. The answer is exact-match rules with your real values. This follows the fleet inventory pattern in `lib/rules.ts`. Those values must never enter this repo. They live in an untracked user config that the engine already loads.

1. Copy `user-config.example.json` to `~/.config/sensitive-canary/config.json`. You can use any other path and export `SENSITIVE_CANARY_CONFIG` to point at it.
2. Replace every `EXAMPLE…` value with the real one. Keep each entry narrow. Use full names, exact handles, exact org and network names, and a pinned ticket prefix (`ACME-\d+`, never a bare `[A-Z]+-\d+`, which fires on CVEs).
3. Run `chmod 600` on the copy. The engine ignores a non-file (FIFO, device, directory) with a stderr warning. It skips malformed rules the same way.
4. Restart Pi (or start a new session). Type a value and expect an obvious `__CANARY_*__` token plus the canary notice. `[allow-pii]` bypasses these rules like any other PII rule.

Notes:

- A user rule with the same `id` as a built-in rule replaces it. Defaults and local rules share one override pass. New ids append. Prefer new ids (for example `pii-personal-*`) so updates never silently drop your rules.
- If an override drops a validator that the built-in rule had, the engine keeps the built-in rule and prints a stderr warning.
- `secretGroup: 0` on the GitHub-URL rule synthesizes `github.com/you` as one unit. It leaves no half-redacted URL behind.
- Validators by name (`public-ipv4`, …) are available through `"validate"`. `contextWords` and `requireContext` work exactly as in the built-in rules.
- The template example values are inert. They match nothing you will type. Copying the template verbatim changes nothing until you fill it in.
- The `inventory` list is the simpler alternative to hand-written regex. `{ "id": "nickname", "literal": "Your Exact Name", "match": "token" }` compiles to a `pii-inventory-nickname` rule. `match: "phrase"` matches the exact phrase including spaces. `caseSensitive: false` opts into case-insensitive matching. Token matching uses Unicode letter, number, and underscore boundaries. The engine rejects empty literals, duplicate ids, and wrongly typed fields with safe diagnostics (it never prints values). It rejects duplicate entries and keeps the first valid entry.
- Inventory entries only append. They never override built-in rules. The existing 500-entry ceiling remains. The engine does not load entries beyond it and produces a warning. This is a capacity limit, not a fail-closed policy boundary.
- At session start the engine also compiles in-memory inventory rules from the process username, hostname (and its first label), home directory, and `git config user.name` and `user.email` when git is available. These rules never hit disk or the ledger. The engine skips generic names (`localhost`, `root`, distro defaults), example-template tokens, ephemeral `/tmp` homes, and values under three characters. File inventory still wins for employer names, family names, and SSIDs.
- Invalid regexes and unknown validators reject that definition without printing the supplied identifier, regex body, validator name, or config contents. The engine retains the last valid custom rule definition. An isolated fresh-process test covers import-time loading, not only pure helper tests.
