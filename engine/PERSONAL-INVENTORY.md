# Personal PII inventory

Names, handles, employers, home SSIDs, and ticket prefixes have no safe generic shape. Any word could be one of them. The answer is exact-match rules with your real values. This follows the fleet inventory pattern in `lib/rules.ts`. Those values must never enter this repo. They live in an untracked user config that the engine already loads.

1. Copy `user-config.example.json` to `~/.config/ithildin/config.json`. You can use any other path and export `ITHILDIN_CONFIG` to point at it.
2. Replace every `EXAMPLE…` value with the real one. Keep each entry narrow. Use full names, exact handles, exact org and network names, and a pinned ticket prefix (`ACME-\d+`, never a bare `[A-Z]+-\d+`, which fires on CVEs).
3. Run `chmod 600` on the copy. The engine ignores a non-file (FIFO, device, directory) with a stderr warning. It skips malformed rules the same way.
4. Restart Pi (or start a new session). Type a value and expect a stand-in (for example `employer-3c9d0e`) plus the notice. `[allow-pii]` bypasses these rules like any other PII rule.

Notes:

- A user rule with the same `id` as a built-in rule replaces it. Defaults and local rules share one override pass. New ids append. Prefer new ids (for example `pii-personal-*`) so updates never silently drop your rules.
- If an override drops a validator that the built-in rule had, the engine keeps the built-in rule and prints a stderr warning.
- `secretGroup: 0` on the GitHub-URL rule synthesizes `github.com/you` as one unit. It leaves no half-redacted URL behind.
- Validators by name (`public-ipv4`, …) are available through `"validate"`. `contextWords` and `requireContext` work exactly as in the built-in rules.
- The template example values are inert. They match nothing you will type. Copying the template verbatim changes nothing until you fill it in.
- The `inventory` list is the simpler alternative to hand-written regex. `{ "id": "nickname", "literal": "Your Exact Name", "match": "token" }` compiles to a `pii-inventory-nickname` rule. Token matching uses Unicode letter, number, and underscore boundaries, and works for literals with spaces too ("Jane Doe"). Prefer it. `match: "phrase"` drops the boundaries, so it also fires inside longer words ("Jane Doesmith"); use it only for fragments that must match mid-word. `caseSensitive: false` opts into case-insensitive matching (use it for lowercase handles, which otherwise miss a capitalized mention). The engine rejects empty literals, duplicate ids, and wrongly typed fields with safe diagnostics (it never prints values). It rejects duplicate entries and keeps the first valid entry.
- Inventory entries only append. They never override built-in rules. The existing 500-entry ceiling remains. The engine does not load entries beyond it and produces a warning. This is a capacity limit, not a fail-closed policy boundary.
- At session start the engine also compiles in-memory inventory rules from the process username, hostname (and its first label), home directory, and `git config user.name` and `user.email` when git is available. These rules never hit disk or the ledger. The engine skips generic names (`localhost`, `root`, distro defaults), example-template tokens, ephemeral `/tmp` homes, and values under three characters. File inventory still wins for employer names, family names, and SSIDs.
- Invalid regexes and unknown validators reject that definition without printing the supplied identifier, regex body, validator name, or config contents. The engine retains the last valid custom rule definition. An isolated fresh-process test covers import-time loading, not only pure helper tests.
- `scanBudgetMs` in the user config (or `ITHILDIN_SCAN_BUDGET_MS`, which wins) sets the per-hook scan envelope in milliseconds. The default is 30s.
- The engine caches completed scan windows in memory. It writes them next to the session as `<session>.ithildin-scan-cache.json` (mode 0600). That file holds rule ids, categories, and offsets, never values. A resumed session reuses the windows a previous process finished. The engine ignores the cache when the active rule set or the cache format changes.

## Stand-ins

PII findings become stable, meaningful stand-ins instead of numbered tokens. Secrets are unchanged: they still get random, format-preserving fakes.

- Hostnames keep role words and their domain structure: `prod-pg-use1.acme.internal` becomes `prod-pg-use1.n4a5b6c.internal.example`. Identifying words become `n`+hex, and hosts in one domain share one stand-in domain. A bare identifying name becomes `host-3c9d0e`.
- Usernames become `user-3c9d0e`. The same name as an email local part or a home directory gets the same stand-in, so one person stays one person.
- IPv4 addresses move into 240.0.0.0/5 (never assigned). Addresses in one /24 stay in one stand-in /24, and the last octet is kept. IPv6 moves into 2001:db8::/32 with one stand-in /64 per real /64. MACs become locally administered (`02:…`).
- Everything else becomes `<label>-<hex>`. Built-in rules pick a label (`person`, `phone`, `ssid`, `id`, …). Set `"label"` (one lowercase word) on your own rules and inventory entries, otherwise they use `pii`.
- Stand-ins are an HMAC of the value under a random key. The key is the only thing written; there is no table of real values on disk. By default each session has its own key, `<session>.jsonl.ithildin-alias-key` beside the transcript (mode 0600). A new session gets new stand-ins, so a provider cannot join them across sessions into a profile. Resuming a session reuses its key, and a fork inherits its parent's. `/purge-sessions` deletes the key with its transcript.
- `"aliasKey": "shared"` (or `ITHILDIN_ALIAS_KEY_SCOPE=shared`) uses one key for every session instead: `${XDG_STATE_HOME:-~/.local/state}/ithildin/alias-key`, overridable with `ITHILDIN_ALIAS_KEY_FILE`. Stand-ins then stay the same across sessions, and so become linkable. The engine refuses file-tool and Bash reads of either key, like the inventory.
- `"aliases": "tokens"` in this config, or `ITHILDIN_ALIASES=tokens`, restores the `__ITHILDIN_<TYPE>_<N>__` placeholders.

## Infrastructure inventory

At session start the engine also reads `~/.ssh/config` (following `Include`) and the current repository's git remote URLs. It adds match rules for concrete `Host` aliases, `HostName` values (short names too), `User` values, and remote hosts. Public forges (github.com, gitlab.com, …), service accounts (`git`, `ec2-user`, …), wildcard patterns, and `%` tokens are skipped. These rules stay in memory, like the runtime identity rules, and are capped at 100 per source. `ITHILDIN_INFRA_INVENTORY=off` disables them.

## Swap-back

When the model calls a tool with a stand-in, the proxy replaces it with the real value in the call's arguments, in the reply on its way to the agent. The agent runs the tool with the real value and keeps it in its transcript. The next request carries that value again, and the proxy masks it back to the same stand-in. The tool's output is aliased again on the way back. Every value swapped in is added to that scan, so it returns as its stand-in even when no rule would have caught it.

- Exact stand-ins resolve from this session's findings and from every inventory entry (minted at session start, so stand-ins from earlier sessions resolve too). Composed stand-ins resolve from their parts: another host in a known stand-in domain, or another address in a known stand-in /24.
- A stand-in that cannot be resolved (another machine, a re-rolled key) runs as it is. The tool sees the stand-in, not a guess.
- Off-machine rule: `web_fetch` and `web_search` never get swapped values. In a Bash command that talks to the network (curl, wget, nc, ssh, scp, rsync, git push/fetch/pull/clone, …), a stand-in may appear only as the destination host, unless every destination in the command is itself a stand-in (your own hosts). Anything else, such as a stand-in in a query string, a request body, or piped into curl, blocks the call. The proxy blocks this for shell tools; other tools keep the stand-in. `[allow-pii]` lifts this rule. The check is lexical: a script written to disk and run later is out of its reach.
- The secret-file and inventory guards run again on the swapped arguments.
- Secrets are never swapped back. They keep random fakes, and the fake is what runs.
- Stand-in home paths (`/home/user-3c9d0e/…`) work with file tools, because the check for a real home path runs on the model's arguments, before the swap.

## Generalized wording

`generalize` replaces words with a general phrase, so meaning survives without specifics. Put the list in `generalize.json` beside the config (a bare array, or `{ "generalize": [...] }`; `ITHILDIN_GENERALIZE` overrides the path), or under `generalize` in the config itself. Both load. This repo links `home-manager/config/ithildin/generalize.json`, a starter list (health, legal, employment, security vendors) to edit freely:

```json
"generalize": [
  { "id": "medical", "terms": ["headache", "migraine"], "replace": "minor neurological condition" }
]
```

- Terms match whole words, case-insensitively unless `"caseSensitive": true`. Longer terms win ("chronic migraine" over "migraine"). Up to 1,000 terms per entry. `replace` is one line of at most 80 characters.
- The model sees `⟦minor neurological condition⟧`. Text inside `⟦…⟧` is never generalized again.
- One phrase stands for many terms, so it cannot be swapped back. A tool call containing `⟦…⟧` runs with the phrase as written, so general wording can end up in files or commands. `[allow-pii]` bypasses the replacement.
- `"scope": "everywhere"` (default) generalizes everywhere the engine scans: your prompts, tool output, and the provider payload. A file containing such a term cannot be edited around that word while the proxy is on (use `[allow-pii]` for that turn).
- `"scope": "prompts"` generalizes only what you type. Use it for words that also appear in code and config (vendor and product names), so those files stay readable and editable.
- Keep out words that are also ordinary dev vocabulary (`stroke`, `debt`, `fired`, `pip`, Dockerfile `ADD`). Put acronyms in their own `"caseSensitive": true` group.
- The engine refuses file-tool and Bash reads of `generalize.json`: the list says which topics you consider sensitive.

## Session transcripts

The engine refuses direct model reads of Pi session transcripts (`$PI_CODING_AGENT_DIR/sessions`, `~/.pi/agent/sessions`) and of the recall skill's index (`${XDG_DATA_HOME:-~/.local/share}/pi-session-search`). That covers file tools and Bash, including paths an interpreter builds from pieces (`Path.home()/'.pi'/'agent'/'sessions'`). Transcripts hold earlier work from other sessions and projects. An eval model was seen digging through them for past solutions, which sends that history to the provider. The recall skill still works: its script is invoked by name, and its bounded output is scanned like any tool result. `[allow-pii]` bypasses this check.
