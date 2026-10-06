# Ithildin

A local proxy that sits between a coding agent and its model provider. It
removes secrets and personal details from every request before the request
leaves the machine, and puts the real values back into the model's tool calls
before they run. The model works with stand-ins, and your machine keeps the
real values.

## The name

In *The Lord of the Rings*, the West-gate of Moria is marked in ithildin, a
metal worked from mithril. Gandalf says it "mirrors only starlight and
moonlight" (*ithil* is the Sindarin word for the moon). In daylight the
door is a blank cliff face. The drawing and the inscription are there all the
time, but only the right light shows them.

This proxy works the same way. The real hostname, the real address and the
real token stay in the conversation on your side, but the provider only ever
sees the blank door.

## How it works

Agents that let you set a provider base URL can use it. Claude Code takes
`ANTHROPIC_BASE_URL`, and Pi takes a per-provider `baseUrl`:

```
agent ──> http://127.0.0.1:18733/<route>/... ──> provider
```

- **Requests.** Each JSON body is scanned before it is forwarded. That covers
  prompts, tool output, system prompts, compaction summaries and subagents.
  Every finding is replaced with a stand-in.
- **Responses.** Stand-ins in the model's tool-call arguments and reply text
  get their real values back, so a tool runs against the real host and you
  read the real name. Tool-call fragments are held until the call is complete,
  so a stand-in split across two stream chunks still swaps. Thinking blocks
  pass through untouched because they are signed.
- **Refusals.** The proxy refuses to forward anything it cannot scan: an
  unknown route, a body that isn't JSON, a compressed body, a WebSocket
  upgrade, a scan that throws or runs out of time. It refuses an upstream
  redirect too: a client following one would resend its unredacted body.
- **Self-test.** On startup, and every five minutes after, the proxy sends
  synthetic secrets, a file read and an image through itself in every wire
  format, JSON and streamed. It checks that none of them reach the provider,
  that a tool call gets its real value back, and that the guards below block a
  call sending that value to a web host, one deleting `.git`, and a `git push`
  after the conversation read a web page. Until it
  passes, the proxy serves nothing and the footer reads `ITHILDIN DOWN`. A
  pass proves those paths work; it does not prove nothing else gets out (see
  [What it does not do](#what-it-does-not-do)).

Stand-ins look like the values they replace. An IPv4 address becomes another
IPv4 address in 240.0.0.0/5, a space that is never assigned, and addresses in
the same /24 stay together. A hostname becomes another word of the same
length. A ticket key keeps its shape. They come from an HMAC under a key kept
in `~/.local/state/ithildin`, so they stay the same across restarts and the
provider's prompt cache stays warm. No table of real values is ever written
to disk.

## What it catches

**Secrets** get random fakes in the same format, and those fakes are never
swapped back:

- Cloud and platform keys: AWS, GCP, Azure, DigitalOcean, Fly.io, Databricks,
  Vault, Doppler, Tailscale and others.
- Forge and package tokens: GitHub, GitLab, npm, PyPI.
- Service tokens: Slack, Discord, Telegram, Twilio, Stripe, Shopify, Sentry,
  Linear, Notion, Grafana and others.
- Model API keys: Anthropic, OpenAI, Hugging Face, Groq, OpenRouter, xAI and
  others.
- Private keys (PEM and base64), `age` keys, JWTs, bearer and basic-auth
  headers, credentials in URLs, connection strings, TOTP URIs, Wi-Fi PSKs.
- Generic `KEY=value` assignments and high-entropy tokens next to words like
  `secret` or `token`.
- Base64 and hex dumps of any of the above, and rot13 copies of a value
  already masked.

**Personal and infrastructure details** get stand-ins that swap back:

- Emails, phone numbers, street addresses, postal codes, coordinates, names
  near a title or label, card numbers (Luhn-checked), IBANs and bank
  accounts, and national ID formats for the US, FR, DE, IT, ES, JP, KR
  and CN.
- IPv4 and IPv6 addresses, MACs, machine IDs, SSIDs.
- Hostnames and usernames in home paths, `user@host` and labelled fields.
- This machine's identity, read at startup and again every five minutes:
  - username, hostname, home directory, `git config` name and email
  - hosts and users in `~/.ssh/config`
  - git remote hosts of every repository under `$ITHILDIN_REPO_ROOTS`
    (default: your home directory)
  - saved Wi-Fi networks
  - `resolv.conf` search domains
  - your own `/etc/hosts` entries
  - Tailscale MagicDNS names

  A value found once stays covered for the life of the process, even after
  you leave that network. The list is capped at 1000 values.

**Your own list.** Names, employers and family members can't be recognised by
their shape, so you list them yourself in `~/.config/ithildin/config.json`.
See [`engine/PERSONAL-INVENTORY.md`](engine/PERSONAL-INVENTORY.md). The same
file sets up `generalize`, which replaces a sensitive topic with a vaguer
phrase instead of a stand-in: `⟦minor neurological condition⟧`.

**Files.** If a tool result read a file that holds secrets by nature (`.env`,
`.netrc`, `.npmrc`, SSH private keys, `*.pem`, `*.key`, kubeconfig), the whole
result is withheld. The same happens to search lines that came from such a
file.

A shell command that reads such a file and runs a network client (`curl`,
`scp`, `nc`, a git push) doesn't run at all: by the time its result could be
withheld, the data would be gone. `[allow-secrets]` lifts both.

**Images.** Inline images are withheld, since their text can't be scanned.
`[allow-images]` lets one prompt's through, `[allow-images:session]` the rest
of the session's.

**Guarded changes.** The proxy also refuses tool calls that would disable it
or throw work away:

- edits to its own config, or to an agent's settings that point the agent at
  the proxy
- `rm -rf .git`
- `git reset --hard`, `git clean -fdx`, force pushes, `branch -D`
- `git filter-branch`, `git reflog expire`

Ordinary `add`, `commit`, `push` and soft resets go through. A refusal tells
the agent the safer way to the same end where there is one (`git stash`
instead of `reset --hard`, `branch -d` instead of `-D`), so it doesn't hunt
for another spelling of the same change. Each refusal also names an id the
user can type to allow just that one call (see [Allow tags](#allow-tags)).

**Outside content.** A web page, a download or an issue thread can carry
instructions the user never gave. Once a conversation has read any of these,
it is *untrusted* and stays that way, even after compaction. These count as
outside reads:

- web tools (`WebFetch`, `WebSearch`, `web_fetch`) and MCP tools whose names
  say they fetch, browse or search
- `curl`, `wget`, `httpie`/`xh` and text browsers
- `gh issue`, `gh pr`, `gh api` and other `gh` reads

A conversation is *private* once the model has seen a secret file (output let
through by `[allow-secrets]`), or a shell call copied one (`cp`, `tee`, a `>`
redirect). A read whose output was withheld doesn't count: the model never saw
the values.

A subagent's answer carries the labels of what it read. Claude Code's
subagents share their parent's session, so their reads mark it directly. For
opencode's `task` and Codex's `spawn_agent`/`wait`, the answer counts as
untrusted or private if another conversation took that label on while the
work was out. A parallel session reading the web at the same moment counts too.

While a conversation is untrusted or private, calls that send data off the
machine don't run:

- `git push`
- `scp`, `ssh`, `nc`, `rsync` to a host
- uploads and POSTs (`curl -d`/`-F`/`-T`/`-X POST`, `wget --post-file`)
- a URL built at run time (`$(…)`)
- `gh … create/comment`
- MCP tools whose names say they post, send or comment

Plain downloads and local work go through. `[allow-send]` lifts the block.

**Your own guard list.** Under `"guard"` in `config.json` you can protect
more paths, name more tools as outside reads or sends, mark tools you have
reviewed, and take calls back out of the built-in reads and sends. The file
is re-read when it changes.

```json
"guard": {
  "protect": ["~/infra/deploy.yaml"],
  "outsideTools": ["mcp__jira__*"],
  "sendTools": ["mcp__mail__*", "Bash(command:deploy.sh *)"],
  "reviewedTools": ["mcp__db__run_query"],
  "trustedReads": ["Bash(command:gh issue view * --repo me/*)"],
  "allowedSends": ["Bash(command:git push origin *)", "mcp__github__*(repo:me/*)"]
}
```

An entry is a tool name with `*` globs, plus optional argument patterns:
`tool(arg:pattern, ...)` matches when every named argument matches whole. In
a pattern `*` matches anything, `?` one character, and `\` escapes
`* ? , ) \` (any other backslash is just a backslash). `reviewedTools` takes
tool names only. A shell command is matched one command at a time, with the
program named without its directory, so `git push origin *` never covers a
`curl` chained after it.

**Checking it.** `ithildin check` lists the problems in the guard section and
runs your guard tests: `*.guard` files in `~/.config/ithildin/guard-tests`,
or the files and directories you name (naming some that hold none fails).
Each file is one conversation, and
each call is judged by the history before it:

```
# reading the web stops a push, and [allow-send] lets it through
allow WebFetch {"url": "https://example.com/"}
deny  Bash git push origin main
prompt [allow-send] push it
allow Bash git push origin main
```

Arguments are a JSON object, or the rest of the line as the command. `prompt`
is a typed prompt and `cwd` sets the working directory. The calls run through
the proxy's own guards; no tool runs. It exits 1 on a problem or a failed
test, so it can gate a dotfiles repo's CI.

## The footer

Claude Code's status line and Pi's footer both show the same badge, which
the proxy builds:

```
ITHILDIN ON · 12m 1f 3l 2i (+2) · 40 req · untrusted · private · ?1t · +pii
```

| Part        | Meaning                                                     |
|-------------|-------------------------------------------------------------|
| `12m`       | distinct values masked (stand-ins or generalized wording)   |
| `1f`        | tool results withheld because they read a protected file    |
| `3l`        | search lines withheld because they came from one            |
| `2i`        | inline images withheld                                      |
| `(+2)`      | how many of those arrived since your latest prompt          |
| `40 req`    | requests scanned in this conversation                       |
| `untrusted` | the conversation read outside content, so sends are blocked |
| `private`   | a secret file was seen or copied, so sends are blocked      |
| `?1t`       | tools the agent offers that act but no guard reads          |
| `+pii`      | allow tags your latest prompt carries                       |
| `SHAPE`     | context shaping is on (`SHAPE OFF` when the session opted out) |

Counts cover the whole conversation, and kinds at zero are left out. With
nothing hidden, the badge reads `ITHILDIN ON · 0 · N req`. The request count
ticks on every request once the conversation has a second message, so a quiet
badge still proves the proxy is in the path. A lone first message is not
counted: it looks the same as the agent's side requests (titles, quota checks).
Its values show in the counts from the next request on.

`ITHILDIN DOWN` means requests are being refused: the proxy isn't running,
or its self-test hasn't passed. For a failed self-test the badge names the
first failure, `ITHILDIN DOWN · self-test: chat streamed: protected change not
blocked (+1)`. Both footers re-check every five seconds, idle or not. `BYPASS` means the
agent isn't routed through the proxy at all.

For `?Nt`, the proxy log names each such tool once (`tool mcp__db__drop_table
acts, and no guard reads its calls`). Teach the guard about it under `guard`
in `config.json`, or list it in `reviewedTools` once you've checked it.

## The dashboard

The footer says that the proxy is on the path. The dashboard shows what it did.
Open `http://127.0.0.1:18733/dashboard` (your port) in a browser on the same
machine. The page fits the window.

The bar on top answers first: `No leaks` with how many values are watched,
`N leaks found` in red with the time of the latest, or `Nothing watched` when
the watch list is off. Hover it for where the leak was and what is watched.

The left column lists the sessions, in the order the proxy first saw them.
A session goes by the title its agent gave it, read from the agent's own
naming request (Claude Code and opencode make one; Pi does not), or by your
`/rename` in Claude Code, and otherwise by its agent and number (`claude 1`,
`opencode 2`, `pi 1`). An agent that names none still gets a name, taken from
the first thing you asked it; a title from an agent replaces that, and your own
name replaces both. A naming request the proxy does not recognise is logged, so
an agent that rewords its prompt says so instead of going unnamed in silence. A
title from a model comes from its reply as the provider sent it, so it holds
stand-ins, never a real value; a name taken from your prompt is not taken at all
when the watch list finds something in it. A red count
beside a session is its leaks. Requests without a session, and refusals,
gather under *Other traffic*. Below the sessions, *Numbers* has the
values masked by kind, routes, replacements, swaps, blocks, refusals, scan
time and uptime, what shaping saved, and *Cache*: the share of prompt tokens
the provider read from its cache, from the replies' own usage figures, and how
often a conversation's cached prefix broke. A break is put down to the agent
(a changed system prompt, a reordered tool list) or to shaping (a cutoff step),
and the latest names where it happened. The page remembers what you fold.

Pick a session to read its conversation as the provider saw it: its latest
turn as it went upstream, after masking, updated as new turns arrive. It reads
like an agent's terminal, newest turn first: `›` your prompts, `⏺` the model
and its tool calls, `⎿` each call's result, with the system prompt, the
tools and harness text folded. **Raw** shows the JSON.

| Mark | Meaning |
|------|---------|
| blue | a stand-in: a value the proxy masked. Hover it for its kind, the rule that matched it, and a preview of the real value |
| blue with `↩` | a stand-in the model used, in its reply or a tool call, that your machine got back as the real value: the proof the footer cannot give |
| red | what the proxy held back: a guard's refusal, a withheld file or image |
| gold | a match for the search |

A leak is flagged on the message it was found in. Above the conversation, the
session's counts (values masked, swapped back, held back, leaks) and its
latest leaks, blocks and refusals. The key beside the search counts each kind
of mark, and a click goes to the next.

The preview of a real value is its first two and last characters and its
length (one character and the length for a short value). Events live in
memory, the newest 5000, and a restart clears them. The page and its data
answer only to `127.0.0.1`, `localhost` and `[::1]`, so a web page cannot
read them through a rebound name.

The conversation is the proof of what left the machine, so a real value that
masking missed is in it, and the page shows it as it is. The proxy keeps the
last 20 requests' text, and each session's latest turn however busy the
others are, in memory only, each cut at 8 MiB. A body over the cut is cut
where the JSON still parses, so it reads as a conversation less its last turn,
and the note above it says how much of it the page holds. Side requests (a
title, a summary) are kept but not shown as the conversation.
`ITHILDIN_KEEP_REQUESTS` sets how many (0 turns it off, 200 at most).

A leak turns the tab title to `(2) Ithildin` and puts a red mark on the icon.
The **Alert me about leaks** button asks the browser for permission to show a
notice. The notice names the place in the request, and never the string.

## The watch list

The dashboard shows what the proxy caught. A miss leaves no row, so it cannot
show what slipped through. The watch list tests that from outside. The proxy
checks each request after masking, in its body, path and query. A watched
string that is still there means masking missed it. The dashboard shows a red
`leaked` row with the place in the request, such as
`messages[3].content[0].text`, and a preview of the string. The conversation
goes out again every turn, so each place shows once.

Two lists are watched:

- **Known values.** The engine promises to mask these everywhere: your
  inventory, and what the proxy reads from this machine (its user name, host
  name, home directory, git remotes and SSH hosts). They need no setup. A hit
  is flagged and never blocks. Matching follows the inventory entry: whole
  words, and case only when the entry says so. A hit means the value sat where
  the engine does not scan, such as a thinking block, or that a rule has a gap.
  A trial over 871 files found no false alarms, and a scan took 7 ms at most.
- **Your own strings.** List real strings that must never leave the machine,
  such as an internal domain, a project name or a person, under `"watch"` in
  `config.json`:

```
"watch": {
  "terms": ["acme-internal.example", "Project Falcon"],
  "action": "flag",
  "known": true
}
```

- `terms` are plain text, matched case-insensitively anywhere in a text, even
  inside a longer word. Each one has at least 3 characters. The list holds at
  most 200.
- `action` is `flag` (the default) or `block`. `flag` sends the request.
  `block` refuses it with a 403, so nothing leaves. The agent then retries, so
  fix the leak or remove the string. It applies to `terms` only.
- `known` is `true` by default. `false` stops the known list.
- A prompt with `[allow-pii]` or `[allow-all]` skips the check. You lifted
  masking on purpose.
- The `leaks found` tile says what it watches, and `nothing watched` when both
  lists are empty. A zero then means nothing.
- It finds only what is on the lists, and not a value sent encoded (base64 or
  hex). Headers are not checked, because they carry your own credentials.

`ithildin check` shows how many strings the list holds, whether `known` is on,
and any problems with the section. The file is read again when it changes.

## Allow tags

Sometimes the model needs a real value. Put a tag anywhere in your prompt:

| Tag                 | Lifts                                        |
|---------------------|----------------------------------------------|
| `[allow-pii]`       | personal and infrastructure details          |
| `[allow-secrets]`   | secrets                                      |
| `[allow-images]`    | the image hold                               |
| `[allow-images:session]` | the image hold, for the rest of the session |
| `[allow-protected]` | the guard on config and git history          |
| `[allow-send]`      | the send block in untrusted or private chats |
| `[allow-once:<id>]` | the guards, for the one call a refusal named |
| `[allow-all]`       | everything but `protected`                   |

A tag applies to the prompt it is typed in, and ends when you send the next
one. The proxy forwards tags as you typed them, so the model sees what you
lifted and knows what a tag in a notice means. The footer is how you know one
took effect.

`[allow-images:session]` is the exception: images pass from that prompt on,
for the rest of the session, until you type `[mask-images]` or the proxy
restarts. It needs a client that names its session, and the footer shows
`+images` while it is on.

## Shaping

Old tool results are masked before the request leaves: past the cutoff, a
result over 1k characters, or one holding images, becomes a one-line stub
naming the call that made it. Long strings in an old call's input, the file a
`Write` wrote or both sides of an `Edit`, become a note too. Newer results are
compacted where they can be: escape codes, repeated lines, log timestamps,
base64 and hex blobs and JSON whitespace go. A result that repeats one still
whole above it, byte for byte, becomes a note pointing at the first. rtk
condenses command output at the source, so what reaches here is mostly what
rtk does not recognise: MCP results, a direct grep, a fetch.

A stub says to re-run the call, which fails for anything that changed or
cannot run twice. Add the proxy's own MCP server and it keeps what it
shortened, and the stub names an id to read it back with instead:

```sh
claude mcp add --transport http ithildin http://127.0.0.1:18733/mcp
```

With it, shaping also cuts long JSON arrays of similar objects (an MCP tool
listing pods, issues, rows) to the first and last items and the ones that
differ from the rest, by rare values and numeric outliers. That is lossy, so it
only happens when the agent can get the whole output back. The tool answers
only this machine, keeps outputs in memory as they were forwarded, and lets
the oldest go past 64 MiB.

Two things to know about it. It is **pure**: the same request shapes to the
same bytes every time, which is what keeps the provider's prompt cache intact,
so nothing in it may read the clock or a counter. And it **fails open** — a
request it cannot shape is forwarded exactly as redaction left it, never
refused, because it is an optimization and a turn matters more than tokens.

The conversation the dashboard keeps is the one that **arrived**; only the
forwarded copy is shaped.

Three ways to turn it off, each independent:

| How | Scope |
|-----|-------|
| `ITHILDIN_SHAPE=off` in the proxy's environment | every route |
| `[raw]` in a prompt | that session, until `[shape]` |
| no client session header | never off — a session it cannot name cannot have opted out |

`[raw]` and `[shape]` are session switches rather than allow tags: they hold
for the rest of the session however many prompts follow, because the proxy
remembers them and the prompt that set one may be compacted out of the
history. The badge reads `· SHAPE` or `· SHAPE OFF` once a request in the
conversation has an answer, and says nothing before that.

A tag opens every call of its kind. `[allow-once:<id>]` opens only the call
whose refusal gave that id: the same command sent again runs, and anything
else is still checked. It lifts the protected, send and secret-send guards,
but not the hold on personal details.

Only text you type counts: a tag inside an attached file, a code fence or a
summary the agent wrote does nothing. Tags also need a client that names its
session (Claude Code, opencode, Pi with the footer extension); from any
other client the proxy masks everything.

## Running it

The flake builds the `ithildin` package, and the flake checks run the tests,
type checks and format checks:

```sh
nix build
nix flake check
```

Start the proxy, point your agent at it, and check it:

```sh
ithildin --port 18733
export ANTHROPIC_BASE_URL=http://127.0.0.1:18733/anthropic
ithildin selftest        # runs the self-test inside the live proxy
ithildin check           # checks the guard config and runs guard tests
```

Needs Bun 1.4.2 or newer, and says so rather than starting on an older one: the
engine bounds each masking rule with a deadline, and before that release those
deadlines do not fire in time, so one long conversation hangs the proxy for
minutes with nothing in the log. Two megabytes of messages scan in well under a
second on 1.4.2 and were still running after four minutes on 1.3.14.

The built-in routes are `anthropic`, `openai-codex` and `opencode-go`. Add
local or LAN model servers in `~/.config/ithildin/routes.json`. A route is an
upstream, optional path rewrites, and an optional `via`:

```json
{
  "anthropic": { "upstream": "https://api.anthropic.com", "via": "http://127.0.0.1:8787" },
  "modelbox": { "upstream": "http://gw.example.com:4000" }
}
```

`via` sends the request to a proxy in front of the provider (Headroom, say)
with the endpoint on the path and the upstream in `x-headroom-base-url`, which
is how such a host learns where to forward it. Rewrites run first, so the base
named is the upstream the request would really have gone to. A path such a host
would not recognise — Gemini's `/v1beta`, say — is refused rather than passed on
with no base, since passing it would leave the host to choose the upstream. Any
`x-headroom-*` header from the agent is dropped, so the proxy alone names it.

Settings are environment variables:

| Variable                     | Effect                                           |
|------------------------------|--------------------------------------------------|
| `ITHILDIN_PORT`              | listen port (default 18733)                      |
| `ITHILDIN_CONFIG`            | personal inventory file                          |
| `ITHILDIN_ROUTES`            | routes file                                      |
| `ITHILDIN_REPO_ROOTS`        | colon-separated roots for git remote discovery   |
| `ITHILDIN_INFRA_INVENTORY`   | `off` skips SSH, repo, network and Tailscale     |
| `ITHILDIN_SCAN_BUDGET_MS`    | per-request scan time limit (default 30000)      |
| `ITHILDIN_KEEP_REQUESTS`     | requests the dashboard keeps (default 20, 0 is off) |
| `ITHILDIN_SHAPE`             | `off` disables context shaping on every route         |

## What it does not do

It's a guardrail for a cooperative agent. It is not a sandbox.

- **Detection is pattern matching plus the lists above.** A value with no
  recognisable shape, on none of the lists, goes out as written.
- **Real values reach your disk.** A stand-in in a commit message or a file
  becomes the real value when the tool runs. A later push publishes it, and
  nothing flags the push.
- **The network and git guards read command lines.** A script written to
  disk and run later, or a command assembled at runtime, gets past them.
  The send guard has the same limit: an interpreter's own HTTP client
  (`python -c 'requests.post(…)'`) or a web tool's URL is not read as a
  send. An outside read is known by the tool's name or command, so content
  that arrives some other way does not mark the conversation. Labels live in
  memory: a restart, or a file written now and read in a later session,
  starts clean.
- **Some request parts go out unscanned.** Provider credentials and the
  cookie and beta headers, query names and path segments shaped like provider
  object ids (`msgbatch_…`, `resp_…`), thinking blocks and encrypted reasoning
  (providers verify their signatures), and images the provider fetches by URL
  or file id.
- **Routes in unread formats.** A route to a path the proxy can't parse
  (Ollama's `/api/chat`, a wrapping gateway) has its requests scanned, but a
  reply without model-shaped top-level keys passes unread.
- **The identity list stops at 1000 values.** Values found after that aren't
  masked; the log warns.
- **Traffic that skips the proxy isn't covered.** That includes an agent not
  pointed at it and a tool that makes its own network calls.

If you need hard limits, pair it with OS-level controls: a network namespace
or an egress firewall, and a separate process that owns `git push`.

## Layout

```
engine/   detection rules, stand-ins, swap-back (TypeScript, Bun)
proxy/    the HTTP proxy, stream rewriting, guard, status badge
checks/   flake checks: tests, coverage, types, format, function length
```
