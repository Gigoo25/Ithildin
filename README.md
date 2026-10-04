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

## Allow tags

Sometimes the model needs a real value. Put a tag anywhere in your prompt:

| Tag                 | Lifts                                        |
|---------------------|----------------------------------------------|
| `[allow-pii]`       | personal and infrastructure details          |
| `[allow-secrets]`   | secrets                                      |
| `[allow-images]`    | the image hold                               |
| `[allow-protected]` | the guard on config and git history          |
| `[allow-send]`      | the send block in untrusted or private chats |
| `[allow-once:<id>]` | the guards, for the one call a refusal named |
| `[allow-all]`       | everything but `protected`                   |

A tag applies to the prompt it is typed in, and ends when you send the next
one. The proxy removes tags before forwarding, so the model never sees them.
The footer is how you know one took effect.

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

The built-in routes are `anthropic`, `openai-codex` and `opencode-go`. Add
local or LAN model servers in `~/.config/ithildin/routes.json`.

Settings are environment variables:

| Variable                     | Effect                                           |
|------------------------------|--------------------------------------------------|
| `ITHILDIN_PORT`              | listen port (default 18733)                      |
| `ITHILDIN_CONFIG`            | personal inventory file                          |
| `ITHILDIN_ROUTES`            | routes file                                      |
| `ITHILDIN_REPO_ROOTS`        | colon-separated roots for git remote discovery   |
| `ITHILDIN_INFRA_INVENTORY`   | `off` skips SSH, repo, network and Tailscale     |
| `ITHILDIN_SCAN_BUDGET_MS`    | per-request scan time limit (default 30000)      |

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
