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
  upgrade, a scan that throws or runs out of time. On startup it sends
  synthetic secrets through itself and serves nothing until none of them get
  through.

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
- Base64 and hex dumps of any of the above.

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

**Images.** Inline images are withheld, since their text can't be scanned.

**Guarded changes.** The proxy also refuses tool calls that would disable it
or throw work away:

- edits to its own config, or to an agent's settings that point the agent at
  the proxy
- `rm -rf .git`
- `git reset --hard`, `git clean -fdx`, force pushes, `branch -D`
- `git filter-branch`, `git reflog expire`

Ordinary `add`, `commit`, `push` and soft resets go through.

## The footer

Claude Code's status line and Pi's footer both show the same badge, which
the proxy builds:

```
ITHILDIN ON · 12m 1f 3l 2i (+2) · 40 req · +pii
```

| Part     | Meaning                                                     |
|----------|-------------------------------------------------------------|
| `12m`    | distinct values masked (stand-ins or generalized wording)   |
| `1f`     | tool results withheld because they read a protected file    |
| `3l`     | search lines withheld because they came from one            |
| `2i`     | inline images withheld                                      |
| `(+2)`   | how many of those arrived since your latest prompt          |
| `40 req` | requests scanned in this conversation                       |
| `+pii`   | allow tags your latest prompt carries                       |

Counts cover the whole conversation, and kinds at zero are left out. With
nothing hidden, the badge reads `ITHILDIN ON · 0 · N req`. The request count
ticks on every request once the conversation has a second message, so a quiet
badge still proves the proxy is in the path. A lone first message is not
counted: it looks the same as the agent's side requests (titles, quota checks).
Its values show in the counts from the next request on.

`ITHILDIN DOWN` means the health check failed: the proxy isn't running, or
its self-test didn't pass, and requests are being refused. `BYPASS` means the
agent isn't routed through the proxy at all.

## Allow tags

Sometimes the model needs a real value. Put a tag anywhere in your prompt:

| Tag                 | Lifts                                   |
|---------------------|-----------------------------------------|
| `[allow-pii]`       | personal and infrastructure details     |
| `[allow-secrets]`   | secrets                                 |
| `[allow-images]`    | the image hold                          |
| `[allow-protected]` | the guard on config and git history     |
| `[allow-all]`       | everything but `protected`              |

A tag applies to the prompt it is typed in, and ends when you send the next
one. The proxy removes tags before forwarding, so the model never sees them.
The footer is how you know one took effect.

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
