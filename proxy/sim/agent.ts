// The simulated harness: holds the conversation with the real values in it,
// sends it through the proxy as Claude Code, Codex or opencode would, runs the
// model's calls against the world and appends what came back.
//
// Faults are switched on per seed (swarm testing) and fire at random: the
// things harnesses do to a conversation that the proxy has to survive.

import type { Format } from "../src/redact.ts";
import { canary } from "./canaries.ts";
import type { Turn } from "./model.ts";
import { Random } from "./random.ts";
import { runTool, type World } from "./world.ts";

type Fields = Record<string, unknown>;

export interface Faults {
  notes: boolean;
  midTurn: boolean;
  pastes: boolean;
  clear: boolean;
  compact: boolean;
  tools: boolean;
  ttl: boolean;
  unicode: boolean;
  retry: boolean;
  upstreamErrors: boolean;
}

export function faultsFor(random: Random): Faults {
  const on = () => random.chance(0.5);
  return {
    notes: on(),
    midTurn: on(),
    pastes: on(),
    clear: random.chance(0.3),
    compact: random.chance(0.3),
    tools: random.chance(0.3),
    ttl: random.chance(0.3),
    unicode: random.chance(0.3),
    retry: on(),
    upstreamErrors: random.chance(0.3),
  };
}

export interface Outgoing {
  path: string;
  headers: Record<string, string>;
  body: Fields;
}

const TOOL_NAMES = ["Read", "Bash", "Write"];
const HIDDEN = "​‍\u{E0041}\u{E0042}‮";

export class Agent {
  list: Fields[] = [];
  // Bumped when the conversation was cut (clear, compaction): the prefix the
  // provider cached is gone on purpose.
  epoch = 0;
  private ttl = "1h";
  private tools = [...TOOL_NAMES];
  private ids = 0;

  constructor(
    readonly format: Format,
    readonly world: World,
    readonly random: Random,
    readonly faults: Faults,
    readonly session: string,
    // A subagent: the parent's session and machine, its own model and system
    // prompt, as Claude Code runs one (proxy/sim/subagents.ts).
    readonly subagent = false,
  ) {
    this.prompt(true);
  }

  nextId(): string {
    const prefix = this.format === "anthropic" ? "toolu_sim" : "call_sim";
    return `${prefix}_${this.ids++}`;
  }

  private note(): string {
    const changed = this.random.text(30).split("\n")[0];
    return `<system-reminder>\nFiles changed: ${changed}\n</system-reminder>`;
  }

  // A typed prompt, sometimes with a value pasted into it.
  prompt(first = false): void {
    const { random, world } = this;
    const parts = [
      first ? `Please look at ${this.world.root}/README.md and fix the config.` : random.text(80),
    ];
    if (this.faults.pastes && random.chance(0.5)) {
      const pasted = canary(random);
      world.canaries.push(pasted);
      parts.push(`Here is what I have: ${pasted.value}`);
    }
    if (this.faults.unicode && random.chance(0.3)) parts.push(`note${HIDDEN}hidden`);
    // A mutation for checking the checks: with every prompt allowing all, the
    // leak check has to fire.
    if (process.env.SIM_MUTATE === "allow-all") parts.push("[allow-all]");
    const text = parts.join("\n");
    const notes = this.faults.notes && random.chance(0.5) ? [this.note()] : [];
    this.pushUser(text, notes);
  }

  private pushUser(text: string, notes: string[]): void {
    if (this.format === "anthropic")
      this.list.push({
        role: "user",
        content: [...notes, text].map((t) => ({ type: "text", text: t })),
      });
    else if (this.format === "responses")
      this.list.push({
        type: "message",
        role: "user",
        content: [...notes, text].map((t) => ({ type: "input_text", text: t })),
      });
    else this.list.push({ role: "user", content: [...notes, text].join("\n") });
  }

  // The model's turn as the harness stores it, then the results of its calls.
  take(turn: Turn): void {
    this.pushModel(turn);
    if (turn.calls.length === 0) {
      this.between();
      this.prompt();
      return;
    }
    const outputs = turn.calls.map((c) => runTool(this.world, c.name, c.input));
    this.pushResults(turn, outputs);
  }

  private pushModel(turn: Turn): void {
    this.list.push(...modelItems(this.format, turn));
  }

  private pushResults(turn: Turn, outputs: string[]): void {
    const { random, faults } = this;
    const typed = faults.midTurn && random.chance(0.05) ? random.text(60) : undefined;
    const notes = faults.notes && random.chance(0.3) ? [this.note()] : [];
    if (this.format === "anthropic") {
      const content: Fields[] = turn.calls.map((c, i) => ({
        type: "tool_result",
        tool_use_id: c.id,
        content: [{ type: "text", text: outputs[i]! }],
      }));
      for (const t of [...notes, ...(typed ? [typed] : [])])
        content.push({ type: "text", text: t });
      this.list.push({ role: "user", content });
      return;
    }
    turn.calls.forEach((c, i) =>
      this.list.push(
        this.format === "responses"
          ? { type: "function_call_output", call_id: c.id, output: outputs[i] }
          : { role: "tool", tool_call_id: c.id, content: outputs[i] },
      ),
    );
    if (typed) this.pushUser(typed, []);
  }

  // What a harness may do between one task and the next.
  private between(): void {
    const { random, faults } = this;
    if (faults.tools && random.chance(0.2))
      this.tools = this.tools.length > 3 ? TOOL_NAMES.slice() : [...TOOL_NAMES, "Grep"];
    if (faults.ttl && random.chance(0.2)) this.ttl = this.ttl === "1h" ? "5m" : "1h";
    if (faults.clear && random.chance(0.1)) {
      this.list = [];
      this.epoch++;
    } else if (faults.compact && random.chance(0.1)) {
      const seen = this.world.canaries
        .slice(0, 3)
        .map((c) => c.value)
        .join("; ");
      const summary =
        `This session is being continued from a previous conversation. ` + `Summary: ${seen}`;
      this.list = [];
      this.epoch++;
      this.pushUser(summary, []);
      this.list.push(
        this.format === "chat"
          ? { role: "assistant", content: "Understood." }
          : this.format === "responses"
            ? {
                type: "message",
                role: "assistant",
                content: [{ type: "output_text", text: "Understood." }],
              }
            : { role: "assistant", content: [{ type: "text", text: "Understood." }] },
      );
    }
  }

  outgoing(): Outgoing {
    const auth = { authorization: "Bearer sim-token", "content-type": "application/json" };
    if (this.format === "anthropic")
      return {
        path: "anthropic/v1/messages",
        headers: {
          ...auth,
          "x-claude-code-session-id": this.session,
          "anthropic-version": "2023-06-01",
        },
        body: this.anthropicBody(),
      };
    const tools = this.tools.map((name) => ({
      type: "function",
      name,
      parameters: { type: "object" },
    }));
    if (this.format === "responses")
      return {
        path: "openai-codex/codex/responses",
        headers: { ...auth, session_id: this.session },
        body: {
          model: this.subagent ? "gpt-6-luna-mini" : "gpt-6-luna",
          instructions: `${this.persona("Codex")}\n\n${this.world.memory}`,
          tools,
          input: structuredClone(this.list),
          stream: true,
          store: false,
        },
      };
    return {
      path: "opencode-go/chat/completions",
      headers: { ...auth, "x-opencode-session": this.session, "x-opencode-client": "opencode" },
      body: {
        model: this.subagent ? "deepseek-v4-flash" : "deepseek-v4",
        stream: true,
        tools: this.tools.map((name) => ({
          type: "function",
          function: { name, parameters: { type: "object" } },
        })),
        messages: [
          { role: "system", content: `${this.persona("opencode")}\n\n${this.world.memory}` },
          ...structuredClone(this.list),
        ],
      },
    };
  }

  private persona(name: string): string {
    return this.subagent ? `You are a subagent of ${name}.` : `You are ${name}.`;
  }

  // Claude Code's shape: a billing header, a marked system prompt, and its
  // marker moved to the newest message on every request.
  private anthropicBody(): Fields {
    const marker = { type: "ephemeral", ttl: this.ttl };
    const messages = structuredClone(this.list);
    const last = messages.at(-1);
    const blocks = (last?.content ?? []) as Fields[];
    const at = blocks.findLastIndex((b) => b.type !== "thinking");
    if (at >= 0) blocks[at] = { ...blocks[at], cache_control: marker };
    return {
      model: this.subagent ? "claude-haiku-5-5" : "claude-opus-5-5",
      max_tokens: 32000,
      stream: true,
      thinking: { type: "adaptive" },
      system: [
        { type: "text", text: "x-anthropic-billing-header: cc_version=2.1" },
        {
          type: "text",
          text: `${this.persona("Claude Code")}\n\n${this.world.memory}`,
          cache_control: marker,
        },
      ],
      tools: this.tools.map((name) => ({
        name,
        description: `The ${name} tool.`,
        input_schema: { type: "object" },
      })),
      messages,
    };
  }
}

// A model turn as the harness keeps it in its list, in each format.
export function modelItems(format: Format, turn: Turn): Fields[] {
  const out: Fields[] = [];
  if (format === "anthropic") {
    const content: Fields[] = [
      { type: "thinking", thinking: turn.thinking, signature: `sig-${turn.thinking.length}` },
    ];
    if (turn.text) content.push({ type: "text", text: turn.text });
    for (const c of turn.calls)
      content.push({ type: "tool_use", id: c.id, name: c.name, input: c.input });
    out.push({ role: "assistant", content });
    return out;
  }
  if (format === "responses") {
    out.push({
      type: "reasoning",
      summary: [{ type: "summary_text", text: turn.thinking }],
      encrypted_content: Buffer.from(turn.thinking).toString("base64"),
    });
    if (turn.text)
      out.push({
        type: "message",
        role: "assistant",
        content: [{ type: "output_text", text: turn.text }],
      });
    for (const c of turn.calls)
      out.push({
        type: "function_call",
        call_id: c.id,
        name: c.name,
        arguments: JSON.stringify(c.input),
      });
    return out;
  }
  const calls = turn.calls.map((c) => ({
    id: c.id,
    type: "function",
    function: { name: c.name, arguments: JSON.stringify(c.input) },
  }));
  out.push({
    role: "assistant",
    content: turn.text,
    reasoning_content: turn.thinking,
    ...(calls.length > 0 ? { tool_calls: calls } : {}),
  });
  return out;
}
