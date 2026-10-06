// Names for the dashboard's sessions. An agent's session id is a hash, so the
// page shows "claude 2" for the second Claude session this proxy has seen,
// with the id's first characters beside it for the one who needs them.

// Bounds memory across many short sessions. A dropped session that comes back
// gets a new number, so a name never stands for two sessions.
const NAMES_MAX = 1000;

export interface SessionTitle {
  // The id's first characters, as on the dashboard's events.
  id: string;
  name: string;
  title?: string;
  // True when the title came from the conversation rather than an agent.
  guessed?: boolean;
}

const ID_CHARS = 8;

// Where a title came from, so a better one may replace a worse and never the
// other way round: what the user typed beats what an agent made up, and what an
// agent made up beats a name taken from the conversation.
export const GUESS = 0;
export const AGENT = 1;
export const USER = 2;

export class SessionNames {
  private readonly names = new Map<string, string>();
  private readonly counts = new Map<string, number>();
  // A session's title and where it came from (titles.ts).
  private readonly titles = new Map<string, { title: string; from: number }>();

  // Spelled out, though it does nothing: an implicit constructor is counted as
  // a function that is never called, and this file's function coverage fails its
  // floor on it.
  constructor() {}

  name(client: string, id: string): string {
    const known = this.names.get(id);
    if (known) return known;
    const count = (this.counts.get(client) ?? 0) + 1;
    this.counts.set(client, count);
    const name = `${client} ${count}`;
    this.names.set(id, name);
    if (this.names.size > NAMES_MAX) {
      const oldest = this.names.keys().next().value!;
      this.names.delete(oldest);
      this.titles.delete(oldest);
    }
    return name;
  }

  title(id: string, title: string, from: number = AGENT): void {
    if (!this.names.has(id) || title === "") return;
    const known = this.titles.get(id);
    if (known && known.from > from) return;
    this.titles.set(id, { title, from });
  }

  list(): SessionTitle[] {
    return [...this.names].map(([id, name]) => {
      const title = this.titles.get(id);
      return {
        id: id.slice(0, ID_CHARS),
        name,
        ...(title?.title ? { title: title.title } : {}),
        ...(title && title.from === GUESS ? { guessed: true } : {}),
      };
    });
  }
}
