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
}

const ID_CHARS = 8;

export class SessionNames {
  private readonly names = new Map<string, string>();
  private readonly counts = new Map<string, number>();
  // A session's title, from its agent's traffic (titles.ts), and whether the
  // user gave it: a model's title never replaces the user's.
  private readonly titles = new Map<string, { title: string; user: boolean }>();

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

  title(id: string, title: string, user: boolean): void {
    if (!this.names.has(id) || (this.titles.get(id)?.user && !user)) return;
    this.titles.set(id, { title, user });
  }

  list(): SessionTitle[] {
    return [...this.names].map(([id, name]) => {
      const title = this.titles.get(id)?.title;
      return { id: id.slice(0, ID_CHARS), name, ...(title ? { title } : {}) };
    });
  }
}
