// Names for the dashboard's sessions. An agent's session id is a hash, so the
// page shows "claude 2" for the second Claude session this proxy has seen,
// with the id's first characters beside it for the one who needs them.

// Bounds memory across many short sessions. A dropped session that comes back
// gets a new number, so a name never stands for two sessions.
const NAMES_MAX = 1000;

export class SessionNames {
  private readonly names = new Map<string, string>();
  private readonly counts = new Map<string, number>();

  name(client: string, id: string): string {
    const known = this.names.get(id);
    if (known) return known;
    const count = (this.counts.get(client) ?? 0) + 1;
    this.counts.set(client, count);
    const name = `${client} ${count}`;
    this.names.set(id, name);
    if (this.names.size > NAMES_MAX) this.names.delete(this.names.keys().next().value!);
    return name;
  }
}
