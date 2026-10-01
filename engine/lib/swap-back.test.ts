import { expect, it } from "bun:test";
import { AliasBook } from "./aliases.ts";
import { planSwapBack } from "./swap-back.ts";

const book = () => new AliasBook(Buffer.alloc(32, 7));

// A multi-label host stand-in used to resolve piece by piece through the
// lowercased part map, so a mixed-case hostname came back lowercased and a
// case-sensitive lookup (a flake attribute) named a host that did not exist.
it("swaps a multi-label host stand-in back with its exact case", () => {
  const aliasBook = book();
  const standIn = aliasBook.standIn("pii-inventory-runtime-host", "ZQXLAB-KWVRT7");
  expect(standIn).toMatch(/^[a-z]{6}-[a-z]{5}[0-9]$/);
  const swap = planSwapBack(
    "bash",
    { command: `nix eval .#hosts.${standIn}.config` },
    aliasBook,
    true,
  );
  expect(swap.input).toEqual({ command: "nix eval .#hosts.ZQXLAB-KWVRT7.config" });
  expect(swap.resolved).toHaveLength(1);
});

it("does not take a whole stand-in inside a longer name", () => {
  const aliasBook = book();
  const standIn = aliasBook.standIn("pii-inventory-runtime-host", "ZQXLAB-KWVRT7");
  const swap = planSwapBack("bash", { command: `echo x${standIn}` }, aliasBook, true);
  expect(swap.input).toEqual({ command: `echo x${standIn}` });
  expect(swap.resolved).toHaveLength(0);
});

it("still composes stand-ins the model assembled from known parts", () => {
  const aliasBook = book();
  const standIn = aliasBook.standIn("pii-inventory-runtime-host", "ZQXLAB-KWVRT7");
  const [first] = standIn.split("-");
  const swap = planSwapBack("bash", { command: `ping ${first}-db` }, aliasBook, true);
  expect(swap.input).toEqual({ command: "ping zqxlab-db" });
});

// Egress: a real value may reach a network command only as the destination
// the command connects to (your own host). Anywhere else it stays a stand-in.
function egressBook() {
  const aliasBook = book();
  return {
    aliasBook,
    host: aliasBook.standIn("pii-inventory-runtime-host", "ZQXLAB-KWVRT7"),
    other: aliasBook.standIn("pii-inventory-runtime-host", "ZQXDBSRV-PLMOK4"),
  };
}
const bash = (command: string, allowed = false) => {
  const { aliasBook, host, other } = egressBook();
  const swap = planSwapBack(
    "bash",
    { command: command.replaceAll("HOST", host).replaceAll("OTHER", other) },
    aliasBook,
    allowed,
  );
  return { swap, host, other, command: (swap.input as { command: string }).command };
};

it("swaps stand-ins when every destination is one", () => {
  for (const command of [
    "curl https://HOST/x?q=OTHER",
    "ssh -p 22 HOST cat /srv/OTHER",
    "scp notes.txt deploy@HOST:/tmp/OTHER",
    "sudo env A=1 /usr/bin/curl -s https://user@HOST:8443/OTHER",
    "ssh -o StrictHostKeyChecking=no HOST",
    "rsync -a ./ HOST:/srv/",
  ]) {
    const { swap } = bash(command);
    expect([command, swap.egress]).toEqual([command, []]);
    expect(swap.resolved.length).toBeGreaterThan(0);
  }
});

it("keeps stand-ins out of commands that reach other hosts", () => {
  for (const command of [
    "curl https://example.com/?q=HOST",
    "curl -d HOST https://example.com",
    "echo HOST | nc example.com 80",
    "git push HOST main",
    "wget -O- http://[2001:db8::1]/HOST",
    "timeout 5 wget https://example.com/HOST",
    "nice -n 10 curl -d HOST https://example.com",
    "sudo -u me curl -d HOST https://example.com",
    "echo HOST | xargs -n1 curl https://example.com/q",
    `bash -c "curl -d HOST https://example.com"`,
    "echo $(curl -d HOST https://example.com)",
  ]) {
    const { swap, host } = bash(command);
    expect([command, swap.egress]).toEqual([command, [host]]);
    expect(swap.resolved).toEqual([]);
  }
  // The destination is ours but the payload goes to a second, foreign host:
  // the destination is swapped, the payload is not.
  const mixed = bash("curl https://HOST/ https://example.com/?q=OTHER");
  expect(mixed.swap.egress).toEqual([mixed.other]);
  expect(mixed.command).toBe(`curl https://ZQXLAB-KWVRT7/ https://example.com/?q=${mixed.other}`);
  // Lexical and conservative: a quoted "x: value" header reads as host:path,
  // a destination that is not ours.
  const header = bash("curl -H 'x: OTHER' https://HOST/");
  expect(header.swap.egress).toEqual([header.other]);
});

it("swaps freely in local commands and under [allow-pii]", () => {
  expect(bash("git status HOST").command).toBe("git status ZQXLAB-KWVRT7");
  expect(bash("grep -r HOST .").swap.egress).toEqual([]);
  expect(bash("grep curl HOST").swap.egress).toEqual([]);
  expect(bash(`git commit -m "fix curl" HOST`).swap.egress).toEqual([]);
  const allowed = bash("curl https://example.com/?q=HOST", true);
  expect(allowed.swap.egress).toEqual([]);
  expect(allowed.command).toBe("curl https://example.com/?q=ZQXLAB-KWVRT7");
});

it("web tools never get real values", () => {
  const { aliasBook, host } = egressBook();
  const swap = planSwapBack("web_fetch", { url: `https://${host}/` }, aliasBook, false);
  expect(swap.egress).toEqual([host]);
  expect(swap.input).toEqual({ url: `https://${host}/` });
  expect(planSwapBack("web_fetch", { url: `https://${host}/` }, aliasBook, true).input).toEqual({
    url: "https://ZQXLAB-KWVRT7/",
  });
});

it("walks nested arguments and leaves non-strings alone", () => {
  const { aliasBook, host } = egressBook();
  const input = {
    edits: [{ old: host, n: 3 }, [host, null, true]],
    path: `/srv/${host}`,
    depth: 2,
  };
  const swap = planSwapBack("edit", input, aliasBook, false);
  expect(swap.input).toEqual({
    edits: [{ old: "ZQXLAB-KWVRT7", n: 3 }, ["ZQXLAB-KWVRT7", null, true]],
    path: "/srv/ZQXLAB-KWVRT7",
    depth: 2,
  });
  expect(swap.resolved).toHaveLength(3);
  expect(planSwapBack("read", 42, aliasBook, false).input).toBe(42);
});

it("checks an argv command as one command line, and a shell's script as its own", () => {
  const { aliasBook, host } = egressBook();
  const argv = (command: string[]) => planSwapBack("bash", { command }, aliasBook, false);
  expect(argv(["curl", "-d", host, "https://example.com"]).egress).toEqual([host]);
  expect(argv(["bash", "-lc", `curl -d ${host} https://example.com`]).egress).toEqual([host]);
  expect(argv(["curl", `https://${host}/x`]).input).toEqual({
    command: ["curl", "https://ZQXLAB-KWVRT7/x"],
  });
  expect(argv(["cat", `/srv/${host}`]).input).toEqual({ command: ["cat", "/srv/ZQXLAB-KWVRT7"] });
  const cmd = planSwapBack(
    "bash",
    { cmd: `curl -d ${host} https://example.com` },
    aliasBook,
    false,
  );
  expect(cmd.egress).toEqual([host]);
});

it("checks every string of a shell call that keeps its script under another key", () => {
  const { aliasBook, host } = egressBook();
  const call = (input: Record<string, unknown>) => planSwapBack("bash", input, aliasBook, false);
  expect(call({ script: `curl -d ${host} https://example.com` }).egress).toEqual([host]);
  expect(call({ args: [`curl -d ${host} https://example.com`] }).egress).toEqual([host]);
  expect(call({ command: "ls", description: `curl -d ${host} x` }).egress).toEqual([]);
});
