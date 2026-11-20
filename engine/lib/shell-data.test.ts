import { describe, expect, it } from "bun:test";
import { heredocBodies, withoutShellData } from "./shell-data.ts";

// What survives blanking, words only.
const kept = (command: string) => withoutShellData(command).split(/\s+/).filter(Boolean);

describe("withoutShellData", () => {
  it("blanks a jq filter, keeps its input file", () => {
    expect(kept(`jq -r '.providers | .key' models.json`)).toEqual(["jq", "-r", "models.json"]);
    expect(kept("jq .key f.json")).toEqual(["jq", "f.json"]);
    expect(kept(`jq --indent 2 '.env' f.json`)).toEqual(["jq", "--indent", "2", "f.json"]);
    // --rawfile's file is read: it stays, only the filter goes.
    expect(kept(`jq --rawfile k id.key '.a' f.json`)).toEqual(
      expect.arrayContaining(["id.key", "f.json"]),
    );
    expect(kept(`jq --rawfile k id.key '.a' f.json`)).not.toContain("'.a'");
  });

  it("blanks an rg or grep pattern, keeps paths and option values", () => {
    expect(kept(String.raw`rg -n 'foo\.key' src`)).toEqual(["rg", "-n", "src"]);
    expect(kept("grep -rn tls.pem config/")).toEqual(["grep", "-rn", "config/"]);
    expect(kept("rg -C 3 x.pem .")).toEqual(["rg", "-C", "3", "."]);
    expect(kept("rg --max-count=1 x.pem .")).toEqual(["rg", "--max-count=1", "."]);
    expect(kept("rg -- -x.pem src")).toEqual(["rg", "--", "src"]);
    expect(kept("sudo env A=1 grep -i x.pem f")).toEqual(["sudo", "env", "A=1", "grep", "-i", "f"]);
    expect(kept("/usr/bin/rg x.pem f")).toEqual(["/usr/bin/rg", "f"]);
  });

  it("keeps everything when the pattern is not certain", () => {
    // An option's value is never mistaken for the pattern: the glob stays.
    expect(kept("rg -g '*.key' foo")).toContain("'*.key'");
    // Unknown option: give up.
    expect(kept("rg --frobnicate x.pem f")).toContain("x.pem");
    // -e/-f/--files make every operand a file, before or after it.
    for (const command of [
      "grep -e foo id.key",
      "grep -rf pats id.key",
      "grep id.key -e foo",
      "rg --regexp=foo id.key",
      "rg --files id.key",
      "jq -f prog.jq id.key",
      "jq --from-file prog.jq id.key",
    ])
      expect(kept(command)).toContain("id.key");
    // The shell runs these: what they read stays checked.
    expect(withoutShellData("rg $(cat id.key) src")).toContain("cat id.key");
    expect(withoutShellData("rg `cat id.key` src")).toContain("cat id.key");
    expect(withoutShellData('rg "$(cat id.key)" src')).toContain("cat id.key");
  });

  it("never blanks awk or sed programs, which open files", () => {
    expect(kept(`awk '{getline l < ".env"}' f`)).toContain(`'{getline`);
    expect(kept("sed 'r id.key' f")).toContain("id.key'");
  });

  it("blanks heredoc text cat or tee only copies", () => {
    const notes = "cat > notes.md <<'EOF'\nkeep .env out of git\nEOF\necho done";
    expect(kept(notes)).toEqual(["cat", ">", "notes.md", "<<'EOF'", "EOF", "echo", "done"]);
    expect(kept("tee out.txt <<EOF\nsee id.key\nEOF")).not.toContain("id.key");
    expect(kept("cat <<-EOF > x\n\tid.key\n\tEOF")).not.toContain("id.key");
    // A stray quote in prose does not hide what follows the body.
    expect(kept("cat > n <<'EOF'\ndon't\nEOF\ncat id.key")).toContain("id.key");
  });

  it("keeps heredoc text anything could run", () => {
    expect(kept("bash <<EOF\ncat id.key\nEOF")).toContain("id.key");
    expect(kept("cat <<EOF | sh\ncat id.key\nEOF")).toContain("id.key");
    expect(kept("cat > /tmp/s <<'EOF'\ncat id.key\nEOF\n/tmp/s")).toContain("id.key");
    expect(kept("python3 - <<EOF\nopen('id.key')\nEOF")).toContain("open('id.key')");
    // Unquoted, the shell expands command substitution in the body.
    expect(kept("cat <<EOF > out\n$(cat id.key)\nEOF")).toContain("id.key)");
    expect(kept("cat <<'EOF' > out\n$(cat id.key)\nEOF")).not.toContain("id.key)");
  });

  it("keeps the command's length and lines", () => {
    const command = "jq '.key' a.json\ncat <<'EOF'\nid.key\nEOF";
    const out = withoutShellData(command);
    expect(out.length).toBe(command.length);
    expect(out.split("\n").length).toBe(command.split("\n").length);
    expect(withoutShellData("echo hi")).toBe("echo hi");
  });

  it("reads separators and redirections, not quoted ones", () => {
    expect(kept("rg 'a|b.pem' f 2>&1 | head")).toEqual(["rg", "f", "2>&1", "|", "head"]);
    expect(kept("rg x.pem f &> log; cat id.key")).toContain("id.key");
    expect(kept("rg -n x < id.key")).toContain("id.key");
  });
});

describe("heredocBodies", () => {
  it("finds each body, stacked and unterminated", () => {
    const command = "cat <<A <<'B'\none\nA\ntwo\nB\ncat <<C\nthree";
    const bodies = heredocBodies(command).map(({ body }) => command.slice(...body));
    expect(bodies).toEqual(["one\n", "two\n", "three"]);
    expect(heredocBodies("echo a<<<b")).toEqual([]);
  });
});
