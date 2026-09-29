// Closed list of files whose contents are treated as secrets even when the
// values have no detectable shape. Callers expand shell spellings first
// (variables, braces, globs; see commandPathCandidates in index.ts). Computed
// names (base64, $(...) output) stay out of scope, same as the inventory guard.

const SECRET_BASENAMES = new Set([
  ".env",
  ".netrc",
  ".npmrc",
  ".pypirc",
  "credentials.json",
  "kubeconfig",
]);

const SSH_PRIVATE_KEY = /^id_(?:rsa|ed25519|ecdsa|dsa)(?:_[a-z0-9_-]+)?$/i;
const SECRET_SUFFIX = /\.(?:pem|p12|pfx|key|keystore)$/i;
const ENV_EXAMPLE = /^\.env\.example$/i;
const ENV_EXAMPLE_SUFFIX = /\.env\.example$/i;

function candidates(filePath: string): string[] {
  return filePath.split(/[?:]/).filter(Boolean);
}

function basename(posixPath: string): string {
  const parts = posixPath.split("/");
  return parts[parts.length - 1] ?? "";
}

function isEnvExample(name: string): boolean {
  return ENV_EXAMPLE.test(name) || ENV_EXAMPLE_SUFFIX.test(name);
}

function isDotenvName(base: string): boolean {
  if (!base || isEnvExample(base)) return false;
  const lower = base.toLowerCase();
  return lower === ".env" || lower.startsWith(".env.") || /\.env$/i.test(base);
}

export function isDotenvFile(filePath: string): boolean {
  if (!filePath) return false;
  return candidates(filePath).some((candidate) =>
    isDotenvName(basename(candidate.replace(/\\/g, "/"))),
  );
}

export function isSecretFile(filePath: string): boolean {
  if (!filePath) return false;
  return candidates(filePath).some((candidate) => {
    const normalized = candidate.replace(/\\/g, "/");
    const base = basename(normalized);
    if (!base || isEnvExample(base)) return false;
    if (base.toLowerCase().endsWith(".pub")) return false;
    if (isDotenvName(base)) return true;
    const lower = base.toLowerCase();
    if (SECRET_BASENAMES.has(lower)) return true;
    if (SSH_PRIVATE_KEY.test(base)) return true;
    if (SECRET_SUFFIX.test(base)) return true;
    // Prefix a separator so root-level relative spellings match the suffix
    // rules below ("kube/config", not just "x/kube/config" or "/kube/config").
    const pathLower = `/${normalized}`.toLowerCase();
    if (pathLower.endsWith("/application_default_credentials.json")) return true;
    if (pathLower.endsWith("/gh/hosts.yml") || pathLower.endsWith("/gh/hosts.yaml")) return true;
    if (/(?:^|\/)\.kube\/config$/.test(pathLower) || pathLower.endsWith("/kube/config")) return true;
    if (/(?:^|\/)\.docker\/config\.json$/.test(pathLower) || pathLower.endsWith("/docker/config.json")) return true;
    return false;
  });
}
