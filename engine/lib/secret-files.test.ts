import { describe, expect, it } from "bun:test";
import { isDotenvFile, isSecretFile } from "./secret-files.ts";

describe("isSecretFile", () => {
  it("keeps the existing dotenv class and adds sibling spellings", () => {
    expect(isSecretFile(".env")).toBe(true);
    expect(isSecretFile(".env.local")).toBe(true);
    expect(isSecretFile(".env.production")).toBe(true);
    expect(isSecretFile("config/.env")).toBe(true);
    expect(isSecretFile(".env:img")).toBe(true);
    expect(isSecretFile("prod.env")).toBe(true);
    expect(isSecretFile("staging.env")).toBe(true);
    expect(isSecretFile(".env.example")).toBe(false);
    expect(isSecretFile("foo.env.example")).toBe(false);
  });

  it("blocks private key and credential filenames, not public keys", () => {
    expect(isSecretFile("id_rsa")).toBe(true);
    expect(isSecretFile("secrets/id_rsa")).toBe(true);
    expect(isSecretFile(".ssh/id_ed25519")).toBe(true);
    expect(isSecretFile("id_ed25519_sk")).toBe(true);
    expect(isSecretFile("id_rsa.pub")).toBe(false);
    expect(isSecretFile("id_ed25519.pub")).toBe(false);
    expect(isSecretFile("tls.pem")).toBe(true);
    expect(isSecretFile("tls.p12")).toBe(true);
    expect(isSecretFile("tls.pfx")).toBe(true);
    expect(isSecretFile("service.key")).toBe(true);
    expect(isSecretFile("app.keystore")).toBe(true);
  });

  it("blocks well-known credential path suffixes", () => {
    expect(isSecretFile(".netrc")).toBe(true);
    expect(isSecretFile(".npmrc")).toBe(true);
    expect(isSecretFile(".pypirc")).toBe(true);
    expect(isSecretFile("credentials.json")).toBe(true);
    expect(isSecretFile("kubeconfig")).toBe(true);
    expect(isSecretFile(".kube/config")).toBe(true);
    expect(isSecretFile(".config/gh/hosts.yml")).toBe(true);
    expect(isSecretFile(".config/gh/hosts.yaml")).toBe(true);
    expect(isSecretFile(".config/gcloud/application_default_credentials.json")).toBe(true);
    expect(isSecretFile(".docker/config.json")).toBe(true);
    // Root-level relative spellings carry no leading separator; they must
    // still match the same credential paths as "./" and nested spellings.
    expect(isSecretFile("application_default_credentials.json")).toBe(true);
    expect(isSecretFile("kube/config")).toBe(true);
    expect(isSecretFile("gh/hosts.yml")).toBe(true);
    expect(isSecretFile("gh/hosts.yaml")).toBe(true);
    expect(isSecretFile("docker/config.json")).toBe(true);
    expect(isSecretFile("hosts.yml")).toBe(false);
    expect(isSecretFile("src/config.json")).toBe(false);
    expect(isDotenvFile(".env.local")).toBe(true);
    expect(isDotenvFile("prod.env")).toBe(true);
    expect(isDotenvFile("id_rsa")).toBe(false);
  });

  it("accepts empty and ordinary paths", () => {
    expect(isSecretFile("")).toBe(false);
    expect(isSecretFile("README.md")).toBe(false);
    expect(isSecretFile("src/index.ts")).toBe(false);
  });
});
