// Shared CLI plumbing: a small report model (rendered as text or JSON), input reading,
// certificate summaries and fetch. Node-only; never imported by the plugin itself.
import { X509Certificate } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";

export type Status = "pass" | "warn" | "fail" | "info";

export class UsageError extends Error {}

export interface Field {
  label: string;
  value: string;
}

export interface Section {
  title: string;
  fields: Field[];
}

export interface Check {
  status: Status;
  message: string;
}

/** What every command produces: sections of facts, a list of checks, and optional raw data. */
export class Report {
  readonly sections: Section[] = [];
  readonly checks: Check[] = [];
  data: Record<string, unknown> = {};
  /** Printed verbatim after the report in text mode (e.g. a URL or a config snippet). */
  output: string | undefined;

  section(title: string, fields: Record<string, string | number | boolean | undefined | null>): void {
    const list: Field[] = [];
    for (const [label, v] of Object.entries(fields)) if (v !== undefined && v !== null && v !== "") list.push({ label, value: String(v) });
    this.sections.push({ title, fields: list });
  }

  check(status: Status, message: string): void {
    this.checks.push({ status, message });
  }

  pass(message: string): void {
    this.check("pass", message);
  }
  warn(message: string): void {
    this.check("warn", message);
  }
  fail(message: string): void {
    this.check("fail", message);
  }
  info(message: string): void {
    this.check("info", message);
  }

  get failed(): boolean {
    return this.checks.some((c) => c.status === "fail");
  }
}

const useColor = () => process.stdout.isTTY === true && !process.env.NO_COLOR;
const paint = (code: string, s: string) => (useColor() ? `\u001b[${code}m${s}\u001b[0m` : s);
export const bold = (s: string) => paint("1", s);
export const dim = (s: string) => paint("2", s);
const ICON: Record<Status, string> = { pass: "32m✓", warn: "33m!", fail: "31m✗", info: "36mi" };
const icon = (s: Status) => (useColor() ? `\u001b[${ICON[s]}\u001b[0m` : ICON[s].slice(3));

export function render(report: Report, json: boolean): string {
  if (json)
    return JSON.stringify(
      { ok: !report.failed, sections: report.sections, checks: report.checks, data: report.data, output: report.output },
      null,
      2,
    );
  const lines: string[] = [];
  for (const s of report.sections) {
    lines.push(bold(s.title));
    const width = Math.max(0, ...s.fields.map((f) => f.label.length));
    for (const f of s.fields) {
      const [first, ...rest] = f.value.split("\n");
      lines.push(`  ${dim(f.label.padEnd(width))}  ${first}`);
      for (const r of rest) lines.push(`  ${" ".repeat(width)}  ${r}`);
    }
    lines.push("");
  }
  if (report.checks.length) {
    lines.push(bold("Checks"));
    for (const c of report.checks) lines.push(`  ${icon(c.status)} ${c.message}`);
    lines.push("");
  }
  if (report.output !== undefined) lines.push(report.output);
  return lines.join("\n").replace(/\n+$/, "\n");
}

/** Read an argument that may be "-" (stdin), a file path, or the literal value. */
export async function readInput(arg: string | undefined): Promise<string> {
  if (arg === undefined || arg === "-") {
    if (process.stdin.isTTY) throw new UsageError("no input: pass it as an argument, a file path, or on stdin");
    const chunks: Buffer[] = [];
    for await (const c of process.stdin) chunks.push(c as Buffer);
    return Buffer.concat(chunks).toString("utf8");
  }
  if (arg.length < 4096 && !arg.includes("\n") && existsSync(arg)) return readFileSync(arg, "utf8");
  return arg;
}

export function readFileArg(path: string, what: string): string {
  try {
    return readFileSync(path, "utf8");
  } catch (e) {
    throw new UsageError(`cannot read ${what} ${path}: ${(e as Error).message}`);
  }
}

/** Every PEM CERTIFICATE block in a string. */
export function pemCertificates(text: string): string[] {
  return text.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g)?.map((b) => `${b}\n`) ?? [];
}

export function certFromBase64(b64: string): string {
  const body = b64.replace(/\s+/g, "");
  return `-----BEGIN CERTIFICATE-----\n${(body.match(/.{1,64}/g) ?? []).join("\n")}\n-----END CERTIFICATE-----\n`;
}

export interface CertSummary {
  subject: string;
  issuer: string;
  notBefore: string;
  notAfter: string;
  daysLeft: number;
  keyType: string;
  keyBits: number | undefined;
  sha256: string;
  selfSigned: boolean;
}

export function certSummary(pem: string, now = new Date()): CertSummary {
  const c = new X509Certificate(pem);
  const details = c.publicKey.asymmetricKeyDetails;
  return {
    subject: c.subject.replace(/\n/g, ", "),
    issuer: c.issuer.replace(/\n/g, ", "),
    notBefore: new Date(c.validFrom).toISOString(),
    notAfter: new Date(c.validTo).toISOString(),
    daysLeft: Math.floor((new Date(c.validTo).getTime() - now.getTime()) / 86_400_000),
    keyType: c.publicKey.asymmetricKeyType ?? "unknown",
    keyBits: details?.modulusLength,
    sha256: c.fingerprint256,
    selfSigned: c.checkIssued(c),
  };
}

export function describeCert(s: CertSummary): string {
  const key = s.keyBits ? `${s.keyType.toUpperCase()} ${s.keyBits}` : s.keyType;
  return `${s.subject}\n${key}, expires ${s.notAfter.slice(0, 10)} (${s.daysLeft} days)\nSHA-256 ${s.sha256}`;
}

/** Standard certificate checks, shared by inspect and check-config. */
export function checkCert(report: Report, label: string, s: CertSummary): void {
  if (s.daysLeft < 0) report.fail(`${label}: expired ${-s.daysLeft} days ago`);
  else if (s.daysLeft <= 30) report.warn(`${label}: expires in ${s.daysLeft} days; plan a rotation (docs/key-rotation.md)`);
  else report.pass(`${label}: valid for ${s.daysLeft} more days`);
  if (s.keyType !== "rsa") report.fail(`${label}: ${s.keyType} key; SAML SPs expect RSA`);
  else if ((s.keyBits ?? 0) < 2048) report.fail(`${label}: RSA ${s.keyBits} bits is too small (minimum 2048)`);
}

export async function fetchText(url: string, init: RequestInit = {}): Promise<{ res: Response; text: string }> {
  let res: Response;
  try {
    res = await fetch(url, { redirect: "manual", signal: AbortSignal.timeout(15_000), ...init });
  } catch (e) {
    const cause = (e as { cause?: Error }).cause;
    throw new UsageError(`cannot fetch ${url}: ${cause?.message ?? (e as Error).message}`);
  }
  return { res, text: await res.text() };
}

export function httpsOnly(url: string, allowHttp: boolean): URL {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    throw new UsageError(`not a URL: ${url}`);
  }
  if (u.protocol !== "https:" && !(allowHttp && u.protocol === "http:"))
    throw new UsageError(`${url}: use https (or pass --allow-http for a local server)`);
  return u;
}

export const since = (d: Date, now = new Date()): string => {
  const s = Math.round((now.getTime() - d.getTime()) / 1000);
  const abs = Math.abs(s);
  const text = abs < 90 ? `${abs}s` : abs < 5400 ? `${Math.round(abs / 60)}m` : abs < 172_800 ? `${Math.round(abs / 3600)}h` : `${Math.round(abs / 86400)}d`;
  return s >= 0 ? `${text} ago` : `in ${text}`;
};
