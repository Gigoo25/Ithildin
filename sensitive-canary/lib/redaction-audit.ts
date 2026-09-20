// Opt-in, synchronous, value-free instrumentation for local synthetic checks.
// No observer is installed in normal operation. Nothing is persisted or sent.
export interface Range { start: number; end: number }
export interface RedactionAudit {
  sourceLength: number;
  detections: Range[];
  replacements: Range[];
  omissions: Range[];
  coordinateSystem: "original" | "cookie-transformed";
}
let observer: ((audit: RedactionAudit) => void) | undefined;
export function reportRedaction(audit: RedactionAudit): void { observer?.(audit); }
export function observeRedactions<T>(fn: (audit: RedactionAudit) => void, work: () => T): T {
  const previous=observer;
  observer=fn;
  try { return work(); } finally { observer=previous; }
}
