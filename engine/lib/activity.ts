// What redaction and swap-back did, for the local dashboard (proxy/src/events.ts).
// Opt-in and synchronous, like redaction-audit.ts: no observer is installed in
// normal operation, and nothing is persisted or sent from here.
//
// Unlike redaction-audit.ts, an event carries the real value, because the
// observer has to shorten it to a preview. An observer must not keep it.
export type ActivityEvent =
  // A value was replaced in a request.
  | { type: "masked"; ruleId: string; category: string; value: string; standIn: string }
  // A stand-in the model wrote was given its real value back. `tool` is the
  // tool the call names, or REPLY_TEXT for reply text.
  | { type: "swapped"; ruleId: string; value: string; standIn: string; tool: string }
  // A guard stopped a tool call. The notice names no values. `call` is the
  // call's id, for the dashboard to find it in the conversation.
  | { type: "blocked"; notice: string; call?: string }
  // Text sent as an "[ithildin: omitted …]" marker instead of itself: its scan
  // ran out of time, or it is over the scan limit. `chars` is how much.
  | { type: "withheld"; chars: number };

// The tool name swap-back is given for reply text, which is no tool call.
export const REPLY_TEXT = "reply-text";

let observer: ((event: ActivityEvent) => void) | undefined;

export function reportActivity(event: ActivityEvent): void {
  observer?.(event);
}

// The events `work` reports, which still reach whatever observer is installed.
// For redactText to keep with a result it reuses (core.ts): the values stay in
// memory only, as the text they came from does.
export function recordActivity<T>(work: () => T): { result: T; events: ActivityEvent[] } {
  const previous = observer;
  const events: ActivityEvent[] = [];
  observer = (event) => {
    events.push(event);
    previous?.(event);
  };
  try {
    return { result: work(), events };
  } finally {
    observer = previous;
  }
}

export function observeActivity<T>(fn: (event: ActivityEvent) => void, work: () => T): T {
  const previous = observer;
  observer = fn;
  try {
    return work();
  } finally {
    observer = previous;
  }
}
