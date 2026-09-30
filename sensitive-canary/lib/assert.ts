// TigerStyle: state what must hold, and stop when it does not. A failed
// assertion throws, and every caller fails closed on a throw: the engine
// omits the text, the proxy refuses the request (500, or 502 mid-reply)
// rather than forward what a broken invariant produced. Messages name the
// invariant and never a value: values here may be the secrets being hidden.
export class AssertionFailed extends Error {
  constructor(invariant: string) {
    super(`invariant violated: ${invariant}`);
    this.name = "AssertionFailed";
  }
}

export function assert(condition: unknown, invariant: string): asserts condition {
  if (!condition) throw new AssertionFailed(invariant);
}
