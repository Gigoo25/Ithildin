# TODO

## Measure a Pi session, then decide on dropping old reasoning

Shaping drops old thinking only on Anthropic requests. Chat completions carry
it as `reasoning_content`, `reasoning` or `reasoning_details` on assistant
messages; Responses as `reasoning` items, often with `encrypted_content`.
`shape.ts` touches none of them. Measure before building it.

1. Run a Pi session on an opencode-go model (`/model`), with a real task of
   20+ tool calls, so there are old turns to measure.
2. Save its newest request before 20 others push it out of the dashboard's
   memory:

   ```sh
   id=$(curl -s http://127.0.0.1:18733/dashboard/requests \
     | jq '[.requests[] | select(.route=="opencode-go" and .main)] | max_by(.id).id')
   curl -s "http://127.0.0.1:18733/dashboard/request?id=$id" > /tmp/pi.json
   ```

   Without `jq`: open `/dashboard`, pick the session, save its latest request.
3. Break `/tmp/pi.json` down by part (reasoning fields, results, call inputs,
   tools, system prompt), as was done for a Claude Code request: there, old
   thinking was 41% of the prompt.
4. Check the dashboard's *Cache* group for that session: whether opencode-go
   caches at all decides if a smaller prompt saves money or only prefill.

If reasoning is a large share, build it:

- Chat completions: drop the reasoning fields from assistant messages past the
  cutoff.
- Responses: `reasoning` items are whole list entries, and the walk can only
  replace one, so the walk needs to be able to remove an entry first.
- Both through the step's cost check; keep the current tool loop's reasoning
  (Kimi requires it). Tests per field.

## Watch after deploying 29de40f

- 400s from Anthropic on turns without their thinking. Fallback:
  `ITHILDIN_SHAPE=off`, or `[raw]` in a session.
- Long sessions losing track of decisions made more than 10 turns back.
