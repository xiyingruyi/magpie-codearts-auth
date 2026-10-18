export const meta = {
  name: 'codearts-live-verify',
  description: 'Live multi-round verification of magpie-codearts-auth 0.2.7 through the running gateway',
  phases: [
    { title: 'Verify', detail: 'five independent live probes against the running magpie gateway' },
  ],
}

const GW = 'http://127.0.0.1:3425'
const PRE = [
  'You are verifying a live magpie gateway at ' + GW + ' serving the codearts (Huawei CodeArts) provider.',
  'The plugin source is /Users/wangxin/code/magpie-codearts-auth/index.mjs (v0.2.7).',
  'Use Bash with curl. Do NOT modify any files. Do NOT print any credential (mask anything that looks like an AK/SK).',
  'Report what you actually observed: exact HTTP status, and whether the body had real content.',
  'If a probe fails, report the failure — do not claim success you did not see.',
].join('\n')

const FINDINGS = {
  type: 'object',
  properties: {
    findings: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          title: { type: 'string' },
          observed: { type: 'string' },
          verdict: { type: 'string', enum: ['pass', 'fail', 'inconclusive'] },
          severity: { type: 'string', enum: ['high', 'medium', 'low', 'none'] },
          detail: { type: 'string' },
        },
        required: ['title', 'observed', 'verdict', 'severity', 'detail'],
      },
    },
  },
  required: ['findings'],
}

phase('Verify')
const results = await parallel([
  () => agent(PRE + `

PROBE 1 — model catalogue correctness.
1. GET ${GW}/v1/models and list every codearts model with context_window and max_output_tokens.
2. For every codearts model: max_output_tokens MUST be <= 65536. Anything above is a defect
   (the upstream rejects max_tokens > 65536 and magpie wraps the 400 into an empty HTTP 200 stream).
3. Check the routing groups that CONTAIN a codearts model (GET ${GW}/v1/models, ids starting with group/)
   and whether their max_output_tokens is also <= 65536 if all their members are codearts.
4. Report a finding for each model/group over 65536.`, { label: 'probe:catalogue', schema: FINDINGS }),

  () => agent(PRE + `

PROBE 2 — chat across every benefit model, streaming and non-streaming.
For EACH of these models send a tiny non-stream request with max_tokens 32 and model prefix codearts/:
  codearts/glm-5.3-flash, codearts/deepseek-v4-pro-0813, codearts/deepseek-v4-flash-0731, codearts/deepseek-v4.1-flash
Then do the same with "stream": true for two of them.
A pass = HTTP 200 AND choices[0].message.content or reasoning_content is non-empty
(or for streaming, at least one data: chunk with a delta).
An HTTP 200 with an empty message and a content-less body is a FAIL — report it.`,
    { label: 'probe:chat', schema: FINDINGS }),

  () => agent(PRE + `

PROBE 3 — the agent-facing routing groups.
The user actually runs the agents on group/v4-pro-v4.1-flash.
1. Send a request to model group/v4-pro-v4.1-flash with max_tokens 393216 (the old, too-high value)
   and a simple prompt. A pass = HTTP 200 with non-empty content.
2. Send the same with max_tokens 65536.
3. Send the same with NO max_tokens at all.
Report all three outcomes. An empty body is a FAIL.`,
    { label: 'probe:groups', schema: FINDINGS }),

  () => agent(PRE + `

PROBE 4 — concurrency (the original bug).
Fire 8 simultaneous streaming requests (curl with & and wait) to codearts/deepseek-v4.1-flash,
each with max_tokens 64 and "stream": true.
Count how many return HTTP 200 and how many return 400 with TM.00001041 (并发会话数已达上限).
Zero TM.00001041 is a pass. Then read the last 200 lines of
/Users/wangxin/.config/magpie/routing/2026-10-19.jsonl and report whether any codearts request
in the last 10 minutes has fail quota / status 400.
Do NOT report a pass if you did not actually run 8 concurrent requests.`,
    { label: 'probe:concurrency', schema: FINDINGS }),

  () => agent(PRE + `

PROBE 5 — quota and credential hygiene.
1. Run: /Applications/magpie.app/Contents/MacOS/magpie quota and report only the codearts lines.
   Check: the 每日免费 Token window shows a percentage consistent with amount/limit,
   and the balance line is a token count (NOT a percentage > 100 or a negative number).
2. Run: /Applications/magpie.app/Contents/MacOS/magpie plugin list and confirm exactly ONE
   codearts plugin entry and that its version is 0.2.7.
3. Check /Users/wangxin/.config/magpie/plugin-auth.json: confirm there is exactly one codearts
   account per real account (two entries total) and that any stored 'credential' metadata field
   does not appear more than once per account. Report keys and types only — never the values.
4. Report any place where an AK/SK appears in plaintext in a tool output you can see
   (do not paste it; just say where).`,
    { label: 'probe:quota', schema: FINDINGS }),
])

const all = results.filter(Boolean).flatMap((r) => r.findings ?? [])
log('probes returned ' + all.length + ' observations')
return {
  pass: all.filter((f) => f.verdict === 'pass').length,
  fail: all.filter((f) => f.verdict === 'fail').length,
  inconclusive: all.filter((f) => f.verdict === 'inconclusive').length,
  failures: all.filter((f) => f.verdict === 'fail'),
  all,
}
