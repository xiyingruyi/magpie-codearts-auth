export const meta = {
  name: 'codearts-round4',
  description: 'Fourth-round verification: tool calls, long context, errors, usage, multi-account, sign-in flow',
  phases: [
    { title: 'Probe', detail: 'six probes, each a fresh angle not covered before' },
  ],
}

const GW = 'http://127.0.0.1:3425'
const SRC = '/Users/wangxin/code/magpie-codearts-auth/index.mjs'
const PRE = [
  'Live verification of a magpie gateway at ' + GW + ' serving the codearts (Huawei CodeArts) provider.',
  'Plugin source: ' + SRC + ' (v0.2.9). Host: /Users/wangxin/.cache/magpie/plugin-host/host-448c7c8917b1.js.',
  'Use Bash + curl. Do NOT modify any file under /Users/wangxin/code or ~/.config/magpie.',
  'Never print a credential. Mask anything that looks like an AK/SK.',
  'Report exactly what you observed. If a probe cannot run, say so — never claim an unobserved pass.',
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

phase('Probe')
const results = await parallel([
  () => agent(PRE + `

PROBE A — tool calling (never tested before).
Send a non-stream request to codearts/deepseek-v4.1-flash with TWO tool definitions
(get_weather with a city param, get_time with a timezone param) and the prompt
"What is the weather in Beijing? Use the tool." with tool_choice auto.
A pass = the response has choices[0].message.tool_calls non-empty with a well-formed
function name and a JSON arguments string.
Then do the same with "stream": true and check that tool_calls arrive in the deltas.
An HTTP 200 with no tool_calls while the model was clearly asked to call one is a FAIL.
Report the raw tool_calls shape you got.`, { label: 'probe:tools', schema: FINDINGS }),

  () => agent(PRE + `

PROBE B — usage / quota accounting correctness against the plugin source.
1. Read /Users/wangxin/code/magpie-codearts-auth/index.mjs, the usage() function.
2. Run: /Applications/magpie.app/Contents/MacOS/magpie quota --json 2>/dev/null | python3 -c '...'
   to dump the codearts entries and check each window: used must equal round(amount/limit*100, 1),
   amount <= limit, used >= 0, no NaN/Infinity/negative.
3. Also check the balance string is "<n> tokens" and not a percentage.
4. Make 3 chat requests and re-read quota; verify amount increased (the numbers track real usage).
Report any inconsistency between used/amount/limit, or a value that would render wrongly.`,
    { label: 'probe:usage', schema: FINDINGS }),

  () => agent(PRE + `

PROBE C — long context and truncation behaviour.
1. Send a request to codearts/deepseek-v4.1-flash whose prompt is ~30000 tokens
   (build it by repeating a filler sentence; use python to generate the JSON body).
   A pass = HTTP 200 with real content — this proves context_window 1048576 is honoured
   and the request is not silently truncated to a small window.
2. Send a request with a prompt of ~200 chars and max_tokens=1: check the response is a
   clean truncation (finish_reason "length", no error) rather than an empty body.
3. Report the token counts the gateway reports for each.
Report any silent truncation, empty body, or error.`,
    { label: 'probe:context', schema: FINDINGS }),

  () => agent(PRE + `

PROBE D — error handling and classification.
These must NOT be misclassified as "quota used up" — that was the original bug, where
most errors went through magpie's usedUpWords regex.
1. Send a request with an unknown model: model "codearts/does-not-exist". Report the HTTP status
   and whether the error body mentions quota.
2. Send a malformed JSON body. Report status and body.
3. Send a request with an empty messages array.
4. Then run: /Applications/magpie.app/Contents/MacOS/magpie quota and check that the codearts
   accounts are NOT marked as rested / out of quota after these failures
   (they should still show a normal 每日免费 Token window).
Report any error that got classified as quota exhaustion, and any account that went into rest.`,
    { label: 'probe:errors', schema: FINDINGS }),

  () => agent(PRE + `

PROBE E — multi-account routing and channel correctness.
There are two codearts accounts (…1XCY and …BJ0C). The plugin routes by model channel
(benefit vs agent/AgentCenter).
1. For each of the 7 models, send one tiny request and record: HTTP status, whether content
   came back, and which upstream model id the response reports.
   Models: glm-5.3-flash, deepseek-v4-pro-0813, deepseek-v4-flash-0731, deepseek-v4.1-flash,
   openpangu-2.0-pro, openpangu-2.0-flash, GLM-5.2.
2. The "agent channel" models (openpangu-*, GLM-5.2) must NOT receive the maas_type/model-id/
   model-name headers — a wrong channel shows up as an upstream "unsupported model" error.
   So: any model returning such an error is a FAIL.
3. Report each model's outcome. Note which ones fail and with what exact upstream message.`,
    { label: 'probe:channels', schema: FINDINGS }),

  () => agent(PRE + `

PROBE F — sign-in flow and credential storage (read-only inspection).
1. Run: /Applications/magpie.app/Contents/MacOS/magpie plugin login --help and report whether a
   non-interactive check is possible WITHOUT going through with a login (do NOT actually
   sign in; do not type any credential).
2. Read /Users/wangxin/code/magpie-codearts-auth/index.mjs authorize(): confirm that it
   only reads inputs.credential, validates both parts, verifies via the balance endpoint,
   and returns {type:"success", key, metadata:{sk}}.
3. Read /Users/wangxin/.config/magpie/plugin-auth.json with python and report, for the two
   codearts entries ONLY: the set of metadata keys and their types (never their values),
   and whether the full "AK:SK" combined string is stored anywhere (search for a ':' in any
   metadata value of those entries) — report only yes/no and the key name.
4. Check the file mode of plugin-auth.json.
Report any place a secret is stored redundantly or with loose permissions.`,
    { label: 'probe:signin', schema: FINDINGS }),
])

const all = results.filter(Boolean).flatMap((r) => r.findings ?? [])
log('round-4 returned ' + all.length + ' observations')
return {
  pass: all.filter((f) => f.verdict === 'pass').length,
  fail: all.filter((f) => f.verdict === 'fail').length,
  inconclusive: all.filter((f) => f.verdict === 'inconclusive').length,
  failures: all.filter((f) => f.verdict === 'fail'),
  all,
}
