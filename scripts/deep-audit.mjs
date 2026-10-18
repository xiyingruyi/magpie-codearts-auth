export const meta = {
  name: 'codearts-deep-audit',
  description: 'Fresh-lens audit of the finalized magpie-codearts-auth plugin',
  phases: [
    { title: 'Find', detail: 'five independent reviewers, one specific technical lens each' },
    { title: 'Verify', detail: 'two skeptics try to refute each finding against host + reference source' },
  ],
}

const PLUGIN = '/Users/wangxin/code/magpie-codearts-auth/index.mjs'
const TESTS = '/Users/wangxin/code/magpie-codearts-auth/tests/index.test.mjs'
const HOST = '/Users/wangxin/.cache/magpie/plugin-host/host-448c7c8917b1.js'
const HOSTSRC = '/private/tmp/magpie_tag_src/magpie-0.1.1267'

const PRE = [
  'You are auditing ' + PLUGIN + ', a magpie provider plugin for Huawei Cloud CodeArts.',
  'Read ' + PLUGIN + ' and ' + TESTS + ' in full. The host contract is in ' + HOST + ' (the live',
  'Bun host.js) and Go source under ' + HOSTSRC + '/internal/provider (and plugin, gateway) —',
  'read those to verify any claim about what the host does; do not assume.',
  '',
  'For Huawei SDK signing, also consult the reference implementation the plugin is based on:',
  'github.com/Johnsheng1/codearts2api (Python benefit.py) and cnb.cool/itq5/codearts2api (Go).',
  'If you cannot fetch them, reason from the AWS SigV4 / Huawei Cloud SDK-HMAC-SHA256 canonical-request',
  'spec and say so explicitly.',
  '',
  'Already fixed and verified (do NOT re-report): session-ID concurrency; usage amount=used / used=percent;',
  'context/output not guessed; baseURL /api/v2 (live 200); sameHost origin check; x-magpie-* stripping;',
  'probe AK masking; per-account channel cache; models[] null filtering; checkin re-read failure -> failed.',
  '',
  'Report only NEW, concrete, reproducible defects. For each: file, line, what breaks, and a concrete',
  'failure scenario (inputs -> wrong output/behavior). Return an empty findings array if your lens finds nothing.',
].join('\n')

const LENSES = [
  {
    key: 'signing',
    prompt: PRE + `

LENS: SDK-HMAC-SHA256 signing exactness (highest stakes — this silently breaks upstream on a spec mismatch).
Scrutinize sdkSignedHeaders() line by line against the Huawei Cloud SDK canonical-request spec:
- canonical URI: it appends a trailing "/" to every non-empty path. The AWS SigV4 / Huawei spec says the
  URI is the URI-encoded path, "/" only when the path is EMPTY — NOT a forced trailing slash on every
  path. If the upstream recomputes the canonical URI from the real request path (which has no trailing
  slash), the signature mismatches and every request 401s. Yet live requests return 200. Reconcile this:
  is the trailing slash actually correct for Huawei opengw/snap-access, or only passing because upstream
  tolerates it? Cite the reference implementation's canonicalization.
- query encoding: params are rfc3986-encoded and sorted; is that what Huawei wants? What about a param
  whose value is empty or missing "="?
- x-sdk-date: is toISOString with -: stripped and the millis+Z removed the correct basic-ISO format?
  Clock skew: no retry/clock-offset handling — is that a problem?
- the signed header set: host, content-type, x-sdk-date + extra. Are any REQUIRED headers omitted that
  Huawei rejects on? Is content-type: application/json correct for GET requests with no body (claim/balance),
  or would omitting content-type be more correct for GET?`,
  },
  {
    key: 'checkin',
    prompt: PRE + `

LENS: checkin() outcome contract against the host. Read the host checkin handling (grep host.js and
${HOSTSRC}/internal/provider for checkin, Checkin, outcome, claimed, ineligible, captcha, streak,
settled, retryAfter). Verify EVERY outcome value the plugin emits:
- claimed / done / ineligible / inactive / captcha / failed — which does the host actually accept as
  valid enum values, and what does it do with one it does not recognize?
- the streak: 0 field on the done result — correct, ignored, or harmful?
- credit: 1000 on claimed — does the host expect a credit field at all, and is the number used?
- the inactive outcome for "未登录" — can that ever fire given the host only calls checkin for a
  signed-in account? What should it be?
- Is there any path where checkin() throws (not returns) and how does the host treat a thrown checkin?`,
  },
  {
    key: 'modelmeta',
    prompt: PRE + `

LENS: provider.models() and model metadata completeness for routing + billing. magpie routes and
charges on model metadata. Read the host model handling (host.js fromModelsDev, info(), and Go
internal/provider/modelprefs.go, cost, limit) and determine what each model object MUST carry for
magpie to route and bill correctly. Check codeartsModels() and the cloud-built objects:
- cost: is cost required? If absent, does magpie charge 0, refuse, or fall back to a default that
  mis-bills? What do OTHER providers/plugins supply, and what does the models.dev entry for these
  models carry (input/output USD per 1M tokens)?
- limit: cloud context/output via optNumber (undefined when 0/negative). Is undefined vs 0 vs a real
  number handled differently by the host? Can a 0/undefined output limit cap a request at 0?
- capabilities: reasoning:false, tool_call:true — are there models that actually support reasoning or
  images that this misdeclares? Does misdeclaring break tool calls or reasoning?
- the static fallback sets context:0 output:0 — given that a positive limit is a HARD cap, is 0 =
  "unlimited" correctly honored by the host, or does 0 mean "capped at 0"?`,
  },
  {
    key: 'creds',
    prompt: PRE + `

LENS: credential storage and secret handling. Trace exactly what lands in the host stored auth record
(plugin-auth.json). Read host.js save() and apiKey() and the plugin authorize(). The plugin returns
{type:"success", key: ak, metadata:{sk}} from a type:"api" method that also has a prompt (key
"credential"). In apiKey(), save() builds metadata as {...inputs, ...result.metadata} — so the user's
full pasted "AK:SK" string is ALSO stored as metadata.credential alongside metadata.sk and key=ak.
- Is that a real problem (redundant plaintext duplication of the secret), or is the secret already
  fully present in key+metadata.sk regardless?
- Does the full "AK:SK" string ever leak into UI, logs, or error output via whoOf/hintOf/accountId?
- Does authorize()'s error path (the message 'AK/SK 验证失败: <error>') ever echo the AK or SK? envelope()
  throws text.slice(0,200) of the upstream body — can that body contain the AK/SK?
- The prompt uses type:"password" — does the host mask it, or is it collected in plaintext and stored
  in inputs (hence metadata)?`,
  },
  {
    key: 'hostcontract',
    prompt: PRE + `

LENS: remaining host-contract corner cases that would bite at runtime. Verify each against host.js:
- loader(getAuth): the host calls loader() once and caches options per account (loaders Map). If the
  account re-signs in (new AK), is the loader re-invoked, or does the stale session ID / baseURL persist
  until the host restarts? Is that a plugin bug or host behavior?
- loader returns {} when auth?.type !== "api" || !auth.key — but creds() throws when sk missing. Can
  loader throw on a half-stored account and what does the host do with a throwing loader?
- usage(): returns {error, windows:[]} on failure — does the host render error correctly, or does it
  expect a throw, or expect windows to be absent vs []?
- provider.id is "codearts" and the auth provider is also "codearts" — is the id contract consistent
  with how the host keys models and routes (plugin://codearts/v1)?
- models(provider, {auth}): the host calls ph.models(given, {auth: all[k]}) where given is the full
  provider info object. Does the plugin's {...provider.models} correctly read .models? Any case where
  provider.models is undefined and it throws?
- concurrency: channelCache / module state — any race between two accounts' provider.models calls and
  loader.fetch reads? (single-threaded Bun, but interleaved awaits).`,
  },
]

const FINDINGS = {
  type: 'object',
  properties: {
    findings: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          file: { type: 'string' },
          line: { type: 'integer' },
          title: { type: 'string' },
          detail: { type: 'string' },
          scenario: { type: 'string' },
          severity: { type: 'string', enum: ['high', 'medium', 'low'] },
        },
        required: ['file', 'line', 'title', 'detail', 'scenario', 'severity'],
      },
    },
  },
  required: ['findings'],
}

const VERDICT = {
  type: 'object',
  properties: {
    refuted: { type: 'boolean' },
    reason: { type: 'string' },
    corrected_severity: { type: 'string', enum: ['high', 'medium', 'low', 'not-a-defect'] },
  },
  required: ['refuted', 'reason', 'corrected_severity'],
}

phase('Find')
const found = await parallel(
  LENSES.map((l) => () => agent(l.prompt, { label: 'find:' + l.key, phase: 'Find', schema: FINDINGS, effort: 'high' })),
)
const all = found.filter(Boolean).flatMap((r) => r.findings ?? [])
log('finders returned ' + all.length + ' raw findings')

const seen = new Set()
const fresh = all.filter((f) => {
  const k = f.file + ':' + f.line + ':' + f.title
  if (seen.has(k)) return false
  seen.add(k)
  return true
})
log(fresh.length + ' unique findings to verify')

phase('Verify')
const verified = await pipeline(
  fresh,
  (f) =>
    parallel(
      ['correctness', 'does-it-reproduce'].map((lens) => () =>
        agent(
          PRE + `

A reviewer claims this is a defect:

FILE: ${f.file}:${f.line}
TITLE: ${f.title}
DETAIL: ${f.detail}
SCENARIO: ${f.scenario}
SEVERITY: ${f.severity}

Your lens: ${lens}. Read the actual code and the host/reference source. Try hard to REFUTE it: is this
already handled, impossible given the host's actual behavior, or a misreading of the spec? Default to
refuted=true unless you can point at the exact line that fails and a concrete input that triggers it.
If it is real, give the corrected severity.`,
          { label: 'verify:' + f.title.slice(0, 40), phase: 'Verify', schema: VERDICT, effort: 'high' },
        ),
      ),
    ).then((votes) => {
      const ok = votes.filter(Boolean)
      return { ...f, survived: ok.filter((v) => !v.refuted).length >= 2, votes: ok.map((v) => v.reason) }
    }),
)
const confirmed = verified.filter(Boolean).filter((f) => f.survived)
log('confirmed ' + confirmed.length + ' of ' + fresh.length)
return { confirmed, rejected: verified.filter(Boolean).filter((f) => !f.survived).map((f) => f.title) }
