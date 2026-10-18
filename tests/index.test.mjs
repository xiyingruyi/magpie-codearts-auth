import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";

const mod = await import("../index.mjs");
const {
  rfc3986, sdkSignedHeaders, creds, parseCredential, num, round1,
  checkinOutcome, startOfTodayMs, isBenefitChannel, codeartsModels,
  upstreamSessionId, sessionHeaders, CN_OFFSET_MS,
  channelCache, MODEL_META, BENEFIT_MODELS, AGENT_MODELS,
  SNAP_HOST, CHAT_PATH, OPENGW_HOST,
} = mod._internal;

const AK = "LTAI5tABCDEFGHIJKLMN";
const SK = "y8QwERtyuiopASDfghjKLzxcvbnm1234567890Ab";

/** 造一个带凭据的插件实例。 */
const pluginWith = () => mod.default({}, {});

/** 用给定的 fetch 实现跑一次 usage()。 */
async function usageWith(respond, ak = AK, sk = SK) {
  const plugin = await pluginWith();
  const real = globalThis.fetch;
  globalThis.fetch = respond;
  try {
    return await plugin.auth.usage(async () => ({ type: "api", key: ak, metadata: { sk } }));
  } finally {
    globalThis.fetch = real;
  }
}

/** 默认应答：余额 + 签到。 */
const balanceResponder = (balance, claimTimeMs = Date.now()) => async (url) =>
  String(url).includes("tokens/balance")
    ? new Response(JSON.stringify({ result: balance }), { status: 200 })
    : new Response(JSON.stringify({ result: { create_time: claimTimeMs } }), { status: 200 });

// ---------------------------------------------------------------------------
// 凭据解析
// ---------------------------------------------------------------------------

test("parseCredential: 冒号分隔", () => {
  const r = parseCredential(`${AK}:${SK}`);
  assert.equal(r.ak, AK);
  assert.equal(r.sk, SK);
});

test("parseCredential: 中文冒号与等号也认", () => {
  assert.equal(parseCredential(`AK1234567890123456789：SKabcdefghijklmnopqrs`).ak, "AK1234567890123456789");
  assert.equal(parseCredential(`AK1234567890123456789=SKabcdefghijklmnopqrs`).sk, "SKabcdefghijklmnopqrs");
  assert.equal(parseCredential(`AK1234567890123456789  SKabcdefghijklmnopqrs`).sk, "SKabcdefghijklmnopqrs");
});

test("parseCredential: 只有 AK 时 sk 为空", () => {
  const r = parseCredential(AK);
  assert.equal(r.ak, AK);
  assert.equal(r.sk, "");
});

test("parseCredential: 空串", () => {
  assert.deepEqual(parseCredential(""), { ak: "", sk: "" });
  assert.deepEqual(parseCredential(undefined), { ak: "", sk: "" });
});

test("parseCredential: 剥离 Bearer 前缀", () => {
  assert.equal(parseCredential(`Bearer AK1234567890123456789:SKabcdefghijklmnopqrs`).ak, "AK1234567890123456789");
});

test("creds: 标准保存格式（key=AK, metadata.sk）", () => {
  const r = creds({ type: "api", key: "AK1234567890123456789", metadata: { sk: "SKabcdefghijklmnopqrs" } });
  assert.deepEqual(r, { ak: "AK1234567890123456789", sk: "SKabcdefghijklmnopqrs" });
});

test("creds: 兼容 key 里直接存的是 AK:SK 组合串", () => {
  const r = creds({ type: "api", key: "AK1234567890123456789:SKabcdefghijklmnopqrs" });
  assert.deepEqual(r, { ak: "AK1234567890123456789", sk: "SKabcdefghijklmnopqrs" });
});

test("creds: 缺 SK 抛错", () => {
  assert.throws(() => creds({ type: "api", key: "AK1234567890123456789" }), /凭据不完整/);
});

// ---------------------------------------------------------------------------
// 上游会话 ID（0.2.4）
// ---------------------------------------------------------------------------

test("upstreamSessionId: 同一 AK 恒定不变（跨调用）", () => {
  assert.equal(upstreamSessionId(AK), upstreamSessionId(AK));
  assert.equal(upstreamSessionId(AK), upstreamSessionId(`  ${AK}  `), "前后空白不应改变结果");
});

test("upstreamSessionId: 形如 ses_ + 16 位十六进制", () => {
  assert.match(upstreamSessionId(AK), /^ses_[0-9a-f]{16}$/);
});

test("upstreamSessionId: 不同账号 → 不同 ID", () => {
  assert.notEqual(upstreamSessionId(AK), upstreamSessionId("LTAI5tZZZZZZZZZZZZZZZ"));
});

test("upstreamSessionId: 由 AK 派生（可与独立复算对齐）", () => {
  const expect = "ses_" + createHash("sha256").update(AK).digest("hex").slice(0, 16);
  assert.equal(upstreamSessionId(AK), expect);
});

test("upstreamSessionId: 无 AK → 空串（调用方据此不发头）", () => {
  assert.equal(upstreamSessionId(""), "");
  assert.equal(upstreamSessionId(undefined), "");
  assert.deepEqual(sessionHeaders(""), {});
});

test("sessionHeaders: IDE 同款两个名字，值相同", () => {
  const h = sessionHeaders(AK);
  assert.equal(h["x-ot-session-id"], upstreamSessionId(AK));
  assert.equal(h["user-session-id"], upstreamSessionId(AK));
});

test("sessionHeaders: 参与签名（出现在 SignedHeaders 里）", () => {
  const h = sdkSignedHeaders("POST", `${SNAP_HOST}${CHAT_PATH}`, "{}", AK, SK, sessionHeaders(AK));
  assert.match(h.Authorization, /SignedHeaders=content-type;host;user-session-id;x-ot-session-id;x-sdk-date/);
  assert.equal(h["x-ot-session-id"], upstreamSessionId(AK));
});

// ---------------------------------------------------------------------------
// 通道判定
// ---------------------------------------------------------------------------

test("isBenefitChannel: 已知老套餐模型 → false", () => {
  for (const m of AGENT_MODELS) {
    assert.equal(isBenefitChannel(m), false, m);
  }
});

test("isBenefitChannel: 未知模型按黑名单语义 → benefit", () => {
  for (const m of ["glm-5.3-flash", "deepseek-v4-pro-0813", "brand-new-model-2027"]) {
    assert.equal(isBenefitChannel(m), true, m);
  }
});

test("isBenefitChannel: 云端 channel 优先于黑名单", () => {
  channelCache.clear();
  channelCache.set("some-new-agent-model", "agent");
  assert.equal(isBenefitChannel("some-new-agent-model"), false);
  channelCache.set("openpangu-2.0-pro", "benefit");
  assert.equal(isBenefitChannel("openpangu-2.0-pro"), true);
  channelCache.clear();
});

test("isBenefitChannel: 显式传入 channel 参数优先于 cache", () => {
  channelCache.clear();
  channelCache.set("m1", "benefit");
  assert.equal(isBenefitChannel("m1", "agent"), false);
  assert.equal(isBenefitChannel("m1"), true);
  channelCache.clear();
});

test("isBenefitChannel: 大小写不敏感", () => {
  assert.equal(isBenefitChannel("glm-5.2"), false);
  assert.equal(isBenefitChannel("GLM-5.2"), false);
  assert.equal(isBenefitChannel("GlM-5.2"), false);
});

test("isBenefitChannel: 空模型名 → false", () => {
  assert.equal(isBenefitChannel(""), false);
  assert.equal(isBenefitChannel(undefined), false);
});

test("BENEFIT_MODELS 全部落在黑名单外（一致性自检）", () => {
  for (const m of BENEFIT_MODELS) {
    assert.equal(isBenefitChannel(m), true, `${m} 应为 benefit`);
  }
});

// ---------------------------------------------------------------------------
// 签名
// ---------------------------------------------------------------------------

test("rfc3986: 保留 -_.~ ，其余编码", () => {
  assert.equal(rfc3986("a-b_c.d~e"), "a-b_c.d~e");
  assert.equal(rfc3986("a b"), "a%20b");
  assert.equal(rfc3986("a!b"), "a%21b");
});

test("sdkSignedHeaders: 三个默认头都参与签名", () => {
  const h = sdkSignedHeaders("GET", "https://opengw.developer.huaweicloud.com/api/v1/user/tokens/balance", "", "AKTEST", "SKTEST");
  assert.match(h.Authorization, /^SDK-HMAC-SHA256 Access=AKTEST, SignedHeaders=content-type;host;x-sdk-date, Signature=[0-9a-f]{64}$/);
  assert.ok(h["x-sdk-date"].match(/^\d{8}T\d{6}Z$/));
  assert.equal(h["content-type"], "application/json");
  assert.equal(h.host, undefined, "host 不发送（由 fetch 自动加）");
});

test("sdkSignedHeaders: canonical_uri 自动补尾斜杠", () => {
  const a = sdkSignedHeaders("GET", "https://h.cn/api/v1/x", "", "AK", "SK");
  const b = sdkSignedHeaders("GET", "https://h.cn/api/v1/x/", "", "AK", "SK");
  assert.equal(a.SignedHeaders, b.SignedHeaders);
});

test("sdkSignedHeaders: 业务头参与签名（benefit 三头）", () => {
  const extra = { maas_type: "benefit", "model-id": "glm-5.3-flash", "model-name": "glm-5.3-flash" };
  const h = sdkSignedHeaders("POST", "https://snap.cn/api/v2/chat/completions", "{}", "AK", "SK", extra);
  assert.match(h.Authorization, /SignedHeaders=content-type;host;maas_type;model-id;model-name;x-sdk-date/);
  assert.equal(h.maas_type, "benefit");
  assert.equal(h["model-id"], "glm-5.3-flash");
});

test("sdkSignedHeaders: 签名可被独立复算（verify）", () => {
  const body = JSON.stringify({ model: "glm-5.3-flash", messages: [] });
  const h = sdkSignedHeaders("POST", "https://snap.cn/api/v2/chat/completions", body, "AKTEST", "SKTEST", {
    maas_type: "benefit", "model-id": "glm-5.3-flash", "model-name": "glm-5.3-flash",
  });
  const sig = h.Authorization.match(/Signature=([0-9a-f]{64})/)[1];
  const signedNames = ["content-type", "host", "maas_type", "model-id", "model-name", "x-sdk-date"];
  const vals = {
    "content-type": "application/json", host: "snap.cn",
    maas_type: "benefit", "model-id": "glm-5.3-flash", "model-name": "glm-5.3-flash",
    "x-sdk-date": h["x-sdk-date"],
  };
  const canonicalHeaders = signedNames.map((n) => `${n}:${vals[n]}\n`).join("");
  const payloadHash = createHash("sha256").update(body).digest("hex");
  const canonicalRequest = `POST\n/api/v2/chat/completions/\n\n${canonicalHeaders}\n${signedNames.join(";")}\n${payloadHash}`;
  const stringToSign = `SDK-HMAC-SHA256\n${h["x-sdk-date"]}\n${createHash("sha256").update(canonicalRequest).digest("hex")}`;
  const expect = createHmac("sha256", "SKTEST").update(stringToSign).digest("hex");
  assert.equal(sig, expect);
});

test("sdkSignedHeaders: 会话头也参与签名后签名仍可复算", () => {
  const body = "{}";
  const h = sdkSignedHeaders("POST", `${SNAP_HOST}${CHAT_PATH}`, body, AK, SK, sessionHeaders(AK));
  const sig = h.Authorization.match(/Signature=([0-9a-f]{64})/)[1];
  const signedNames = ["content-type", "host", "user-session-id", "x-ot-session-id", "x-sdk-date"];
  const vals = {
    "content-type": "application/json",
    host: new URL(SNAP_HOST).host,
    "user-session-id": upstreamSessionId(AK),
    "x-ot-session-id": upstreamSessionId(AK),
    "x-sdk-date": h["x-sdk-date"],
  };
  const canonicalHeaders = signedNames.map((n) => `${n}:${vals[n]}\n`).join("");
  const payloadHash = createHash("sha256").update(body).digest("hex");
  const canonicalRequest = `POST\n${CHAT_PATH}/\n\n${canonicalHeaders}\n${signedNames.join(";")}\n${payloadHash}`;
  const stringToSign = `SDK-HMAC-SHA256\n${h["x-sdk-date"]}\n${createHash("sha256").update(canonicalRequest).digest("hex")}`;
  const expect = createHmac("sha256", SK).update(stringToSign).digest("hex");
  assert.equal(sig, expect);
});

// ---------------------------------------------------------------------------
// 签到 outcome
// ---------------------------------------------------------------------------

test("checkinOutcome: 今日已签 → done", () => {
  assert.equal(checkinOutcome(false, startOfTodayMs() + 1000).outcome, "done");
});

test("checkinOutcome: 刚签到成功 → claimed + credit", () => {
  const r = checkinOutcome(true, startOfTodayMs() + 1000);
  assert.equal(r.outcome, "claimed");
  assert.equal(r.credit, 1000);
});

test("checkinOutcome: 活动结束 → ineligible", () => {
  assert.equal(checkinOutcome(false, undefined, { message: "CodeArts 业务错误 X: 活动已结束" }).outcome, "ineligible");
});

test("checkinOutcome: 未实名 → inactive", () => {
  assert.equal(checkinOutcome(false, undefined, { message: "账号未实名认证" }).outcome, "inactive");
});

test("checkinOutcome: 验证码 → captcha", () => {
  assert.equal(checkinOutcome(false, undefined, { message: "需要人机验证 captcha" }).outcome, "captcha");
});

test("checkinOutcome: 普通错误 → failed", () => {
  assert.equal(checkinOutcome(false, undefined, { message: "网络超时" }).outcome, "failed");
});

test("checkinOutcome: POST 成功但时间戳未推进 → ineligible（不空转重试）", () => {
  const old = startOfTodayMs() - 86400000;
  const r = checkinOutcome(true, old, undefined, old);
  assert.equal(r.outcome, "ineligible");
  assert.match(r.message, /未推进/);
});

test("checkinOutcome: 时间戳虽老但未发起签到 → failed", () => {
  const old = startOfTodayMs() - 86400000;
  assert.equal(checkinOutcome(false, old, undefined, old).outcome, "failed");
});

test("checkinOutcome: 无参 → failed（不产生非枚举值）", () => {
  assert.equal(checkinOutcome(false, undefined).outcome, "failed");
});

test("checkinOutcome: 所有 outcome 都在 magpie 枚举内", () => {
  const allowed = ["claimed", "done", "ineligible", "inactive", "captcha", "failed"];
  const old = startOfTodayMs() - 86400000;
  const cases = [
    checkinOutcome(true, startOfTodayMs() + 1),
    checkinOutcome(false, startOfTodayMs() + 1),
    checkinOutcome(false, undefined, { message: "活动已结束" }),
    checkinOutcome(false, undefined, { message: "未实名" }),
    checkinOutcome(false, undefined, { message: "captcha" }),
    checkinOutcome(false, undefined, { message: "err" }),
    checkinOutcome(false, undefined),
    checkinOutcome(true, old, undefined, old),
    checkinOutcome(false, old, undefined, old),
  ];
  for (const c of cases) assert.ok(allowed.includes(c.outcome), c.outcome);
});

// ---------------------------------------------------------------------------
// 天界（上游按中国时区 24:00 清零）
// ---------------------------------------------------------------------------

test("startOfTodayMs: 天界落在 UTC+8 的 0 点", () => {
  assert.equal((startOfTodayMs() + CN_OFFSET_MS) % 86400000, 0);
});

test("startOfTodayMs: 东八区 00:30 属于新的一天", () => {
  // 2026-10-19 00:30 +08:00 === 2026-10-18T16:30Z
  const now = Date.UTC(2026, 9, 18, 16, 30, 0);
  assert.equal(startOfTodayMs(now), Date.UTC(2026, 9, 18, 16, 0, 0));
});

test("startOfTodayMs: 东八区 23:59 仍属当天", () => {
  // 2026-10-18 23:59 +08:00 === 2026-10-18T15:59Z
  const now = Date.UTC(2026, 9, 18, 15, 59, 0);
  assert.equal(startOfTodayMs(now), Date.UTC(2026, 9, 17, 16, 0, 0));
});

test("startOfTodayMs: 结果与机器本地时区无关（只由入参决定）", () => {
  const now = Date.UTC(2026, 9, 18, 3, 0, 0);
  assert.equal(startOfTodayMs(now), startOfTodayMs(new Date(now).getTime()));
  assert.equal(startOfTodayMs(now), Date.UTC(2026, 9, 17, 16, 0, 0));
});

// ---------------------------------------------------------------------------
// 数值工具
// ---------------------------------------------------------------------------

test("num: 0 是合法值，null/空串/非数不算", () => {
  assert.equal(num(0), 0);
  assert.equal(num("0"), 0);
  assert.equal(num("123"), 123);
  assert.equal(num(null), undefined);
  assert.equal(num(undefined), undefined);
  assert.equal(num(""), undefined);
  assert.equal(num("abc"), undefined);
  assert.equal(num(NaN), undefined);
});

test("round1: 一位小数", () => {
  assert.equal(round1(3.14159), 3.1);
  assert.equal(round1(21.8499), 21.8);
  assert.equal(round1(0), 0);
});

// ---------------------------------------------------------------------------
// 模型清单
// ---------------------------------------------------------------------------

test("codeartsModels: 含全部内置模型且形状正确", () => {
  const m = codeartsModels();
  assert.equal(Object.keys(m).length, Object.keys(MODEL_META).length);
  for (const [id, v] of Object.entries(m)) {
    assert.equal(v.id, id);
    assert.equal(typeof v.name, "string");
    assert.equal(typeof v.limit.context, "number");
    assert.equal(typeof v.limit.output, "number");
    assert.equal(v.reasoning, false);
  }
});

test("codeartsModels: 不猜 context/output（0 = 不设限）", () => {
  for (const [id, v] of Object.entries(codeartsModels())) {
    assert.equal(v.limit.context, 0, `${id} 的 context 不该是猜出来的正数`);
    assert.equal(v.limit.output, 0, `${id} 的 output 不该是猜出来的正数`);
  }
});

// ---------------------------------------------------------------------------
// 插件整体装配
// ---------------------------------------------------------------------------

test("插件导出形态：default 是返回 plugin 的工厂", async () => {
  const factory = mod.default;
  assert.equal(typeof factory, "function");
  const plugin = await factory({ client: {} }, {});
  assert.equal(typeof plugin.config, "function");
  assert.equal(plugin.auth.provider, "codearts");
  assert.equal(plugin.provider.id, "codearts");
  assert.equal(plugin.auth.methods.length, 1);
  assert.equal(plugin.auth.methods[0].type, "api");
});

test("config: 注册 codearts provider", async () => {
  const plugin = await mod.default({}, {});
  const cfg = {};
  await plugin.config(cfg);
  assert.ok(cfg.provider.codearts);
  assert.equal(cfg.provider.codearts.api, `${SNAP_HOST}${CHAT_PATH}`);
});

// ---------------------------------------------------------------------------
// 🔴 关键回归：authorize 必须只靠 inputs 拿到 AK/SK
// ---------------------------------------------------------------------------

test("authorize: 只靠 inputs.credential 就能拿到 AK/SK（宿主不传 key）", async () => {
  const plugin = await mod.default({}, {});
  const r = await plugin.auth.methods[0].authorize({ credential: `${AK}:${SK}` });
  assert.equal(r.type, "failed");
  assert.ok(!/不能为空/.test(r.error), `不该是缺凭据错误，实际: ${r.error}`);
  assert.match(r.error, /验证失败/);
});

test("authorize: inputs 为空 → 明确报 AK 为空", async () => {
  const plugin = await mod.default({}, {});
  const r = await plugin.auth.methods[0].authorize({});
  assert.equal(r.type, "failed");
  assert.match(r.error, /Access Key Id 不能为空/);
});

test("authorize: 只有 AK 没 SK → 提示格式", async () => {
  const plugin = await mod.default({}, {});
  const r = await plugin.auth.methods[0].authorize({ credential: AK });
  assert.equal(r.type, "failed");
  assert.match(r.error, /Secret Access Key 不能为空/);
  assert.match(r.error, /冒号/);
});

test("method.prompts: 使用单个 credential 项（AK 必须走 prompts）", async () => {
  const plugin = await mod.default({}, {});
  const prompts = plugin.auth.methods[0].prompts;
  assert.equal(prompts.length, 1);
  assert.equal(prompts[0].key, "credential");
  assert.equal(prompts[0].type, "password");
});

test("prompts[0].validate: 校验组合串格式", async () => {
  const plugin = await mod.default({}, {});
  const v = plugin.auth.methods[0].prompts[0].validate;
  assert.equal(v(`${AK}:${SK}`), undefined);
  assert.match(v(AK), /冒号/);
  assert.match(v("short:sk"), /太短/);
});

test("loader: 无凭据返回空对象", async () => {
  const plugin = await mod.default({}, {});
  assert.deepEqual(await plugin.auth.loader(async () => undefined), {});
});

test("loader: 有凭据时给出 baseURL 与 fetch", async () => {
  const plugin = await mod.default({}, {});
  const l = await plugin.auth.loader(async () => ({ type: "api", key: AK, metadata: { sk: SK } }));
  assert.equal(l.baseURL, SNAP_HOST);
  assert.equal(typeof l.fetch, "function");
});

/**
 * 跑一次 loader 的 fetch，返回实际发出去的 {url, init}。
 * 只接手 SNAP_HOST 的地址，所以对话测试必须用真实对话 URL。
 */
async function callLoader(plugin, { key = AK, sk = SK, url = `${SNAP_HOST}${CHAT_PATH}`, init = {} } = {}) {
  const l = await plugin.auth.loader(async () => ({ type: "api", key, metadata: { sk } }));
  let seen;
  const real = globalThis.fetch;
  globalThis.fetch = async (u, i) => { seen = { url: u, init: i }; return new Response("{}", { status: 200 }); };
  try {
    await l.fetch(url, init);
  } finally {
    globalThis.fetch = real;
  }
  return seen;
}

test("loader.fetch: benefit 模型带三头，agent 模型不带", async () => {
  const plugin = await mod.default({}, {});
  const a = await callLoader(plugin, { init: { method: "POST", body: JSON.stringify({ model: "glm-5.3-flash" }) } });
  const b = await callLoader(plugin, { init: { method: "POST", body: JSON.stringify({ model: "GLM-5.2" }) } });
  assert.match(a.init.headers.get("Authorization"), /maas_type/, "benefit 模型应带 maas_type");
  assert.equal(a.init.headers.get("maas_type"), "benefit");
  assert.doesNotMatch(b.init.headers.get("Authorization"), /maas_type/, "agent 模型不该带 maas_type");
  assert.equal(b.init.headers.get("maas_type"), null);
});

test("loader.fetch: 每次请求都带同一个会话 ID（并发上限的钥匙）", async () => {
  const plugin = await mod.default({}, {});
  const seen = [];
  for (const model of ["deepseek-v4.1-flash", "deepseek-v4.1-flash", "GLM-5.2"]) {
    seen.push(await callLoader(plugin, { init: { method: "POST", body: JSON.stringify({ model }) } }));
  }
  const sid = upstreamSessionId(AK);
  for (const s of seen) {
    assert.equal(s.init.headers.get("x-ot-session-id"), sid);
    assert.equal(s.init.headers.get("user-session-id"), sid);
    assert.ok(s.init.headers.get("Authorization").includes("x-ot-session-id"), "会话头必须参与签名");
  }
});

test("loader.fetch: 两个账号拿到不同会话 ID", async () => {
  const plugin = await mod.default({}, {});
  const a = await callLoader(plugin, { init: { method: "POST", body: JSON.stringify({ model: "deepseek-v4.1-flash" }) } });
  const b = await callLoader(plugin, { key: "LTAI5tZZZZZZZZZZZZZZZ", init: { method: "POST", body: JSON.stringify({ model: "deepseek-v4.1-flash" }) } });
  assert.notEqual(a.init.headers.get("x-ot-session-id"), b.init.headers.get("x-ot-session-id"));
});

test("loader.fetch: 空 body 不伪造 '{}'（payload hash 要与实际发出的 body 一致）", async () => {
  const plugin = await mod.default({}, {});
  const s = await callLoader(plugin, { init: { method: "POST" } });
  assert.equal(s.init.body, undefined);
  assert.match(s.init.headers.get("Authorization"), /Signature=[0-9a-f]{64}$/);
});

test("loader.fetch: 非对话路径按实际 URL 与方法签名（GET 不带 maas 三头）", async () => {
  const plugin = await mod.default({}, {});
  const s = await callLoader(plugin, { url: `${SNAP_HOST}/v1/model/builtin`, init: { method: "GET" } });
  assert.equal(s.url, `${SNAP_HOST}/v1/model/builtin`);
  assert.equal(s.init.method, "GET");
  assert.equal(s.init.headers.get("maas_type"), null);
  assert.equal(s.init.headers.get("x-ot-session-id"), upstreamSessionId(AK));
});

test("loader.fetch: 非本 provider 的地址原样转发，不签名也不改写", async () => {
  const plugin = await mod.default({}, {});
  const l = await plugin.auth.loader(async () => ({ type: "api", key: AK, metadata: { sk: SK } }));
  let seen;
  const real = globalThis.fetch;
  globalThis.fetch = async (u, i) => { seen = { url: u, init: i }; return new Response("{}", { status: 200 }); };
  const other = "https://example.com/elsewhere";
  try {
    await l.fetch(other, { method: "POST", body: "x" });
  } finally {
    globalThis.fetch = real;
  }
  assert.equal(seen.url, other, "不能把别的地址改写成对话端点");
  assert.equal(seen.init.headers, undefined, "不能把我们的签名套到别的地址上");
  assert.equal(seen.init.body, "x");
});

test("loader.fetch: 保留调用方的其它头（accept: text/event-stream 决定流式）", async () => {
  const plugin = await mod.default({}, {});
  const s = await callLoader(plugin, {
    init: {
      method: "POST",
      body: JSON.stringify({ model: "deepseek-v4.1-flash", stream: true }),
      headers: { accept: "text/event-stream" },
    },
  });
  assert.equal(s.init.headers.get("accept"), "text/event-stream", "流式靠这个头，丢了会被当非流式");
  assert.equal(s.init.headers.get("content-type"), "application/json");
  assert.equal(s.init.headers.get("x-ot-session-id"), upstreamSessionId(AK));
});

test("loader.fetch: Request 对象作 input 时也能签对（方法与 URL 取自它）", async () => {
  const plugin = await mod.default({}, {});
  const l = await plugin.auth.loader(async () => ({ type: "api", key: AK, metadata: { sk: SK } }));
  let seen;
  const real = globalThis.fetch;
  globalThis.fetch = async (u, i) => { seen = { url: u, init: i }; return new Response("{}", { status: 200 }); };
  try {
    await l.fetch(new Request(`${SNAP_HOST}${CHAT_PATH}`, { method: "POST", body: JSON.stringify({ model: "deepseek-v4.1-flash" }) }));
  } finally {
    globalThis.fetch = real;
  }
  assert.equal(seen.url, `${SNAP_HOST}${CHAT_PATH}`);
  assert.equal(seen.init.headers.get("x-ot-session-id"), upstreamSessionId(AK));
  assert.equal(seen.init.headers.get("maas_type"), "benefit");
});

test("loader.fetch: GET + 空 body 时不带 body（否则 undici 会拒绝 GET 带 body）", async () => {
  const plugin = await mod.default({}, {});
  const s = await callLoader(plugin, { url: `${SNAP_HOST}${CHAT_PATH}`, init: { method: "GET" } });
  assert.equal(s.init.body, undefined);
});

test("loader.fetch: 乱 body 不会抛错（模型名解析失败保持空）", async () => {
  const plugin = await mod.default({}, {});
  const l = await plugin.auth.loader(async () => ({ type: "api", key: AK, metadata: { sk: SK } }));
  let seen;
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => { seen = init; return new Response("{}", { status: 200 }); };
  try {
    await l.fetch(`${SNAP_HOST}${CHAT_PATH}`, { method: "POST", body: "not json at all" });
  } finally {
    globalThis.fetch = realFetch;
  }
  // 解析失败 → model 为空 → isBenefitChannel("") 为 false → 不带 maas 三头
  assert.equal(seen.headers.get("maas_type"), null);
  assert.equal(seen.headers.get("x-ot-session-id"), upstreamSessionId(AK));
});

// ---------------------------------------------------------------------------
// usage（0.2.4：amount = 已用、unit = tokens）
// ---------------------------------------------------------------------------

test("usage: 未登录时返回 error", async () => {
  const plugin = await mod.default({}, {});
  const u = await plugin.auth.usage(async () => undefined);
  assert.match(u.error, /未登录/);
  assert.deepEqual(u.windows, []);
});

test("usage: used 是百分比，amount 是**已用**、limit 是总量", async () => {
  const u = await usageWith(balanceResponder({ total_quota: 10000000, total_balance: 9700000, used_amount: 300000 }));
  const w = u.windows[0];
  assert.equal(w.used, 3, "300000/10000000 = 3%");
  assert.ok(w.used >= 0 && w.used <= 100);
  assert.equal(w.limit, 10000000);
  assert.equal(w.amount, 300000, "amount 是已用，不是剩余");
  assert.equal(w.unit, "tokens", "这是每日免费 Token，不是积分");
  assert.equal(w.display, "300000 / 10000000");
});

test("usage: amount / limit 与 used 百分比自洽（宿主按 amount/limit 渲染）", () => {
  // 这条把「数字与百分比互相矛盾」的回归钉死：amount/limit 必须等于 used。
  return usageWith(balanceResponder({ total_quota: 10000000, total_balance: 7819948, used_amount: 2180052 })).then((u) => {
    const w = u.windows[0];
    assert.equal(w.amount, 2180052);
    assert.equal(w.limit, 10000000);
    assert.equal(round1((w.amount / w.limit) * 100), w.used);
    assert.equal(w.used, 21.8);
  });
});

test("usage: balance 文本只有「数量 + 单位」（宿主会自动追加 left）", async () => {
  const u = await usageWith(balanceResponder({ total_quota: 10000000, total_balance: 7819948, used_amount: 2180052 }));
  assert.equal(u.balance, "7819948 tokens");
  assert.doesNotMatch(u.balance, /剩余|left/);
});

test("usage: 字段缺失时回退 daily_token_limit / daily_tokens_used", async () => {
  const u = await usageWith(balanceResponder({ daily_token_limit: 10000000, daily_tokens_used: 2500000, total_balance: 7500000 }));
  const w = u.windows[0];
  assert.equal(w.limit, 10000000);
  assert.equal(w.amount, 2500000);
  assert.equal(w.used, 25);
});

test("usage: 没有 used 字段时由 quota - balance 反推", async () => {
  const u = await usageWith(balanceResponder({ total_quota: 10000000, total_balance: 9000000 }));
  const w = u.windows[0];
  assert.equal(w.amount, 1000000);
  assert.equal(w.used, 10);
});

test("usage: 没有 balance 字段时由 quota - used 反推", async () => {
  const u = await usageWith(balanceResponder({ total_quota: 10000000, used_amount: 1000000 }));
  assert.match(u.balance, /9000000/);
});

test("usage: 余额字段为 0 是合法值（不会被 || 吞成 undefined）", async () => {
  const u = await usageWith(balanceResponder({ total_quota: 10000000, total_balance: 0, used_amount: 10000000 }));
  const w = u.windows[0];
  assert.equal(w.used, 100);
  assert.equal(w.amount, 10000000);
});

test("usage: 拿不到 quota 时不填 limit/amount，也不产生 NaN", async () => {
  const u = await usageWith(balanceResponder({ total_balance: 5000 }));
  const w = u.windows[0];
  assert.equal(w.limit, undefined);
  assert.equal(w.amount, undefined);
  assert.equal(w.used, 0);
  assert.ok(Number.isFinite(w.used));
  assert.match(w.display, /5000/);
});

test("usage: 完全空响应也不抛错", async () => {
  const u = await usageWith(balanceResponder({}));
  assert.equal(u.windows.length, 2);
  assert.ok(Number.isFinite(u.windows[0].used));
});

test("usage: 签到窗口是 aside 状态行 —— 没有 limit、永远不是 100%", async () => {
  for (const signed of [true, false]) {
    const claimTime = signed ? Date.now() : 0;
    const u = await usageWith(balanceResponder({ total_quota: 10000000, total_balance: 9000000, used_amount: 1000000 }, claimTime));
    const w = u.windows[1];
    assert.equal(w.name, "每日签到");
    assert.equal(w.aside, true);
    assert.equal(w.limit, undefined, "不该有 limit（否则宿主渲染成 x/1 的额度条）");
    assert.ok(w.used < 98, "不该刷成 100%（宿主把 used>=98 渲染成 spent 红条）");
    assert.match(w.display, signed ? /已签/ : /未签/);
  }
});

test("usage: 额度窗口在任何路径下 used 都不为 NaN（宿主会直接渲染）", async () => {
  const bodies = [
    { total_quota: 10000000, total_balance: 9700000, used_amount: 300000 },
    { total_quota: 0, total_balance: 0 },
    { total_balance: 1 },
    {},
    { total_quota: "abc", used_amount: "def" },
    { total_quota: 100, total_balance: 200 },
  ];
  for (const b of bodies) {
    const u = await usageWith(balanceResponder(b));
    for (const w of u.windows) {
      assert.ok(Number.isFinite(w.used), `used 必须是有限数: ${JSON.stringify(b)} → ${w.used}`);
    }
    assert.ok(u.windows[0].limit === undefined || Number.isFinite(u.windows[0].limit));
    assert.ok(u.windows[0].amount === undefined || Number.isFinite(u.windows[0].amount));
  }
});

test("usage: 余额接口失败 → 返回 error 而不是抛错", async () => {
  const u = await usageWith(async (url) => {
    if (String(url).includes("tokens/balance")) return new Response("boom", { status: 500 });
    return new Response(JSON.stringify({ result: {} }), { status: 200 });
  });
  assert.match(u.error, /额度/);
  assert.deepEqual(u.windows, []);
});

test("usage: 查询余额/签到不带会话头（opengw 不是对话会话，且登录依赖它）", async () => {
  const seen = [];
  await usageWith(async (url, init) => {
    seen.push(init.headers);
    return String(url).includes("tokens/balance")
      ? new Response(JSON.stringify({ result: { total_quota: 10, total_balance: 5, used_amount: 5 } }), { status: 200 })
      : new Response(JSON.stringify({ result: { create_time: Date.now() } }), { status: 200 });
  });
  assert.equal(seen.length, 2, "余额 + 签到各一次");
  for (const h of seen) {
    assert.equal(h["x-ot-session-id"], undefined, "opengw 接口不该带会话头");
    assert.match(h.Authorization, /SignedHeaders=content-type;host;x-sdk-date, Signature=/);
  }
});

// ---------------------------------------------------------------------------
// checkin
// ---------------------------------------------------------------------------

test("checkin: 未登录 → inactive", async () => {
  const plugin = await mod.default({}, {});
  assert.equal((await plugin.auth.checkin(async () => undefined)).outcome, "inactive");
});

// ---------------------------------------------------------------------------
// provider.models
// ---------------------------------------------------------------------------

test("provider.models: 无凭据时回退静态列表", async () => {
  const plugin = await mod.default({}, {});
  const base = { "GLM-5.2": { id: "GLM-5.2", name: "GLM-5.2" } };
  assert.deepEqual(await plugin.provider.models({ models: base }, { auth: undefined }), base);
});

test("provider.models: 云端清单覆盖并保留真实 context/output", async () => {
  const plugin = await mod.default({}, {});
  const real = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({
    result: {
      models: [
        { model_id: "deepseek-v4-pro-0813", context_window: 1000000, max_tokens: 393216, channel: "benefit" },
        { model_id: "GLM-5.2", context_window: 200000, max_tokens: 128000, channel: "agent" },
      ],
    },
  }), { status: 200 });
  try {
    const base = { "GLM-5.2": { id: "GLM-5.2", name: "GLM-5.2", limit: { context: 0, output: 0 } } };
    const r = await plugin.provider.models({ models: base }, { auth: { type: "api", key: AK, metadata: { sk: SK } } });
    assert.equal(r["deepseek-v4-pro-0813"].limit.context, 1000000);
    assert.equal(r["deepseek-v4-pro-0813"].limit.output, 393216);
    assert.equal(r["GLM-5.2"].limit.context, 200000);
    assert.equal(channelCache.get("deepseek-v4-pro-0813"), "benefit");
    assert.equal(channelCache.get("GLM-5.2"), "agent");
  } finally {
    globalThis.fetch = real;
    channelCache.clear();
  }
});

test("provider.models: 换账号时清掉上一个账号的 channel 判定", async () => {
  const plugin = await mod.default({}, {});
  const real = globalThis.fetch;
  channelCache.set("stale-model", "agent");
  globalThis.fetch = async () => new Response(JSON.stringify({
    result: { models: [{ model_id: "another-model", context_window: 1000, max_tokens: 100, channel: "benefit" }] },
  }), { status: 200 });
  try {
    await plugin.provider.models({ models: {} }, { auth: { type: "api", key: AK, metadata: { sk: SK } } });
    assert.equal(channelCache.has("stale-model"), false, "上一个账号的判定必须被清掉");
    assert.equal(channelCache.get("another-model"), "benefit");
  } finally {
    globalThis.fetch = real;
    channelCache.clear();
  }
});

test("provider.models: 云端没有 limit 时不写死 0 以外的猜测值", async () => {
  const plugin = await mod.default({}, {});
  const real = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({ result: { models: [{ model_id: "mystery" }] } }), { status: 200 });
  try {
    const r = await plugin.provider.models({ models: {} }, { auth: { type: "api", key: AK, metadata: { sk: SK } } });
    assert.equal(r.mystery.limit.context, undefined);
    assert.equal(r.mystery.limit.output, undefined);
  } finally {
    globalThis.fetch = real;
  }
});
