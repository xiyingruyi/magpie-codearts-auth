import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";

const mod = await import("../index.mjs");
const {
  rfc3986, sdkSignedHeaders, creds, parseCredential,
  checkinOutcome, startOfTodayMs, isBenefitChannel, codeartsModels,
  channelCache, MODEL_META, BENEFIT_MODELS, AGENT_MODELS,
} = mod._internal;

// ---------------------------------------------------------------------------
// 凭据解析
// ---------------------------------------------------------------------------

test("parseCredential: 冒号分隔", () => {
  const r = parseCredential("LTAI5tABCDEFGHIJKLMN:y8QwERtyuiopASDfghjKLzxcvbnm1234567890Ab");
  assert.equal(r.ak, "LTAI5tABCDEFGHIJKLMN");
  assert.equal(r.sk, "y8QwERtyuiopASDfghjKLzxcvbnm1234567890Ab");
});

test("parseCredential: 中文冒号与等号也认", () => {
  assert.equal(parseCredential("AK1234567890123456789：SKabcdefghijklmnopqrs").ak, "AK1234567890123456789");
  assert.equal(parseCredential("AK1234567890123456789=SKabcdefghijklmnopqrs").sk, "SKabcdefghijklmnopqrs");
  assert.equal(parseCredential("AK1234567890123456789  SKabcdefghijklmnopqrs").sk, "SKabcdefghijklmnopqrs");
});

test("parseCredential: 只有 AK 时 sk 为空", () => {
  const r = parseCredential("LTAI5tABCDEFGHIJKLMN");
  assert.equal(r.ak, "LTAI5tABCDEFGHIJKLMN");
  assert.equal(r.sk, "");
});

test("parseCredential: 空串", () => {
  assert.deepEqual(parseCredential(""), { ak: "", sk: "" });
  assert.deepEqual(parseCredential(undefined), { ak: "", sk: "" });
});

test("parseCredential: 剥离 Bearer 前缀", () => {
  assert.equal(parseCredential("Bearer AK1234567890123456789:SKabcdefghijklmnopqrs").ak, "AK1234567890123456789");
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
// 通道判定（核心修复 #2）
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
  // 一个名字不在老名单里的模型，但云端说它是 agent 通道
  channelCache.set("some-new-agent-model", "agent");
  assert.equal(isBenefitChannel("some-new-agent-model"), false);
  // 一个名字在老名单里的模型，但云端说它是 benefit
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
  // x-sdk-date 可能差一秒，只比 Signature 之外的部分
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
  // 复算 canonicalRequest
  const signedNames = ["content-type", "host", "maas_type", "model-id", "model-name", "x-sdk-date"];
  const vals = {
    "content-type": "application/json", host: "snap.cn",
    maas_type: "benefit", "model-id": "glm-5.3-flash", "model-name": "glm-5.3-flash",
    "x-sdk-date": h["x-sdk-date"],
  };
  const canonicalHeaders = signedNames.map((n) => `${n}:${vals[n]}\n`).join("");
  const signedHeaders = signedNames.join(";");
  const payloadHash = createHash("sha256").update(body).digest("hex");
  const canonicalRequest = `POST\n/api/v2/chat/completions/\n\n${canonicalHeaders}\n${signedHeaders}\n${payloadHash}`;
  const stringToSign = `SDK-HMAC-SHA256\n${h["x-sdk-date"]}\n${createHash("sha256").update(canonicalRequest).digest("hex")}`;
  const expect = createHmac("sha256", "SKTEST").update(stringToSign).digest("hex");
  assert.equal(sig, expect);
});

// ---------------------------------------------------------------------------
// 签到 outcome
// ---------------------------------------------------------------------------

test("checkinOutcome: 今日已签 → done", () => {
  const r = checkinOutcome(false, startOfTodayMs() + 1000);
  assert.equal(r.outcome, "done");
});

test("checkinOutcome: 刚签到成功 → claimed + credit", () => {
  const r = checkinOutcome(true, startOfTodayMs() + 1000);
  assert.equal(r.outcome, "claimed");
  assert.equal(r.credit, 1000);
});

test("checkinOutcome: 活动结束 → ineligible", () => {
  const r = checkinOutcome(false, undefined, { message: "CodeArts 业务错误 X: 活动已结束" });
  assert.equal(r.outcome, "ineligible");
});

test("checkinOutcome: 未实名 → inactive", () => {
  const r = checkinOutcome(false, undefined, { message: "账号未实名认证" });
  assert.equal(r.outcome, "inactive");
});

test("checkinOutcome: 验证码 → captcha", () => {
  const r = checkinOutcome(false, undefined, { message: "需要人机验证 captcha" });
  assert.equal(r.outcome, "captcha");
});

test("checkinOutcome: 普通错误 → failed", () => {
  const r = checkinOutcome(false, undefined, { message: "网络超时" });
  assert.equal(r.outcome, "failed");
});

test("checkinOutcome: 无参 → failed（不产生非枚举值）", () => {
  const r = checkinOutcome(false, undefined);
  assert.equal(r.outcome, "failed");
});

test("checkinOutcome: 所有 outcome 都在 magpie 枚举内", () => {
  const allowed = ["claimed", "done", "ineligible", "inactive", "captcha", "failed"];
  const cases = [
    checkinOutcome(true, startOfTodayMs() + 1),
    checkinOutcome(false, startOfTodayMs() + 1),
    checkinOutcome(false, undefined, { message: "活动已结束" }),
    checkinOutcome(false, undefined, { message: "未实名" }),
    checkinOutcome(false, undefined, { message: "captcha" }),
    checkinOutcome(false, undefined, { message: "err" }),
    checkinOutcome(false, undefined),
  ];
  for (const c of cases) assert.ok(allowed.includes(c.outcome), c.outcome);
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
  assert.equal(cfg.provider.codearts.api, "https://snap-access.cn-north-4.myhuaweicloud.com/api/v2/chat/completions");
});

// ---------------------------------------------------------------------------
// 🔴 关键回归：authorize 必须只靠 inputs 拿到 AK/SK
// ---------------------------------------------------------------------------

test("authorize: 只靠 inputs.credential 就能拿到 AK/SK（宿主不传 key）", async () => {
  const plugin = await mod.default({}, {});
  const m = plugin.auth.methods[0];
  // 模拟宿主：apiKey({inputs:{credential:"..."}, key:undefined})
  // 用假凭据 → 网络会失败，但错误信息不应是「不能为空」
  const r = await m.authorize({ credential: "LTAI5tABCDEFGHIJKLMN:y8QwERtyuiopASDfghjKLzxcvbnm1234567890Ab" });
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
  const r = await plugin.auth.methods[0].authorize({ credential: "LTAI5tABCDEFGHIJKLMN" });
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
  assert.equal(v("LTAI5tABCDEFGHIJKLMN:y8QwERtyuiopASDfghjKLzxcvbnm1234567890Ab"), undefined);
  assert.match(v("LTAI5tABCDEFGHIJKLMN"), /冒号/);
  assert.match(v("short:sk"), /太短/);
});

test("loader: 无凭据返回空对象", async () => {
  const plugin = await mod.default({}, {});
  const l = await plugin.auth.loader(async () => undefined);
  assert.deepEqual(l, {});
});

test("loader: 有凭据时给出 baseURL 与 fetch", async () => {
  const plugin = await mod.default({}, {});
  const l = await plugin.auth.loader(async () => ({
    type: "api", key: "LTAI5tABCDEFGHIJKLMN", metadata: { sk: "y8QwERtyuiopASDfghjKLzxcvbnm1234567890Ab" },
  }));
  assert.equal(l.baseURL, "https://snap-access.cn-north-4.myhuaweicloud.com");
  assert.equal(typeof l.fetch, "function");
});

test("loader.fetch: benefit 模型带三头，agent 模型不带", async () => {
  const plugin = await mod.default({}, {});
  const l = await plugin.auth.loader(async () => ({
    type: "api", key: "LTAI5tABCDEFGHIJKLMN", metadata: { sk: "y8QwERtyuiopASDfghjKLzxcvbnm1234567890Ab" },
  }));
  const seen = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => { seen.push(init.headers); return new Response("{}", { status: 200 }); };
  try {
    await l.fetch("x", { method: "POST", body: JSON.stringify({ model: "glm-5.3-flash" }) });
    await l.fetch("x", { method: "POST", body: JSON.stringify({ model: "GLM-5.2" }) });
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.match(seen[0].Authorization, /maas_type/, "benefit 模型应带 maas_type");
  assert.equal(seen[0].maas_type, "benefit");
  assert.doesNotMatch(seen[1].Authorization, /maas_type/, "agent 模型不该带 maas_type");
  assert.equal(seen[1].maas_type, undefined);
});

test("usage: 未登录时返回 error", async () => {
  const plugin = await mod.default({}, {});
  const u = await plugin.auth.usage(async () => undefined);
  assert.match(u.error, /未登录/);
  assert.deepEqual(u.windows, []);
});

test("checkin: 未登录 → inactive", async () => {
  const plugin = await mod.default({}, {});
  const c = await plugin.auth.checkin(async () => undefined);
  assert.equal(c.outcome, "inactive");
});

test("provider.models: 无凭据时回退静态列表", async () => {
  const plugin = await mod.default({}, {});
  const base = { "GLM-5.2": { id: "GLM-5.2", name: "GLM-5.2" } };
  const r = await plugin.provider.models({ models: base }, { auth: undefined });
  assert.deepEqual(r, base);
});
