import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { readFileSync } from "node:fs";

const mod = await import("../index.mjs");
const {
  rfc3986, sdkSignedHeaders, envelope, snapEnvelope, creds, parseCredential, num, round1,
  checkinPlan, checkinErrorOutcome, checkinFlow,
  fetchCredits, fetchCampaigns, opsClaim, opsConfirm, pickDailyCampaign, usableCampaignId,
  startOfTodayMs, isBenefitChannel, codeartsModels, redact, clampChatBody,
  outputLimit, MAX_OUTPUT_TOKENS, normalizeChatBody,
  upstreamError, normalizeChatResponse, PEEK_MS,
  upstreamSessionId, sessionHeaders, CN_OFFSET_MS,
  channelCache, channelTable, MODEL_META, VISION_MODELS, AGENT_MODELS, RETIRED_MODELS, modelRetired,
  benefitBroken, markBenefitBroken, benefitGone, gatewayRetired, benefitDown, BENEFIT_DOWN_MS,
  modalitiesField, capabilitiesField, imageCapable,
  SNAP_HOST, CHAT_PATH, OPENGW_HOST,
  STATS_PATH, OPS_DELIVERY_PATH, OPS_CHANNEL, AGENT_TYPE_HEADER,
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
    // 🔴 用传入的 sk，不要写死模块常量：写死时 `usageWith(r, "AK2", "SK2")` 会拿
    //    AK2 配第一账号的 SK，签名自然错，而测试看起来「过了」。
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
  channelTable().set("some-new-agent-model", "agent");
  assert.equal(isBenefitChannel("some-new-agent-model"), false);
  channelTable().set("openpangu-2.0-pro", "benefit");
  assert.equal(isBenefitChannel("openpangu-2.0-pro"), true);
  channelCache.clear();
});

test("isBenefitChannel: 显式传入 channel 参数优先于 cache", () => {
  channelCache.clear();
  channelTable().set("m1", "benefit");
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

test("MODEL_META 里标了 benefit 的模型，判定也确实是 benefit（一致性自检）", () => {
  for (const [id, meta] of Object.entries(MODEL_META)) {
    assert.equal(isBenefitChannel(id), meta.benefit, `${id} 的 benefit 标记与黑名单判定不一致`);
  }
});

// ---------------------------------------------------------------------------
// 福利通道下线（2026-10-20 上游改动）
// ---------------------------------------------------------------------------

test("benefitGone: 认得上游两种写法（非流式 4004 / 流式 InferHub.4004.200）", () => {
  assert.equal(benefitGone(JSON.stringify({ error_code: "4004", error_msg: "benefit not found", result: null })), true);
  assert.equal(benefitGone(`data:{"error_code":"InferHub.4004.200","error_msg":"benefit not found"}`), true);
  assert.equal(benefitGone('{"error_code":"InferHub.4004.200"}'), true);
});

test("benefitGone: 不误伤别的错误（4004 单独出现、model not registered、正常回答）", () => {
  assert.equal(benefitGone('{"error_code":"4004","error_msg":"something else"}'), false, "4004 本身太宽，不能当判据");
  assert.equal(benefitGone('{"error_code":"InferHub.002002009.404","error_msg":"The model is not registered"}'), false);
  assert.equal(benefitGone('{"usage":{"prompt_tokens":1},"choices":[]}'), false);
  assert.equal(benefitGone(""), false);
});

test("benefitBroken / markBenefitBroken: 按账号+模型记账，TTL 过后自动放行", () => {
  benefitDown.clear();
  const now = 1_800_000_000_000;
  assert.equal(benefitBroken(AK, "deepseek-v4.1-flash", now), false, "没记过 → 不熔断");
  markBenefitBroken(AK, "deepseek-v4.1-flash", now);
  assert.equal(benefitBroken(AK, "deepseek-v4.1-flash", now + 1000), true);
  assert.equal(benefitBroken(AK, "DeepSeek-V4.1-Flash", now + 1000), true, "模型名大小写不敏感");
  assert.equal(benefitBroken("LTAIother", "deepseek-v4.1-flash", now + 1000), false, "换个账号不算熔断");
  assert.equal(benefitBroken(AK, "glm-5.3-flash", now + 1000), false, "只熔断出事的那个模型");
  assert.equal(benefitBroken(AK, "deepseek-v4.1-flash", now + BENEFIT_DOWN_MS + 1), false, "TTL 过后再试一次福利通道");
  benefitDown.clear();
});

test("loader.fetch: 撞到 benefit not found 就去掉三头重发，并把这条模型熔断", async () => {
  benefitDown.clear();
  const plugin = await mod.default({}, {});
  const l = await plugin.auth.loader(async () => ({ type: "api", key: AK, metadata: { sk: SK } }));
  const target = hostUrl(l.baseURL);
  const body = JSON.stringify({ model: "deepseek-v4.1-flash", messages: [{ role: "user", content: "hi" }], stream: false });
  const calls = [];
  const real = globalThis.fetch;
  globalThis.fetch = async (u, i) => {
    calls.push({ url: u, headers: new Headers(i.headers), body: i.body });
    if (i.headers.get("maas_type") === "benefit") {
      return new Response(JSON.stringify({ error_code: "4004", error_msg: "benefit not found", result: null }), {
        status: 200, headers: { "content-type": "application/json" },
      });
    }
    return new Response(JSON.stringify({ id: "ok", choices: [{ message: { role: "assistant", content: "hi" } }], usage: {} }), {
      status: 200, headers: { "content-type": "application/json" },
    });
  };
  let res;
  try {
    res = await l.fetch(target, { method: "POST", body });
  } finally {
    globalThis.fetch = real;
  }
  assert.equal(calls.length, 2, "应恰好重发一次");
  assert.equal(calls[0].headers.get("maas_type"), "benefit", "第一次按福利通道走");
  assert.equal(calls[1].headers.get("maas_type"), null, "第二次去掉福利头");
  assert.doesNotMatch(calls[1].headers.get("Authorization"), /maas_type/, "签名也要跟着去掉这个头");
  assert.equal(calls[1].body, body, "body 一个字节都不改（只有头变了）");
  assert.equal(res.status, 200, "普通通道成功后应把正常回答交给调用方");
  assert.equal(benefitBroken(AK, "deepseek-v4.1-flash"), true, "这条模型应被熔断");

  // 熔断期内再来一次：直接走普通通道，不再先撞一次
  calls.length = 0;
  globalThis.fetch = async (u, i) => {
    calls.push({ url: u, headers: new Headers(i.headers), body: i.body });
    return new Response(JSON.stringify({ id: "ok", choices: [], usage: {} }), {
      status: 200, headers: { "content-type": "application/json" },
    });
  };
  try {
    await l.fetch(target, { method: "POST", body });
  } finally {
    globalThis.fetch = real;
  }
  assert.equal(calls.length, 1, "熔断期内不该再试福利通道");
  assert.equal(calls[0].headers.get("maas_type"), null);
  benefitDown.clear();
});

test("loader.fetch: 普通通道也不认这条模型时，报「福利没了」而不是顺带把问题糊掉", async () => {
  benefitDown.clear();
  const plugin = await mod.default({}, {});
  const l = await plugin.auth.loader(async () => ({ type: "api", key: AK, metadata: { sk: SK } }));
  const target = hostUrl(l.baseURL);
  const body = JSON.stringify({ model: "deepseek-v4-pro-0813", messages: [{ role: "user", content: "hi" }], stream: false });
  const real = globalThis.fetch;
  globalThis.fetch = async (u, i) => {
    if (i.headers.get("maas_type") === "benefit") {
      return new Response(JSON.stringify({ error_code: "4004", error_msg: "benefit not found", result: null }), {
        status: 200, headers: { "content-type": "application/json" },
      });
    }
    return new Response(JSON.stringify({ error_code: "InferHub.002002009.404", error_msg: "The model is not registered" }), {
      status: 200, headers: { "content-type": "application/json" },
    });
  };
  let res;
  try {
    res = await l.fetch(target, { method: "POST", body });
  } finally {
    globalThis.fetch = real;
  }
  const parsed = JSON.parse(await res.text());
  assert.equal(parsed.error.message, "benefit not found", "上游摘掉的就是福利通道，报这条才可行动");
  assert.equal(benefitBroken(AK, "deepseek-v4-pro-0813"), true, "无论重发结果如何都熔断，避免每次都双倍延迟");
  benefitDown.clear();
});

test("loader.fetch: 流式首帧是福利下线错误时同样摘头重发（不能把错误事件当回答转出去）", async () => {
  benefitDown.clear();
  const plugin = await mod.default({}, {});
  const l = await plugin.auth.loader(async () => ({ type: "api", key: AK, metadata: { sk: SK } }));
  const target = hostUrl(l.baseURL);
  const body = JSON.stringify({ model: "deepseek-v4.1-flash", messages: [{ role: "user", content: "hi" }], stream: true });
  let calls = 0;
  const real = globalThis.fetch;
  globalThis.fetch = async (u, i) => {
    calls += 1;
    if (i.headers.get("maas_type") === "benefit") {
      return new Response(
        `data:${JSON.stringify({ error_code: "InferHub.4004.200", error_msg: "benefit not found" })}\n\n`,
        { status: 200, headers: { "content-type": "text/event-stream" } },
      );
    }
    return new Response(
      `data:${JSON.stringify({ choices: [{ delta: { content: "hi" } }] })}\n\ndata:[DONE]\n\n`,
      { status: 200, headers: { "content-type": "text/event-stream" } },
    );
  };
  let res;
  try {
    res = await l.fetch(target, { method: "POST", body });
  } finally {
    globalThis.fetch = real;
  }
  assert.equal(calls, 2, "流式也要重发一次");
  assert.equal(res.status, 200);
  const text = await res.text();
  assert.match(text, /"content":"hi"/, "应拿到普通通道的正常分片");
  assert.doesNotMatch(text, /benefit not found/);
  benefitDown.clear();
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

// ---------------------------------------------------------------------------
// 签到：状态机（checkinPlan）
// ---------------------------------------------------------------------------

const dailyCampaign = (over = {}) => ({
  campaignId: 1,
  title: "每日签到领1000积分",
  type: "USER_LOGIN",
  benefitAmount: 1000,
  benefitUnit: "CREDIT",
  claimable: true,
  status: "ELIGIBLE",
  pendingCount: 0,
  pendingTotalAmount: 0,
  ...over,
});

test("checkinPlan: ELIGIBLE → claim", () => {
  const p = checkinPlan(dailyCampaign());
  assert.equal(p.action, "claim");
  assert.equal(p.credit, 1000);
});

test("checkinPlan: CLAIMED 是「已领未确认」→ 只补 confirm，不能当成已签跳过", () => {
  const p = checkinPlan(dailyCampaign({ status: "CLAIMED", claimable: false }));
  assert.equal(p.action, "confirm", "漏掉这一步，活动会永远卡在 CLAIMED");
});

test("checkinPlan: CONFIRMED / CONSUMED → done，不碰写接口", () => {
  for (const status of ["CONFIRMED", "CONSUMED"]) {
    const p = checkinPlan(dailyCampaign({ status, claimable: false }));
    assert.equal(p.action, "none");
    assert.equal(p.outcome, "done");
    assert.equal(p.credit, 1000, "已签也报得出每日额度（上游给了 benefitAmount）");
  }
});

test("checkinPlan: status 为 null / 未知 → ineligible（活动不在期，不必重试）", () => {
  for (const status of [null, undefined, "", "WHATEVER"]) {
    const p = checkinPlan(dailyCampaign({ status }));
    assert.equal(p.outcome, "ineligible");
    assert.equal(p.action, "none");
  }
});

test("checkinPlan: 没有每日签到活动 → ineligible", () => {
  const p = checkinPlan(null);
  assert.equal(p.action, "none");
  assert.equal(p.outcome, "ineligible");
  assert.match(p.message, /没有每日签到/);
});

test("checkinPlan: ELIGIBLE 但服务端说 claimable=false → failed（自相矛盾，交给宿主重试）", () => {
  const p = checkinPlan(dailyCampaign({ claimable: false }));
  assert.equal(p.action, "none");
  assert.equal(p.outcome, "failed");
});

test("checkinPlan: status 大小写不敏感", () => {
  assert.equal(checkinPlan(dailyCampaign({ status: "eligible" })).action, "claim");
  assert.equal(checkinPlan(dailyCampaign({ status: "claimed" })).action, "confirm");
});

test("checkinErrorOutcome: 只有枚举里的 outcome（宿主会归一非枚举值为 failed）", () => {
  const allowed = ["claimed", "done", "ineligible", "inactive", "captcha", "failed"];
  const cases = [
    checkinErrorOutcome({ errorCode: "40001", message: "尚未到达权益刷新时间" }),
    checkinErrorOutcome({ errorCode: "4006", message: "名额领完" }),
    checkinErrorOutcome({ errorCode: "40401", message: "运营事件不存在: 1" }),
    checkinErrorOutcome({ message: "账号未实名认证" }),
    checkinErrorOutcome({ message: "需要人机验证 captcha" }),
    checkinErrorOutcome({ errorCode: "APIG.0602", message: "Invalid token" }),
    checkinErrorOutcome({ errorCode: "APIG.0301", message: "verify ak sk signature fail" }),
    checkinErrorOutcome(new Error("网络超时")),
    checkinErrorOutcome(undefined),
  ];
  for (const c of cases) assert.ok(allowed.includes(c.outcome), c.outcome);
  // checkinErrorOutcome 只在写请求失败时被调用，永远不该返回 claimed
  // （claimed 只来自 checkinFlow 的成功路径）—— 这条把「映射跑偏」钉住。
  for (const c of cases) assert.notEqual(c.outcome, "claimed");
  assert.equal(checkinErrorOutcome({ errorCode: "4006", message: "名额领完" }).outcome, "ineligible");
  assert.equal(checkinErrorOutcome({ errorCode: "50000", message: "系统繁忙" }).outcome, "failed");
});

test("checkinErrorOutcome: 40001「尚未到达权益刷新时间」按已签处理（不是错误）", () => {
  const r = checkinErrorOutcome({ errorCode: "40001", message: "尚未到达权益刷新时间" });
  assert.equal(r.outcome, "done");
});

test("checkinErrorOutcome: 40001 是同一个码两种含义，按 claim/confirm 分开判", () => {
  // claim 回 40001 = 今天这轮已领；confirm 回 40001 = 没有待确认记录。
  // 两种都不用重试，但**不能**把 confirm 的失败一律说成 done ——
  // 混在一起会让状态卡在 CLAIMED 而宿主不再补。
  assert.match(checkinErrorOutcome({ errorCode: "40001" }, {}, "claim").message, /已签到/);
  assert.match(checkinErrorOutcome({ errorCode: "40001" }, {}, "confirm").message, /已确认/);
  // confirm 的其它错误必须报 failed，宿主下一轮才会补
  assert.equal(checkinErrorOutcome({ errorCode: "50000", message: "系统繁忙" }, {}, "confirm").outcome, "failed");
});

test("checkinErrorOutcome: 名额领完 / 活动不存在 → ineligible（不必重试）", () => {
  assert.equal(checkinErrorOutcome({ errorCode: "4006", message: "名额已抢完" }).outcome, "ineligible");
  assert.equal(checkinErrorOutcome({ errorCode: "40401", message: "运营事件不存在: 1" }).outcome, "ineligible");
});

test("checkinErrorOutcome: 凭据失效与签名失败要给出可操作的提示", () => {
  assert.match(checkinErrorOutcome({ errorCode: "APIG.0602", message: "Invalid token" }).message, /重新登录/);
  assert.match(checkinErrorOutcome({ message: "verify ak sk signature fail" }).message, /AK\/SK/);
});

test("modelRetired: 福利下线后两条通道都不通的模型被摘掉，能跑的留着", () => {
  // 2026-10-20 实测：带福利头 4004，不带福利头 404 model is not registered
  for (const id of ["deepseek-v4-pro-0813", "glm-5.3-flash", "deepseek-v4-flash-0731"]) {
    assert.equal(modelRetired(id), true, `${id} 应退役`);
    assert.equal(modelRetired(id.toUpperCase()), true, `${id} 大小写不敏感`);
  }
  // 不带福利头能正常推理的 —— 必须留着
  for (const id of ["deepseek-v4.1-flash", "openpangu-2.0-flash", "GLM-5.2"]) {
    assert.equal(modelRetired(id), false, `${id} 还能跑，不该退役`);
    assert.ok(codeartsModels()[id], `${id} 应该在清单里`);
  }
});

test("provider.models: 云端清单里的退役模型同样被过滤掉", async () => {
  const plugin = await mod.default({}, {});
  const real = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({
    result: {
      models: [
        { model_id: "deepseek-v4-pro-0813", context_window: 1000000, max_tokens: 393216, channel: "benefit" },
        { model_id: "deepseek-v4.1-flash", context_window: 1000000, max_tokens: 393216, channel: "benefit" },
      ],
    },
  }), { status: 200 });
  try {
    const r = await plugin.provider.models({ models: {} }, { auth: { type: "api", key: AK, metadata: { sk: SK } } });
    assert.equal(r["deepseek-v4-pro-0813"], undefined, "退役模型不该被发布（否则宿主轮询到就是不带 failover 的 400）");
    assert.ok(r["deepseek-v4.1-flash"]);
  } finally {
    globalThis.fetch = real;
    channelCache.clear();
  }
});

test("checkinPlan: 旧版把 opengw 福利通道当签到 —— 它下线后不该再影响到签到结论", () => {
  // 2026-10-20 实测：balance / claim / config 三个 opengw 接口同时回
  // `invalid channel, group not found`。积分签到走的是 snap 侧的 /v1/ops/*，
  // 与这本账无关，所以签到不再读它、也不该据它报 ineligible。
  const r = checkinPlan(dailyCampaign({ status: "CONFIRMED", claimable: false }));
  assert.equal(r.outcome, "done");
});

test("gatewayRetired: 只认「网关下线」这一句，临时错误照旧可重试", () => {
  assert.equal(gatewayRetired(new Error("CodeArts /api/v1/user/tokens/balance 业务错误 4000: invalid channel, group not found")), true);
  assert.equal(gatewayRetired(new Error("CodeArts /api/v1/benefit/claim HTTP 502: bad gateway")), false);
  assert.equal(gatewayRetired(new Error("CodeArts 请求失败: fetch failed")), false);
});

test("provider.models: 权益网关永久下线时静默退回静态清单（不再每次刷一条 listError）", async () => {
  const plugin = await mod.default({}, {});
  const real = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response(JSON.stringify({ error_code: "4000", error_msg: "invalid channel, group not found", result: null }), {
      status: 200, headers: { "content-type": "application/json" },
    });
  let got;
  try {
    got = await plugin.provider.models({ models: codeartsModels() }, { auth: { type: "api", key: AK, metadata: { sk: SK } } });
  } finally {
    globalThis.fetch = real;
  }
  assert.deepEqual(got, codeartsModels(), "应原样退回静态清单");

  // 网络类错误仍要抛（宿主据此显示 listError）
  globalThis.fetch = async () => { throw new Error("fetch failed"); };
  let threw = false;
  try {
    await plugin.provider.models({ models: codeartsModels() }, { auth: { type: "api", key: AK, metadata: { sk: SK } } });
  } catch { threw = true; } finally { globalThis.fetch = real; }
  assert.equal(threw, true, "临时错误必须上抛");
});

// ---------------------------------------------------------------------------
// 签到：完整流程（checkinFlow）—— 查活动 → claim → confirm
// ---------------------------------------------------------------------------

/** 按路径分派的假上游，并记录每次调用（含签名后的头与 body）。 */
const jsonResponse = (payload, status = 200) =>
  new Response(JSON.stringify(payload), { status, headers: { "content-type": "application/json" } });

function opsResponder(routes = {}) {
  const calls = [];
  const respond = async (url, init = {}) => {
    const u = new URL(String(url));
    const body = init.body ? JSON.parse(String(init.body)) : undefined;
    calls.push({ path: u.pathname, search: u.search, method: init.method ?? "GET", body, headers: init.headers ?? {} });
    const reply = (route, fallback) =>
      typeof route === "function" ? route(body) : jsonResponse(route ?? fallback);
    if (u.pathname.endsWith("/v1/ops/delivery")) {
      return reply(routes.delivery, { code: 0, message: "ok", data: { items: [] } });
    }
    if (u.pathname.endsWith("/v1/ops/claim")) {
      return reply(routes.claim, { code: 0, message: "ok", data: { id: 42, benefitAmount: 1000 } });
    }
    if (u.pathname.endsWith("/v1/ops/confirm")) {
      return reply(routes.confirm, { code: 0, message: "ok", data: {} });
    }
    if (u.pathname.includes("/snap-manager/v1/statistics/plugin")) {
      return reply(routes.stats, { metrics: [] });
    }
    return jsonResponse(
      { error_code: "APIG.0101", error_msg: "The API does not exist or has not been published in the environment" },
      404,
    );
  };
  respond.calls = calls;
  return respond;
}

/** 用给定的 fetch 实现跑一次 checkin()。 */
async function checkinWith(respond) {
  const plugin = await pluginWith();
  const real = globalThis.fetch;
  globalThis.fetch = respond;
  try {
    return await plugin.auth.checkin(async () => ({ type: "api", key: AK, metadata: { sk: SK } }));
  } finally {
    globalThis.fetch = real;
  }
}

const deliveryOf = (items) => ({ code: 0, message: "ok", data: { channel: "IDE", serverTime: 1, items } });

test("checkinFlow: ELIGIBLE → claim + confirm，body 带 channel 与 idempotentKey", async () => {
  const f = opsResponder({ delivery: deliveryOf([dailyCampaign()]) });
  const r = await checkinWith(f);
  assert.equal(r.outcome, "claimed");
  assert.equal(r.credit, 1000);
  const paths = f.calls.map((c) => `${c.method} ${c.path}`);
  assert.deepEqual(paths, ["GET /v1/ops/delivery", "POST /v1/ops/claim", "POST /v1/ops/confirm"]);
  const claim = f.calls[1];
  assert.equal(claim.body.campaignId, 1);
  assert.equal(claim.body.channel, "IDE", "channel 必须放在 body —— 缺了上游回「channel : 参数无效」");
  assert.match(claim.body.idempotentKey, /^claim_1_\d+$/);
  // confirm 不带 channel / idempotentKey（带了 channel 上游会 HTTP 400）
  assert.deepEqual(f.calls[2].body, { campaignId: 1 });
});

test("checkinFlow: claim 成功但每日活动的 confirm 失败 → 仍然报 claimed（积分已到账）", async () => {
  // confirm 只是收尾：它失败不能把「已经领到积分」说成签到失败。
  // 变异：把 claim 分支里那次 confirm 的 try/catch 去掉 → 异常穿透到钩子外层
  // catch → 返回 failed，本条会红。
  const f = opsResponder({
    delivery: deliveryOf([dailyCampaign()]),
    claim: { code: 0, message: "ok", data: { id: 42, benefitAmount: 1000 } },
    confirm: { code: 50000, message: "系统繁忙" },
  });
  const r = await checkinWith(f);
  assert.equal(r.outcome, "claimed");
  assert.equal(r.credit, 1000);
});

test("checkinFlow: 第一步（活动清单）就失败也要映射成契约，而不是把异常抛给宿主", async () => {
  // delivery 业务码（HTTP 200 + code!=0）
  const business = opsResponder({ delivery: { code: 40401, message: "运营事件不存在: 1" } });
  assert.equal((await checkinWith(business)).outcome, "ineligible");

  // delivery 的 APIG 层错误（HTTP 500）
  const apig = opsResponder({
    delivery: () => jsonResponse({ error_code: "APIG.0502", error_msg: "service unavailable" }, 500),
  });
  const r = await checkinWith(apig);
  assert.equal(r.outcome, "failed");
  assert.ok(["claimed", "done", "ineligible", "inactive", "captcha", "failed"].includes(r.outcome));
});

test("checkinFlow: 活动清单里多条每日活动时取第一条（顺序确定，不随机）", async () => {
  const f = opsResponder({
    delivery: deliveryOf([
      { campaignId: 1, type: "USER_LOGIN", benefitAmount: 1000, status: "ELIGIBLE", claimable: true },
      { campaignId: 99, type: "USER_LOGIN", benefitAmount: 9999, status: "ELIGIBLE", claimable: true },
    ]),
  });
  const r = await checkinWith(f);
  assert.equal(r.credit, 1000, "取第一条（上游下发的顺序即优先级）");
  assert.equal(f.calls.find((c) => c.method === "POST").body.campaignId, 1);
});

test("checkinFlow: 活动清单必须按 channel=IDE 查（网页端才是 WEB）", async () => {
  const f = opsResponder({ delivery: deliveryOf([dailyCampaign()]) });
  await checkinWith(f);
  assert.equal(f.calls[0].search, "?channel=IDE");
  assert.match(String(f.calls[0].headers.Authorization ?? ""), /^SDK-HMAC-SHA256 Access=/);
});

test("checkinFlow: claim 返回 data.id 为空也照样补 confirm（不能拿 id 猜「要不要确认」）", async () => {
  const f = opsResponder({
    delivery: deliveryOf([dailyCampaign()]),
    claim: { code: 0, message: "ok", data: { id: null, benefitAmount: 1000 } },
    // 没有待确认记录时上游回 40001 —— 属于正常，不许影响结论
    confirm: { code: 40001, message: "该活动没有可确认的权益记录" },
  });
  const r = await checkinWith(f);
  assert.equal(r.outcome, "claimed");
  assert.equal(r.credit, 1000);
  assert.deepEqual(f.calls.map((c) => c.method), ["GET", "POST", "POST"], "仍然要补一次 confirm");
});

test("checkinFlow: 补 confirm 报 40001 不当成「确认失败」（那个码是「没有待确认记录」）", async () => {
  const f = opsResponder({
    delivery: deliveryOf([dailyCampaign({ status: "CLAIMED", claimable: false })]),
    confirm: { code: 40001, message: "该活动没有可确认的权益记录" },
  });
  const r = await checkinWith(f);
  assert.equal(r.outcome, "done", "没有待确认记录 = 已经处理完，不是失败");
  assert.match(r.message, /已确认|已签到/);
});

test("checkinFlow: confirm 报其它错 → failed（状态会停在 CLAIMED，交给宿主下一轮补）", async () => {
  const f = opsResponder({
    delivery: deliveryOf([dailyCampaign({ status: "CLAIMED", claimable: false })]),
    confirm: { code: 50000, message: "系统繁忙" },
  });
  assert.equal((await checkinWith(f)).outcome, "failed");
});

test("checkinFlow: 活动号缺失/为 null 时不发畸形写请求", async () => {
  // type 认得出来但没有可用活动号 —— 发出去只会变成 {campaignId: null} 或字段被丢掉
  const f = opsResponder({ delivery: deliveryOf([{ type: "USER_LOGIN", status: "ELIGIBLE", claimable: true }]) });
  const r = await checkinWith(f);
  assert.equal(r.outcome, "ineligible");
  assert.deepEqual(f.calls.map((c) => c.method), ["GET"], "一个写请求都不该发");
});

test("checkinFlow: 补确认时跳过活动号非法的条目（null / 0 / 字符串垃圾）", async () => {
  const f = opsResponder({
    delivery: deliveryOf([
      dailyCampaign({ status: "CONFIRMED", claimable: false }),
      { campaignId: null, type: "NEW_USER_REGISTER", benefitAmount: 4000, status: "CLAIMED" },
      { campaignId: 0, type: "INVITE_USER", benefitAmount: 1000, status: "CLAIMED" },
    ]),
  });
  const r = await checkinWith(f);
  assert.equal(r.outcome, "done");
  assert.deepEqual(f.calls.map((c) => c.method), ["GET"], "非法活动号不该触发 confirm");
  assert.doesNotMatch(r.message, /4000/, "没确认成功就不能把它写进结果");
});

test("checkinFlow: CLAIMED → 只补 confirm（不发 claim，绝不重复领取）", async () => {
  const f = opsResponder({ delivery: deliveryOf([dailyCampaign({ status: "CLAIMED", claimable: false })]) });
  const r = await checkinWith(f);
  assert.equal(r.outcome, "done");
  assert.equal(r.credit, 1000);
  assert.deepEqual(f.calls.map((c) => c.path), ["/v1/ops/delivery", "/v1/ops/confirm"]);
});

test("checkinFlow: CONFIRMED → done，一个写请求都不发", async () => {
  const f = opsResponder({ delivery: deliveryOf([dailyCampaign({ status: "CONFIRMED", claimable: false })]) });
  const r = await checkinWith(f);
  assert.equal(r.outcome, "done");
  assert.deepEqual(f.calls.map((c) => c.method), ["GET"]);
});

test("checkinFlow: 清单里没有每日签到活动 → ineligible，不发写请求", async () => {
  const f = opsResponder({ delivery: deliveryOf([{ campaignId: 3, type: "INVITE_USER", status: null }]) });
  const r = await checkinWith(f);
  assert.equal(r.outcome, "ineligible");
  assert.deepEqual(f.calls.map((c) => c.method), ["GET"]);
});

test("checkinFlow: 顺带补确认其它卡在 CLAIMED 的活动（新用户注册 4000 积分）", async () => {
  const f = opsResponder({
    delivery: deliveryOf([
      dailyCampaign({ status: "CONFIRMED", claimable: false }),
      { campaignId: 4, type: "NEW_USER_REGISTER", benefitAmount: 4000, status: "CLAIMED", claimable: false },
    ]),
  });
  const r = await checkinWith(f);
  assert.equal(r.outcome, "done");
  assert.deepEqual(f.calls.map((c) => c.path), ["/v1/ops/delivery", "/v1/ops/confirm"]);
  assert.equal(f.calls[1].body.campaignId, 4);
  assert.match(r.message, /4000/, "到手的 4000 积分要写在结果里");
});

test("checkinFlow: 补确认失败不影响签到结论（积分在 claim 时就已到账）", async () => {
  const f = opsResponder({
    delivery: deliveryOf([
      dailyCampaign({ status: "ELIGIBLE" }),
      { campaignId: 4, type: "NEW_USER_REGISTER", benefitAmount: 4000, status: "CLAIMED" },
    ]),
    // 只让「新用户注册」那次确认失败
    confirm: (body) => (body.campaignId === 4 ? jsonResponse({ code: 50000, message: "boom" }) : jsonResponse({ code: 0, message: "ok", data: {} })),
  });
  const r = await checkinWith(f);
  assert.equal(r.outcome, "claimed");
  assert.equal(r.credit, 1000);
  assert.doesNotMatch(r.message, /4000/, "没确认成功就不能把 4000 写进结果");
});

test("checkinFlow: 每天的活动按 type 认，不按标题（标题会被上游改文案）", async () => {
  const f = opsResponder({ delivery: deliveryOf([dailyCampaign({ title: "签到", status: "ELIGIBLE" })]) });
  assert.equal((await checkinWith(f)).outcome, "claimed");
});

test("checkinFlow: campaignId 认得出字符串形式的活动（上游两种都出现过）", async () => {
  const f = opsResponder({ delivery: deliveryOf([dailyCampaign({ campaignId: "1", type: undefined })]) });
  assert.equal((await checkinWith(f)).outcome, "claimed");
});

test("checkinFlow: claim 业务码 40001 → done（今天这一轮已领过）", async () => {
  const f = opsResponder({
    delivery: deliveryOf([dailyCampaign()]),
    claim: { code: 40001, message: "尚未到达权益刷新时间" },
  });
  const r = await checkinWith(f);
  assert.equal(r.outcome, "done");
});

test("checkinFlow: claim 业务码 40401（活动已下线）→ ineligible，不再每 30 分钟重试", async () => {
  const f = opsResponder({
    delivery: deliveryOf([dailyCampaign()]),
    claim: { code: 40401, message: "运营事件不存在: 1" },
  });
  assert.equal((await checkinWith(f)).outcome, "ineligible");
});

test("checkinFlow: 网络错误 → failed（宿主 30 分钟后重试）", async () => {
  const r = await checkinWith(async () => { throw new Error("fetch failed"); });
  assert.equal(r.outcome, "failed");
});

test("checkinFlow: 未登录 / 无凭据 → inactive", async () => {
  const plugin = await pluginWith();
  assert.equal((await plugin.auth.checkin(async () => ({ type: "api", key: "" }))).outcome, "inactive");
});

test("checkinFlow: 结果只带 magpie 契约里的字段（outcome / credit / message）", async () => {
  const f = opsResponder({ delivery: deliveryOf([dailyCampaign()]) });
  const r = await checkinWith(f);
  assert.deepEqual(Object.keys(r).sort(), ["credit", "message", "outcome"]);
});

// ---------------------------------------------------------------------------
// snap 信封（前缀规则与业务码都藏在这里）
// ---------------------------------------------------------------------------

/** 用给定的 fetch 实现跑一段。 */
async function withFetch(respond, fn) {
  const real = globalThis.fetch;
  globalThis.fetch = respond;
  try {
    return await fn();
  } finally {
    globalThis.fetch = real;
  }
}

test("snapEnvelope: /v1/ops 的 code 非 0 抛业务码（HTTP 仍是 200）", async () => {
  await withFetch(
    async () => jsonResponse({ code: 40401, message: "运营事件不存在: 1" }),
    async () => {
      await assert.rejects(
        () => snapEnvelope("/v1/ops/claim", { method: "POST", ak: AK, sk: SK, body: { campaignId: 1 } }),
        (e) => e.errorCode === "40401",
      );
    },
  );
});

test("snapEnvelope: code 为字符串 \"0\" 也算成功（上游两种写法都有）", async () => {
  const r = await withFetch(async () => jsonResponse({ code: "0", message: "ok", data: { id: 7 } }), () =>
    snapEnvelope("/v1/ops/claim", { method: "POST", ak: AK, sk: SK, body: { campaignId: 1 } }));
  assert.deepEqual(r, { id: 7 });
});

test("snapEnvelope: statistics/plugin 是裸对象，没有 code 信封，整份返回", async () => {
  const r = await withFetch(async () => jsonResponse({ metrics: [{ name: "usageTotalPackageCredit" }] }), () =>
    snapEnvelope(STATS_PATH, { ak: AK, sk: SK }));
  assert.equal(Array.isArray(r.metrics), true, "裸对象不该被当作信封剥成空 data");
});

test("snapEnvelope: 前缀写错（APIG.0101）也带出 errorCode，别把「接口不存在」当成网络故障", async () => {
  await withFetch(
    async () =>
      jsonResponse({ error_code: "APIG.0101", error_msg: "The API does not exist or has not been published in the environment" }, 404),
    async () => {
      await assert.rejects(
        () => snapEnvelope(STATS_PATH, { ak: AK, sk: SK }),
        (e) => e.errorCode === "APIG.0101" && /APIG\.0101/.test(e.message),
      );
    },
  );
});

test("snapEnvelope: 401 APIG.0301 → 去掉 agent-type 再发一次就自愈", async () => {
  const seen = [];
  const r = await withFetch(
    async (url, init) => {
      seen.push(init.headers);
      if (seen.length === 1) {
        return jsonResponse({ error_code: "APIG.0301", error_msg: "verify ak sk signature fail" }, 401);
      }
      return jsonResponse({ metrics: [] });
    },
    () => snapEnvelope(STATS_PATH, { ak: AK, sk: SK }),
  );
  assert.deepEqual(r, { metrics: [] });
  assert.equal(seen.length, 2, "应当重发一次");
  assert.equal(seen[0]["agent-type"], "PromptCenter", "第一次带可选头");
  assert.equal(seen[1]["agent-type"], undefined, "第二次去掉可选头");
});

test("snapEnvelope: agent-type 参与签名（大写的 Agent-Type 不入签名会被 APIG 判 401）", () => {
  const h = sdkSignedHeaders("GET", `${SNAP_HOST}${STATS_PATH}`, "", AK, SK, AGENT_TYPE_HEADER);
  assert.match(h.Authorization, /SignedHeaders=[^,]*agent-type/);
});

test("snapEnvelope: query 参与签名（channel=IDE 写错就 401）", () => {
  const h = sdkSignedHeaders("GET", `${SNAP_HOST}/v1/ops/delivery?channel=IDE`, "", AK, SK, AGENT_TYPE_HEADER);
  assert.match(h.Authorization, /SignedHeaders=/);
  // canonicalQuery 进了签名：换个 channel 值签名必然不同
  const other = sdkSignedHeaders("GET", `${SNAP_HOST}/v1/ops/delivery?channel=WEB`, "", AK, SK, AGENT_TYPE_HEADER);
  assert.notEqual(h.Authorization, other.Authorization);
});

// ---------------------------------------------------------------------------
// 积分账（fetchCredits）
// ---------------------------------------------------------------------------

const statsPayload = (over = {}) => ({
  start_date: "2026-10-11",
  end_date: "2026-11-12",
  package: {
    spec_code: "codearts.agent.individual.trial",
    status: "normal",
    package_name_cn: "体验版",
    package_name_en: "Trial",
    is_token_package: false,
    is_credit_package: true,
  },
  show: { metrics: true, package: true },
  metrics: [
    { name: "usageTokenChatMessages", usage_token_num: 4170599, package_token_amount: 1 },
    {
      name: "usageTotalPackageCredit",
      package_credit_amount: 12500,
      package_credit_used: 337.22,
      package_credit_remain: 12162.78,
      package_credit_expiring_amount: 0,
    },
    { name: "usageBasicPackageCredit", package_credit_amount: 500, package_credit_used: 0, package_credit_remain: 500 },
    { name: "usageOnDemandPackageCredit", package_credit_amount: 0, package_credit_used: 0, package_credit_remain: 0 },
    { name: "usageBonusPackageCredit", package_credit_amount: 12000, package_credit_used: 337.22, package_credit_remain: 11662.78 },
  ],
  model_metrics: [],
  ...over,
});

test("fetchCredits: 只认总数，不累加分项（500 + 0 + 12000 = 12500 是构成明细）", async () => {
  const f = opsResponder({ stats: statsPayload() });
  const c = await withFetch(f, () => fetchCredits(AK, SK));
  assert.equal(c.remain, 12162.78);
  assert.equal(c.amount, 12500);
  assert.equal(c.used, 337.22);
  assert.equal(c.endDate, "2026-11-12");
  assert.equal(c.packageName, "体验版");
  assert.equal(c.isCreditPackage, true);
  // 分项只用于展示，amount=0 的不进列表
  assert.deepEqual(c.packages.map((p) => p.name), ["基础积分", "福利积分"]);
  assert.equal(f.calls[0].path, STATS_PATH, "必须带 snap-manager 前缀");
});

test("fetchCredits: 读的是总数指标本身，不是三个分项的累加", async () => {
  // 🔴 上面那个夹具里「总数 == 分项之和」在数值上完全一致，无法区分「读总数」与
  //    「累加分项」。这里故意让两者不等（上游统计滞后/分项被裁剪时就会出现），
  //    只有真去读 usageTotalPackageCredit 才拿得到 12162.78。
  const payload = statsPayload({
    metrics: [
      { name: "usageBasicPackageCredit", package_credit_amount: 100, package_credit_used: 0, package_credit_remain: 100 },
      { name: "usageBonusPackageCredit", package_credit_amount: 200, package_credit_used: 0, package_credit_remain: 200 },
      // 总数故意不放在第一位，顺序也不该影响结果
      { name: "usageTotalPackageCredit", package_credit_amount: 12500, package_credit_used: 337.22, package_credit_remain: 12162.78 },
    ],
  });
  const c = await withFetch(opsResponder({ stats: payload }), () => fetchCredits(AK, SK));
  assert.equal(c.remain, 12162.78);
  assert.equal(c.amount, 12500);
  assert.equal(c.used, 337.22);
});

test("fetchCredits: 数值就是积分，不做 token 折算（套 1 积分=10000 token 会算成 1.2 亿）", () => {
  // 上游没给任何单位换算字段，直接照抄 12162.78
  return withFetch(async () => jsonResponse(statsPayload()), async () => {
    const c = await fetchCredits(AK, SK);
    assert.ok(c.remain < 100000, "不该被放大成 token 口径");
  });
});

test("fetchCredits: 旧 Token 计费账户没有积分指标 → remain undefined，不判 0", async () => {
  const payload = statsPayload({
    package: { package_name_cn: "老套餐", is_credit_package: false, is_token_package: true },
    metrics: [{ name: "usageTokenChatMessages", usage_token_num: 100, package_token_amount: 1 }],
  });
  const c = await withFetch(opsResponder({ stats: payload }), () => fetchCredits(AK, SK));
  assert.equal(c.remain, undefined);
  assert.equal(c.isCreditPackage, false);
});

test("fetchCredits: 指标缺失/脏数据不抛（只是拿不到数）", async () => {
  const c = await withFetch(opsResponder({ stats: { metrics: [null, "x", { name: "usageTotalPackageCredit" }] } }), () =>
    fetchCredits(AK, SK));
  assert.equal(c.remain, undefined);
});

test("fetchCampaigns: 只放行对象元素（上游数组里偶尔有 null）", async () => {
  const items = await withFetch(
    opsResponder({ delivery: { code: 0, message: "ok", data: { items: [null, 7, dailyCampaign()] } } }),
    () => fetchCampaigns(AK, SK),
  );
  assert.equal(items.length, 1);
  assert.equal(items[0].campaignId, 1);
});

test("pickDailyCampaign: 按 type 认；type 缺失才退回 campaignId", () => {
  assert.equal(pickDailyCampaign([{ campaignId: 9, type: "USER_LOGIN" }]).campaignId, 9);
  assert.equal(pickDailyCampaign([{ campaignId: 1, type: "SOMETHING_ELSE" }]).campaignId, 1);
  assert.equal(pickDailyCampaign([{ campaignId: 3, type: "INVITE_USER" }]), null);
  assert.equal(pickDailyCampaign([]), null);
  assert.equal(pickDailyCampaign(undefined), null);
});

test("pickDailyCampaign: 活动号不可用的条目直接跳过（发了就是畸形请求）", () => {
  assert.equal(pickDailyCampaign([{ type: "USER_LOGIN", status: "ELIGIBLE" }]), null);
  assert.equal(pickDailyCampaign([{ campaignId: null, type: "USER_LOGIN" }]), null);
  assert.equal(pickDailyCampaign([{ campaignId: 0, type: "USER_LOGIN" }]), null);
  assert.equal(pickDailyCampaign([{ campaignId: "abc", type: "USER_LOGIN" }]), null);
  // 字符串数字是上游真实出现过的形态，要认
  assert.equal(pickDailyCampaign([{ campaignId: "1", type: "USER_LOGIN" }]).campaignId, "1");
});

test("usableCampaignId: 只认正整数（含字符串数字）", () => {
  assert.equal(usableCampaignId(1), 1);
  assert.equal(usableCampaignId("1"), 1);
  assert.equal(usableCampaignId(0), undefined);
  assert.equal(usableCampaignId(-3), undefined);
  assert.equal(usableCampaignId(null), undefined);
  assert.equal(usableCampaignId(undefined), undefined);
  assert.equal(usableCampaignId("abc"), undefined);
  assert.equal(usableCampaignId(NaN), undefined);
});

test("opsClaim / opsConfirm: 活动号非法时直接抛，绝不发出畸形写请求", async () => {
  const f = opsResponder();
  await withFetch(f, async () => {
    for (const bad of [undefined, null, 0, "abc"]) {
      // 这两个是同步抛（在 fetch 之前就挡下），用 throws 断言
      assert.throws(() => opsClaim(AK, SK, bad), /活动号/);
      assert.throws(() => opsConfirm(AK, SK, bad), /活动号/);
    }
  });
  assert.equal(f.calls.length, 0, "一次请求都不该发出去");
});

test("opsClaim: idempotentKey 是 body 字段（格式 claim_<campaignId>_<毫秒>），channel 也在 body", async () => {
  const f = opsResponder();
  await withFetch(f, () => opsClaim(AK, SK, 1, 1792515974422));
  assert.deepEqual(f.calls[0].body, { campaignId: 1, channel: "IDE", idempotentKey: "claim_1_1792515974422" });
});

test("opsConfirm: 只带 campaignId（带 channel 上游会 HTTP 400）", async () => {
  const f = opsResponder();
  await withFetch(f, () => opsConfirm(AK, SK, 1));
  assert.deepEqual(f.calls[0].body, { campaignId: 1 });
  assert.equal(f.calls[0].method, "POST");
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

test("codeartsModels: 含全部内置模型且形状正确（已退役的不在其中）", () => {
  const m = codeartsModels();
  const live = Object.keys(MODEL_META).filter((id) => !modelRetired(id));
  assert.equal(Object.keys(m).length, live.length);
  for (const id of RETIRED_MODELS) {
    assert.equal(m[id], undefined, `${id} 两条通道都不通，不该再出现在清单里`);
  }
  for (const [id, v] of Object.entries(m)) {
    assert.equal(v.id, id);
    assert.equal(typeof v.name, "string");
    assert.equal(typeof v.limit.context, "number");
    assert.equal(typeof v.limit.output, "number");
    assert.equal(v.reasoning, false);
  }
});

test("codeartsModels: context 不猜；output 用实测参数上限（不是猜的）", () => {
  for (const [id, v] of Object.entries(codeartsModels())) {
    assert.equal(v.limit.context, 0, `${id} 的 context 不该是猜出来的正数`);
    // output 不能是 0（= 不设限）：客户端会去要 393216，上游 400 → magpie 包成 200 空流
    assert.equal(v.limit.output, MAX_OUTPUT_TOKENS, `${id} 的 output 应为实测上限`);
    assert.ok(v.limit.output > 0);
  }
});

// --- 图片能力声明（0.2.13 起）---------------------------------------------
// 三态：没写 = 「没说」；`image:false` = 「明确说不收」；`image:true` = 「会看图」。
// magpie 只对**明确声明**不收图的模型硬过滤带图请求，所以「没说」和
// 「明确说不收」的行为完全不同 —— 这几个测试就是钉死这条区别。
//
// 下面三个 helper 是**照抄宿主 `internal/plugin/host.js`** 的读法，用来验证
// 「配置钩子」与「provider.models 钩子」这两条路给宿主的结论完全一致。
// 0.2.13 之所以翻车，就是云端那条路少写了 `image: false` 这个键。

/** 宿主 MODALITIES：每个键都在，值必须是布尔。 */
const HOST_MODALITIES = ["text", "image", "audio", "video", "pdf"];
const hostModalities = (list) =>
  Object.fromEntries(HOST_MODALITIES.map((k) => [k, (list ?? ["text"]).includes(k)]));

/** 宿主的 kinds()：只留值为 true 的键，一个都没有就 undefined。 */
const hostKinds = (c) => {
  if (!c || typeof c !== "object") return undefined;
  const out = Object.keys(c).filter((k) => c[k] === true);
  return out.length ? out : undefined;
};

/** 宿主从一条模型定义里最终读出的能力。 */
const hostView = (m) => ({
  image: !!m.capabilities?.input?.image,
  imageSaid: typeof m.capabilities?.input?.image === "boolean",
  inputs: hostKinds(m.capabilities?.input),
  outputs: hostKinds(m.capabilities?.output),
});

/** 宿主对**配置钩子**模型做的事：用 modalities 重建 capabilities。 */
const viaConfigHook = (entry) => ({
  capabilities: {
    temperature: true,
    toolcall: true,
    input: { text: true },
    output: { text: true },
    ...(entry.modalities?.input ? { input: hostModalities(entry.modalities.input) } : {}),
    ...(entry.modalities?.output ? { output: hostModalities(entry.modalities.output) } : {}),
  },
});

test("imageCapable: codearts 全线不收图，且清单外的模型也按「不收」处理", () => {
  // 2026-10-20 直连实测（同一端点、同一 benefit 头，只改有没有图）：
  //   deepseek-v4-pro-0813 纯文本 → 200 ；同一模型带图 → 406 not multimodal
  // AgentCenter 给的 supports_images 也是全 false。所以默认必须是 false。
  assert.equal(VISION_MODELS.size, 0, "例外名单为空 —— 不要凭一次探测就往里加");
  for (const id of Object.keys(MODEL_META)) {
    assert.equal(imageCapable(id), false, `${id} 不该被标成能收图`);
  }
  // 清单里没有的（云端新上的）同样按「不收」处理，不能退回「没说」
  assert.equal(imageCapable("brand-new-model"), false);
  assert.equal(imageCapable("kimi-k2.6-vl"), false, "名字带 vl 也不代表这个通道能用");
  // 大小写与空值
  assert.equal(imageCapable("GLM-5.2"), false);
  assert.equal(imageCapable(undefined), false, "拿不到 id 时也不能变成 true");
  assert.equal(imageCapable(""), false);
});

test("modalitiesField: 未知就不写键；只认布尔值", () => {
  assert.deepEqual(modalitiesField(undefined), {}, "未知 = 一个键都不写（保持 0.2.12 行为）");
  assert.deepEqual(modalitiesField(null), {});
  assert.deepEqual(modalitiesField("true"), {}, "字符串不算说了");
  assert.deepEqual(modalitiesField(false), { modalities: { input: ["text"], output: ["text"] } });
  assert.deepEqual(modalitiesField(true), { modalities: { input: ["text", "image"], output: ["text"] } });
});

test("capabilitiesField: image 必须是真布尔 —— 省掉 false 那个键就等于没声明", () => {
  assert.deepEqual(capabilitiesField(undefined), {}, "未知 = 一个键都不写");
  assert.deepEqual(capabilitiesField("true"), {}, "字符串不算说了");
  // 🔴 这里必须断言 typeof === "boolean"：宿主的 imageSaid 判的是
  //    `typeof m.capabilities?.input?.image === "boolean"`，
  //    写成 `{ text: true }`（省掉 image）= undefined → imageSaid 仍是 false，
  //    带图请求照旧发给纯文本模型。0.2.13 就是这么错的。
  for (const image of [true, false]) {
    const got = capabilitiesField(image);
    assert.equal(typeof got.capabilities.input.image, "boolean", `image=${image} 时 image 键必须在且是布尔`);
    assert.equal(got.capabilities.input.image, image);
    assert.equal(got.capabilities.input.text, true, "text 不能被挤掉");
    assert.deepEqual(got.capabilities.output, hostModalities(["text"]));
  }
});

test("两条路给宿主的结论必须一致（配置钩子 vs provider.models 钩子）", () => {
  for (const image of [true, false]) {
    const fromConfig = hostView(viaConfigHook(modalitiesField(image)));
    const fromHook = hostView(capabilitiesField(image));
    assert.deepEqual(fromHook, fromConfig, `image=${image} 时两条路的 image/imageSaid/inputs/outputs 必须一致`);
    assert.equal(fromHook.imageSaid, true, "声明了就必须是「说过了」，不能退回「没说」");
    assert.equal(fromHook.image, image);
    assert.deepEqual(fromHook.inputs, image ? ["text", "image"] : ["text"]);
    assert.deepEqual(fromHook.outputs, ["text"]);
  }
  // 没声明：两条路都保持「没说」，行为退回 0.2.12
  assert.equal(hostView(viaConfigHook(modalitiesField(undefined))).imageSaid, false);
  assert.equal(hostView(capabilitiesField(undefined)).imageSaid, false);
});

test("配置钩子路径: 每个模型在宿主眼里都是「明确说不收图」", () => {
  for (const [id, v] of Object.entries(codeartsModels())) {
    const seen = hostView(viaConfigHook(v));
    assert.equal(seen.imageSaid, true, `${id} 必须明确声明收不收图，不能是「没说」`);
    assert.equal(seen.image, false, `${id} 实测不收图`);
  }
});

test("codeartsModels（配置钩子路径）: 每个模型都带 modalities，只有文本", () => {
  for (const [id, v] of Object.entries(codeartsModels())) {
    assert.deepEqual(v.modalities.output, ["text"], `${id} 的输出只有文本`);
    assert.deepEqual(v.modalities.input, ["text"], `${id} 实测不收图，输入只声明文本`);
  }
});

test("outputLimit: 云端超过参数上限的值被收敛，正常值原样保留", () => {
  assert.equal(outputLimit(393216), MAX_OUTPUT_TOKENS, "393216 → 65536");
  assert.equal(outputLimit(384000), MAX_OUTPUT_TOKENS);
  assert.equal(outputLimit(131072), MAX_OUTPUT_TOKENS);
  assert.equal(outputLimit(4096), 4096, "上限以内的真实值不能动");
  assert.equal(outputLimit(65536), 65536, "恰好等于上限");
  assert.equal(outputLimit(0), undefined, "0 = 没给");
  assert.equal(outputLimit(undefined), undefined);
  assert.equal(outputLimit("abc"), undefined);
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
  // api 是 **base**：宿主会用它兜底拼 `base + "/chat/completions"`，
  // 写完整端点会拼出 `…/api/v2/chat/completions/chat/completions`
  assert.equal(cfg.provider.codearts.api, `${SNAP_HOST}/api/v2`);
  assert.ok(!cfg.provider.codearts.api.endsWith("/chat/completions"));
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

test("authorize: 成功时返回的 metadata 把宿主会合并进来的 credential 盖成空串", async () => {
  // 宿主 save(): md = { ...inputs, ...result.metadata } —— inputs 里就带着
  // prompt 收集的原始 "AK:SK" 组合串，不盖就会原样落到 plugin-auth.json。
  const plugin = await mod.default({}, {});
  const real = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({ result: { total_quota: 1, total_balance: 1 } }), { status: 200 });
  let r;
  try {
    r = await plugin.auth.methods[0].authorize({ credential: `${AK}:${SK}` });
  } finally {
    globalThis.fetch = real;
  }
  assert.equal(r.type, "success");
  assert.equal(r.key, AK);
  assert.equal(r.metadata.sk, SK);
  assert.equal(r.metadata.credential, "", "必须覆盖 prompt 里的组合串");
  const merged = { credential: `${AK}:${SK}`, ...r.metadata };
  assert.equal(merged.credential, "", "合并后不能残留 AK:SK");
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
  // baseURL 必须含 /api/v2：宿主按 baseURL + "/chat/completions" 拼
  assert.equal(l.baseURL, `${SNAP_HOST}/api/v2`);
  assert.equal(typeof l.fetch, "function");
});

test("loader: 宿主拼出来的 URL 正好是对话端点（URL 拼接回归）", async () => {
  const plugin = await mod.default({}, {});
  const l = await plugin.auth.loader(async () => ({ type: "api", key: AK, metadata: { sk: SK } }));
  assert.equal(hostUrl(l.baseURL), `${SNAP_HOST}${CHAT_PATH}`);
  // 端到端：宿主给的 URL → 发出去仍是对端点，且带 maas 三头
  const s = await callLoader(plugin, { init: { method: "POST", body: JSON.stringify({ model: "deepseek-v4.1-flash" }) } });
  assert.equal(s.url, `${SNAP_HOST}${CHAT_PATH}`);
  assert.equal(s.init.headers.get("maas_type"), "benefit");
});

/**
 * 模拟宿主 internal/provider/plugins.go 的 pluginFetch URL 拼接。
 *
 * 宿主并不用 provider.api 拼 URL：它给插件 provider 的对话地址是固定的
 * `plugin://<id>/v1`（Chat 协议），于是
 *   rest  = "/v1/chat/completions"
 *   url   = baseURL + TrimPrefix(rest, "/v1")  ← 因为 rest 以 "/v1/" 开头
 *         = baseURL + "/chat/completions"
 *
 * 插件把 provider.api 设成 `${SNAP_HOST}${CHAT_PATH}`，而 baseURL 给了
 * `${SNAP_HOST}/api/v2` —— 两者拼起来正好是对话端点。
 */
function hostUrl(baseURL) {
  const base = String(baseURL).replace(/\/+$/, "");
  const rest = "/v1/chat/completions";
  return rest.startsWith("/v1/") ? base + rest.slice(3) : base + rest;
}

/**
 * 跑一次 loader 的 fetch，返回实际发出去的 {url, init}。
 * 只接手 SNAP_HOST 的地址，所以对话测试必须用宿主会给的 URL。
 */
async function callLoader(plugin, { key = AK, sk = SK, url, init = {}, respond } = {}) {
  const l = await plugin.auth.loader(async () => ({ type: "api", key, metadata: { sk: SK } }));
  const target = url ?? hostUrl(l.baseURL);
  let seen;
  const real = globalThis.fetch;
  globalThis.fetch = respond ?? (async (u, i) => { seen = { url: u, init: i }; return new Response("{}", { status: 200 }); });
  try {
    const res = await l.fetch(target, init);
    seen = { ...(seen ?? {}), res };
  } finally {
    globalThis.fetch = real;
  }
  return seen;
}

test("loader.fetch: 宿主若只给 …/chat/completions（漏了 /api/v2），补回来再签名", async () => {
  const plugin = await mod.default({}, {});
  // 兜底路径：万一宿主换了拼法，请求也不能静默 404（APIG.0101）
  for (const wrong of [`${SNAP_HOST}/chat/completions`, `${SNAP_HOST}/v1/chat/completions`]) {
    const s = await callLoader(plugin, {
      url: wrong,
      init: { method: "POST", body: JSON.stringify({ model: "deepseek-v4.1-flash" }) },
    });
    assert.equal(s.url, `${SNAP_HOST}${CHAT_PATH}`, `${wrong} 应被补成真实端点`);
    assert.equal(s.init.headers.get("maas_type"), "benefit", "补正后仍然认得出是对话请求");
    assert.equal(s.init.headers.get("x-ot-session-id"), upstreamSessionId(AK));
  }
});

test("loader.fetch: 非对话路径不补 /api/v2（/v1/model/builtin 不属于 /api/v2）", async () => {
  const plugin = await mod.default({}, {});
  const u = `${SNAP_HOST}/v1/model/builtin`;
  const s = await callLoader(plugin, { url: u, init: { method: "GET" } });
  assert.equal(s.url, u);
});

test("normalizeChatBody: 超过 65536 的输出字段被收敛", () => {
  const big = JSON.stringify({ model: "m", max_tokens: 393216, messages: [], stream: false });
  assert.equal(JSON.parse(normalizeChatBody(big)).max_tokens, MAX_OUTPUT_TOKENS);
  const ok = JSON.stringify({ model: "m", max_tokens: 4096, stream: false });
  assert.equal(normalizeChatBody(ok), null, "上限以内不该改写");
  assert.equal(normalizeChatBody(JSON.stringify({ model: "m", stream: false })), null, "没这个字段不该改写");
  assert.equal(normalizeChatBody("not json"), null, "不是 JSON 就交给上游");
  assert.equal(normalizeChatBody(""), null);
  assert.equal(normalizeChatBody("[1,2]"), null, "数组不是对话体");
  // 三个名字都认
  const three = JSON.stringify({ max_completion_tokens: 999999, max_output_tokens: 70000, stream: false });
  const got = JSON.parse(normalizeChatBody(three));
  assert.equal(got.max_completion_tokens, MAX_OUTPUT_TOKENS);
  assert.equal(got.max_output_tokens, MAX_OUTPUT_TOKENS);
});

test("normalizeChatBody: 缺省 stream 补成 false（上游缺省按 SSE 应答，错误会被吞成 200 空回答）", () => {
  // 实测：body 不带 stream 字段 → 上游 content-type text/event-stream，
  // 错误事件是 {"error_code","error_msg"}，magpie 嗅探器只认 {"error"}，
  // 于是 unknown model 变成 HTTP 200 + content:null + 0 tokens。
  const got = JSON.parse(normalizeChatBody(JSON.stringify({ model: "m", messages: [] })));
  assert.equal(got.stream, false);
  assert.equal(got.model, "m", "其它字段不能丢");
});

test("normalizeChatBody: 已显式写出的 stream 一律不动（true/false 都不改）", () => {
  for (const v of [true, false]) {
    const body = JSON.stringify({ model: "m", stream: v });
    assert.equal(normalizeChatBody(body), null, `stream:${v} 不该被改写`);
  }
});

test("loader.fetch: 裸模型 max_tokens=393216 在签名前被降到 65536（签名与实际 body 一致）", async () => {
  const plugin = await mod.default({}, {});
  const s = await callLoader(plugin, {
    init: { method: "POST", body: JSON.stringify({ model: "deepseek-v4.1-flash", max_tokens: 393216, stream: true }) },
  });
  const sent = JSON.parse(s.init.body);
  assert.equal(sent.max_tokens, MAX_OUTPUT_TOKENS, "发出去的就该是 65536");
  assert.equal(sent.model, "deepseek-v4.1-flash", "其它字段不能丢");
  assert.equal(sent.stream, true, "调用方写了 stream:true 就必须保留");
  // 签名覆盖的是**改写后**的 body：用同样的 body 重算必须一致
  const expected = sdkSignedHeaders("POST", s.url, s.init.body, AK, SK, {
    ...sessionHeaders(AK), maas_type: "benefit", "model-id": "deepseek-v4.1-flash", "model-name": "deepseek-v4.1-flash",
  });
  assert.equal(s.init.headers.get("Authorization"), expected.Authorization, "签名必须对应实际发出的 body");
});

test("loader.fetch: 非流式对话请求会被补上显式 stream:false", async () => {
  const plugin = await mod.default({}, {});
  const s = await callLoader(plugin, {
    init: { method: "POST", body: JSON.stringify({ model: "deepseek-v4.1-flash", messages: [{ role: "user", content: "hi" }] }) },
  });
  assert.equal(JSON.parse(s.init.body).stream, false);
  const expected = sdkSignedHeaders("POST", s.url, s.init.body, AK, SK, {
    ...sessionHeaders(AK), maas_type: "benefit", "model-id": "deepseek-v4.1-flash", "model-name": "deepseek-v4.1-flash",
  });
  assert.equal(s.init.headers.get("Authorization"), expected.Authorization, "签名必须对应补过 stream 的 body");
});

test("loader.fetch: 已经合规的 body 原样转发（连字节都不该变）", async () => {
  const plugin = await mod.default({}, {});
  const body = JSON.stringify({ model: "deepseek-v4.1-flash", max_tokens: 4096, stream: false });
  const s = await callLoader(plugin, { init: { method: "POST", body } });
  assert.equal(s.init.body, body, "上限以内且 stream 已写明 → 一个字节都不改");
});

test("loader.fetch: benefit 模型带三头，agent 模型不带", async () => {
  const plugin = await mod.default({}, {});
  const a = await callLoader(plugin, { init: { method: "POST", body: JSON.stringify({ model: "glm-5.3-flash" }) } });
  const b = await callLoader(plugin, { init: { method: "POST", body: JSON.stringify({ model: "GLM-5.2" }) } });
  assert.match(a.init.headers.get("Authorization"), /maas_type/, "benefit 模型应带 maas_type");
  assert.equal(a.init.headers.get("maas_type"), "benefit");
  assert.doesNotMatch(b.init.headers.get("Authorization"), /maas_type/, "agent 模型不该带 maas_type");
  assert.equal(b.init.headers.get("maas_type"), null);
});

test("loader.fetch: 不把 magpie 只给插件看的交接头转给上游", async () => {
  const plugin = await mod.default({}, {});
  const s = await callLoader(plugin, {
    init: {
      method: "POST",
      body: JSON.stringify({ model: "deepseek-v4.1-flash" }),
      headers: {
        "x-magpie-work-dir": "/Users/someone/private/repo",
        "x-magpie-work-git": "https://github.com/someone/private",
        accept: "application/json",
      },
    },
  });
  assert.equal(s.init.headers.get("x-magpie-work-dir"), null, "工作目录不能泄露给上游厂商");
  assert.equal(s.init.headers.get("x-magpie-work-git"), null, "仓库地址不能泄露给上游厂商");
  assert.equal(s.init.headers.get("accept"), "application/json", "其它头照旧保留");
});

test("loader.fetch: 同主机但换了后缀的域名不会被当成自己（防签名外泄）", async () => {
  const plugin = await mod.default({}, {});
  const l = await plugin.auth.loader(async () => ({ type: "api", key: AK, metadata: { sk: SK } }));
  const evil = `${SNAP_HOST}.evil.example/api/v2/chat/completions`;
  let seen;
  const real = globalThis.fetch;
  globalThis.fetch = async (u, i) => { seen = { url: u, init: i }; return new Response("{}", { status: 200 }); };
  try {
    await l.fetch(evil, { method: "POST", body: JSON.stringify({ model: "deepseek-v4.1-flash" }) });
  } finally {
    globalThis.fetch = real;
  }
  assert.equal(seen.url, evil);
  assert.equal(seen.init.headers, undefined, "签名绝不能发给形似域名");
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
// 响应侧：上游把错误藏在 HTTP 200 里（第四轮实测发现）
// ---------------------------------------------------------------------------

test("upstreamError: 认出 error_code / error_msg 形态", () => {
  assert.deepEqual(upstreamError('{"error_code":"4005","error_msg":"unsupported model","result":null}'),
    { code: "4005", message: "unsupported model" });
  assert.equal(upstreamError('{"id":"x","choices":[{"index":0,"message":{"content":"hi"}}]}'), null);
  assert.equal(upstreamError('{"error_code":"0000","error_msg":"","result":{}}'), null, "0000 是成功码");
  assert.equal(upstreamError("not json"), null);
  assert.deepEqual(upstreamError('{"error_msg":"only a message"}'), { code: "", message: "only a message" });
});

test("normalizeChatResponse: JSON 200 + error_code → 400 OpenAI 错误形态", async () => {
  const res = new Response('{"error_code":"4005","error_msg":"unsupported model","result":null}', {
    status: 200, headers: { "content-type": "application/json" },
  });
  const out = await normalizeChatResponse(res);
  assert.equal(out.status, 400);
  const body = JSON.parse(await out.text());
  assert.equal(body.error.message, "unsupported model");
  assert.equal(body.error.code, "4005");
});

test("normalizeChatResponse: 正常 JSON 200 原样返回", async () => {
  const ok = '{"id":"x","choices":[{"index":0,"message":{"content":"hi"}}]}';
  const out = await normalizeChatResponse(new Response(ok, { status: 200, headers: { "content-type": "application/json" } }));
  assert.equal(out.status, 200);
  assert.equal(await out.text(), ok);
});

test("normalizeChatResponse: 流式首事件就是错误 → 整条改成 400", async () => {
  const res = new Response('data:{"error_code":"4005","error_msg":"unsupported model","result":null}\ndata:\n\n', {
    status: 200, headers: { "content-type": "text/event-stream" },
  });
  const out = await normalizeChatResponse(res);
  assert.equal(out.status, 400);
  assert.equal(JSON.parse(await out.text()).error.message, "unsupported model");
});

test("normalizeChatResponse: 流式中途的错误事件改写成 {\"error\":…}，其余分片原样", async () => {
  const mid = 'data:{"id":"a","choices":[{"delta":{"content":"hi"}}]}\n\ndata:{"error_code":"4005","error_msg":"boom","result":null}\n\ndata:[DONE]\n\n';
  const out = await normalizeChatResponse(new Response(mid, { status: 200, headers: { "content-type": "text/event-stream" } }));
  assert.equal(out.status, 200);
  const text = await out.text();
  assert.match(text, /"error":\{"message":"boom"/);
  assert.ok(!text.includes("error_code"), "上游形态不能留在流里（客户端认不出）");
  assert.ok(text.startsWith('data:{"id":"a"'), "前面的正常分片要原样保留");
  assert.ok(text.endsWith("data:[DONE]\n\n"));
});

test("normalizeChatResponse: 正常流式一个字节都不改（含跨 chunk 断行与中文）", async () => {
  const enc = new TextEncoder();
  const parts = ['data:{"id":"a","choices":[{"delta":{"content":"你好', '世界"}}]}\n\ndata:[DONE]\n\n'];
  const res = new Response(new ReadableStream({
    start(c) { for (const p of parts) c.enqueue(enc.encode(p)); c.close(); },
  }), { status: 200, headers: { "content-type": "text/event-stream" } });
  assert.equal(await (await normalizeChatResponse(res)).text(), parts.join(""));
});

test("normalizeChatResponse: 上游迟迟不发首个事件时，超时后按时交出头且数据不丢", async () => {
  // 窥探必须有硬时限：上游长思考时可能几秒不发一个字节，而 reader.read()
  // 会在没有数据时一直挂着 —— 只判 Date.now() 是拦不住的。
  const enc = new TextEncoder();
  const t0 = Date.now();
  const res = new Response(new ReadableStream({
    start(c) {
      setTimeout(() => c.enqueue(enc.encode('data:{"id":"a","choices":[{"delta":{"content":"late"}}]}\n\ndata:[DONE]\n\n')), PEEK_MS + 400);
      setTimeout(() => c.close(), PEEK_MS + 800);
    },
  }), { status: 200, headers: { "content-type": "text/event-stream" } });
  const out = await normalizeChatResponse(res);
  const headMs = Date.now() - t0;
  assert.ok(headMs < PEEK_MS + 1000, `应在上限附近交出响应头，实际 ${headMs}ms`);
  const text = await out.text();
  assert.ok(text.includes("late"), "超时放弃窥探后，之后的正常分片必须照常转发");
  assert.ok(text.includes("[DONE]"));
});

test("normalizeChatResponse: 非 200、非对话内容类型一律原样", async () => {
  const bad = new Response("x", { status: 500, headers: { "content-type": "application/json" } });
  const out = await normalizeChatResponse(bad);
  assert.equal(out.status, 500);
  assert.equal(await out.text(), "x");
});

test("loader.fetch: 对话端点返回 200+error_code 时，交给宿主的是 400", async () => {
  const plugin = await mod.default({}, {});
  const s = await callLoader(plugin, {
    init: { method: "POST", body: JSON.stringify({ model: "nope", messages: [{ role: "user", content: "hi" }] }) },
    respond: async () =>
      new Response('{"error_code":"4005","error_msg":"unsupported model","result":null}', {
        status: 200, headers: { "content-type": "application/json" },
      }),
  });
  assert.equal(typeof s.res, "object");
  assert.equal(s.res.status, 400);
  assert.equal(JSON.parse(await s.res.text()).error.message, "unsupported model");
});

test("loader.fetch: 非对话路径不做响应改写", async () => {
  const plugin = await mod.default({}, {});
  const s = await callLoader(plugin, {
    url: `${SNAP_HOST}/v1/model/builtin`, init: { method: "GET" },
    respond: async () => new Response('{"error_code":"4005","error_msg":"x"}', {
      status: 200, headers: { "content-type": "application/json" },
    }),
  });
  assert.equal(s.res.status, 200, "别的路径不是我们的业务，别动");
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

test("usage: 凭据不完整时返回 error 而不是抛 ReferenceError", async () => {
  // 回归：catch 里用 ak/sk 做脱敏，若它们在 try 内声明，creds() 抛错后
  // catch 会再抛 ReferenceError（宿主拿到异常而非 error 字段）。
  const plugin = await mod.default({}, {});
  const u = await plugin.auth.usage(async () => ({ type: "api", key: AK })); // 只有 AK，没有 SK
  assert.equal(typeof u.error, "string");
  assert.match(u.error, /额度查询失败/);
  assert.deepEqual(u.windows, []);
});

test("usage: 凭据不完整时错误里也不会带出 AK", async () => {
  const plugin = await mod.default({}, {});
  const u = await plugin.auth.usage(async () => ({ type: "api", key: AK }));
  assert.ok(!u.error.includes(AK));
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
  assert.equal(u.windows.length, 1);
  assert.ok(Number.isFinite(u.windows[0].used));
});

// 🔴 2026-10-19：插件不再自己画签到状态行。
//    原来那行读 claim.create_time，而该字段是权益记录的创建时间，从不随签到
//    推进（两个真实账号上它与 update_time 相同、落在首次登录时刻；8 种请求
//    变体都没有让它动过），于是卡片上永远写着「今日未签」—— 用户开了自动签到
//    也还是这句。签到结果由宿主从 plugin-checkin.json 显示，插件不该再画一份。
test("usage: 不再画自己的「今日签到」状态行（宿主负责）", async () => {
  for (const claimTime of [Date.now(), 0, Date.now() - 86400_000]) {
    const u = await usageWith(balanceResponder({ total_quota: 10000000, total_balance: 9000000, used_amount: 1000000 }, claimTime));
    assert.equal(u.windows.length, 1, "只剩额度窗口");
    assert.equal(u.windows[0].name, "每日免费 Token");
    for (const w of u.windows) {
      assert.doesNotMatch(String(w.display ?? ""), /未签|已签/, "任何窗口都不该再出现签到判断");
    }
  }
});

// 断言的是「真实行为」：usage 钩子现在只打余额接口这一个请求。
test("usage: 不再为签到状态多打一次 claim 端点", async () => {
  const urls = [];
  const respond = async (url) => {
    urls.push(String(url));
    return new Response(JSON.stringify({ result: { total_quota: 10000000, total_balance: 9000000, used_amount: 1000000 } }), { status: 200 });
  };
  await usageWith(respond);
  assert.equal(urls.filter((u) => u.includes("benefit/claim")).length, 0);
  assert.equal(urls.filter((u) => u.includes("tokens/balance")).length, 1);
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

test("usage: 余额查询不带会话头（opengw 不是对话会话，且登录依赖它）", async () => {
  const seen = [];
  await usageWith(async (url, init) => {
    seen.push({ url: String(url), headers: init.headers });
    if (String(url).includes(STATS_PATH)) return jsonResponse(statsPayload());
    return new Response(JSON.stringify({ result: { total_quota: 10, total_balance: 5, used_amount: 5 } }), { status: 200 });
  });
  assert.equal(seen.length, 2, "积分账 + token 池各一次");
  for (const { headers } of seen) {
    assert.equal(headers["x-ot-session-id"], undefined, "额度类接口不该带会话头");
  }
  // 积分账走 snap 引擎：必须带 snap-manager 前缀与 agent-type 可选头
  const stats = seen.find((s) => s.url.includes(STATS_PATH));
  assert.equal(stats.headers["agent-type"], AGENT_TYPE_HEADER["agent-type"], "snap 侧接口带 agent-type");
  assert.match(stats.headers.Authorization, /agent-type/);
  // token 池走 opengw：不额外加头
  const pool = seen.find((s) => s.url.includes("tokens/balance"));
  assert.equal(pool.headers["agent-type"], undefined);
  assert.match(pool.headers.Authorization, /SignedHeaders=content-type;host;x-sdk-date, Signature=/);
});

// ---------------------------------------------------------------------------
// usage：积分账（snap 侧）—— 用户控制台上的 12000+ 就是它
// ---------------------------------------------------------------------------

/** 积分账 + token 池。任一传 undefined 表示该接口不可用。 */
const accountsResponder = (credits, balance) => async (url) => {
  if (String(url).includes(STATS_PATH)) {
    return credits === undefined
      ? jsonResponse({ error_code: "APIG.0502", error_msg: "service unavailable" }, 500)
      : jsonResponse(credits);
  }
  if (balance === undefined) return jsonResponse({ error_code: "4000", error_msg: "invalid channel, group not found" });
  return jsonResponse({ result: balance });
};

test("usage: 积分账是主窗口（token 池下线后仍能显示 12000+ 积分）", async () => {
  // token 池（opengw）= 2026-10-20 起的真实状态：整组回 invalid channel
  const u = await usageWith(accountsResponder(statsPayload(), undefined));
  assert.equal(u.windows.length, 1, "token 池取不到就不画那个窗口");
  const w = u.windows[0];
  assert.equal(w.name, "积分");
  assert.equal(w.unit, "积分");
  assert.equal(w.limit, 12500);
  assert.equal(w.amount, 337.2, "amount 是已用");
  assert.equal(w.used, 2.7, "337.22/12500 = 2.7%");
  assert.equal(w.display, "12162.8 / 12500");
  assert.match(u.balance, /12162\.8 积分/);
});

test("usage: 两本账都在时各画一个窗口，互不折算", async () => {
  const u = await usageWith(accountsResponder(statsPayload(), { total_quota: 10000000, total_balance: 7819948, used_amount: 2180052 }));
  assert.deepEqual(u.windows.map((w) => w.name), ["积分", "每日免费 Token"]);
  assert.equal(u.windows[0].unit, "积分");
  assert.equal(u.windows[1].unit, "tokens");
  assert.equal(u.windows[1].used, 21.8);
});

test("usage: 积分窗口 amount / limit 与 used 百分比自洽（宿主按 amount/limit 渲染）", async () => {
  const u = await usageWith(accountsResponder(statsPayload(), undefined));
  const w = u.windows[0];
  // 🔴 先钉死绝对值，再验自洽 —— 只验 `round1(amount/limit*100) === used` 是重言式，
  //    「把剩余当已用」这类同改两处的变异能蒙过去。
  assert.equal(w.amount, 337.2);
  assert.equal(w.limit, 12500);
  assert.equal(w.used, 2.7);
  assert.equal(round1((w.amount / w.limit) * 100), w.used);
});

test("usage: 第二个账号（不同套餐/额度/到期日）也各画各的", async () => {
  const second = statsPayload({
    end_date: "2026-11-17",
    package: { package_name_cn: "体验版", is_credit_package: true, is_token_package: false },
    metrics: [
      { name: "usageTotalPackageCredit", package_credit_amount: 7500, package_credit_used: 24.3, package_credit_remain: 7475.7 },
    ],
  });
  // 用第二个账号的凭据跑，签名必须是拿这组 AK/SK 算的
  const u = await usageWith(accountsResponder(second, undefined), "LTAI5tSECONDACCOUNT000", "SKsecond000000000000000000000000000000000");
  assert.equal(u.balance, "7475.7 积分");
  assert.equal(u.windows[0].limit, 7500);
  assert.match(u.windows[0].aside, /2026-11-17/);
});

test("usage: 积分用不完会作废 —— 套餐到期日写进 aside", async () => {
  const u = await usageWith(accountsResponder(statsPayload(), undefined));
  assert.match(u.windows[0].aside, /体验版/);
  assert.match(u.windows[0].aside, /2026-11-12/);
});

test("usage: 没有总额度字段时不产生 NaN（只报剩余）", async () => {
  const payload = statsPayload({
    metrics: [{ name: "usageTotalPackageCredit", package_credit_remain: 42, package_credit_amount: 0, package_credit_used: 0 }],
  });
  const u = await usageWith(accountsResponder(payload, undefined));
  const w = u.windows[0];
  assert.equal(w.used, 0);
  assert.ok(Number.isFinite(w.used));
  assert.equal(w.limit, undefined);
  assert.match(w.display, /42/);
});

test("usage: 非积分账户（旧 Token 计费）给出可读原因，而不是「失败」", async () => {
  const payload = statsPayload({
    package: { package_name_cn: "老套餐", is_credit_package: false, is_token_package: true },
    metrics: [],
  });
  const u = await usageWith(accountsResponder(payload, undefined));
  assert.match(u.error, /Token 计费账户/);
  assert.deepEqual(u.windows, []);
});

test("usage: 积分接口挂了但 token 池还在 → 照常出窗口，不整体报错", async () => {
  const u = await usageWith(accountsResponder(undefined, { total_quota: 10000000, total_balance: 9000000, used_amount: 1000000 }));
  assert.equal(u.windows.length, 1);
  assert.equal(u.windows[0].name, "每日免费 Token");
  assert.equal(u.error, undefined);
});

test("usage: 两本账都取不到 → error（不画空窗口）", async () => {
  const u = await usageWith(accountsResponder(undefined, undefined));
  assert.match(u.error, /积分账|额度/);
  assert.deepEqual(u.windows, []);
});

test("usage: 积分窗口的 used 在任何脏数据下都不为 NaN", async () => {
  const bodies = [
    statsPayload(),
    { metrics: [{ name: "usageTotalPackageCredit", package_credit_amount: "abc", package_credit_used: "def" }] },
    { metrics: [{ name: "usageTotalPackageCredit", package_credit_amount: 100, package_credit_used: 200 }] },
    { metrics: null },
    {},
  ];
  for (const b of bodies) {
    const u = await usageWith(accountsResponder(b, undefined));
    for (const w of u.windows) {
      assert.ok(Number.isFinite(w.used), `used 必须是有限数: ${JSON.stringify(b)} → ${w.used}`);
      assert.ok(w.amount === undefined || Number.isFinite(w.amount));
      assert.ok(w.limit === undefined || Number.isFinite(w.limit));
    }
  }
});

test("usage: 积分出现负已用 / 剩余超总额时夹住，不画负百分比、不倒欠", async () => {
  // 上游退积分或统计回滚时会给负数/越界值；宿主会照单渲染成 "-0.1%" 与 "13000 / 12500"
  const negative = await usageWith(
    accountsResponder(
      statsPayload({
        metrics: [{ name: "usageTotalPackageCredit", package_credit_amount: 12500, package_credit_used: -10, package_credit_remain: 12510 }],
      }),
      undefined,
    ),
  );
  assert.equal(negative.windows[0].used, 0);
  assert.equal(negative.windows[0].amount, 0);

  // 已用 > 总额（统计滞后）→ 夹到 100%，amount 不超过 limit
  const over = await usageWith(
    accountsResponder(
      statsPayload({
        metrics: [{ name: "usageTotalPackageCredit", package_credit_amount: 12500, package_credit_used: 99999, package_credit_remain: 0 }],
      }),
      undefined,
    ),
  );
  assert.equal(over.windows[0].used, 100);
  assert.equal(over.windows[0].amount, 12500);
});

test("usage: 积分与 token 池并行取（串行会吃掉宿主 20 秒预算的两倍）", async () => {
  const started = [];
  let release;
  const gate = new Promise((r) => { release = r; });
  const respond = async (url) => {
    started.push(String(url));
    await gate; // 谁先到都得等闸门，串行实现会在这里卡死（第二个请求永远发不出）
    if (String(url).includes(STATS_PATH)) return jsonResponse(statsPayload());
    return jsonResponse({ result: { total_quota: 10, total_balance: 5, used_amount: 5 } });
  };
  const pending = usageWith(respond);
  await new Promise((r) => setTimeout(r, 30));
  assert.equal(started.length, 2, `两个账接口必须同时在飞，实际只发了 ${started.length} 个`);
  release();
  const u = await pending;
  assert.deepEqual(u.windows.map((w) => w.name), ["积分", "每日免费 Token"]);
});

test("redact: 上游错误体里回显的 AK/SK 会被擦掉", async () => {
  const AK2 = "LTAI5tFAKEKEY000000000";
  const SK2 = "FAKESECRET0000000000000000000000000000";
  assert.equal(
    redact(`the access key ${AK2} is malformed`, AK2, SK2),
    "the access key *** is malformed",
  );
  assert.equal(redact(`bad ${SK2} here`, AK2, SK2), "bad *** here");
  // 太短的串不擦，免得把正常文本切碎
  assert.equal(redact("abc is fine", "abc", ""), "abc is fine");
  assert.equal(redact("", AK2, SK2), "");
});

test("authorize: 上游回显 Access Key 时，失败信息里不能带凭据", async () => {
  const plugin = await mod.default({}, {});
  const real = globalThis.fetch;
  const AK2 = "LTAI5tFAKEKEY000000000";
  const SK2 = "FAKESECRET0000000000000000000000000000";
  globalThis.fetch = async () => new Response(
    JSON.stringify({ error_msg: `Bad request: the access key ${AK2} is malformed`, error_code: "APIG.0602" }),
    { status: 400 },
  );
  try {
    const r = await plugin.auth.methods[0].authorize({ credential: `${AK2}:${SK2}` });
    assert.equal(r.type, "failed");
    const dump = JSON.stringify(r);
    assert.ok(!dump.includes(AK2), "失败信息里不能有 AK");
    assert.ok(!dump.includes(SK2), "失败信息里不能有 SK");
    assert.match(r.error, /malformed/, "错误原因要保留，便于排查");
  } finally {
    globalThis.fetch = real;
  }
});

// ---------------------------------------------------------------------------
// checkin
// ---------------------------------------------------------------------------

test("checkin: 未登录 → inactive", async () => {
  const plugin = await mod.default({}, {});
  assert.equal((await plugin.auth.checkin(async () => undefined)).outcome, "inactive");
});

test("checkin: 钩子打的是 snap 的活动接口，不再碰 opengw 的 benefit/claim", async () => {
  const plugin = await mod.default({}, {});
  const real = globalThis.fetch;
  const f = opsResponder({ delivery: deliveryOf([dailyCampaign({ status: "CONFIRMED", claimable: false })]) });
  globalThis.fetch = f;
  try {
    const got = await plugin.auth.checkin(async () => ({ type: "api", key: AK, metadata: { sk: SK } }));
    assert.equal(got.outcome, "done");
    assert.equal(f.calls.filter((c) => c.path.includes("benefit/claim")).length, 0, "福利通道不是签到");
    assert.deepEqual(f.calls.map((c) => c.path), ["/v1/ops/delivery"]);
  } finally {
    globalThis.fetch = real;
  }
});

test("checkin: 活动不在期 → ineligible（不是 failed，宿主不必反复重试）", async () => {
  const plugin = await mod.default({}, {});
  const real = globalThis.fetch;
  globalThis.fetch = opsResponder({ delivery: deliveryOf([dailyCampaign({ status: null, claimable: false })]) });
  try {
    const got = await plugin.auth.checkin(async () => ({ type: "api", key: AK, metadata: { sk: SK } }));
    assert.equal(got.outcome, "ineligible");
  } finally {
    globalThis.fetch = real;
  }
});

test("checkin: 网络失败 → failed（宿主 30 分钟后重试）", async () => {
  const plugin = await mod.default({}, {});
  const real = globalThis.fetch;
  globalThis.fetch = async () => { throw new Error("network blip"); };
  try {
    const got = await plugin.auth.checkin(async () => ({ type: "api", key: AK, metadata: { sk: SK } }));
    assert.equal(got.outcome, "failed");
  } finally {
    globalThis.fetch = real;
  }
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
        { model_id: "deepseek-v4.1-flash", context_window: 1000000, max_tokens: 393216, channel: "benefit" },
        { model_id: "GLM-5.2", context_window: 200000, max_tokens: 128000, channel: "agent" },
      ],
    },
  }), { status: 200 });
  try {
    const base = { "GLM-5.2": { id: "GLM-5.2", name: "GLM-5.2", limit: { context: 0, output: 0 } } };
    const r = await plugin.provider.models({ models: base }, { auth: { type: "api", key: AK, metadata: { sk: SK } } });
    assert.equal(r["deepseek-v4.1-flash"].limit.context, 1000000);
    // 云端 393216 是模型能力，上游 max_tokens 参数上限 65536 —— 发布前收敛
    assert.equal(r["deepseek-v4.1-flash"].limit.output, MAX_OUTPUT_TOKENS);
    assert.equal(r["GLM-5.2"].limit.context, 200000);
    // 缓存按账号隔离：AK 那一层里能查到本账号的判定
    const mine = channelCache.get(AK);
    assert.equal(mine.get("deepseek-v4.1-flash"), "benefit");
    assert.equal(mine.get("glm-5.2"), "agent", "键统一小写");
  } finally {
    globalThis.fetch = real;
    channelCache.clear();
  }
});

test("provider.models: 云端模型带 capabilities.input.image（钩子路径不走 modalities）", async () => {
  const plugin = await mod.default({}, {});
  const real = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({
    result: {
      models: [
        { model_id: "deepseek-v4.1-flash", context_window: 1000000, max_tokens: 393216, channel: "benefit" },
        { model_id: "GLM-5.2", context_window: 200000, max_tokens: 128000, channel: "agent" },
        { model_id: "brand-new-model", context_window: 1000, max_tokens: 100, channel: "benefit" },
      ],
    },
  }), { status: 200 });
  try {
    const r = await plugin.provider.models({ models: {} }, { auth: { type: "api", key: AK, metadata: { sk: SK } } });
    // 🔴 宿主对 provider.models 的返回值是**原样采用**的，不走 modalities 转换 ——
    // 这里写 modalities 会被静默丢掉，imageSaid 永远是 false
    for (const id of ["deepseek-v4.1-flash", "GLM-5.2"]) {
      const seen = hostView(r[id]);
      assert.equal(seen.imageSaid, true, `${id} 必须明确声明，不能是「没说」`);
      assert.equal(seen.image, false, `${id} 实测不收图（带图 → 406 not multimodal）`);
      assert.deepEqual(seen.inputs, ["text"], `${id} 只声明文本输入`);
      assert.deepEqual(seen.outputs, ["text"]);
    }
    assert.equal(r["deepseek-v4.1-flash"].modalities, undefined, "这条路上 modalities 是死字段");
    // 清单里没有的模型**同样明确声明 false**：以前是「不写键」，结果宿主照发图片 → 406
    assert.equal(hostView(r["brand-new-model"]).imageSaid, true, "清单外的模型也要明确说「不收图」");
    assert.equal(hostView(r["brand-new-model"]).image, false);
    assert.equal(r["brand-new-model"].modalities, undefined, "这条路上要用 capabilities 而不是 modalities");
  } finally {
    globalThis.fetch = real;
    channelCache.clear();
  }
});

test("provider.models: 换账号时清掉上一个账号的 channel 判定", async () => {
  const plugin = await mod.default({}, {});
  const real = globalThis.fetch;
  // 上一个账号留下的判定
  channelTable(AK).set("stale-model", "agent");
  globalThis.fetch = async () => new Response(JSON.stringify({
    result: { models: [{ model_id: "another-model", context_window: 1000, max_tokens: 100, channel: "benefit" }] },
  }), { status: 200 });
  try {
    await plugin.provider.models({ models: {} }, { auth: { type: "api", key: AK, metadata: { sk: SK } } });
    const mine = channelCache.get(AK);
    assert.equal(mine.has("stale-model"), false, "本账号的旧判定必须被清掉");
    assert.equal(mine.get("another-model"), "benefit");
  } finally {
    globalThis.fetch = real;
    channelCache.clear();
  }
});

test("provider.models: 拉取失败不清缓存，并把原因抛给宿主（宿主显示 listError）", async () => {
  const plugin = await mod.default({}, {});
  const real = globalThis.fetch;
  channelTable(AK).set("keep-me", "agent");
  globalThis.fetch = async () => new Response(JSON.stringify({ error_code: "TM.00002001", error_msg: "boom" }), { status: 200 });
  try {
    await assert.rejects(
      () => plugin.provider.models({ models: {} }, { auth: { type: "api", key: AK, metadata: { sk: SK } } }),
      /模型清单获取失败/,
    );
    assert.equal(channelTable(AK).get("keep-me"), "agent", "拉不到清单时旧判定必须保留");
  } finally {
    globalThis.fetch = real;
    channelCache.clear();
  }
});

test("provider.models: 清单里有 null 元素不会打断整份列表", async () => {
  const plugin = await mod.default({}, {});
  const real = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({
    result: { models: [null, 42, { model_id: "good-model", context_window: 1000, max_tokens: 100, channel: "benefit" }] },
  }), { status: 200 });
  try {
    const r = await plugin.provider.models({ models: {} }, { auth: { type: "api", key: AK, metadata: { sk: SK } } });
    assert.ok(r["good-model"], "正常元素要留下来");
    assert.equal(r["good-model"].limit.context, 1000);
  } finally {
    globalThis.fetch = real;
    channelCache.clear();
  }
});

test("channelCache: 两个账号的通道判定互不影响", async () => {
  const plugin = await mod.default({}, {});
  const real = globalThis.fetch;
  const OTHER = "LTAI5tOTHERACCOUNT";
  try {
    globalThis.fetch = async () => new Response(JSON.stringify({
      result: { models: [{ model_id: "m-agent", channel: "agent" }] },
    }), { status: 200 });
    await plugin.provider.models({ models: {} }, { auth: { type: "api", key: AK, metadata: { sk: SK } } });

    globalThis.fetch = async () => new Response(JSON.stringify({
      result: { models: [{ model_id: "m-benefit", channel: "benefit" }] },
    }), { status: 200 });
    await plugin.provider.models({ models: {} }, { auth: { type: "api", key: OTHER, metadata: { sk: SK } } });

    assert.equal(channelTable(AK).get("m-agent"), "agent", "账号 A 的判定不能被账号 B 抹掉");
    assert.equal(channelTable(OTHER).get("m-benefit"), "benefit");
    assert.equal(channelTable(AK).has("m-benefit"), false);
    assert.equal(isBenefitChannel("m-agent", "", AK), false);
    assert.equal(isBenefitChannel("m-agent", "", OTHER), true, "B 账号没有这条判定 → 按黑名单回退");
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

// 🔴 magpie 给插件的 auth.usage / auth.checkin 钩子只有 20 秒
// （internal/provider/plugin_usage.go 的 context.WithTimeout），从钩子被调起
// 那一刻开始走。插件单次请求的预算必须留出余量，否则上游一慢就是
// 「宿主先放弃、插件后报超时」—— 卡片显示「暂时无法获取最新额度」、
// 签到记成 failed。0.2.12 之前 envelope 默认 30 秒，比宿主的期限还长。
test("envelope 的默认超时必须在 magpie 的 20 秒钩子期限内留足余量", () => {
  const src = readFileSync(new URL("../index.mjs", import.meta.url), "utf8");
  const m = src.match(/async function envelope\(path[^)]*timeout = ([\d_]+)/);
  assert.ok(m, "找不到 envelope 的默认超时");
  const t = Number(m[1].replace(/_/g, ""));
  assert.ok(t < 20_000, `envelope 默认超时 ${t}ms 必须小于 20000ms`);
  assert.ok(20_000 - t >= 4_000, `要给宿主留足余量，实际只剩 ${20_000 - t}ms`);
});

test("签到链上的每次调用都走 envelope 的默认预算（不另设更长的）", () => {
  const src = readFileSync(new URL("../index.mjs", import.meta.url), "utf8");
  const fn = src.slice(src.indexOf("async checkin(getAuth)"), src.indexOf("provider: {"));
  assert.ok(!/timeout\s*:/.test(fn), "checkin 里不该再给单个请求设更长的超时");
});
