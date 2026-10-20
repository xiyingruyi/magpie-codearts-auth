import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { readFileSync } from "node:fs";

const mod = await import("../index.mjs");
const {
  rfc3986, sdkSignedHeaders, creds, parseCredential, num, round1,
  checkinOutcome, startOfTodayMs, isBenefitChannel, codeartsModels, redact, clampChatBody,
  outputLimit, MAX_OUTPUT_TOKENS, normalizeChatBody,
  upstreamError, normalizeChatResponse, PEEK_MS,
  upstreamSessionId, sessionHeaders, CN_OFFSET_MS,
  channelCache, channelTable, MODEL_META, AGENT_MODELS,
  modalitiesField, capabilitiesField,
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
  assert.equal(checkinOutcome(true, startOfTodayMs() + 1000).outcome, "done");
});

test("checkinOutcome: 刚签到成功 → done，不编造 credit", () => {
  const r = checkinOutcome(true, startOfTodayMs() + 1000);
  assert.equal(r.outcome, "done");
  // 上游没有字段说明这次发了多少；报一个 1000 是在撒谎
  assert.equal(r.credit, undefined);
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

test("checkinOutcome: POST 受理即 done —— create_time 与签到无关，不能据它判失败", () => {
  // 旧实现把「时间戳未推进」判成 ineligible，于是卡片永远显示未签。
  const old = startOfTodayMs() - 86400000;
  const r = checkinOutcome(true, old, undefined, old);
  assert.equal(r.outcome, "done");
  // 上游没有任何字段说这次发多少，不编造 credit
  assert.equal(r.credit, undefined);
});

test("checkinOutcome: POST 受理但没有时间戳 → 仍然 done", () => {
  assert.equal(checkinOutcome(true, undefined).outcome, "done");
});

test("checkinOutcome: 未发起签到、时间戳再新也不算已签", () => {
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

test("MODEL_META: 每个模型都实测声明了 image，且只有 pro-0813 会看图", () => {
  for (const [id, meta] of Object.entries(MODEL_META)) {
    assert.equal(typeof meta.image, "boolean", `${id} 必须带布尔 image —— 漏了会退回「没说」`);
  }
  // 实测（2026-10-20，发 64×64 纯色 PNG 要求答颜色）：绿/红/黄 3/3 全对
  assert.equal(MODEL_META["deepseek-v4-pro-0813"].image, true);
  const seeing = Object.entries(MODEL_META).filter(([, m]) => m.image).map(([id]) => id);
  assert.deepEqual(seeing, ["deepseek-v4-pro-0813"], "当前只有这一个能看图，多出来就是没实测就标了");
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

test("配置钩子路径: 每个模型在宿主眼里都是「说过了」（不能是「没说」）", () => {
  for (const [id, v] of Object.entries(codeartsModels())) {
    assert.equal(hostView(viaConfigHook(v)).imageSaid, true, `${id} 必须明确声明收不收图`);
  }
});

test("codeartsModels（配置钩子路径）: 每个模型都带 modalities，text 打头", () => {
  for (const [id, v] of Object.entries(codeartsModels())) {
    assert.deepEqual(v.modalities.output, ["text"], `${id} 的输出只有文本`);
    assert.equal(v.modalities.input[0], "text", `${id} 必须先收文本`);
    assert.equal(
      v.modalities.input.includes("image"),
      MODEL_META[id].image,
      `${id} 的 modalities 必须和 MODEL_META.image 一致`,
    );
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
  const l = await plugin.auth.loader(async () => ({ type: "api", key, metadata: { sk } }));
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
    seen.push(init.headers);
    return new Response(JSON.stringify({ result: { total_quota: 10, total_balance: 5, used_amount: 5 } }), { status: 200 });
  });
  assert.equal(seen.length, 1, "usage 只该问余额一次（签到状态由宿主显示）");
  for (const h of seen) {
    assert.equal(h["x-ot-session-id"], undefined, "opengw 接口不该带会话头");
    assert.match(h.Authorization, /SignedHeaders=content-type;host;x-sdk-date, Signature=/);
  }
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

/**
 * 签到钩子：只发一次 POST，按「受理即今日已签」报 done。
 *
 * 旧实现先 GET 一次状态、再 POST、再回读，全是为了从 create_time 推签到
 * 状态。实测那个字段是权益记录的创建时间，从不随签到推进（见
 * checkinOutcome 的注释），所以这一整套推导连同它带来的 ineligible 都是错的。
 */
test("checkin: 只发一次 POST，受理即 done", async () => {
  const plugin = await mod.default({}, {});
  const real = globalThis.fetch;
  const urls = [];
  globalThis.fetch = async (url, init) => {
    urls.push(`${init?.method ?? "GET"} ${String(url)}`);
    return new Response(JSON.stringify({ result: { create_time: Date.now() - 86400_000 } }), { status: 200 });
  };
  try {
    const got = await plugin.auth.checkin(async () => ({ type: "api", key: AK, metadata: { sk: SK } }));
    assert.equal(got.outcome, "done", `受理就该是 done，实际 ${got.outcome}`);
    assert.equal(urls.length, 1, `只该打一次接口，实际 ${urls.join(", ")}`);
    assert.match(urls[0], /^POST .*\/benefit\/claim/);
  } finally {
    globalThis.fetch = real;
  }
});

test("checkin: 旧时间戳不再被判成 ineligible（这就是「开了自动签到还显示未签」的根因）", async () => {
  const plugin = await mod.default({}, {});
  const real = globalThis.fetch;
  const yesterday = Date.now() - 86400_000;
  globalThis.fetch = async () => new Response(JSON.stringify({ result: { create_time: yesterday } }), { status: 200 });
  try {
    const got = await plugin.auth.checkin(async () => ({ type: "api", key: AK, metadata: { sk: SK } }));
    assert.equal(got.outcome, "done");
  } finally {
    globalThis.fetch = real;
  }
});

test("checkin: 上游没给 result 也报 done（200 + 0000 就是受理）", async () => {
  const plugin = await mod.default({}, {});
  const real = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({ error_code: "0000" }), { status: 200 });
  try {
    const got = await plugin.auth.checkin(async () => ({ type: "api", key: AK, metadata: { sk: SK } }));
    assert.equal(got.outcome, "done");
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
        { model_id: "deepseek-v4-pro-0813", context_window: 1000000, max_tokens: 393216, channel: "benefit" },
        { model_id: "GLM-5.2", context_window: 200000, max_tokens: 128000, channel: "agent" },
      ],
    },
  }), { status: 200 });
  try {
    const base = { "GLM-5.2": { id: "GLM-5.2", name: "GLM-5.2", limit: { context: 0, output: 0 } } };
    const r = await plugin.provider.models({ models: base }, { auth: { type: "api", key: AK, metadata: { sk: SK } } });
    assert.equal(r["deepseek-v4-pro-0813"].limit.context, 1000000);
    // 云端 393216 是模型能力，上游 max_tokens 参数上限 65536 —— 发布前收敛
    assert.equal(r["deepseek-v4-pro-0813"].limit.output, MAX_OUTPUT_TOKENS);
    assert.equal(r["GLM-5.2"].limit.context, 200000);
    // 缓存按账号隔离：AK 那一层里能查到本账号的判定
    const mine = channelCache.get(AK);
    assert.equal(mine.get("deepseek-v4-pro-0813"), "benefit");
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
        { model_id: "deepseek-v4-pro-0813", context_window: 1000000, max_tokens: 393216, channel: "benefit" },
        { model_id: "deepseek-v4.1-flash", context_window: 1000000, max_tokens: 393216, channel: "benefit" },
        { model_id: "brand-new-model", context_window: 1000, max_tokens: 100, channel: "benefit" },
      ],
    },
  }), { status: 200 });
  try {
    const r = await plugin.provider.models({ models: {} }, { auth: { type: "api", key: AK, metadata: { sk: SK } } });
    // 🔴 宿主对 provider.models 的返回值是**原样采用**的，不走 modalities 转换 ——
    // 这里写 modalities 会被静默丢掉，imageSaid 永远是 false
    assert.equal(hostView(r["deepseek-v4-pro-0813"]).imageSaid, true, "能看图的模型要「说过了」");
    assert.equal(hostView(r["deepseek-v4-pro-0813"]).image, true);
    assert.deepEqual(hostView(r["deepseek-v4-pro-0813"]).inputs, ["text", "image"]);
    // 纯文本模型必须落在「明确说不收」这一态，不是「没说」——
    // 只有前者会让宿主在带图请求里跳过它
    assert.equal(hostView(r["deepseek-v4.1-flash"]).imageSaid, true, "纯文本模型要明确说不收图，不能是「没说」");
    assert.equal(hostView(r["deepseek-v4.1-flash"]).image, false);
    assert.deepEqual(hostView(r["deepseek-v4.1-flash"]).inputs, ["text"]);
    assert.equal(r["deepseek-v4.1-flash"].modalities, undefined, "这条路上 modalities 是死字段");
    // 表里没有的模型：保持「没说」，宁可退回 0.2.12 行为也不编一个可能错的 false
    assert.equal(r["brand-new-model"].capabilities, undefined, "查不到就不写，保持「没说」");
    assert.equal(hostView(r["brand-new-model"]).imageSaid, false, "查不到 = 没说 = 带图请求仍会尝试它");
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
