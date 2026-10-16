/**
 * magpie-codearts-auth —— magpie/OpenCode provider 插件：华为云码道 CodeArts。
 *
 * - 授权：华为云访问密钥 AK/SK（一个输入框粘贴 "AK:SK"，SDK-HMAC-SHA256 签名）
 * - 每日签到：POST opengw /api/v1/benefit/claim（auth.checkin，magpie ≥ v0.1.1083）
 * - 免费额度：GET /api/v1/user/tokens/balance（auth.usage）
 * - 对话：POST snap-access /api/v2/chat/completions（OpenAI chat 形态，body 原样转发）
 *   · 福利模型（benefit）必须附加 maas_type/model-id/model-name 三个头并参与签名
 *   · 老套餐模型（AgentCenter）不能带这三个头（上游报 unsupported model）
 * - 模型清单：GET opengw /api/v1/gateway/config（福利）+ 内置兜底（老套餐）
 *
 * 协议事实来源：codearts2api（cnb.cool/itq5）与 Johnsheng1/codearts2api 的逆向实测记录。
 * 基于 MIT 开源协议与社区逆向成果，详见 README 致谢节。
 *
 * --- 相对骨架版（0.1.0）的三处修正 ---
 * ① 登录：宿主的 apiKey 分支只把用户输入放进 `key` 参数，**从不并入 inputs**，
 *    因此 `m.prompts` 里的项能进 inputs、而 key 框的值不能。骨架版 `authorize`
 *    读 `inputs.key` ⇒ 永远拿到空 AK ⇒ 100% 无法登录。本版改为**单个 prompt 项**
 *    收集 "AK:SK" 组合串，由插件 split，AK/SK 都在 inputs 里 ⇒ authorize 拿得到。
 * ② 通道判定：上游是黑名单（`benefit = model not in AGENT_MODELS`），骨架版用
 *    硬编码白名单 ⇒ 云端同步来的新模型会走错通道报 `unsupported model`。本版按
 *    黑名单判定，并优先采用云端返回的 `channel` 字段。
 * ③ 模型清单：保留云端返回的 `channel` 字段（上游 server.py 正是用它构建黑名单）。
 */

import { createHash, createHmac } from "node:crypto";

// ---------------------------------------------------------------------------
// 端点常量
// ---------------------------------------------------------------------------

const SNAP_HOST = "https://snap-access.cn-north-4.myhuaweicloud.com";
const CHAT_PATH = "/api/v2/chat/completions";
const OPENGW_HOST = "https://opengw.developer.huaweicloud.com";
const CLAIM_PATH = "/api/v1/benefit/claim";
const BALANCE_PATH = "/api/v1/user/tokens/balance";
const CONFIG_PATH = "/api/v1/gateway/config";

/**
 * 老套餐（AgentCenter）模型 —— **黑名单语义**：
 * 上游 `benefit = model not in AGENT_MODELS`，即不在这个名单里的一律按 benefit 处理。
 * 只是云端拿不到清单时的兜底，运行时会被 `provider.models` 拉回的 channel 覆盖。
 */
const AGENT_MODELS = ["openpangu-2.0-pro", "openpangu-2.0-flash", "GLM-5.2"];
/** 已知福利模型（仅用于静态兜底展示；判定走黑名单，不依赖此表）。 */
const BENEFIT_MODELS = ["glm-5.3-flash", "deepseek-v4-pro-0813", "deepseek-v4-flash-0731"];

const MODEL_META = {
  "glm-5.3-flash": { name: "GLM-5.3 Flash", context: 200000, output: 32000, benefit: true },
  "deepseek-v4-pro-0813": { name: "DeepSeek V4 Pro", context: 200000, output: 32000, benefit: true },
  "deepseek-v4-flash-0731": { name: "DeepSeek V4 Flash", context: 200000, output: 32000, benefit: true },
  "openpangu-2.0-pro": { name: "OpenPangu 2.0 Pro", context: 200000, output: 32000, benefit: false },
  "openpangu-2.0-flash": { name: "OpenPangu 2.0 Flash", context: 200000, output: 32000, benefit: false },
  "GLM-5.2": { name: "GLM-5.2", context: 200000, output: 32000, benefit: false },
};

/**
 * 云端 channel 缓存：modelId → "agent" | "benefit" | ""（未知）。
 * 由 provider.models 写入，供 loader 判定通道。跨请求存活（模块级）。
 */
const channelCache = new Map();

/**
 * 通道判定：返回 true 表示走 benefit（免费额度）通道。
 * 优先用云端 channel；否则按上游黑名单语义 —— 不在 AGENT_MODELS 里的一律 benefit。
 */
function isBenefitChannel(modelId, knownChannel = "") {
  const id = String(modelId ?? "").trim();
  if (!id) return false;
  const ch = String(knownChannel || channelCache.get(id) || "").toLowerCase();
  if (ch === "benefit") return true;
  if (ch === "agent") return false;
  // 无 channel 信息 → 黑名单：命中 AgentCenter 名单才算老套餐，其余按 benefit
  return !AGENT_MODELS.some((m) => m.toLowerCase() === id.toLowerCase());
}

// ---------------------------------------------------------------------------
// 华为云 SDK-HMAC-SHA256 签名
// ---------------------------------------------------------------------------

/** RFC3986 编码（safe = "-_.~"，与华为云 SDK 一致）。 */
function rfc3986(v) {
  return encodeURIComponent(String(v)).replace(/[!'()*]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase());
}

/**
 * 构造带华为云 SDK-HMAC-SHA256 签名的请求头。
 * 参与签名的头：host / content-type / x-sdk-date（+ 业务附加头）。
 * host 只参与签名计算，实际由 fetch 自动发送（undici 不允许手动设置）。
 */
function sdkSignedHeaders(method, url, bodyStr, ak, sk, extraHeaders = {}) {
  const u = new URL(url);
  const canonicalUri = u.pathname.endsWith("/") ? u.pathname : `${u.pathname}/`;
  const params = [...u.searchParams.entries()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  const canonicalQuery = params.map(([k, v]) => `${rfc3986(k)}=${rfc3986(v)}`).join("&");

  const sdkDate = new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
  const headers = {
    host: u.host,
    "content-type": "application/json",
    "x-sdk-date": sdkDate,
    ...extraHeaders,
  };
  const signedNames = Object.keys(headers).sort();
  const canonicalHeaders = signedNames.map((n) => `${n}:${String(headers[n]).trim()}\n`).join("");
  const signedHeaders = signedNames.join(";");
  const payloadHash = createHash("sha256").update(bodyStr ?? "").digest("hex");
  const canonicalRequest = `${method.toUpperCase()}\n${canonicalUri}\n${canonicalQuery}\n${canonicalHeaders}\n${signedHeaders}\n${payloadHash}`;
  const stringToSign = `SDK-HMAC-SHA256\n${sdkDate}\n${createHash("sha256").update(canonicalRequest).digest("hex")}`;
  const signature = createHmac("sha256", sk).update(stringToSign).digest("hex");

  const out = {};
  for (const n of signedNames) if (n !== "host") out[n] = headers[n];
  out.Authorization = `SDK-HMAC-SHA256 Access=${ak}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
  return out;
}

// ---------------------------------------------------------------------------
// opengw 信封（error_code "0000" 成功，数据在 result）
// ---------------------------------------------------------------------------

async function envelope(path, { method = "GET", body, ak, sk, timeout = 30_000 }) {
  const url = `${OPENGW_HOST}${path}`;
  const bodyStr = body !== undefined ? JSON.stringify(body) : "";
  const headers = sdkSignedHeaders(method, url, bodyStr, ak, sk);
  let res, text;
  try {
    res = await fetch(url, {
      method,
      headers,
      ...(bodyStr ? { body: bodyStr } : {}),
      signal: AbortSignal.timeout(timeout),
    });
    text = await res.text();
  } catch (cause) {
    throw Object.assign(new Error(`CodeArts 请求失败: ${cause?.message ?? cause}`), { cause });
  }
  let data;
  try { data = text ? JSON.parse(text) : undefined; } catch { data = undefined; }
  if (res.status !== 200 || !data) {
    throw new Error(`CodeArts ${path} HTTP ${res.status}: ${text.slice(0, 200)}`);
  }
  if (data.error_code !== undefined && !["0000", 0, null].includes(data.error_code)) {
    throw Object.assign(new Error(`CodeArts ${path} 业务错误 ${data.error_code}: ${data.error_msg ?? ""}`), {
      errorCode: String(data.error_code),
    });
  }
  return data.result ?? {};
}

/** 签到状态：result.create_time = 最近一次签到时间（毫秒时间戳）。 */
async function claimStatus(ak, sk) {
  return envelope(CLAIM_PATH, { ak, sk });
}

/** 签到领取当日免费额度（服务端按天幂等）。 */
function claimToday(ak, sk) {
  return envelope(CLAIM_PATH, { method: "POST", ak, sk });
}

/** 免费额度余额：{total_quota, total_balance, used_amount, …}。 */
function fetchBalance(ak, sk) {
  return envelope(BALANCE_PATH, { ak, sk });
}

/** 福利模型列表：result.models = [{model_id, context_window, max_tokens, channel, …}]。 */
async function fetchBenefitModels(ak, sk) {
  const r = await envelope(CONFIG_PATH, { ak, sk }).catch(() => ({}));
  return Array.isArray(r.models) ? r.models : [];
}

// ---------------------------------------------------------------------------
// 工具
// ---------------------------------------------------------------------------

function bare(v) {
  let t = String(v ?? "").trim();
  while (t.toLowerCase().startsWith("bearer ")) t = t.slice(7).trim();
  return t;
}

/**
 * 解析用户粘贴的凭据串为 {ak, sk}。
 * 接受形式：
 *   - "AK:SK" / "AK=SK" / "AK、SK" —— 组合串（推荐，宿主单框）
 *   - 纯 AK —— 仅当已从别处拿到 SK 时才够，否则报错
 * 华为云 AK 形如 20 位大写字母数字，SK 为 40 位。
 */
function parseCredential(raw) {
  const s = bare(raw);
  if (!s) return { ak: "", sk: "" };
  // 分隔符：中英文冒号、等号、逗号、分号、空白、顿号
  const m = s.match(/^([^:：=,，;；\s、]+)\s*[:：=,，;；\s、]\s*(\S+)$/);
  if (m) return { ak: m[1], sk: m[2] };
  return { ak: s, sk: "" };
}

/** 从登录凭据里取 AK/SK（兼容 type:"api" 保存格式与手动 metadata）。 */
function creds(auth) {
  const ak = bare(auth?.key ?? auth?.ak ?? auth?.access_key);
  let sk = bare(auth?.metadata?.sk ?? auth?.metadata?.secretKey ?? auth?.secret ?? auth?.sk);
  // 兜底：key 里存的是 "AK:SK" 组合串
  if (!sk && ak) {
    const p = parseCredential(ak);
    if (p.sk) return { ak: p.ak, sk: p.sk };
  }
  if (!ak || !sk) throw new Error("未登录或凭据不完整（需要 Access Key Id / Secret Access Key）");
  return { ak, sk };
}

function optNumber(v) {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? n : undefined;
}

/** 本地时区当天 0 点（毫秒）。 */
function startOfTodayMs() {
  const d = new Date();
  d.setHours(0, 0, 0, 0);
  return d.getTime();
}

/**
 * 签到结果 → magpie checkin 契约 {outcome, credit?, streak?, message?}。
 * outcome 必须是 claimed | done | ineligible | inactive | captcha | failed 之一；
 * 非枚举值会被宿主归一为 failed 并在 message 里附「the plugin answered no outcome」。
 */
function checkinOutcome(posted, createMs, err, beforeMs) {
  const nowDay = startOfTodayMs();
  const ok = createMs !== undefined && Number(createMs) >= nowDay;
  if (posted && ok) {
    return { outcome: "claimed", credit: 1000, message: "已签到 +1000 积分" };
  }
  if (ok) return { outcome: "done" };
  // 发起过签到（POST 成功返回但时间戳未推进）：
  // 上游对「不在活动期 / 账号不参与」的账号不报错，只是原样返回旧时间戳。
  // 此时重试无意义 —— 归为 ineligible，避免宿主每 30 分钟空转。
  if (posted && beforeMs !== undefined) {
    return {
      outcome: "ineligible",
      message: "签到未生效：上游未推进签到时间（该账号可能不参与签到活动，或活动已结束）",
    };
  }
  const code = String(err?.errorCode ?? "");
  const msg = String(err?.message ?? "");
  // 活动已结束 / 不在活动期 → 不是失败，不必重试
  if (/已结束|not\s*in\s*(the\s*)?activity|activity.*(end|expired)/i.test(msg) || code === "0004") {
    return { outcome: "ineligible", message: "当前不在签到活动期内" };
  }
  // 账号未开通 / 未实名 → 无需重试
  if (/未开通|未实名|not\s*(activated|enabled|realname)/i.test(msg) || ["0401", "0403"].includes(code)) {
    return { outcome: "inactive", message: "账号未开通该权益或未实名认证" };
  }
  // 需要验证码 → 交给用户手动完成
  if (/captcha|验证码|人机|robot/i.test(msg)) {
    return { outcome: "captcha", message: "需要人机验证，请到华为云控制台手动签到" };
  }
  if (err) return { outcome: "failed", message: `签到失败: ${msg.slice(0, 120)}` };
  return { outcome: "failed", message: "签到未生效，请重试或检查账号" };
}

// ---------------------------------------------------------------------------
// 模型清单
// ---------------------------------------------------------------------------

function codeartsModels() {
  const out = {};
  for (const [id, meta] of Object.entries(MODEL_META)) {
    out[id] = {
      name: meta.name,
      id,
      limit: { context: meta.context, output: meta.output },
      reasoning: false,
      tool_call: true,
    };
  }
  return out;
}

// ---------------------------------------------------------------------------
// 插件
// ---------------------------------------------------------------------------

export default async function codeartsPlugin(_input, options) {
  void options;

  return {
    config: async (cfg) => {
      cfg.provider ??= {};
      cfg.provider.codearts ??= {
        name: "CodeArts 码道 (Huawei)",
        npm: "@ai-sdk/openai-compatible",
        api: `${SNAP_HOST}${CHAT_PATH}`,
        models: codeartsModels(),
      };
    },

    auth: {
      provider: "codearts",
      methods: [
        {
          type: "api",
          label: "华为云访问密钥 AK/SK",
          placeholder: "AccessKeyId:SecretAccessKey",
          // 🔴 关键：AK 必须走 prompts 才拿得到（宿主的 key 框值不进 inputs）。
          // 用一个 prompt 收集 "AK:SK" 组合串，再自行拆分。
          prompts: [
            {
              type: "password",
              key: "credential",
              message: "粘贴「Access Key Id:Secret Access Key」（中间用冒号隔开）",
              placeholder: "例如 LTAI5txxxxxx:y8Qwxxxxxx",
              validate: (v) => {
                const { ak, sk } = parseCredential(v);
                if (!ak || !sk) return "需要「Access Key Id:Secret Access Key」两段，中间用冒号隔开";
                if (ak.length < 16) return "Access Key Id 太短（华为云通常 20 位）";
                if (sk.length < 20) return "Secret Access Key 太短（华为云通常 40 位）";
                return undefined;
              },
            },
          ],
          async authorize(inputs) {
            // 🔴 只读 inputs —— 宿主从不把 key 框的值并进来，不能依赖 inputs.key。
            const raw = String(inputs?.credential ?? inputs?.key ?? "").trim();
            const { ak, sk } = parseCredential(raw);
            if (!ak) return { type: "failed", error: "Access Key Id 不能为空" };
            if (!sk) {
              return {
                type: "failed",
                error: "Secret Access Key 不能为空。请按「Access Key Id:Secret Access Key」的格式粘贴（中间要有冒号）",
              };
            }
            // 用余额接口验证 AK/SK 有效性（签到接口幂等，不在此处触发）
            try {
              await fetchBalance(ak, sk);
            } catch (e) {
              return { type: "failed", error: `AK/SK 验证失败: ${e?.message ?? e}` };
            }
            return { type: "success", key: ak, metadata: { sk } };
          },
        },
      ],

      async loader(getAuth) {
        const auth = await getAuth();
        if (auth?.type !== "api" || !auth.key) return {};
        const { ak, sk } = creds(auth);
        return {
          baseURL: SNAP_HOST,
          async fetch(input, init) {
            const bodyStr = String(init?.body ?? "{}");
            let model = "";
            try { model = String(JSON.parse(bodyStr).model ?? ""); } catch { /* 保持空 */ }
            // 福利/老套餐通道判定（黑名单 + 云端 channel）
            const extra = isBenefitChannel(model)
              ? { maas_type: "benefit", "model-id": model, "model-name": model }
              : {};
            const headers = sdkSignedHeaders("POST", `${SNAP_HOST}${CHAT_PATH}`, bodyStr, ak, sk, extra);
            return fetch(`${SNAP_HOST}${CHAT_PATH}`, {
              method: "POST",
              headers,
              body: bodyStr,
              signal: init?.signal,
            });
          },
        };
      },

      async usage(getAuth) {
        try {
          const auth = await getAuth();
          if (auth?.type !== "api" || !auth.key) return { error: "未登录", windows: [] };
          const { ak, sk } = creds(auth);
          const [bal, claim] = await Promise.all([
            fetchBalance(ak, sk).catch(() => null),
            claimStatus(ak, sk).catch(() => null),
          ]);
          if (!bal) return { error: "额度接口无数据", windows: [] };
          const total = Number(bal.total_balance ?? 0);
          const quota = Number(bal.total_quota ?? 0);
          const used = Number(bal.used_amount ?? 0);
          const signedToday = Number(claim?.create_time ?? 0) >= startOfTodayMs();
          return {
            balance: `${Math.round(total)} 积分`,
            windows: [
              {
                name: "免费额度",
                // magpie 的百分比 = used / limit，所以两者都要给
                used: Number.isFinite(used) ? used : undefined,
                limit: Number.isFinite(quota) && quota > 0 ? quota : undefined,
                amount: Number.isFinite(total) ? total : undefined,
                display: `${Math.round(total)} / ${Math.round(quota)}`,
              },
              {
                name: "每日签到",
                used: signedToday ? 0 : 1,
                limit: 1,
                display: signedToday ? "今日已签 ✓" : "今日未签（+1000）",
                aside: true,
              },
            ],
          };
        } catch (e) {
          return { error: `额度查询失败: ${e?.message ?? e}`, windows: [] };
        }
      },

      async checkin(getAuth) {
        try {
          const auth = await getAuth();
          if (auth?.type !== "api" || !auth.key) return { outcome: "inactive", message: "未登录" };
          const { ak, sk } = creds(auth);
          const before = await claimStatus(ak, sk).catch(() => ({}));
          const beforeMs = Number(before?.create_time ?? 0);
          if (beforeMs >= startOfTodayMs()) return { outcome: "done", streak: 0, message: "今日已签到" };
          try {
            await claimToday(ak, sk);
          } catch (e) {
            return checkinOutcome(false, undefined, e);
          }
          const after = await claimStatus(ak, sk).catch(() => ({}));
          return checkinOutcome(true, after?.create_time, undefined, beforeMs);
        } catch (e) {
          return checkinOutcome(false, undefined, e);
        }
      },
    },

    provider: {
      id: "codearts",
      async models(provider, { auth }) {
        // 尽力拉云端模型清单；失败保留 config 静态列表
        try {
          const { ak, sk } = creds(auth ?? {});
          const rows = await fetchBenefitModels(ak, sk);
          if (!rows.length) return provider.models;
          const out = { ...provider.models };
          for (const m of rows) {
            const id = String(m.model_id ?? m.modelId ?? m.id ?? "").trim();
            if (!id) continue;
            // 🔴 保留云端 channel：既用于本次判定，也写进 channelCache 供 loader 用
            const channel = String(m.channel ?? "").trim().toLowerCase();
            if (channel === "agent" || channel === "benefit") channelCache.set(id, channel);
            out[id] = {
              name: String(m.model_name ?? m.modelName ?? m.name ?? id),
              id,
              limit: {
                context: optNumber(m.context_window ?? m.contextWindow),
                output: optNumber(m.max_tokens ?? m.maxTokens),
              },
              reasoning: false,
              tool_call: true,
            };
          }
          return out;
        } catch {
          return provider.models;
        }
      },
    },
  };
}

/** 测试辅助（宿主不会把它当插件调用）。 */
export const _internal = {
  rfc3986, sdkSignedHeaders, envelope, creds, bare, parseCredential,
  claimStatus, claimToday, fetchBalance, fetchBenefitModels,
  checkinOutcome, startOfTodayMs, isBenefitChannel, codeartsModels,
  channelCache, MODEL_META, BENEFIT_MODELS, AGENT_MODELS,
};
