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
 *
 * --- 0.2.4 的四处修正（见 README「0.2.4」节） ---
 * ④ 会话 ID：所有请求带上稳定的 `x-ot-session-id`。不带时上游按请求各自计一个新
 *    会话，几个并发就撞上「每账号 3 个并发会话」的上限，返回 TM.00001041 ——
 *    而 magpie 会把这条错误里的「上限」二字当成额度用尽的特征（宿主
 *    `internal/gateway/routing.go` 的 usedUpWords 含 `上限`），把账号误标成
 *    「额度用尽」并休息 15 分钟。这是「额度明明没用完却显示已用完」的根因。
 * ⑤ usage window 的 `amount` 是「已用」不是「剩余」（宿主 quotaCount 按
 *    `amount / limit` 渲染），`unit` 是 tokens 不是积分（与控制台的积分是两种货币）。
 * ⑥ 模型 context/output 不再猜（猜出来的正数会被宿主当成硬上限，把长上下文截断）。
 * ⑦ 签到状态窗口不再填满 100%（`aside` 虽已免责路由，但满格红条会被误读成额度用尽）。
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

/**
 * 上游**已确认不可用**的模型 —— 不再出现在清单里。
 *
 * 2026-10-20 福利通道下线后逐个直连实测（两个账号、流式与非流式都试）：
 *
 *   模型                     带福利头            不带福利头
 *   deepseek-v4.1-flash      4004 benefit gone   **200 正常推理**
 *   deepseek-v4-pro-0813     4004 benefit gone   404 model is not registered
 *   glm-5.3-flash            4004 benefit gone   404 model is not registered
 *   deepseek-v4-flash-0731   4004 benefit gone   404 model is not registered
 *
 * 后三个现在**两条通道都不通**。留在清单里只会让 magpie 轮询到它们、拿一个 400
 * —— 而 magpie 对不带额度关键词的 400 是不 failover 的（整组直接失败，实测
 * `group/auto-deepseek-v4-pro` 4 次里 1 次这样挂）。摘掉它们，组里就只剩真能跑
 * 的成员。
 *
 * 活动恢复后它们会重新出现在云端清单里 —— 那时把名字从这里删掉即可（云端清单
 * 本来就会覆盖静态兜底，这里只影响「不该被轮询」的那一层）。名字统一小写比较。
 */
const RETIRED_MODELS = new Set(["deepseek-v4-pro-0813", "glm-5.3-flash", "deepseek-v4-flash-0731"]);

/** 这条模型还该不该出现在清单里。 */
function modelRetired(id) {
  return RETIRED_MODELS.has(String(id ?? "").trim().toLowerCase());
}

/**
 * 上游 `max_tokens` **参数的硬上限**（实测出来的，不是猜的）。
 *
 * 实测：`max_tokens=65536` 正常返回；`65537` 起上游报
 * `RANGE_VALIDATOR max_tokens should be between 1 and 65536`，而 magpie 会把这条
 * 400 包成 **HTTP 200 的空流** —— 客户端只看到「成功但没有内容」，没有任何错误。
 *
 * 🔴 云端 `gateway/config` 返回的 `max_tokens`（393216 / 384000 …）是**模型能力**，
 *    不是这个参数的允许范围。把它直接发布成 magpie 的 `limit.output`，等于邀请每个
 *    消费方去要一个必然失败的数（magpie 的 `withMaxOutput` 只在下调时才动手，
 *    不会把 393216 降到 65536）。所以发布前按参数上限收敛。
 */
const MAX_OUTPUT_TOKENS = 65536;

/**
 * 静态兜底清单 —— **只在 `provider.models` 拉云端清单失败时**才会被用到。
 *
 * 🔴 `context` 留 **0（= 不设限）**，绝不猜：magpie 的 `limit` 不是说明文字而是
 *    **硬上限**，一个猜出来的正数会真的把请求截断（这几个模型上游实测 1M 上下文，
 *    猜 200000 会把长上下文任务压爆）。真实值由 `provider.models` 从云端
 *    `context_window` 填回来。
 *    `output` 则用**实测的参数上限** `MAX_OUTPUT_TOKENS` —— 它是真的，不是猜的，
 *    而且不设限会让客户端去要一个上游必然拒绝的数（见上）。
 *
 * 🔴 **codearts 全线不收图**（0.2.15 定论，0.2.13/0.2.14 判错了，见下）。
 *
 *    宿主 `internal/plugin/host.js` 最终读的是模型条目的 `capabilities.input.image`，
 *    再摊成 `image` / `imageSaid` 两个字段，而 `imageSaid` 只在它是**布尔值**时才为真：
 *    能力不写 ＝ 「没说」，写了 = 「厂商说过了」。这两种「不收」在路由里待遇**完全不同**：
 *      · 「明确说不收」的模型，宿主不把带图请求发给它 —— 实测同一个
 *        raccoon 纯文本模型，纯文本请求被试 160 次、带图请求被试 **0** 次；
 *      · 「没说」的照发不误 —— 撞上游
 *        `406 InferHub.001001020.406 The request model is not multimodal`，
 *        还让账号白挨一次 60 秒 backoff（2026-10-20 18:47 的两次就是这样来的）。
 *    所以必须**明确**声明，留空就是留了个坑。
 *
 *    **为什么是「全线不收」**（2026-10-20 三个独立证据，详见 README）：
 *      ① 直连实测（同一端点、同一 benefit 头、只改有没有图）：
 *         `deepseek-v4-pro-0813` 纯文本 → **200**，同一模型带图 → **406 not multimodal**；
 *         `deepseek-v4.1-flash` / `glm-5.3-flash` 带图同样 406。
 *      ② AgentCenter（`/v1/agent-center/agents/detail`，老套餐通道）**真的给
 *         `supports_images` 字段** —— 该账号下 5 个模型全是 `false`。
 *      ③ 免费额度网关（`gateway/config`，本插件用的）只有
 *         `model_id/model_name/context_window/max_tokens/sort` 五个字段、**不含任何能力信息**；
 *         社区参考实现 codearts2api 对这条通道同样硬编码 `supports_images: False`。
 *
 *    ⚠️ 0.2.13 曾据一次**方法有误**的探测把 `deepseek-v4-pro-0813` 标成 `image: true`，
 *    0.2.14 又把云端路径修对形状 —— 方向都是反的：那等于**请宿主把图片发给一个必然 406
 *    的模型**。凌晨日志里它「成功服务 18 次带图请求」是假象：那是第 30 轮长对话，
 *    图片出现在早前轮次，宿主已用「识图模型转文字描述」把原图替成了文字（所以 200）。
 */
const MODEL_META = {
  "glm-5.3-flash": { name: "GLM-5.3 Flash", context: 0, output: MAX_OUTPUT_TOKENS, benefit: true },
  "deepseek-v4-pro-0813": { name: "DeepSeek V4 Pro", context: 0, output: MAX_OUTPUT_TOKENS, benefit: true },
  "deepseek-v4-flash-0731": { name: "DeepSeek V4 Flash", context: 0, output: MAX_OUTPUT_TOKENS, benefit: true },
  "deepseek-v4.1-flash": { name: "DeepSeek V4.1 Flash", context: 0, output: MAX_OUTPUT_TOKENS, benefit: true },
  "openpangu-2.0-pro": { name: "OpenPangu 2.0 Pro", context: 0, output: MAX_OUTPUT_TOKENS, benefit: false },
  "openpangu-2.0-flash": { name: "OpenPangu 2.0 Flash", context: 0, output: MAX_OUTPUT_TOKENS, benefit: false },
  "GLM-5.2": { name: "GLM-5.2", context: 0, output: MAX_OUTPUT_TOKENS, benefit: false },
};

/**
 * **实测确认能通过 magpie 的图片格式收图**的模型 id（小写）—— 目前为空。
 *
 * 这是唯一的例外名单，也是将来华为真支持图片时的扩展点：把模型 id 加进来，
 * 两个产出模型的路径会自动把它声明成 `image: true`。加之前**必须直连实测过**
 * （同一端点、同一通道头、只改有没有图，且纯文本对照必须是 200），
 * 不要再像 0.2.13 那样凭一次方法有误的探测就标 true。
 */
const VISION_MODELS = new Set([]);

/**
 * 这个模型收不收图。
 *
 * **默认 false（明确说不收），不是「没说」** —— 理由见 `MODEL_META` 上面那段：
 * codearts 全线实测不收图，而「没说」会让宿主把带图请求发过来撞 406。
 * 清单里查不到的模型（云端新上的）同样按 false 发，宁可漏掉一个将来可能支持图片的
 * 新模型（后果只是它不接带图请求），也不让带图请求打到一个必然失败的地方。
 */
function imageCapable(id) {
  return VISION_MODELS.has(String(id ?? "").trim().toLowerCase());
}

/**
 * 模型条目里要合并的 `modalities` 字段 —— **只给配置钩子（`codeartsModels()`）用**。
 *
 * 宿主把 `modalities.input` 转成 `capabilities.input` 只发生在一个地方：
 * `internal/plugin/host.js` 的**配置钩子模型**合并循环里
 * （`...(m.modalities?.input ? { input: modalities(m.modalities.input) } : {})`）。
 * 而 `provider.models` 钩子的返回值是**原样采用**的（同一文件
 * `out.models = Object.fromEntries(...{ ...m, id: k, providerID: id })`），
 * 那条路上写 `modalities` 会被静默丢掉 —— 那边要用下面的 `capabilitiesField()`。
 *
 * **未知就一个键都不写** —— 写 `image: false` 会被宿主当成「明确说不收」而把带图
 * 请求整个跳过，写 `true` 又是撒谎。宁可退回「没说」（行为与 0.2.12 一致），
 * 也不编一个可能错的值。与 `context: 0`、`MAX_OUTPUT_TOKENS` 同一条原则。
 *
 * @param {unknown} image `MODEL_META[id].image`：布尔值才算说了
 * @returns {{ modalities?: { input: string[], output: string[] } }}
 */
function modalitiesField(image) {
  if (typeof image !== "boolean") return {};
  return { modalities: { input: image ? ["text", "image"] : ["text"], output: ["text"] } };
}

/**
 * 宿主认可的模态种类，顺序照抄 `internal/plugin/host.js` 的 `MODALITIES`。
 */
const MODALITIES = ["text", "image", "audio", "video", "pdf"];

/**
 * 把模态清单摊成宿主 `capabilities.input` / `.output` 要的形状。
 *
 * **这必须和宿主自己的 `modalities()` 逐字一致 —— 每个键都要在，值必须是布尔。**
 * 宿主判定「厂商有没有说」用的是：
 *
 *   `imageSaid: typeof m.capabilities?.input?.image === "boolean"`
 *
 * 所以省掉值为 false 的键不是「简洁」，是把「明确说不收」降级成「没说」：
 * `{ text: true }` 里根本没有 `image`，`typeof undefined !== "boolean"`，
 * `imageSaid` 依旧是 false —— 带图请求照旧发给这个纯文本模型。
 * （0.2.13 就是这么写错的，已在 0.2.14 修掉。）
 *
 * @param {string[]} list 该方向支持的模态
 * @returns {Record<string, boolean>}
 */
const modalities = (list) =>
  Object.fromEntries(MODALITIES.map((k) => [k, (list ?? ["text"]).includes(k)]));

/**
 * 模型条目里要合并的 `capabilities` 字段 —— **只给 `provider.models` 钩子用**。
 *
 * 与 `modalitiesField()` 是同一件事的两条路（原因见上面那段）。宿主最终读的是
 * `m.capabilities?.input?.image`，所以：
 *
 *   · `input: { …, image: true }`   → `image:true,  imageSaid:true`（会看图）
 *   · `input: { …, image: false }`  → `image:false, imageSaid:true`（**明确**不看）
 *   · 整个键不写                     → `image:false, imageSaid:false`（没说）
 *
 * 中间那条就是本函数存在的理由：只有显式写了 `image: false`，宿主才会在带图请求里
 * **跳过**这个模型。输出方向固定只有文本，与配置路径的默认值保持一致。
 *
 * @param {unknown} image `MODEL_META[id].image`：布尔值才算说了
 * @returns {{ capabilities?: { input: Record<string, boolean>, output: Record<string, boolean> } }}
 */
function capabilitiesField(image) {
  if (typeof image !== "boolean") return {};
  return {
    capabilities: {
      input: modalities(image ? ["text", "image"] : ["text"]),
      output: modalities(["text"]),
    },
  };
}

/** 对话端点的绝对地址（loader 里判断「这是不是对话请求」用）。 */
const CHAT_ABS = `${SNAP_HOST}${CHAT_PATH}`;

/**
 * 把宿主给的地址解析成真正要打的地址；不是本 provider 的主机则返回 null。
 *
 * 宿主（plugins.go 的 pluginFetch）用 `baseURL + strings.TrimPrefix(rest, "/v1")`
 * 拼地址：baseURL 已经是 `SNAP_HOST/api/v2` 时拼出来正好是对话端点。但如果宿主
 * 哪天换了拼法、只给出 `…/chat/completions`，请求会静默 404（APIG.0101）。
 * 这里补第二道保险：只对**对话路径**把缺掉的 `/api/v2` 补回来，其它路径一律
 * 按原样签名转发（例如 `/v1/model/builtin` 不属于 `/api/v2`）。
 */
function resolveTarget(asked) {
  if (!sameHost(asked, SNAP_HOST)) return null;
  try {
    const u = new URL(asked);
    if (u.pathname === "/chat/completions" || u.pathname === "/v1/chat/completions") {
      u.pathname = CHAT_PATH;
      return u.toString();
    }
  } catch {
    return null;
  }
  return asked;
}

/**
 * magpie 宿主塞进插件 fetch 的「仅供插件阅读」的交接头（host.js 的 MAGPIE_ONLY）：
 * 它们告诉插件调用方的工作目录/仓库，**不是给上游厂商看的**。
 * 宿主通常会自己擦掉，但那是宿主的实现细节 —— 插件自己再擦一遍。
 */
const MAGPIE_ONLY_HEADERS = ["x-magpie-work-dir", "x-magpie-work-git"];

/**
 * 两个 URL 是否同一个主机。
 *
 * 用 origin 比较而不是 `startsWith(SNAP_HOST)`：字符串前缀会把
 * `https://snap-access.cn-north-4.myhuaweicloud.com.evil.example/…`
 * 当成自己的地址，把 AK/SK 签名送出去。URL 解析失败一律视为「不是」。
 */
function sameHost(a, b) {
  try {
    return new URL(a).origin === new URL(b).origin;
  } catch {
    return false;
  }
}

/**
 * 云端 channel 缓存：**按账号**存 modelId → "agent" | "benefit"。
 * 由 provider.models 写入，供 loader 判定通道。跨请求存活（模块级）。
 *
 * 两点必须按账号隔离：
 *   ① channel 跟着账号的订阅走，不同账号可能把同一个模型放在不同通道；
 *   ② 同一模型名在不同账号下可能属于不同套餐，串用会走错通道报
 *      `unsupported model`。
 * 所以缓存键是 `AK → (modelId → channel)`，每个账号拉到清单时只替换自己那一层。
 */
const channelCache = new Map();

/** 该账号的 channel 表（测试里也能用空账号名直接灌数据）。 */
function channelTable(ak = "") {
  const key = String(ak ?? "");
  let t = channelCache.get(key);
  if (!t) channelCache.set(key, (t = new Map()));
  return t;
}

/**
 * 通道判定：返回 true 表示走 benefit（免费额度）通道。
 * 优先用云端 channel（先按账号查，再看传进来的显式值）；否则按上游黑名单语义
 * —— 不在 AGENT_MODELS 里的一律 benefit。
 */
function isBenefitChannel(modelId, knownChannel = "", ak = "") {
  const id = String(modelId ?? "").trim();
  if (!id) return false;
  const ch = String(knownChannel || channelTable(ak).get(id.toLowerCase()) || "").toLowerCase();
  if (ch === "benefit") return true;
  if (ch === "agent") return false;
  // 无 channel 信息 → 黑名单：命中 AgentCenter 名单才算老套餐，其余按 benefit
  return !AGENT_MODELS.some((m) => m.toLowerCase() === id.toLowerCase());
}

/**
 * 福利通道的熔断表：`AK|modelId` → 到期时间戳。
 *
 * 🔴 2026-10-20 22:00 前后，上游把福利通道整个摘掉了（两个账号、四个福利模型
 *    全部复现）。任何此前属于「限时福利」的模型只要带上那三个头就回
 *      {"error_code":"4004","error_msg":"benefit not found"}      （非流式）
 *      data:{"error_code":"InferHub.4004.200","error_msg":"benefit not found"} （流式首帧）
 *    而**不带**这三个头时 `deepseek-v4.1-flash` 照常推理（实测 200）。
 *
 *    这三个头参与签名，所以「该不该带」只能在拿到响应之后才知道 —— 每次都先撞
 *    一次再重发，等于把每个请求的延迟翻倍。这里按「账号 + 模型」记一笔：撞到
 *    `benefit not found` 就在 TTL 内直接走普通通道，TTL 过后再试一次福利通道
 *    （上游把活动恢复时能自动切回去）。
 *
 *    按模型而不是按账号记账，是因为「福利没了」完全可能只发生在某个模型上
 *    （活动只续了其中几个），一刀切会让好用的模型也跟着降级。
 */
const BENEFIT_DOWN_MS = 10 * 60 * 1000;
const benefitDown = new Map();

const benefitKey = (ak, model) => `${String(ak ?? "")}|${String(model ?? "").trim().toLowerCase()}`;

/** 该账号这条模型的福利通道是否处于熔断期。 */
function benefitBroken(ak, model, now = Date.now()) {
  const until = benefitDown.get(benefitKey(ak, model));
  if (until === undefined) return false;
  if (until > now) return true;
  benefitDown.delete(benefitKey(ak, model)); // 过期就清掉，允许再试福利通道
  return false;
}

/** 记一笔「这账号这条模型的福利通道不通」，TTL 内不再带那三个头。 */
function markBenefitBroken(ak, model, now = Date.now()) {
  benefitDown.set(benefitKey(ak, model), now + BENEFIT_DOWN_MS);
}

/**
 * 上游「福利通道没了」的两种写法（非流式 `4004 benefit not found`、
 * 流式首帧 `InferHub.4004.200 benefit not found`）。
 *
 * 只认这个签名，不认错误码 —— `4004` 太宽，别把别的业务错误也当成福利下线
 * 而去掉签名头重发。
 */
function benefitGone(text) {
  return /benefit\s+not\s+found|InferHub\.4004\b/i.test(String(text ?? ""));
}

/**
 * 权益网关整体下线（余额 / 领取 / 清单三个接口同一句
 * `4000 invalid channel, group not found`，实测 2026-10-20）。
 *
 * 这类错误是**终局**，不是「这次没拉到」：调用方据此静默退回静态清单 / 报
 * `ineligible`，而不是一直重试并刷日志。服务端哪天恢复，这条判定自然不再命中。
 */
function gatewayRetired(err) {
  const msg = String(err?.message ?? err ?? "");
  return /invalid\s+channel|group\s+not\s+found/i.test(msg);
}

// ---------------------------------------------------------------------------
// 上游会话 ID（并发上限的钥匙）
// ---------------------------------------------------------------------------

/**
 * 该账号在上游的会话 ID —— **必须稳定复用**。
 *
 * 上游按请求头 `x-ot-session-id` 统计并发会话，每账号上限 3 个。不带这个头时，
 * 上游只能按每个请求各记一个新会话，几个并发（主任务 + 子任务 + 后台任务）就
 * 打满上限，返回 `TM.00001041 并发会话数已达上限(3个)`。
 *
 * 而这条错误会被 magpie **误判成额度用尽**：宿主 `internal/gateway/routing.go`
 * 的 `usedUpWords` 正则里含中文词 `上限`，`TM.00001041` 的文案「已达上限」正好
 * 命中 → 判为 `failQuota` → 账号被标「额度用尽」并休息 15 分钟。额度其实没用完。
 * 带上稳定的会话 ID 后并发会话恒为 1，从源头避免这条错误。
 *
 * 由 AK 派生：同一账号恒定不变（跨请求、跨重启），换账号自然换新 ID。
 * 纯函数、不缓存 —— 与上游 IDE 侧的做法一致。
 */
function upstreamSessionId(ak) {
  const key = String(ak ?? "").trim();
  if (!key) return "";
  return "ses_" + createHash("sha256").update(key).digest("hex").slice(0, 16);
}

/**
 * 会话请求头（参与签名）。IDE 同时发这两个名字，这里保持一致。
 * 无 AK 时返回空对象，调用方按「没有就不发」处理。
 */
function sessionHeaders(ak) {
  const sid = upstreamSessionId(ak);
  return sid ? { "x-ot-session-id": sid, "user-session-id": sid } : {};
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

// 🔴 默认别超过 magpie 的 20 秒。宿主给插件的 auth.usage / auth.checkin 钩子
//    `context.WithTimeout(ctx, 20*time.Second)`，从钩子被调起那一刻开始算。
//    这里原来给 30 秒 —— 上游一慢，宿主先放弃、插件后报超时，卡片上就是
//    「暂时无法获取最新额度」，签到则记成 failed。opengw 实测 p50 约 40ms。
async function envelope(path, { method = "GET", body, ak, sk, timeout = 12_000 }) {
  const url = `${OPENGW_HOST}${path}`;
  const bodyStr = body !== undefined ? JSON.stringify(body) : "";
  // 会话头只发给**对话端点**：并发上限是按对话会话算的，余额/签到这些
  // opengw 接口不是会话，多签一个头只是徒增「上游不认这个头」的风险
  // （登录就是靠余额接口做的，一旦它挂了整个插件都登不进来）。
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
    throw Object.assign(new Error(`CodeArts 请求失败: ${redact(cause?.message ?? String(cause), ak, sk)}`), { cause });
  }
  let data;
  try { data = text ? JSON.parse(text) : undefined; } catch { data = undefined; }
  if (res.status !== 200 || !data) {
    throw new Error(`CodeArts ${path} HTTP ${res.status}: ${redact(text.slice(0, 200), ak, sk)}`);
  }
  if (data.error_code !== undefined && !["0000", 0, null].includes(data.error_code)) {
    throw Object.assign(new Error(`CodeArts ${path} 业务错误 ${data.error_code}: ${redact(data.error_msg ?? "", ak, sk)}`), {
      errorCode: String(data.error_code),
    });
  }
  return data.result ?? {};
}

/**
 * GET 同路径的历史用途：参考实现把它当作「签到状态」。
 *
 * 🔴 实测（2026-10）：`result.create_time` **不是**签到时间 —— 它与同一响应的
 *    `update_time` 逐字节相同，落在账号首次登录的时刻，且 8 种请求变体都没有
 *    让它推进过一次。它读不出「今天签没签」。插件里已经没有地方再依赖它，
 *    保留导出只是为了让测试与外部探针还能读到原始响应。
 */
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

/**
 * 福利模型列表：result.models = [{model_id, context_window, max_tokens, channel, …}]。
 *
 * 🔴 失败**不吞**：吞成空数组会让调用方分不清「真的没有模型」和「这次没拉到」，
 * 进而把缓存清空、拿静态兜底清单去判定通道。网络/业务错误一律往上抛。
 */
async function fetchBenefitModels(ak, sk) {
  const r = await envelope(CONFIG_PATH, { ak, sk });
  if (!Array.isArray(r.models)) return [];
  // 上游数组里偶尔有 null / 非对象元素，不能让它打断整份清单
  return r.models.filter((m) => m && typeof m === "object");
}

// ---------------------------------------------------------------------------
// 工具
// ---------------------------------------------------------------------------

/**
 * 把一段文本里可能出现的 AK/SK 换成 `***`。
 *
 * 上游的错误体会**回显请求里的 Access Key**（例如
 * `the access key LTAI5t… is malformed`），而这条消息会进登录失败提示、
 * 提供商页的 listError、以及 magpie 的日志。凭据不该出现在这些地方。
 */
function redact(text, ak, sk) {
  let out = String(text ?? "");
  for (const secret of [sk, ak]) {
    const v = String(secret ?? "").trim();
    if (v.length >= 8) out = out.split(v).join("***");
  }
  return out;
}

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

/**
 * `limit.output` 的取值：正数才有效，并且收敛到上游参数上限。
 * 云端给 393216（模型能力）→ 发布 65536（参数允许的最大值）。
 */
function outputLimit(v) {
  const n = optNumber(v);
  return n === undefined ? undefined : Math.min(n, MAX_OUTPUT_TOKENS);
}

/** 余额字段取值：只有拿到有限数才算「有值」（0 合法，null / "" / NaN 不算）。 */
function num(v) {
  if (v === null || v === undefined || v === "") return undefined;
  const n = Number(v);
  return Number.isFinite(n) ? n : undefined;
}

/**
 * 改写对话请求体，使它符合上游的硬性要求：
 *
 * ① **输出上限**收敛到 `MAX_OUTPUT_TOKENS`
 *    宿主只在**路由组内**按成员上限收敛（`gateway.go` 的 `outputLimit` +
 *    `withMaxOutput`），组外只有用户手动设过「Max output」才会下降。裸模型
 *    `codearts/x` 收到 `max_tokens=65537` 时上游 400，magpie 又把它包成
 *    HTTP 200 的空流 —— 客户端只看到「成功、没内容」。
 *
 * ② **显式 `stream` 布尔值**
 *    🔴 上游对**缺省** `stream` 的请求按 **SSE** 应答（实测：body 不带该字段 →
 *    `content-type: text/event-stream`）。而 SSE 里的错误事件长这样：
 *        data:{"error_code":"4005","error_msg":"unsupported model","result":null}
 *    magpie 的嗅探器只认 OpenAI 形态的 `{"error": …}`，于是把它当成一个没有
 *    内容的正常结束 → 客户端拿到的仍是 **HTTP 200 + content:null + 0 tokens**，
 *    真正的错误（模型不存在、参数非法）被完全吞掉。带上显式 `stream: false`
 *    后，同样的请求上游返回 **HTTP 400 + application/json**，错误原样透出
 *    （实测对比：不带 = 200 空回答；带 = 400 `unsupported model`）。
 *    OpenAI 语义里缺省 `stream` 就是 false，这里只是把默认值写明。
 *    已经有 `stream` 字段的请求**一律不动** —— magpie 的翻译路径会显式写
 *    `stream: true` 并期待 SSE，改它会破坏那条路径。
 *
 * 返回改写后的 body 字符串；没有改动时返回 `null`（调用方沿用原 body 与签名）。
 */
function normalizeChatBody(bodyStr) {
  if (!bodyStr) return null;
  let obj;
  try { obj = JSON.parse(bodyStr); } catch { return null; }
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return null;
  let changed = false;
  for (const k of ["max_tokens", "max_completion_tokens", "max_output_tokens"]) {
    const n = Number(obj[k]);
    if (Number.isFinite(n) && n > MAX_OUTPUT_TOKENS) {
      obj[k] = MAX_OUTPUT_TOKENS;
      changed = true;
    }
  }
  if (!("stream" in obj)) {
    obj.stream = false;
    changed = true;
  }
  return changed ? JSON.stringify(obj) : null;
}

/** @deprecated 保留旧名，等价于 `normalizeChatBody`（测试与外部脚本用）。 */
const clampChatBody = normalizeChatBody;

/**
 * 从上游响应体里认出错误。
 *
 * 上游并不总是用 HTTP 状态码表达失败：`unsupported model` 这类是
 * **HTTP 200 + `{"error_code":"4005","error_msg":"unsupported model"}`**
 * （实测，非流式下就是原样 JSON）。magpie 的嗅探器只认 OpenAI 的
 * `{"error": …}` 形态，于是把它当成「一个没有 choices 的正常结束」——
 * 客户端收到 `HTTP 200 + content:null + 0 tokens`，错误彻底消失。
 *
 * 返回 `{code, message}`；不是错误时返回 null。
 */
function upstreamError(text) {
  let obj;
  try { obj = JSON.parse(text); } catch { return null; }
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return null;
  const code = obj.error_code;
  const codeBad = code !== undefined && code !== null && !["0000", 0].includes(code);
  // 没有 choices 又没有正文，也视为错误（上游偶尔只给 error_msg）
  const noAnswer = !Array.isArray(obj.choices) && !obj.id && (obj.error_msg || obj.error);
  if (!codeBad && !noAnswer) return null;
  const message = String(obj.error_msg ?? obj.error?.message ?? obj.error ?? "upstream error");
  return { code: String(code ?? obj.error?.code ?? ""), message };
}

/** 错误响应：400 + OpenAI 错误形态（magpie 的 APIError 从中取出 message）。 */
function errorResponse({ code, message }) {
  const body = JSON.stringify({ error: { message, type: "codearts_error", code } });
  return new Response(body, {
    status: 400,
    statusText: "Bad Request",
    headers: { "content-type": "application/json" },
  });
}

/** 重写响应体时不能沿用的头（body 已不是原始字节）。 */
const REWRITTEN_HEADERS = ["content-length", "content-encoding", "transfer-encoding"];

/** 窥探流式首事件的时限与字节上限（只为认出「首个事件就是错误」这一种情况）。 */
const PEEK_MS = 3000;
const PEEK_BYTES = 64 * 1024;

function cloneHeadersWithout(headers) {
  const out = new Headers(headers);
  for (const k of REWRITTEN_HEADERS) out.delete(k);
  return out;
}

/**
 * 流式响应里，错误同样以 `data:{"error_code": …}` 的形式出现：
 *   · 作为**首个事件**（实测 `unsupported model` 就是这样）；
 *   · 或夹杂在正常分片中间（限流、额度类错误）。
 * 直接透传的话，OpenAI 客户端只会把它当未知分片丢掉，最后得到空回答。
 *
 * 两段处理：
 *   ① 先窥探首个 data 行；是错误就取消上游流，整条改成 400 JSON（最干净）；
 *   ② 不是错误就把已读分片补回，后续按行转发，并把途中出现的错误事件改写为
 *      OpenAI 形态 `{"error":{…}}` —— magpie 的嗅探器认这个，会据此把流标成失败。
 * 转发逐行进行，未改写的行原样重编码（UTF-8 往返无损），不会破坏分片边界。
 */
/**
 * 窥探流的首个 data 事件，只为认出「一上来就是错误」这一种情况。
 *
 * 🔴 `reader.read()` 在**上游一个字节都不发**时会一直挂着 —— 只检查
 *    `Date.now()` 是没用的，必须先和定时器竞速。超时后把那次**尚未完成**的
 *    read 原样交给后续转发（`pending`），不能丢掉，否则那一块的读取就漏了。
 */
async function peekStream(reader, dec) {
  let text = "";
  let pending = null;
  let err = null;
  const deadline = Date.now() + PEEK_MS;
  try {
    while (true) {
      const remaining = deadline - Date.now();
      if (remaining <= 0) break;
      const readP = pending ?? reader.read();
      pending = null;
      let timer;
      const raced = await Promise.race([
        readP.then((v) => ({ v })),
        new Promise((r) => { timer = setTimeout(() => r({ timeout: true }), remaining); }),
      ]);
      clearTimeout(timer);
      if (raced.timeout) {
        pending = readP; // 还没回来，交给转发那一侧接着等
        break;
      }
      const { value, done } = raced.v;
      if (done) break;
      text += dec.decode(value, { stream: true });
      const lines = text.split("\n");
      if (!text.endsWith("\n")) lines.pop(); // 最后一段可能不完整，先不看
      const line = lines.find((l) => {
        const t = l.startsWith("data:") ? l.slice(5).trim() : "";
        return t && t !== "[DONE]";
      });
      if (line) { err = upstreamError(line.slice(5).trim()); break; }
      if (text.length > PEEK_BYTES) break; // 不像错误流，别无限缓冲
    }
  } catch {
    // 读失败就按原样把已有分片交出去
  }
  return { text, pending, err };
}

async function rewriteStreamError(res) {
  const reader = res.body.getReader();
  const dec = new TextDecoder();
  const { text, pending, err } = await peekStream(reader, dec);
  if (err) {
    try { await reader.cancel(); } catch { /* 已经断了 */ }
    return errorResponse(err);
  }
  return new Response(streamWithErrorEvents(text, dec, reader, pending), {
    status: res.status,
    statusText: res.statusText,
    headers: cloneHeadersWithout(res.headers),
  });
}

/** 流式中途的错误事件 → OpenAI 的 `{"error": …}`，其余行原样。 */
function streamWithErrorEvents(prefix, dec, reader, firstRead = null) {
  const enc = new TextEncoder();
  let buf = prefix;
  let pending = firstRead;
  let closed = false;
  const rewrite = (line) => {
    const t = line.startsWith("data:") ? line.slice(5).trim() : "";
    if (!t || t === "[DONE]") return line;
    const err = upstreamError(t);
    if (!err) return line;
    return `data:${JSON.stringify({ error: { message: err.message, type: "codearts_error", code: err.code } })}`;
  };
  /** 把缓冲区里**已经完整**的行入队；返回这次入队的行数。 */
  const drain = (controller) => {
    const lines = buf.split("\n");
    buf = lines.pop();
    if (!lines.length) return 0;
    controller.enqueue(enc.encode(lines.map(rewrite).join("\n") + "\n"));
    return lines.length;
  };
  return new ReadableStream({
    start(controller) {
      drain(controller);
    },
    async pull(controller) {
      if (closed) return;
      // 🔴 一个 pull 里必须读到**至少一整行**才返回。
      //    以前是「读一块 → 入队完整的行 → 返回」，遇到上游把 `data:` 和后面的
      //    内容分成两个 chunk 时（实测很常见），这一轮什么都没入队就返回了；
      //    Node 的 ReadableStream 在 pull 空手而归之后不会再调 pull，
      //    于是流就停在那儿 —— 20 次压测挂 3~4 次，客户端表现为「回答永不结束」。
      try {
        for (;;) {
          const { value, done } = pending ? await pending : await reader.read();
          pending = null;
          if (done) {
            closed = true;
            if (buf) {
              controller.enqueue(enc.encode(rewrite(buf)));
              buf = "";
            }
            controller.close();
            return;
          }
          buf += dec.decode(value, { stream: true });
          if (drain(controller)) return;
        }
      } catch (e) {
        closed = true;
        controller.error(e);
      }
    },
    cancel(reason) {
      closed = true;
      reader.cancel(reason).catch(() => {});
    },
  });
}

/**
 * 把「HTTP 200 里藏着的错误」翻成真正的错误响应，其余原样返回。
 * 只对对话端点调用（其它路径由宿主自己处理）。
 */
async function normalizeChatResponse(res) {
  if (!res || res.status !== 200 || !res.body) return res;
  const ct = String(res.headers.get("content-type") ?? "").toLowerCase();
  if (ct.includes("text/event-stream")) return rewriteStreamError(res);
  if (!ct.includes("application/json")) return res;
  let text;
  try { text = await res.text(); } catch { return res; }
  const err = upstreamError(text);
  if (err) return errorResponse(err);
  return new Response(text, {
    status: res.status,
    statusText: res.statusText,
    headers: cloneHeadersWithout(res.headers),
  });
}

/** 保留一位小数（百分比的展示精度）。 */
function round1(n) {
  return Math.round(Number(n) * 10) / 10;
}

/**
 * 对话应答的统一收尾：先窥探首帧判断「福利通道是不是没了」，再把响应规范化。
 *
 * 两种下线形态都要认（实测 2026-10-20）：
 *   · 非流式：HTTP 200 + `{"error_code":"4004","error_msg":"benefit not found"}`
 *   · 流式  ：HTTP 200 + SSE 首帧 `data:{"error_code":"InferHub.4004.200",…}`
 *
 * 🔴 **窥探与改写必须一次做完，绝不能分两层**。踩过的两个坑：
 *
 *    ① 用 `res.clone()` 窥探 —— clone 会把上游流 tee 成两支，取消窥探那一支
 *       会把另一支一起卡住（对真上游实测：卡在 `reader.cancel()` 上永不返回）。
 *    ② 先在这里 peek 一层、再让 `normalizeChatResponse` 包第二层 —— 同一次
 *       未完成的 `read()` 被两层流各挂一份，~15% 的流式请求永远不结束。
 *
 *    所以这里只拿一次 reader：读出首帧用于判定，然后把「已读到的字节 + 这个
 *    reader + 那次可能还没回来的 read」一起交给 `streamWithErrorEvents` 继续
 *    转发。命中时返回 `{gone:true}`，调用方丢掉这个响应、换个签名重发。
 *
 * 返回 `{gone:true, err}` 或 `{gone:false, res}`（res 已是规范化后的成品，
 * 调用方**直接**交出去，不要再包 normalizeChatResponse）。
 */
async function sniffBenefitGone(res) {
  if (!res || res.status !== 200 || !res.body) return { gone: false, res };
  const ct = String(res.headers.get("content-type") ?? "").toLowerCase();
  // 只有对话的两种应答形态值得看；别的一律不碰
  if (!ct.includes("application/json") && !ct.includes("text/event-stream")) return { gone: false, res };

  if (!ct.includes("text/event-stream")) {
    let text;
    try { text = await res.text(); } catch { return { gone: false, res } };
    if (benefitGone(text)) {
      try { await res.body?.cancel?.(); } catch { /* 已读完 */ }
      return { gone: true, err: upstreamError(text) ?? { message: "benefit not found" } };
    }
    // 与 normalizeChatResponse 的非流式分支同一套处理：藏起来的错误翻成 400
    const err = upstreamError(text);
    if (err) return { gone: false, res: errorResponse(err) };
    return {
      gone: false,
      res: new Response(text, {
        status: res.status,
        statusText: res.statusText,
        headers: cloneHeadersWithout(res.headers),
      }),
    };
  }

  const reader = res.body.getReader();
  const dec = new TextDecoder();
  const { text, pending, err } = await peekStream(reader, dec);
  if (benefitGone(text) || (err && benefitGone(err.message))) {
    try { await reader.cancel(); } catch { /* 已经断了 */ }
    return { gone: true, err: err ?? upstreamError(text) ?? { message: "benefit not found" } };
  }
  // 不是福利下线：把窥探结果原样接回去，剩下的照旧按行转发/改写
  return {
    gone: false,
    res: new Response(streamWithErrorEvents(text, dec, reader, pending), {
      status: res.status,
      statusText: res.statusText,
      headers: cloneHeadersWithout(res.headers),
    }),
  };
}

/**
 * 上游「今天」的 0 点（毫秒）。
 *
 * 🔴 上游的每日免费 Token 按**中国时区 24:00 清零**，所以天界必须按 UTC+8 算，
 *    不能按机器本地时区 —— 否则机器不在东八区时，签到判定与「今日已签」会差一天。
 *    中国无夏令时，固定偏移即可。
 */
const CN_OFFSET_MS = 8 * 60 * 60 * 1000;

function startOfTodayMs(now = Date.now()) {
  return Math.floor((now + CN_OFFSET_MS) / 86400000) * 86400000 - CN_OFFSET_MS;
}

/**
 * 签到结果 → magpie checkin 契约 {outcome, credit?, streak?, message?}。
 * outcome 必须是 claimed | done | ineligible | inactive | captcha | failed 之一；
 * 非枚举值会被宿主归一为 failed 并在 message 里附「the plugin answered no outcome」。
 *
 * 🔴 2026-10 实测推翻了这个接口的旧理解：`result.create_time` **不是**最近签到
 *    时间。两个真实账号上它与同一响应的 `update_time` 逐字节相同，且分别落在
 *    「首次登录码道」「更早」的时刻；随后连续 8 种不同请求（header / body /
 *    query 变体，含 maas_type、x-ot-session-id、JSON body）全返回同一个值，
 *    一次都没有推进。它是账号/权益记录的**创建**时间。
 *
 *    把它当签到时间戳，后果是每天都会判成「未推进」→ ineligible，宿主 UI 与
 *    卡片上就永远写着「未签」。上游也没有第二个接口能读到签到状态（把
 *    /api/v1/benefit/* 与 /api/v1/user/* 的 12 个候选路径全扫过，除 claim 与
 *    tokens/balance 外一律 404 APIG.0101），控制台的积分是另一种货币，
 *    这里读不到。
 *
 *    所以：能确定的只有「POST 得到 error_code 0000」。按服务端按天幂等来算，
 *    这就是今天已签 —— 报 done，不编造积分数量，也不报一个假的「未签」。
 *    拿不到任何回答（网络/超时）才是 failed，交给宿主 30 分钟后重试。
 */
function checkinOutcome(posted, createMs, err) {
  if (posted) {
    // POST 已受理。create_time 与签到无关（见上），不据它判失败。
    // credit 不报：上游没有任何字段说这次发了多少，编一个数就是撒谎。
    return { outcome: "done", message: "今日签到已受理" };
  }
  const code = String(err?.errorCode ?? "");
  const msg = String(err?.message ?? "");
  // 权益网关整个没了（2026-10-20 实测：`invalid channel, group not found`，
  // 余额 / 领取 / 清单三个接口同时这样回）。活动已下线，不是「这次没签上」，
  // 报 ineligible 让宿主别再每 30 分钟重试一次必死的请求。
  if (gatewayRetired(err) || benefitGone(msg)) {
    return { outcome: "ineligible", message: "上游权益网关已下线（福利活动结束），无需签到" };
  }
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
    if (modelRetired(id)) continue; // 两条通道都不通，别让宿主轮询到（见 RETIRED_MODELS）
    out[id] = {
      name: meta.name,
      id,
      limit: { context: meta.context, output: meta.output },
      reasoning: false,
      tool_call: true,
      // 让宿主知道这个模型收不收图（见 MODEL_META 上方的说明）
      ...modalitiesField(imageCapable(id)),
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
        // 这里是 **base**，不是完整端点：宿主会把它当作 `baseURL + "/chat/completions"`
        // 的兜底基址（plugins.go 的 `firstOf(o.BaseURL, m.URL, pp.API, …)`）。
        // 写完整端点会让兜底路径拼出 `…/api/v2/chat/completions/chat/completions`。
        // 主机名部分对 `Provider.Origin()` 仍然正确。
        api: `${SNAP_HOST}/api/v2`,
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
              return { type: "failed", error: `AK/SK 验证失败: ${redact(e?.message ?? String(e), ak, sk)}` };
            }
            // 🔴 metadata 里必须把 `credential` 显式盖成空串。
            //    宿主 `save()` 的实现是 `md = { ...inputs, ...result.metadata }`
            //    （internal/plugin/host.js），而 inputs 里就带着 prompt 收集的
            //    原始 "AK:SK" 组合串。不盖的话这份**完整凭据**会被原样写进
            //    `plugin-auth.json` 的 `metadata.credential`，与 `key` 和
            //    `metadata.sk` 重复三份。返回同名键即可覆盖它（result 后合并、优先）。
            return { type: "success", key: ak, metadata: { sk, credential: "" } };
          },
        },
      ],

      async loader(getAuth) {
        const auth = await getAuth();
        if (auth?.type !== "api" || !auth.key) return {};
        const { ak, sk } = creds(auth);
        // 🔴 会话头在 loader 里只算一次：同一账号所有请求复用同一个 ID
        const session = sessionHeaders(ak);
        return {
          // 🔴 baseURL 是 `SNAP_HOST + /api/v2`，不是 SNAP_HOST 本身。
          // 宿主（internal/provider/plugins.go 的 pluginFetch）把 provider.api 里的
          // `/v1` 段切掉、再拼到 baseURL 后面：baseURL + "/chat/completions"。
          // 所以 baseURL 必须已经含 `/api/v2`，否则请求会打到
          // `…/chat/completions`（少一段）而 404。
          baseURL: `${SNAP_HOST}/api/v2`,
          async fetch(input, init) {
            // 只接手本 provider 自己的主机。别的地址原样转发 —— 绝不能改写目标、
            // 也绝不能把我们的签名套到别的 URL 上。
            const asked = typeof input === "string" ? input : String(input?.url ?? "");
            const target = resolveTarget(asked);
            if (target === null) return fetch(input, init);

            // Request 对象作 input 时，方法和 body 在它身上而不是 init 里
            const req = typeof input === "string" ? null : input;
            const method = String(init?.method ?? req?.method ?? "GET").toUpperCase();
            const rawBody = init?.body ?? null;
            let bodyStr = "";
            if (typeof rawBody === "string") {
              bodyStr = rawBody;
            } else if (rawBody instanceof Uint8Array) {
              bodyStr = new TextDecoder().decode(rawBody);
            } else if (rawBody !== null && rawBody !== undefined) {
              // 其它形态（ReadableStream 等）无法参与签名，交给原样转发
              return fetch(input, init);
            } else if (req?.body) {
              // Request 对象自带的 body：读克隆，不能消费掉原件
              bodyStr = await req.clone().text();
            }

            // 福利/老套餐通道判定（黑名单 + 云端 channel）。这三个头只属于对话端点，
            // 发到别的路径上会被上游当成 unsupported model。会话头则所有对话请求都带。
            const isChat = target === CHAT_ABS || target.startsWith(`${CHAT_ABS}?`);
            // 🔴 上游 max_tokens 硬上限 65536；且缺省 stream 会按 SSE 应答，
            //    把上游错误吞成 200 空回答。两件事都在**签名之前**改，
            //    签名才对得上实际发出的 body。
            if (isChat) {
              const fixed = normalizeChatBody(bodyStr);
              if (fixed !== null) bodyStr = fixed;
            }
            let model = "";
            if (isChat && bodyStr) {
              try { model = String(JSON.parse(bodyStr).model ?? ""); } catch { /* 保持空 */ }
            }
            const benefit = isChat && isBenefitChannel(model, "", ak);
            const send = async (withBenefit) => {
              const extra = withBenefit
                ? { ...session, maas_type: "benefit", "model-id": model, "model-name": model }
                : session;
              const headers = sdkSignedHeaders(method, target, bodyStr, ak, sk, extra);

              // 原请求的其它头（例如 accept: text/event-stream）要保留：
              // 流式与非流式靠它区分，丢了会让上游按非流式应答。
              const merged = new Headers(req?.headers);
              new Headers(init?.headers).forEach((v, k) => merged.set(k, v));
              for (const [k, v] of Object.entries(headers)) merged.set(k, v);
              // host 只参与签名，不能手动发；magpie 自己的交接头只给插件读，
              // 不能转给上游厂商（别指望宿主替我们擦，新版本可能不再擦）
              merged.delete("host");
              for (const k of MAGPIE_ONLY_HEADERS) merged.delete(k);

              const forwarded = bodyStr === "" ? undefined : bodyStr;
              return fetch(target, {
                method,
                headers: merged,
                ...(forwarded !== undefined ? { body: forwarded } : {}),
                signal: init?.signal ?? req?.signal,
              });
            };

            // 福利通道是**按签名头**选的，带错了只有上游知道。撞到 `benefit not found`
            // 就当场去掉那三个头重发一次（同一请求、同一 body，签名随头重算），
            // 并把这条模型记进熔断表，TTL 内不再先撞一次。详见 benefitDown 的注释。
            // 🔴 sniffBenefitGone 返回的 res 已经是成品（窥探 + 改写一次做完），
            //    **不能再包一层 normalizeChatResponse**（见它的注释）。
            if (benefit && !benefitBroken(ak, model)) {
              const probe = await sniffBenefitGone(await send(true));
              if (!probe.gone) return probe.res;
              markBenefitBroken(ak, model);
              // 去掉签名头重发。普通通道若是**真的**能跑就用它；跑不了（`model is
              // not registered`）说明这条模型只有福利通道认，那就把「福利没了」
              // 这条更可执行的错误交给调用方。
              const plain = await normalizeChatResponse(await send(false));
              return plain.status === 400 ? errorResponse(probe.err) : plain;
            }
            const res = await send(false);
            // 上游会把「模型不存在」这类错误藏在 HTTP 200 里（见 normalizeChatResponse）
            return isChat ? normalizeChatResponse(res) : res;
          },
        };
      },

      async usage(getAuth) {
        // 🔴 ak/sk 必须在 try **外面**声明：下面 catch 要用它们做脱敏。
        //    写成 try 内的 const 时，creds() 抛错（凭据不完整）会先跳出块，
        //    catch 里的 ak/sk 变成 TDZ 之外的未绑定标识符 —— 抛 ReferenceError，
        //    宿主拿到的是异常而不是「额度查询失败」的 error 字段。
        let ak = "";
        let sk = "";
        try {
          const auth = await getAuth();
          if (auth?.type !== "api" || !auth.key) return { error: "未登录", windows: [] };
          ({ ak, sk } = creds(auth));
          const bal = await fetchBalance(ak, sk).catch(() => null);
          // 🔴 权益网关下线时（`invalid channel, group not found`）余额接口只会一直
          //    返回空，别让卡片上只写一句「失败」。给出可读的原因，路由不受影响
          //    —— 这个钩子只影响展示。
          if (!bal) return { error: "额度接口无数据（上游权益网关可能已下线）", windows: [] };
          // 🔴 以前这里还会 GET 一次 claim 端点来判断「今日已签」，依据是
          //    create_time —— 那是权益记录的创建时间，从不随签到推进（见
          //    checkinOutcome 注释），于是每张卡片上永远写着「今日未签」。
          //    宿主本来就把签到结果放在卡片上（SubscriptionQuota.checkin，
          //    来自 plugin-checkin.json 里插件钩子的真实回答）。插件再画一行
          //    自己的判断，既和宿主打架、又是错的，这次读也没有任何用处。
          // 字段名在不同响应里不完全一致：优先 total_*，回退 daily_*，再回退互相反推
          const quota = num(bal.total_quota) ?? num(bal.daily_token_limit);
          let usedAbs = num(bal.used_amount) ?? num(bal.daily_tokens_used);
          let left = num(bal.total_balance);
          if (usedAbs === undefined && quota !== undefined && left !== undefined) usedAbs = quota - left;
          if (left === undefined && quota !== undefined && usedAbs !== undefined) left = quota - usedAbs;
          // 上游偶尔会给出「已用 > 总量」或负余额（跨天/统计滞后）。数值不能为负，
          // 否则宿主会把 used 画成负百分比、显示成「剩得比总量还多」。
          if (usedAbs !== undefined && usedAbs < 0) usedAbs = 0;
          if (left !== undefined && left < 0) left = 0;
          if (quota !== undefined && usedAbs !== undefined && usedAbs > quota) usedAbs = quota;

          // 🔴 magpie 的 window 语义（对照宿主源码与社区插件约定，勿改）：
          //   used   = **已用百分比**（0~100+），宿主直接渲染成 "N%"
          //   amount = **已用**的绝对值，宿主 quotaCount() 渲染成 "amount / limit"
          //   limit  = 绝对值总量
          //   unit   = 计量单位，拼在数字后面
          //   aside  = 只展示，不参与路由，也不参与「用尽」判定
          // 曾把 used 填成绝对值（显示 299530%），又把 amount 填成「剩余」
          // （于是 "7819948 / 10000000" 被读成「已用 78%」，而真实已用是 21.8%）。
          const window = { name: "每日免费 Token", used: 0, unit: "tokens" };
          if (quota !== undefined && quota > 0) {
            if (usedAbs !== undefined) {
              window.used = round1((usedAbs / quota) * 100);
              window.amount = usedAbs;
              window.limit = quota;
              window.display = `${Math.round(usedAbs)} / ${Math.round(quota)}`;
            } else if (left !== undefined) {
              window.display = `${Math.round(left)} tokens`;
            }
          } else if (left !== undefined) {
            window.display = `${Math.round(left)} tokens`;
          }
          return {
            // magpie 会在 balance 后面自动追加 "left"，这里只写「数量 + 单位」
            balance: left !== undefined ? `${Math.round(left)} tokens` : "已登录",
            // 只有额度这一个窗口。签到状态由宿主显示（它读 plugin-checkin.json
            // 里插件钩子的真实结果），插件不再画第二个、会自相矛盾的状态行。
            windows: [window],
          };
        } catch (e) {
          return { error: `额度查询失败: ${redact(e?.message ?? String(e), ak, sk)}`, windows: [] };
        }
      },

      async checkin(getAuth) {
        try {
          const auth = await getAuth();
          if (auth?.type !== "api" || !auth.key) return { outcome: "inactive", message: "未登录" };
          const { ak, sk } = creds(auth);
          // 🔴 不再先读一次「签到状态」：那个 GET 的 create_time 是权益记录的
          //    创建时间，不是签到时间（见 checkinOutcome 的注释），拿它判
          //    「今天已签」永远为假，只会白多一次往返。
          //    POST 本身按天幂等：今天已领也返回 0000，所以重复调用无害。
          let posted;
          try {
            posted = await claimToday(ak, sk);
          } catch (e) {
            return checkinOutcome(false, undefined, e);
          }
          return checkinOutcome(true, num(posted?.create_time));
        } catch (e) {
          return checkinOutcome(false, undefined, e);
        }
      },
    },

    provider: {
      id: "codearts",
      async models(provider, { auth }) {
        let ak, sk;
        try {
          ({ ak, sk } = creds(auth ?? {}));
        } catch {
          // 没登录：给静态清单，不算错误
          return provider.models;
        }
        try {
          const rows = await fetchBenefitModels(ak, sk);
          // 只替换**本账号**那一层：channel 跟账号走，留着别的账号的判定会串通道；
          // 但也不能整体清空，否则另一个账号的缓存会被这次拉取抹掉。
          // 空清单同样要替换 —— 否则本账号的旧记录会一直生效。
          const table = channelTable(ak);
          table.clear();
          if (!rows.length) return provider.models;
          const out = { ...provider.models };
          for (const m of rows) {
            const id = String(m.model_id ?? m.modelId ?? m.id ?? "").trim();
            if (!id) continue;
            if (modelRetired(id)) continue; // 福利没了、普通通道也不认（见 RETIRED_MODELS）
            // 🔴 保留云端 channel：既用于本次判定，也写进本账号的 channel 表供 loader 用
            const channel = String(m.channel ?? "").trim().toLowerCase();
            if (channel === "agent" || channel === "benefit") table.set(id.toLowerCase(), channel);
            out[id] = {
              name: String(m.model_name ?? m.modelName ?? m.name ?? id),
              id,
              limit: {
                context: optNumber(m.context_window ?? m.contextWindow),
                // 云端 max_tokens 是模型能力，可能远超上游参数上限 —— 收敛后再发布
                output: outputLimit(m.max_tokens ?? m.maxTokens),
              },
              reasoning: false,
              tool_call: true,
              // 明确声明收不收图（**不许留空**：留空 = 「没说」= 宿主照发图片 → 406）。
              // 这里必须用 capabilities 而不是 modalities —— 这条钩子的返回值
              // 宿主原样采用，不走 modalities 转换（见上方说明）
              ...capabilitiesField(imageCapable(id)),
            };
          }
          return out;
        } catch (e) {
          // 权益网关**永久**下线（2026-10-20 起 `invalid channel, group not found`）
          // 不是「这次没拉到」：每次刷新都抛一次只会刷满日志，而静态清单本来就
          // 是对的。只有网络/临时错误才上抛给宿主记 listError。
          if (gatewayRetired(e)) return provider.models;
          // 拉取失败：**不清缓存**（旧判定仍然是对这个账号最靠谱的信息），
          // 并把原因抛给宿主 —— 宿主会记 listError，在提供商页显示出来
          throw new Error(`CodeArts 模型清单获取失败: ${redact(e?.message ?? String(e), ak, sk)}`);
        }
      },
    },
  };
}

/** 测试辅助（宿主不会把它当插件调用）。 */
export const _internal = {
  rfc3986, sdkSignedHeaders, envelope, creds, bare, parseCredential, redact,
  claimStatus, claimToday, fetchBalance, fetchBenefitModels,
  checkinOutcome, startOfTodayMs, isBenefitChannel, codeartsModels, clampChatBody,
  upstreamSessionId, sessionHeaders, num, round1, optNumber, outputLimit, CN_OFFSET_MS,
  channelCache, channelTable, MODEL_META, VISION_MODELS, AGENT_MODELS, MAX_OUTPUT_TOKENS,
  RETIRED_MODELS, modelRetired,
  benefitBroken, markBenefitBroken, benefitGone, gatewayRetired, benefitDown, BENEFIT_DOWN_MS,
  modalitiesField, capabilitiesField, imageCapable,
  normalizeChatBody, upstreamError, normalizeChatResponse, rewriteStreamError, PEEK_MS,
  sniffBenefitGone,
  SNAP_HOST, CHAT_PATH, OPENGW_HOST,
};
