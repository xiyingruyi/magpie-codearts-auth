/**
 * magpie-codearts-auth —— magpie/OpenCode provider 插件：华为云码道 CodeArts。
 *
 * - 授权：华为云访问密钥 AK/SK（一个输入框粘贴 "AK:SK"，SDK-HMAC-SHA256 签名）
 * - 每日签到：GET /v1/ops/delivery?channel=IDE → POST /v1/ops/claim → POST /v1/ops/confirm
 *   （auth.checkin；领的是**积分**，每日 1000）
 * - 积分余额：GET snap-manager /snap-manager/v1/statistics/plugin（auth.usage）
 * - 免费 Token 池：**2026-10-20 官方已结束**（论坛公告 + 活动 PDF 目录移除 + 实测
 *   `4000 invalid channel, group not found`）。opengw 那套 balance/config 保留为
 *   「拿得到才展示」的可选窗口，但不再指望它——现在只有积分一本账。
 * - 对话：POST snap-access /api/v2/chat/completions（OpenAI chat 形态，body 原样转发）
 *   · 福利模型（benefit）必须附加 maas_type/model-id/model-name 三个头并参与签名
 *   · 老套餐模型（AgentCenter）不能带这三个头（上游报 unsupported model）
 * - 模型清单：GET snap-access /v1/model/builtin（与 IDE 模型下拉同源，实时）
 *   · opengw 的 `/api/v1/gateway/config` 自 2026-10-20 起固定 4000，已不再使用
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
 *
 * --- 0.2.17：签到/余额搬回 snap 侧的两本账（详见 README「0.2.17」节） ---
 * ⑧ 此前把「限时福利」的 `POST opengw /api/v1/benefit/claim` 当成了签到 —— 那是
 *    **每日 1000 万免费 token 池**，不是积分。真正的每日签到领 1000 积分在 snap 引擎上：
 *    `GET /v1/ops/delivery?channel=IDE` 看活动状态 → `POST /v1/ops/claim` 领 →
 *    `POST /v1/ops/confirm` 确认（三步，缺 confirm 会卡在 CLAIMED）。
 * ⑨ 积分余额读 `GET /snap-manager/v1/statistics/plugin` 的
 *    `usageTotalPackageCredit.package_credit_remain`。**前缀必须带 `snap-manager`**
 *    （与 `/v1/ops/*` 相反，混用是此前 12 条候选路径全部扫不到的原因）。
 * ⑩ 可选头 `agent-type: PromptCenter` 用小写且参与签名 —— 大写的 `Agent-Type`
 *    在 APIG 眼里是系统头，不入签名会 401 APIG.0301（实测）。
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
/** 内置模型清单（snap 侧，与 IDE 模型下拉同一份数据）—— 见 fetchBuiltinModels。 */
const BUILTIN_MODELS_PATH = "/v1/model/builtin";

/**
 * snap 引擎上的「积分」这套账（与 opengw 的免费 token 池是两本并行的账）。
 *
 * 🔴 前缀是这个接口最容易踩的坑：这三条 `snap-manager` 前缀**必须带**，
 *    而 `/v1/ops/*` 那三条**必须不带** —— 混起来就是 `APIG.0101 The API does not
 *    exist or has not been published in the environment`（此前扫不到签到接口的根因）。
 */
const STATS_PATH = "/snap-manager/v1/statistics/plugin"; // 积分余额 / 套餐到期
const OPS_DELIVERY_PATH = "/v1/ops/delivery"; // 活动清单（签到状态预检）
const OPS_CLAIM_PATH = "/v1/ops/claim"; // 领取（积分此时即到账）
const OPS_CONFIRM_PATH = "/v1/ops/confirm"; // 确认（把 CLAIMED 推进到 CONFIRMED）

/** 渠道：IDE = 码道客户端/插件（网页端用 WEB）。 */
const OPS_CHANNEL = "IDE";

/**
 * 每日签到活动的身份。`campaignId` 有时会变，所以**按 type 认**，
 * 只有 type 缺失时才回落到这个 id（见 pickDailyCampaign）。
 */
const DAILY_CAMPAIGN_TYPE = "USER_LOGIN";
const DAILY_CAMPAIGN_ID = 1;

/**
 * snap 侧的可选头。🔴 必须用小写 `agent-type` **并参与签名**：
 * 大写的 `Agent-Type` 在 APIG 眼里是系统头，不入 SignedHeaders 直接
 * 401 `APIG.0301 verify ak sk signature fail`（实测；小写不签也能过，
 * 但签上更稳，上游收紧策略时也不会把我们打成未签名请求）。
 */
const AGENT_TYPE_HEADER = { "agent-type": "PromptCenter" };

/**
 * snap 侧请求的单次超时。
 *
 * 🔴 这是**总预算**问题，不是单个请求的问题：宿主给 `auth.usage` / `auth.checkin`
 *    钩子的 context 只有 20 秒（`context.WithTimeout(ctx, 20*time.Second)`），而
 *    签到一次要串 2~3 个请求（delivery → claim → confirm），usage 一次要打两个账
 *    接口。opengw 那边给的 12 秒是单请求时代的余量，照抄到这里就会超预算：
 *    3 × 12 = 36 秒，宿主先放弃、插件后报错。
 *
 *    实测这一侧快得多（delivery 145~180ms、statistics 233~1440ms、claim/confirm 同量级），
 *    6 秒已有 4 倍余量；usage 的两个账接口改成并行，最坏也就一个超时。
 */
const SNAP_TIMEOUT_MS = 6_000;

/**
 * 单次 snap 请求的最小可用时间。
 *
 * 🔴 6 秒是**单个请求**的余量，不是**整条链**的余量：`snapEnvelope` 撞到
 *    APIG.0301 会去掉可选头重发一次，最坏就是 12 秒。签到串 3 步（delivery →
 *    claim → confirm）再加补确认，最坏能到 36 秒 —— 宿主 20 秒就放弃了。
 *    所以签到链改成**共用一条 deadline**：每次发请求前按剩余时间重新算超时，
 *    剩余不够就干脆不发（报预算错误，由上层决定是否还要动作）。
 */
const SNAP_MIN_TIMEOUT_MS = 1_000;

/**
 * 签到这一次调用的内部预算。
 *
 * 宿主给 20 秒，这里只用到 17 秒：留 3 秒给宿主自己的序列化/落库。
 * 超预算就不再「顺手补确认」（那是可选的收尾动作），但**一定会**把已经拿到的
 * 结论准时返回 —— 报出结果比多做一次写请求重要。
 */
const CHECKIN_BUDGET_MS = 17_000;

/**
 * 老套餐（AgentCenter）模型 —— **黑名单语义**：
 * 上游 `benefit = model not in AGENT_MODELS`，即不在这个名单里的一律按 benefit 处理。
 * 只是云端拿不到清单时的兜底，运行时会被 `provider.models` 拉回的 channel 覆盖。
 */
const AGENT_MODELS = ["openpangu-2.0-pro", "openpangu-2.0-flash", "GLM-5.2", "glm-5.3", "glm-5.2-sft-harmony"];

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
  // 福利期结束后它已经转成普通通道，但**留在黑名单外**：上游哪天恢复福利，
  // `benefit not found` 熔断器会在 TTL 后自动切回去，不需要改代码。
  "deepseek-v4.1-flash": { name: "DeepSeek V4.1 Flash", context: 0, output: MAX_OUTPUT_TOKENS, benefit: true },
  "openpangu-2.0-pro": { name: "OpenPangu 2.0 Pro", context: 0, output: MAX_OUTPUT_TOKENS, benefit: false },
  "openpangu-2.0-flash": { name: "OpenPangu 2.0 Flash", context: 0, output: MAX_OUTPUT_TOKENS, benefit: false },
  "GLM-5.2": { name: "GLM-5.2", context: 0, output: MAX_OUTPUT_TOKENS, benefit: false },
  // 2026-10-21 上游 `/v1/model/builtin` 新增/补出的两个内置文本模型（channel_source=codearts，
  // 不带 benefit 头直接 200，带反而 4004 —— 是 agent 通道，不是福利）。
  "glm-5.3": { name: "GLM-5.3", context: 0, output: MAX_OUTPUT_TOKENS, benefit: false },
  "glm-5.2-sft-harmony": { name: "GLM-5.2-ArkTS-SPARK", context: 0, output: MAX_OUTPUT_TOKENS, benefit: false },
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
    throw new Error(`CodeArts ${path} HTTP ${res.status}: ${shorten(redact(text, ak, sk), 200)}`);
  }
  if (data.error_code !== undefined && !["0000", 0, null].includes(data.error_code)) {
    throw Object.assign(new Error(`CodeArts ${path} 业务错误 ${data.error_code}: ${redact(data.error_msg ?? "", ak, sk)}`), {
      errorCode: String(data.error_code),
    });
  }
  return data.result ?? {};
}

/**
 * snap 引擎的请求（积分账 / 活动 / 领取 / 确认都走这里）。
 *
 * 与 `envelope`（opengw）的三点不同，都是实测踩出来的：
 *   ① 带可选头 `agent-type`（小写，参与签名，见 AGENT_TYPE_HEADER）；
 *   ② 两种信封并存 —— `/v1/ops/*` 是 `{code, message, data}`（业务码走 HTTP 200），
 *      `/snap-manager/v1/statistics/plugin` 是**裸对象**。这里按顶层有没有 `code` 分派；
 *   ③ APIG 的失败是 HTTP 401/404 + `error_code`（APIG.0101 前缀错、APIG.0301 签名、
 *      APIG.0602 凭据过期），要连着 errorCode 一起抛出去给 checkinErrorOutcome 判。
 *
 * 🔴 APIG.0301 的兜底重发：这次抓到的是「大写 Agent-Type 未签名」会被拒。
 *    万一上游改成「小写也不许签」，我们去掉这个可选头再发一次就能自愈 ——
 *    它是可选头，去掉不影响语义。
 */
async function snapEnvelope(path, { method = "GET", body, ak, sk, query, timeout = SNAP_TIMEOUT_MS, deadline } = {}) {
  const url = new URL(`${SNAP_HOST}${path}`);
  for (const [k, v] of Object.entries(query ?? {})) url.searchParams.set(k, String(v));
  const href = url.toString();
  const bodyStr = body !== undefined ? JSON.stringify(body) : "";
  // 剩余预算：传了 deadline 就按它算，没传就是单请求模式（整段 timeout 都归它）。
  const budgetLeft = () => (deadline === undefined ? timeout : Math.min(timeout, deadline - Date.now()));
  const send = (extra) => {
    const left = budgetLeft();
    // 🔴 预算见底就别发了：发出去也是被宿主先掐断，还会让上层误以为「网络错误」。
    if (left < SNAP_MIN_TIMEOUT_MS) {
      throw Object.assign(new Error(`CodeArts ${path} 超出本次调用预算，已跳过`), { errorCode: "BUDGET" });
    }
    const target = extra ? sdkSignedHeaders(method, href, bodyStr, ak, sk, extra) : sdkSignedHeaders(method, href, bodyStr, ak, sk);
    return fetch(href, {
      method,
      headers: target,
      ...(bodyStr ? { body: bodyStr } : {}),
      signal: AbortSignal.timeout(left),
    });
  };
  let res, text;
  try {
    res = await send(AGENT_TYPE_HEADER);
    text = await res.text();
    // 重发也要按**剩余**预算算，不能各自再拿一份完整的 timeout —— 否则一次逻辑
    // 请求最坏就是 2 × timeout，签到三步下来直接冲破宿主的 20 秒。
    if (res.status === 401 && text.includes("APIG.0301") && budgetLeft() >= SNAP_MIN_TIMEOUT_MS) {
      res = await send(null);
      text = await res.text();
    }
  } catch (cause) {
    throw Object.assign(new Error(`CodeArts 请求失败: ${redact(cause?.message ?? String(cause), ak, sk)}`), {
      cause,
      // 预算耗尽是**我们自己**判的（errorCode "BUDGET"），不是网络故障：
      // 上层要能区分 —— 这种情况重试没意义，但也不该记成「上游挂了」。
      errorCode: cause?.errorCode,
    });
  }
  let data;
  try { data = text ? JSON.parse(text) : undefined; } catch { data = undefined; }
  if (res.status !== 200 || !data) {
    throw Object.assign(
      new Error(`CodeArts ${path} HTTP ${res.status}: ${shorten(redact(text, ak, sk), 200)}`),
      { errorCode: data?.error_code },
    );
  }
  // `/v1/ops/*` 信封：code 可能是数字 0 也可能是字符串 "0"（业务码一律走 HTTP 200）
  if (data.code !== undefined) {
    if (Number(data.code) !== 0) {
      throw Object.assign(new Error(`CodeArts ${path} 业务错误 ${data.code}: ${redact(data.message ?? "", ak, sk)}`), {
        errorCode: String(data.code),
      });
    }
    return data.data ?? {};
  }
  return data;
}

/** opengw 的 POST /api/v1/benefit/claim 旧路径已不再用于签到（见 README 0.2.17）。 */
async function claimStatus(ak, sk) {
  return envelope(CLAIM_PATH, { ak, sk });
}

/** 免费额度余额：{total_quota, total_balance, used_amount, …}。 */
function fetchBalance(ak, sk) {
  return envelope(BALANCE_PATH, { ak, sk });
}

/**
 * 积分账：`{remain, amount, used, expiring, packages[], endDate, packageName, isCreditPackage}`。
 *
 * 🔴 只认 `usageTotalPackageCredit` 这一个总数。`usageBasicPackageCredit` /
 *    `usageOnDemandPackageCredit` / `usageBonusPackageCredit` 是它的**构成明细**，
 *    相加即重复计算（实测：500 + 0 + 12000 = 12500 = 总数）。
 *    数值本身就是积分，不要再套「1 积分 = 10000 token」的折算 —— 那条只适用于
 *    每日 token 池，套到这里会把 12000 积分算成 1.2 亿。
 */
async function fetchCredits(ak, sk) {
  const r = await snapEnvelope(STATS_PATH, { ak, sk });
  const metrics = (Array.isArray(r.metrics) ? r.metrics : []).filter((m) => m && typeof m === "object");
  const by = (name) => metrics.find((m) => m.name === name) ?? {};
  const total = by("usageTotalPackageCredit");
  const packages = [
    ["基础积分", "usageBasicPackageCredit"],
    ["按需积分", "usageOnDemandPackageCredit"],
    ["福利积分", "usageBonusPackageCredit"],
  ]
    .map(([name, key]) => {
      const m = by(key);
      return { name, amount: num(m.package_credit_amount), used: num(m.package_credit_used), remain: num(m.package_credit_remain) };
    })
    .filter((p) => p.amount !== undefined && p.amount > 0);
  return {
    remain: num(total.package_credit_remain),
    amount: num(total.package_credit_amount),
    used: num(total.package_credit_used),
    expiring: num(total.package_credit_expiring_amount),
    packages,
    endDate: typeof r.end_date === "string" ? r.end_date : undefined,
    packageName: r.package?.package_name_cn ?? r.package?.package_name_en,
    // 非积分账户（旧的 Token 计费）拿不到这一项，此时上面几个字段全是 undefined
    isCreditPackage: r.package?.is_credit_package !== false,
  };
}

/** 活动清单（含每日签到的 claimable / status，是幂等预检的唯一真相源）。 */
async function fetchCampaigns(ak, sk, opts = {}) {
  const d = await snapEnvelope(OPS_DELIVERY_PATH, { ak, sk, query: { channel: OPS_CHANNEL }, ...opts });
  // 🔴 「这次没拿到」与「确实没有活动」必须分开：
  //    items 是数组（哪怕空数组）= 上游明确告诉我们活动清单，按内容判；
  //    items 缺失 / null / 不是数组 = 上游降级或改了字段名，**这次是没查到**。
  //    后者若当成空清单，checkinPlan 会给出终局 ineligible，宿主当天就不再重试 ——
  //    一次后端抖动就白丢一天积分。抛错让它落到 failed（30 分钟后可重试）。
  if (!Array.isArray(d?.items)) {
    throw Object.assign(new Error("CodeArts 活动清单格式异常（缺 items），本次签到未判定"), { errorCode: "BAD_ITEMS" });
  }
  return d.items.filter((i) => i && typeof i === "object");
}

/**
 * 活动号必须是正整数才算可用。
 *
 * 🔴 两种坏值都必须挡住，否则会发出一个**会被静默丢弃字段**的写请求：
 *    undefined → `JSON.stringify({campaignId: undefined})` 里那个键直接消失，
 *    上游只看到缺参数；null → 发出去的是 `{"campaignId":null}`。
 *    两种都不是「业务失败」，而是我们自己造出来的畸形请求。
 */
function usableCampaignId(v) {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? n : undefined;
}

/**
 * 挑出每日签到那一条：**按 type 认**，不按标题（标题会被上游改文案）。
 * campaignId 只在 type 缺失时兜底；没有可用活动号的一律不选（见 usableCampaignId）。
 */
function pickDailyCampaign(items) {
  const list = (Array.isArray(items) ? items : []).filter((i) => i && usableCampaignId(i?.campaignId) !== undefined);
  const wanted = DAILY_CAMPAIGN_TYPE.toUpperCase();
  return (
    list.find((i) => String(i?.type ?? "").toUpperCase() === wanted) ??
    list.find((i) => usableCampaignId(i?.campaignId) === DAILY_CAMPAIGN_ID) ??
    null
  );
}

/** 领取（积分在 claim 这一步就到账，confirm 只推进状态）。 */
function opsClaim(ak, sk, campaignId, now = Date.now(), opts = {}) {
  const id = usableCampaignId(campaignId);
  if (id === undefined) throw new Error("CodeArts 活动号缺失或非法，无法领取");
  return snapEnvelope(OPS_CLAIM_PATH, {
    method: "POST",
    ak,
    sk,
    body: { campaignId: id, channel: OPS_CHANNEL, idempotentKey: `claim_${id}_${now}` },
    ...opts,
  });
}

/** 确认 —— 不带 channel、不带 idempotentKey（带了 channel 会 HTTP 400）。 */
function opsConfirm(ak, sk, campaignId, opts = {}) {
  const id = usableCampaignId(campaignId);
  if (id === undefined) throw new Error("CodeArts 活动号缺失或非法，无法确认");
  return snapEnvelope(OPS_CONFIRM_PATH, { method: "POST", ak, sk, body: { campaignId: id }, ...opts });
}

/**
 * 走一遍每日签到：查活动 → 按状态决定 claim / confirm → 返回 magpie 契约。
 *
 * 顺手把其它卡在 CLAIMED 的活动补上 confirm（例如「新用户注册送 4000 积分」：
 * 上游是 AUTO_GRANT，发放后停在 CLAIMED，等客户端确认）。积分在 claim 时就已到账，
 * confirm 只是把状态推进到 CONFIRMED，所以这一步不会多发也不会少发；
 * 失败只忽略，不影响签到本身的结论。
 */
async function checkinFlow(ak, sk) {
  const startedAt = Date.now();
  // 🔴 整条链共用一条 deadline，而不是每个请求各自拿一份 6 秒。
  //    snapEnvelope 的 401 重发也会按**剩余**时间算，所以最坏耗时不会超过它。
  const deadline = startedAt + CHECKIN_BUDGET_MS;
  const left = () => deadline - Date.now();
  const opts = { deadline };
  const items = await fetchCampaigns(ak, sk, opts);
  const daily = pickDailyCampaign(items);
  const plan = checkinPlan(daily);
  const confirmed = [];
  // 补确认是「顺手做的好事」，不能拖垮签到本身：只留够**一次** confirm 的余量，
  // 装不下就这轮不补，下一轮签到会再试（状态仍是 CLAIMED）。
  const canSpendOneMore = () => left() >= SNAP_MIN_TIMEOUT_MS;

  // 把结果按 magpie 契约裁齐（只留 outcome / credit / message）：
  // 宿主不认的字段不进契约，给用户看的信息一律并进 message。
  // 🔴 补确认只说「几个活动」，**不说积分数量**：那些活动本来就是 CLAIMED
  //    （= 积分在 claim 时已到账，只是缺一步确认），写出金额会被读成「多赚了 N」。
  const finish = (r) => {
    const suffix = confirmed.length ? `（另补确认 ${confirmed.length} 个待确认活动）` : "";
    return {
      outcome: r.outcome,
      ...(r.credit !== undefined ? { credit: r.credit } : {}),
      message: `${r.message ?? ""}${suffix}`,
    };
  };

  const confirmStrays = async () => {
    const strays = items.filter(
      (i) =>
        i &&
        i !== daily &&
        String(i.status ?? "").toUpperCase() === "CLAIMED" &&
        usableCampaignId(i?.campaignId) !== undefined,
    );
    for (const c of strays) {
      if (!canSpendOneMore()) break; // 预算用完就不补了，下一轮再试
      try {
        await opsConfirm(ak, sk, c.campaignId, opts);
        confirmed.push(c.campaignId);
      } catch {
        // 拿不到就不拿：这本来是客户端的收尾动作，失败了下次签到再补
      }
    }
  };

  if (plan.action === "claim") {
    let claimed;
    try {
      claimed = await opsClaim(ak, sk, daily.campaignId, Date.now(), opts);
    } catch (e) {
      return checkinErrorOutcome(e, plan, "claim");
    }
    // 领到之后**一律**补一次 confirm。上游确实会要求补（那时 data.id 非空），
    // 但 `id` 只是「服务端要求」的提示，不能当唯一依据：字段缺失时漏掉这一步，
    // 活动就卡在 CLAIMED（积分已到账但状态不是终态）。没有待确认记录时
    // confirm 回 40001「该活动没有可确认的权益记录」，属于正常，忽略即可。
    try {
      await opsConfirm(ak, sk, daily.campaignId, opts);
    } catch {
      // 积分在 claim 时已到账；确认失败下一轮签到会按 CLAIMED 再补
    }
    await confirmStrays();
    return finish({
      outcome: "claimed",
      credit: num(claimed?.benefitAmount) ?? num(claimed?.credit) ?? num(claimed?.credits) ?? plan.credit,
      message: "已领取今日签到积分",
    });
  }

  if (plan.action === "confirm") {
    try {
      await opsConfirm(ak, sk, daily.campaignId, opts);
    } catch (e) {
      return checkinErrorOutcome(e, plan, "confirm");
    }
    await confirmStrays();
    return finish({ outcome: "done", credit: plan.credit, message: "今日已签到（补确认）" });
  }

  // action === "none"：已签或不在活动期，仍然把别处卡住的确认补掉
  await confirmStrays();
  return finish({ outcome: plan.outcome, credit: plan.credit, message: plan.message });
}

/**
 * 内置模型清单：`{count, builtinModels: [{model_id, model_name, model_category, enable,
 * display_enabled, provider, channel_source, supports_images, credit, …}]}`。
 *
 * 🔴 这是**唯一还活着的**模型清单来源（2026-10-21 实测 200）。
 *    opengw 的 `/api/v1/gateway/config` 自 2026-10-20 起固定回
 *    `4000 invalid channel, group not found`，再也拿不到任何模型 —— 用它等于让
 *    「重新获取模型」永远只是个摆设（每次刷新都静默退回静态清单）。
 *    snap 这条与 IDE 模型下拉用的是同一份数据，华为上新/下架会立刻反映出来。
 *
 * 🔴 失败**不吞**：吞成空数组会让调用方分不清「真的没有模型」和「这次没拉到」，
 * 进而把缓存清空、拿静态兜底清单去判定通道。网络/业务错误一律往上抛。
 */
async function fetchBuiltinModels(ak, sk) {
  const r = await snapEnvelope(BUILTIN_MODELS_PATH, { ak, sk });
  // 「这次没拿到」与「确实没有模型」必须分开（同 fetchCampaigns 的 BAD_ITEMS）
  if (!Array.isArray(r?.builtinModels)) {
    throw Object.assign(new Error("CodeArts 内置模型清单格式异常（缺 builtinModels）"), { errorCode: "BAD_BUILTIN" });
  }
  // 上游数组里偶尔有 null / 非对象元素，不能让它打断整份清单
  return r.builtinModels.filter((m) => m && typeof m === "object");
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

/**
 * 截断到 n 个字符（配 redact 使用，**顺序不能反**）。
 *
 * 🔴 先 slice 再 redact 会漏：上游常把 AK 打在报错体里，若 AK 正好跨在截断位置，
 *    剩下的半截就匹配不上、原样漏进日志和登录提示。所以先脱敏、后截断。
 */
function shorten(text, n) {
  const s = String(text ?? "");
  return s.length > n ? `${s.slice(0, n)}…` : s;
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

/**
 * 错误响应：400 + OpenAI 错误形态（magpie 的 APIError 从中取出 message）。
 *
 * 🔴 这里必须脱敏：上游的报错体会**回显 Access Key**（`the access key … is
 *    malformed` 之类），而这个 400 的 body 会一路进客户端、magpie 日志和会话
 *    记录。`prepare` 是本次请求的 `(text) => text` 脱敏器（见 loader）。
 */
function errorResponse({ code, message }, prepare = (t) => t) {
  const body = JSON.stringify({ error: { message: prepare(message), type: "codearts_error", code } });
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

async function rewriteStreamError(res, prepare = (t) => t) {
  const reader = res.body.getReader();
  const dec = new TextDecoder();
  const { text, pending, err } = await peekStream(reader, dec);
  if (err) {
    try { await reader.cancel(); } catch { /* 已经断了 */ }
    return errorResponse(err, prepare);
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
async function normalizeChatResponse(res, prepare = (t) => t) {
  if (!res || res.status !== 200 || !res.body) return res;
  const ct = String(res.headers.get("content-type") ?? "").toLowerCase();
  if (ct.includes("text/event-stream")) return rewriteStreamError(res, prepare);
  if (!ct.includes("application/json")) return res;
  let text;
  try { text = await res.text(); } catch { return res; }
  const err = upstreamError(text);
  if (err) return errorResponse(err, prepare);
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
async function sniffBenefitGone(res, prepare = (t) => t) {
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
    if (err) return { gone: false, res: errorResponse(err, prepare) };
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
 * 每日签到的四态 → 该做什么。**纯函数**，写请求由调用方按 action 发起。
 *
 * 上游 `status` 是一个状态机，四个值各有各的动作（照抄客户端语义）：
 *   ELIGIBLE  → 还没领：claim（+ 服务端要 confirm 就补 confirm）
 *   CLAIMED   → **已领但未确认，不是终态**：只补 confirm，绝不能当「今天已签」跳过
 *   CONFIRMED / CONSUMED → 真已签：不碰写接口
 *   null / 其它 → 活动不在期（未开始、已过期、账号不在范围）
 * 漏掉中间那行，签到会永远卡在 CLAIMED —— 积分其实已到账，但活动一直显示没签完。
 */
function checkinPlan(daily) {
  if (!daily) return { action: "none", outcome: "ineligible", message: "上游没有每日签到活动" };
  const credit = num(daily.benefitAmount) ?? num(daily.amount);
  const status = String(daily.status ?? "").toUpperCase();
  if (status === "ELIGIBLE") {
    // claimable=false 而 status=ELIGIBLE：服务端自相矛盾（正常是已签才 false）。
    // 不猜、不硬领，交给宿主下一轮重试。
    if (daily.claimable === false) {
      return { action: "none", outcome: "failed", message: "签到可领但服务端标记不可领，稍后重试" };
    }
    return { action: "claim", credit };
  }
  if (status === "CLAIMED") return { action: "confirm", credit };
  if (status === "CONFIRMED" || status === "CONSUMED") {
    return { action: "none", outcome: "done", credit, message: "今日已签到" };
  }
  return { action: "none", outcome: "ineligible", message: "当前不在签到活动期内" };
}

/**
 * 写请求失败 → magpie checkin 契约。outcome 必须是
 * claimed | done | ineligible | inactive | captcha | failed 之一，非枚举值会被
 * 宿主归一成 failed 并附一句「the plugin answered no outcome」。
 *
 * 🔴 业务码一律走 HTTP 200，所以判定必须看 `errorCode`（snapEnvelope 已从
 *    信封的 `code` 或 APIG 的 `error_code` 里取出来），不能只看 HTTP 状态。
 *
 * 🔴 `40001` 是**同一个码两种含义**，必须按 `kind` 分开：
 *    claim  回 40001 = 「尚未到达权益刷新时间」= 今天这轮已经领过了 → done
 *    confirm 回 40001 = 「该活动没有可确认的权益记录」= 压根没有待确认的东西 → done
 *    混在一起写会把「确认失败」说成「已签到」，状态卡在 CLAIMED 而宿主不再重试。
 */
function checkinErrorOutcome(err, plan = {}, kind = "claim") {
  const code = String(err?.errorCode ?? "");
  const msg = String(err?.message ?? "");
  if (code === "40001") {
    return kind === "confirm"
      ? { outcome: "done", credit: plan.credit, message: "签到已确认（服务端无待确认记录）" }
      : { outcome: "done", credit: plan.credit, message: "今日已签到（未到下一轮刷新时间）" };
  }
  // 4006 名额领完 / 40401 运营事件不存在 → 都不必重试
  if (code === "4006" || /名额|抢完|领完/.test(msg)) {
    return { outcome: "ineligible", message: "签到名额已被领完" };
  }
  if (code === "40401" || /运营事件不存在/.test(msg)) {
    return { outcome: "ineligible", message: "签到活动已下线" };
  }
  // 确认失败不丢积分（claim 时已到账），但状态会停在 CLAIMED —— 报 failed 让宿主下一轮补
  if (kind === "confirm") {
    return { outcome: "failed", message: `签到确认未完成，稍后重试: ${msg.slice(0, 100)}` };
  }
  if (/未开通|未实名|not\s*(activated|enabled|realname)/i.test(msg)) {
    return { outcome: "inactive", message: "账号未开通该权益或未实名认证" };
  }
  if (/captcha|验证码|人机|robot/i.test(msg)) {
    return { outcome: "captcha", message: "需要人机验证，请到华为云控制台手动签到" };
  }
  if (code === "APIG.0602" || /Invalid token|token.*expired/i.test(msg)) {
    return { outcome: "failed", message: "凭据已失效，请重新登录" };
  }
  if (code === "APIG.0301" || /signature fail|验签/i.test(msg)) {
    return { outcome: "failed", message: "签名校验失败，请检查 AK/SK" };
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
            // 验证 AK/SK：先打积分账（snap），**只在通道本身已知下线时**才回退到
            // opengw 余额接口。
            // 🔴 以前只打 opengw 的 /user/tokens/balance。该通道 2026-10-20 起固定回
            //    `4000 invalid channel, group not found`，于是**任何** AK/SK 都会被判
            //    成「验证失败」—— 老用户重新登录会看到一条与凭据无关的报错。
            //    积分账那条接口一直活着，而且正是签到攒积分的那本账，更适合当探针。
            //    （签到接口本身幂等，不在这里触发。）
            try {
              await fetchCredits(ak, sk);
            } catch (e) {
              // 老套餐 token 账户在积分账上可能没有指标，但**调用本身**是通的；
              // 只有「整条通道没了」才值得换一个探针再确认，否则 401 就该直接报。
              if (!gatewayRetired(e)) {
                return { type: "failed", error: `AK/SK 验证失败: ${redact(e?.message ?? String(e), ak, sk)}` };
              }
              try {
                await fetchBalance(ak, sk);
              } catch (e2) {
                return { type: "failed", error: `AK/SK 验证失败: ${redact(e2?.message ?? String(e2), ak, sk)}` };
              }
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
              // 🔴 body 在我们手上被改写过（normalizeChatBody 可能补 stream 或裁
              //    max_tokens），调用方带来的长度/编码头已经对不上实际字节：
              //    留着 content-length 会让 undici 按旧长度读或直接 fetch failed，
              //    表现为「请求挂死到超时」。删掉，让它按实际 body 重算。
              for (const k of ["content-length", "transfer-encoding", "content-encoding"]) merged.delete(k);

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
            // 上游报错会回显 Access Key，而这里产出的 400 body 会进客户端与日志：
            // 所有出口统一过一个脱敏器（见 errorResponse 的注释）。
            const prepare = (t) => redact(t, ak, sk);
            if (benefit && !benefitBroken(ak, model)) {
              const probe = await sniffBenefitGone(await send(true), prepare);
              if (!probe.gone) return probe.res;
              markBenefitBroken(ak, model);
              // 去掉签名头重发。普通通道若是**真的**能跑就用它；跑不了（`model is
              // not registered`）说明这条模型只有福利通道认，那就把「福利没了」
              // 这条更可执行的错误交给调用方。
              const plain = await normalizeChatResponse(await send(false), prepare);
              return plain.status === 400 ? errorResponse(probe.err, prepare) : plain;
            }
            const res = await send(false);
            // 上游会把「模型不存在」这类错误藏在 HTTP 200 里（见 normalizeChatResponse）
            return isChat ? normalizeChatResponse(res, prepare) : res;
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
          const windows = [];
          // ① 积分账（snap-manager）：这才是「每日签到 +1000 积分」攒起来的那本账，
          //    用户控制台上看到的 12000+ 就是它。
          // 🔴 两本账**并行**取：串行时最坏是「积分超时 + token 池超时」= 24 秒，
          //    超过宿主给钩子的 20 秒预算（见 SNAP_TIMEOUT_MS 的注释）。并行后
          //    最坏只等于单次超时。
          let credits = null;
          let creditsError = "";
          const [creditsRes, bal] = await Promise.all([
            fetchCredits(ak, sk).then(
              (c) => ({ c }),
              (e) => ({ e }),
            ),
            fetchBalance(ak, sk).catch(() => null),
          ]);
          if (creditsRes.c) credits = creditsRes.c;
          else creditsError = redact(creditsRes.e?.message ?? String(creditsRes.e), ak, sk);
          // remain 单独夹一次：display 与 balance 用的都是它，而 used 那套夹取
          // 只保证 used/amount 自洽。上游给「剩余 > 总量」或负数时会画出
          // 「12510 / 12500」「-3 / 12500」这种自相矛盾的卡片。
          const clampRemain = (c) => {
            if (!c || c.remain === undefined) return undefined;
            if (c.amount === undefined || c.amount <= 0) return Math.max(0, c.remain);
            return Math.min(Math.max(0, c.remain), c.amount);
          };
          if (credits && credits.remain !== undefined) {
            // magpie 的 window 语义（对照宿主源码与社区插件约定，勿改）：
            //   used   = **已用百分比**（0~100+），宿主直接渲染成 "N%"
            //   amount = **已用**的绝对值，宿主 quotaCount() 渲染成 "amount / limit"
            //   limit  = 绝对值总量；unit = 计量单位；aside = 只展示，不参与路由
            const w = { name: "积分", used: 0, unit: "积分" };
            if (credits.amount !== undefined && credits.amount > 0) {
              // 与下面 token 池那段同样的防守：上游会给负值（退积分/统计回滚）或
              // 「剩余 > 总量」。不夹住的话宿主会把 used 画成负百分比、
              // 把 amount/limit 画成负数，看着像「倒欠额度」。
              let usedC = credits.used;
              if (usedC === undefined && credits.remain !== undefined) usedC = credits.amount - credits.remain;
              if (usedC === undefined) usedC = 0;
              if (usedC < 0) usedC = 0;
              if (usedC > credits.amount) usedC = credits.amount;
              w.used = round1((usedC / credits.amount) * 100);
              w.amount = round1(usedC);
              w.limit = credits.amount;
              const remainShown = clampRemain(credits) ?? credits.amount - usedC;
              w.display = `${round1(remainShown)} / ${credits.amount}`;
            } else {
              w.display = `${round1(clampRemain(credits) ?? credits.remain)} 积分`;
            }
            // 套餐到期日：积分用不完同样作废（实测每账号不同）。
            // 🔴 不能写进 `aside`：宿主的 window.aside 是**布尔**标记（`aside: !!w.aside`），
            //    字符串会被归一成 true、文案直接丢失，而且 true 的语义是「只展示、
            //    不参与用尽判定」—— 这恰恰是这里**唯一**的额度窗口，标成只展示
            //    会让积分耗尽也不触发账号用尽。所以并进 display。
            if (credits.endDate) w.display += ` · ${credits.packageName ?? "套餐"} 到期 ${credits.endDate}`;
            windows.push(w);
          } else if (credits && credits.isCreditPackage === false) {
            creditsError = "该账号是 Token 计费账户，没有积分余额";
          }
          // ② 每日免费 token 池（opengw）：另一本账，福利模型走它。
          //    2026-10-20 起上游整组下线，所以它现在是**可选**窗口 —— 拿得到才画。
          //    （请求在开头与积分账并行发出，见上面的 Promise.all。）
          let poolLeft;
          if (bal) {
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
            const w = { name: "每日免费 Token", used: 0, unit: "tokens" };
            if (quota !== undefined && quota > 0 && usedAbs !== undefined) {
              w.used = round1((usedAbs / quota) * 100);
              w.amount = usedAbs;
              w.limit = quota;
              w.display = `${Math.round(usedAbs)} / ${Math.round(quota)}`;
            } else if (left !== undefined) {
              w.display = `${Math.round(left)} tokens`;
            }
            windows.push(w);
            poolLeft = left;
          }
          if (!windows.length) {
            return {
              error: creditsError ? `额度查询失败: ${creditsError}` : "额度接口无数据（积分账与 token 池都取不到）",
              windows: [],
            };
          }
          return {
            // magpie 会在 balance 后面自动追加 "left"，这里只写「数量 + 单位」
            balance:
              // 🔴 这里同样用夹过的 remain：balance 是列表页那行大字，
              //    「12510 积分 left / 12500 总额」比 window 里的数字更显眼。
              credits?.remain !== undefined
                ? `${round1(clampRemain(credits) ?? credits.remain)} 积分`
                : poolLeft !== undefined
                  ? `${Math.round(poolLeft)} tokens`
                  : "已登录",
            // 签到状态由宿主显示（它读 plugin-checkin.json 里插件钩子的真实结果），
            // 插件不再自己画第二个、会与宿主打架的状态行。
            windows,
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
          // 签到 = snap 侧的「活动」三步（查活动 → claim → confirm），
          // 不再碰 opengw 的福利通道 —— 那是另一本账（免费 token 池），
          // 而且 2026-10-20 起已经整组下线（见 README 0.2.17）。
          return await checkinFlow(ak, sk);
        } catch (e) {
          return checkinErrorOutcome(e);
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
          const rows = await fetchBuiltinModels(ak, sk);
          // 只替换**本账号**那一层：channel 跟账号走，留着别的账号的判定会串通道；
          // 但也不能整体清空，否则另一个账号的缓存会被这次拉取抹掉。
          // 空清单同样要替换 —— 否则本账号的旧记录会一直生效。
          const table = channelTable(ak);
          table.clear();
          // 空清单当「这次没拉到」处理，别把用户的模型选择器清空
          if (!rows.length) return provider.models;

          // 🔴 云端清单是**权威**，不是叠加：华为下架的模型必须从选择器里消失。
          //    留着它 = 让宿主继续轮询一个 404，而 magpie 对不带额度关键词的 400/404
          //    不 failover（整组直接失败）—— RETIRED_MODELS 就是手工补这个洞的。
          //    只保留本插件没管过的条目（用户自己往配置里加的），别一起抹掉。
          const managed = new Set(Object.keys(MODEL_META).map((k) => k.toLowerCase()));
          const out = {};
          for (const [id, m] of Object.entries(provider.models ?? {})) {
            if (!managed.has(id.toLowerCase())) out[id] = m;
          }

          for (const m of rows) {
            const id = String(m.model_id ?? m.modelId ?? m.id ?? "").trim();
            if (!id) continue;
            if (modelRetired(id)) continue; // 福利没了、普通通道也不认（见 RETIRED_MODELS）
            // 上游自己下架/隐藏的不要发布：`enable:false` 是停用，`display_enabled:false`
            // 是 IDE 下拉里根本不显示（现在那两个 VL 模型就是这样）。
            // 发布一个 IDE 都不给的模型 = 让用户选中一个上游不认的 id。
            if (m.enable === false || m.display_enabled === false) continue;

            const key = id.toLowerCase();
            // 🔴 channel_source 才是通道：`codearts` = 内置/老套餐（agent）通道，
            //    不能带福利三头（带了回 4004 benefit not found）。opengw 的
            //    `channel` 字段已经随网关一起没了，别再指望它。
            const src = String(m.channel_source ?? "").trim().toLowerCase();
            const channel = src === "codearts" || src === "agent" ? "agent" : src === "benefit" ? "benefit" : "";
            if (channel) table.set(key, channel);

            out[id] = {
              name: String(m.model_name ?? m.modelName ?? m.name ?? id),
              id,
              limit: {
                // 内置清单**不带** context_window / max_tokens：有就收敛着发，
                // 没有就沿用静态兜底（0 = 不设限，绝不猜一个会截断上下文的数）
                context: optNumber(m.context_window ?? m.contextWindow) ?? optNumber(provider.models?.[id]?.limit?.context) ?? 0,
                output: outputLimit(m.max_tokens ?? m.maxTokens) ?? optNumber(provider.models?.[id]?.limit?.output),
              },
              reasoning: false,
              tool_call: true,
              // 明确声明收不收图（**不许留空**：留空 = 「没说」= 宿主照发图片 → 406）。
              // 即使上游写着 supports_images:true 也不采信 —— 0.2.13/0.2.15 实测
              // 走 magpie 的图片格式一律 406，唯一可信来源是 VISION_MODELS（实测过才加）。
              // 这里必须用 capabilities 而不是 modalities —— 这条钩子的返回值
              // 宿主原样采用，不走 modalities 转换（见上方说明）
              ...capabilitiesField(imageCapable(id)),
            };
          }
          return out;
        } catch (e) {
          // 拉取失败：**不清缓存**（旧判定仍然是对这个账号最靠谱的信息），
          // 并把原因抛给宿主 —— 宿主会记 listError，在提供商页显示出来。
          // 静态清单仍由配置钩子给出，所以刷新失败不会让选择器变空。
          throw new Error(`CodeArts 模型清单获取失败: ${redact(e?.message ?? String(e), ak, sk)}`);
        }
      },
    },
  };
}

/** 测试辅助（宿主不会把它当插件调用）。 */
export const _internal = {
  rfc3986, sdkSignedHeaders, envelope, snapEnvelope, creds, bare, parseCredential, redact,
  claimStatus, fetchBalance, fetchBuiltinModels,
  fetchCredits, fetchCampaigns, pickDailyCampaign, usableCampaignId, opsClaim, opsConfirm,
  checkinPlan, checkinErrorOutcome, checkinFlow,
  startOfTodayMs, isBenefitChannel, codeartsModels, clampChatBody,
  upstreamSessionId, sessionHeaders, num, round1, optNumber, outputLimit, CN_OFFSET_MS,
  channelCache, channelTable, MODEL_META, VISION_MODELS, AGENT_MODELS, MAX_OUTPUT_TOKENS,
  RETIRED_MODELS, modelRetired,
  benefitBroken, markBenefitBroken, benefitGone, gatewayRetired, benefitDown, BENEFIT_DOWN_MS,
  modalitiesField, capabilitiesField, imageCapable,
  normalizeChatBody, upstreamError, normalizeChatResponse, rewriteStreamError, PEEK_MS,
  sniffBenefitGone,
  SNAP_HOST, CHAT_PATH, OPENGW_HOST,
  STATS_PATH, OPS_DELIVERY_PATH, OPS_CLAIM_PATH, OPS_CONFIRM_PATH, OPS_CHANNEL,
  BUILTIN_MODELS_PATH,
  DAILY_CAMPAIGN_TYPE, DAILY_CAMPAIGN_ID, AGENT_TYPE_HEADER,
};
