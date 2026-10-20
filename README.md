# magpie-codearts-auth

[magpie](https://usemagpie.ai) / [OpenCode](https://opencode.ai) provider 插件：**华为云码道 CodeArts 代码智能体**。

| 能力 | 说明 |
|---|---|
| 授权 | 华为云访问密钥 **AK/SK**（华为云官方 SDK-HMAC-SHA256 签名），登录时自动验证有效性 |
| **每日签到** ⭐ | 实现 magpie 原生 `auth.checkin` 钩子（magpie ≥ v0.1.1083）——Settings → Usage → Plugins 打开 **Daily check-in**，每天每账号自动签到领 **1000 积分**（`/v1/ops/delivery` → `claim` → `confirm`，四态状态机） |
| **积分余额** | `auth.usage` 显示**积分**（控制台上那个 12000+ 就是它）：已用/总量 + 套餐到期日 |
| ~~免费 Token 池~~ | **2026-10-20 官方已结束**（论坛公告 + 活动 PDF 目录移除 + 实测 `4000 invalid channel, group not found`），只剩积分一本账 |
| 对话 | `POST snap-access /api/v2/chat/completions`（OpenAI 形态），按模型自动选通道 |
| 模型 | 登录后自动同步云端模型清单（含 `channel` 字段），失败时回退内置列表；**逐模型实测声明收不收图**（见 [图片能力](#图片能力0213-实测)） |

## 安装

```sh
magpie plugin add github:liuxigreen/magpie-codearts-auth   # 上游原版
magpie plugin add github:xiyingruyi/magpie-codearts-auth   # 本 fork（含 0.2.17 修复）
magpie plugin login codearts
magpie quota
```

## 登录（重要：粘贴格式）

插件只需**一个输入框**，请按下面的格式粘贴：

```
AccessKeyId:SecretAccessKey
```

例如 `LTAI5tABCDEFGHIJKLMN:y8QwERtyuiopASDfghjKLzxcvbnm1234567890Ab`。

分隔符支持 `:` `：` `=` `,` `，` `;` `；` 或空白。填错格式会当场提示。

**AK/SK 从哪来**：华为云控制台 → 右上角「我的凭证」→「访问密钥」→ 新增访问密钥（下载 `credentials.csv`，`Access Key Id` / `Secret Access Key` 在里面）。

> **为什么不拆成两个框？** magpie 宿主的 `api` 类型登录方法只会给一个「key」输入框，而这个框的值**不会被并进插件 `authorize(inputs)` 收到的 `inputs`**（宿主源码：`apiKey()` 里执行的是 `m.authorize(inputs ?? {})`，用户填的 key 只作为 `save()` 的兜底 `apiKey` 参数）。所以任何依赖 `inputs.key` 的插件都拿不到值。
> 唯一可靠的做法是让需要的字段都走 `method.prompts` —— 宿主 `nextPrompt()` 会把 prompts 里各项依次问完并合并进 `inputs`。这正是本插件采用单框粘贴组合串的原因。

## 每日签到（0.2.17 重写：签到领的是**积分**）

码道有**两本互不相通的账**，插件以前把它们混成了一本：

| 账 | 上游接口 | 单位 | 谁用 |
|---|---|---|---|
| **积分账** | `GET /snap-manager/v1/statistics/plugin` | 积分（CREDIT） | 系统内置模型（GLM-5.2 / OpenPangu 等） |
| ~~每日免费 Token 池~~ | ~~`GET opengw /api/v1/user/tokens/balance`~~ | ~~tokens（1000 万/日，0 点清零）~~ | **2026-10-20 已结束**（见下） |

### 每日免费 Token 池：官方确认已于 2026-10-20 结束

这不是「接口搬家」，是活动本身下线。2026-10-21 查证到的官方证据：

| 证据 | 内容 |
|---|---|
| 华为云开发者论坛活动帖底部「温馨提醒」 | **「华为云码道每日领千万 token 限时活动已于 2026 年 10 月 20 日结束，本活动页面已同步下线相关福利部分。」** |
| 官方《活动》PDF（**文档版本 01，发布日期 2026-10-20**） | 目录只剩 4 篇：Skill 创新大赛、每日签到得积分、完成学生认证得积分、邀请新用户得积分 —— **全文 0 次出现 Token** |
| 帮助中心 `llms.txt` 的「活动」索引 | 同上 4 篇；原 `codeartsagent_offers_0001.html`《限时领取Tokens》**已从索引里删除**，直接访问返回站点 404 |
| 实测（本机两账号） | `GET opengw /api/v1/user/tokens/balance` 与 `/api/v1/gateway/config` 一律 `200 {"error_code":"4000","error_msg":"invalid channel, group not found"}`；不带鉴权则是 `401 APIG.0301`（说明**路由还在、鉴权也还在，是后端那个 channel 分组没了**） |

⚠️ 不要被 `activity.huaweicloud.com/codearts_agent.html` 误导：它仍在线、仍写「每日 1,000 万免费
Token、0 点清零」，但那是 **2026-09-02 的缓存版本**，页面从未写结束日期（只有一句「保留随时终止或
调整的权利」）—— 属于没及时下架的营销页，不能当作活动仍在的依据。

**替代品就是积分**：现行免费来源全在积分账上，且都有明确有效期。

| 来源 | 额度 | 有效期 | 活动截止（UTC+8） |
|---|---|---|---|
| 每日签到 | 1000 积分/天 | 发放起 **30 天** | 2026-12-31 00:00 |
| 新用户注册 | 4000 积分（一次） | 30 天 | 2026-12-31 00:00 |
| 学生认证 | 4000 积分（一次） | **90 天** | 2026-12-31 00:00 |
| 邀请新用户 | 邀请人 1000 / 被邀请人 6000 | 1 个月，上限 5 万 | 2026-11-15 23:59:59 |
| 套餐积分 | 体验版 500/月；标准 2000、高级 4000、旗舰 10000 | 按计费周期刷新，**未用不结转** | —— |

> 体验版（免费）积分用尽后**不能买积分包、不能继续发起请求** —— 所以那 1000/天的签到对
> 免费账号是真的有用，不是可有可无。

来源：[每日签到得积分](https://support.huaweicloud.com/offers-codeartsagent/codeartsagent_offers_0004.html)、
[个人订阅](https://support.huaweicloud.com/price-codeartsagent/codeartsagent_billing_0029.html)、
[积分计费模式](https://support.huaweicloud.com/price-codeartsagent/codeartsagent_billing_0028.html)、
[活动 PDF（2026-10-20）](https://support.huaweicloud.com/offers-codeartsagent/codeartsagent-offers-pdf.pdf)。

「**每日签到领 1000 积分**」进的是**积分账**，走 snap 引擎上的活动接口，三步：

```
① GET  /v1/ops/delivery?channel=IDE   看活动状态（幂等预检，唯一真相源）
② POST /v1/ops/claim                  {campaignId, channel:"IDE", idempotentKey:"claim_<id>_<毫秒>"}
③ POST /v1/ops/confirm                {campaignId}          ← 只在服务端要求时补
```

- **前缀是这套接口最大的坑**：`/v1/ops/*` **不能**带 `snap-manager`，而
  `/snap-manager/v1/statistics/plugin` **必须**带。混用一律 `APIG.0101 The API does not
  exist or has not been published in the environment` —— 这正是此前 12 条候选路径全部
  扫不到签到接口的原因。
- **可选头小写 `agent-type: PromptCenter` 且参与签名**。大写的 `Agent-Type` 在 APIG
  眼里是系统头，不入 SignedHeaders 直接判 401 `APIG.0301`（实测）。插件还在 401
  APIG.0301 时去掉这个可选头自动重发一次。
- **活动状态是四态**，照抄客户端语义：`ELIGIBLE` → claim（+ 按需 confirm）；
  `CLAIMED` = **已领但未确认，不是终态** → 只补 confirm（漏了它活动会永远卡在
  CLAIMED）；`CONFIRMED` / `CONSUMED` → 已签，不碰写接口；`status: null` → 不在活动期。
- **顺带补确认**：其它卡在 `CLAIMED` 的活动（例如「新用户注册送 4000 积分」，上游是
  `AUTO_GRANT`，发放后等客户端确认）也会被一起 confirm。积分在 claim 时就已到账，
  confirm 只推进状态，不会多发也不会少发；失败只忽略，不影响签到结论。结果里只写
  「另补确认 N 个待确认活动」，**不写金额** —— 那些积分本来就在余额里，报数字会被读成「多赚了」。
- 业务码一律走 **HTTP 200**，所以判定看 `code` 不看状态码：`40001` 尚未到达权益刷新
  时间（= 今天这轮已领）按 `done` 处理；`4006` 名额领完、`40401` 运营事件不存在 → `ineligible`。
- **调度**：Settings → Usage → Plugins 的 Daily check-in 开关（默认关）打开后，每天每
  账号自动签一次（启动 2 分钟后首查、每 30 分钟轮询，`failed` 30 分钟后重试）。签到状态
  由 **magpie 宿主**显示（`SubscriptionQuota.checkin`，来自 `plugin-checkin.json` 里插件
  钩子的真实回答），插件不再自己画一行状态。

> **旧版（≤ 0.2.16）为什么错**：它把 `POST opengw /api/v1/benefit/claim` 当成了签到 ——
> 那是**免费 token 池**的领取，不是积分。0.2.12 起虽然不再从 `create_time` 推导状态，
> 但「福利网关 2026-10-20 整组下线」之后签到就跟着报 `ineligible`（「福利活动结束，无需
> 签到」）—— 而**积分签到一直都在**，只是我们从没打对过接口：它挂在 snap 引擎上，前缀
> 规则还和余额接口相反发展。上游也确有一个接口能读到签到状态，即 `/v1/ops/delivery`。

插件向 magpie 返回的标准 outcome：

| outcome | 触发条件 |
|---|---|
| `claimed` | 本次真的领到了（`credit` = 上游给的 `benefitAmount`，实测 1000） |
| `done` | 今天已签（`CONFIRMED`/`CONSUMED`，或 claim 回 `40001` 尚未到达刷新时间） |
| `ineligible` | 活动不在期、活动已下线、名额领完 |
| `inactive` | 账号未开通该权益或未实名 / 未登录 |
| `captcha` | 需要人机验证，提示到控制台手动签到 |
| `failed` | 网络/超时/签名或凭据问题（宿主 30 分钟后重试） |

## Usage 卡片字段语义（实测定论）

magpie 的 `usage()` window 字段，本插件按宿主源码逐条对齐：

| 字段 | 含义 | magpie 如何渲染 |
|---|---|---|
| `used` | **已用百分比**（0~100+，可超 100） | 直接显示为 `N%`，`>=98` 染成「spent」红条 |
| `amount` | 该窗口的**已用**绝对量 | 与 `limit` 组合成 `amount / limit` |
| `limit` | 绝对值总量（0 / 缺省 = 不设限） | 同上；`limit > 0` 才显示括号数字 |
| `unit` | 计量单位文案 | 拼在数字后（积分窗口是 `积分`，token 池是 `tokens`） |
| `aside` | `true` = 只展示，**不参与路由、不参与「用尽」判定** | 侧栏一行 |

**踩坑记录一（0.2.2）**：`used` 被填成绝对值 `299530`，`magpie quota` 显示成 `299530%`。
受控实验（`used:50 → 50%`）定论：**`used` 是百分比**。

**踩坑记录二（0.2.3，仍在）**：`amount` 被填成**剩余**（`total_balance`），而宿主
`quotaCount()` 是按 `amount / limit` 当「已用」渲染的。于是明明只用了 21.8%，
卡片却显示 `7819948 / 10000000`——看起来像「用掉了 78%」。0.2.4 改为填已用。

**踩坑记录三（0.2.3，0.2.17 修正）**：`total_quota = 10,000,000` 是**每日免费 Token**
（官方口径：每位用户每日 1000 万 Tokens，当日 24:00 清零，**不与积分包互通**）。当年由此
得出「控制台里那一万多积分插件没有接口去读」——**这个结论是错的**：接口一直都在，只是
余额有两本账，积分那本在 `GET /snap-manager/v1/statistics/plugin`，前缀必须带
`snap-manager`（而 `/v1/ops/*` 不能带），扫候选路径时正好绕过了它。0.2.17 起两本账分开
展示：**积分**优先（那是用户真正在控制台上看到的那个数），token 池拿得到才多画一个窗口。

### 显示成「额度用尽」的真凶（0.2.4 修复）

代码里没有一处会返回「已用尽」——这个标记是 **magpie 宿主**贴上去的。

上游对每个账号有 **3 个并发会话**的上限，超了返回：

```
400 {"error_code":"TM.00001041","error_msg":"并发会话数已达上限(3个)，请关闭部分会话后重试。"}
```

这条**并发**错误里的「已达**上限**」命中了宿主 `internal/gateway/routing.go` 的
`usedUpWords` 正则（含中文词 `上限`），于是被判成 `failQuota`，账号被标「额度用尽」
并休息 15 分钟（`quotaRest`）—— 而此时额度可能一格都没少。

**证据**：宿主的路由日志里有一条 `used: 0, amount: 10000000`（额度满格）的账号
仍被标 `fail: "quota"`；某天 78 条 `TM.00001041` 中有 55 条 `rest.why = "quota"`。

**修法**：所有对话请求带上稳定的 `x-ot-session-id` / `user-session-id`（由 AK 派生，
同一账号恒定），上游就会把它们算作同一个会话，从源头避免这条错误。
会话 ID 只发给对话端点，余额/签到等 opengw 接口不带——登录正是靠余额接口做的，
不给它加额外的头。

### 实测（2026-10-18，单账号流式并发）

`scripts/probe-session.mjs`，两轮之间留 100–120 秒让上游回收会话，避免上一轮
残留把下一轮一起带进上限：

| 并发 | 不带会话头 | 带稳定会话头 |
|---|---|---|
| 3 | ok×2 **CONCURRENCY×1** | ok×3 |
| 4 | ok×2 **CONCURRENCY×2** | ok×4 |
| 8 | ok×2 **CONCURRENCY×6** | ok×8 |
| 16 | ok×2 **CONCURRENCY×14** | ok×16 |

三点结论：
1. 上游的「3 个并发会话」是按**会话**计数 —— 不带会话头时每个请求各算一个，
   所以第 3 个之后全部 `TM.00001041`；
2. 复用同一个会话 ID 后，**会话内并发不受这个上限约束**（16 并发全过）；
3. 这也是为什么不必再把 magpie 的「并发上限」调低 —— 那个设置是另一回事。

### 其它两处顺手修掉的问题

- **静态兜底清单不再猜 context/output**：magpie 的 `limit` 是**硬上限**，
  写死 200000/32000 会真的把长上下文请求截断（上游实测 1M 上下文 / 384k 输出）。
  兜底一律留 0（= 不设限），真实值由云端 `context_window` / `max_tokens` 填回。
- **签到状态行不再刷满**：未签到时原来的 `used: 1, limit: 1` 是恰好 100%，
  虽然 `aside` 已让它不参与路由，但满格红条仍会被误读成「额度用尽」。
  现在它是纯状态行，不带 `limit`、`used` 恒为 0。

> **宿主的责任仍在**：把并发错误归类成 `failQuota` 是 magpie 的判定缺陷，
> 插件只能避开它、不能改它。若你用的是别的 CodeArts 插件，仍会遇到同样的问题。

## 对话通道（重要）

上游 `/api/v2/chat/completions` 有**两条严格区分的通道**：

| 通道 | 判定 | 附加请求头（参与签名） |
|---|---|---|
| 福利（benefit） | **不在** AgentCenter 名单里的一律按此处理 | `maas_type: benefit`、`model-id`、`model-name` |
| 老套餐（AgentCenter） | 命中 `openpangu-2.0-pro` / `openpangu-2.0-flash` / `GLM-5.2` | 无（带了反而报 unsupported model） |

> **上游是黑名单，不是白名单。** 上游 `server.py` 的判定是 `benefit = model not in AGENT_MODELS`，且 `AGENT_MODELS` 由模型缓存里 `channel == "agent"` 的项动态构建。因此**新上线的免费模型默认走 benefit 通道**。本插件的 `isBenefitChannel()` 优先采用云端返回的 `channel` 字段，无该字段时按黑名单语义回退，不会因为硬编码白名单而把新模型判错通道。

请求体为标准 OpenAI chat completions 形态（`model` / `messages` / `stream` 等），原样转发，支持流式与工具调用。

## 开发与测试

```sh
node --check index.mjs            # 语法检查
node --test tests/index.test.mjs  # 纯函数 + loader 单测（无网络，Node ≥ 18）
```

可测辅助函数经 `_internal` 导出。涉及真实上游的并发验证可跑（凭据只从环境变量读）：

```sh
CODEARTS_AK=... CODEARTS_SK=... node scripts/probe-session.mjs <模式> [并发数]
```

`<模式>`：`nosid` 只跑不带会话头、`sid` 只跑带的、`both`（默认）先 `nosid` 再
冷却 90 秒跑 `sid`。**一次只跑一种模式很重要** —— 上游按*活跃*会话计数，
上一轮的流式连接若还没被回收，会把下一轮一起带进上限（这一点踩过）。

## 与官方骨架版（0.1.0）的差异

本仓库起自一份社区骨架，修掉了三个会实际影响使用的问题：

1. **登录不可用（致命）** —— 骨架版 `authorize()` 读 `inputs.key`，而宿主从不把 key 框的值并进 `inputs`，导致 AK 永远为空、100% 登录失败。本版改为单框粘贴 `AK:SK` 并在插件内拆分，AK/SK 均经 `prompts` 进入 `inputs`。
2. **通道判定方向反了** —— 骨架版用硬编码白名单判定 benefit，与上游的黑名单语义相反，云端新模型会走错通道报 `unsupported model`。
3. **丢弃云端 `channel` 字段** —— 该字段正是上游构建 `AGENT_MODELS` 的依据；本版保留并写入运行期缓存。

此外补齐了 `ineligible` / `captcha` / `inactive` 三种签到 outcome（骨架版遇到会落到 `failed` 并每 30 分钟无意义重试）。

## 0.2.18（2026-10-21：确认免费 Token 池已结束，文档对齐）

只有文档与注释变更，**代码逻辑未动**，193 条测试全绿。起因是用户追问「每日免费池还在吗」。

**结论：2026-10-20 官方已结束，不是接口搬家。** 证据见上文
[每日免费 Token 池：官方确认已于 2026-10-20 结束](#每日免费-token-池官方确认已于-2026-10-20-结束)：

- 华为云开发者论坛活动帖的「温馨提醒」原文写明 **2026 年 10 月 20 日结束**；
- 2026-10-20 发布的官方《活动》PDF（文档版本 01）目录里已**整篇移除**《限时领取Tokens》，全文 0 次 Token；
- 帮助中心 `llms.txt` 的「活动」索引同步删掉了该篇，直连返回站点 404；
- 实测两账号：`opengw` 的 `/user/tokens/balance`、`/gateway/config` 仍是 `200 + 4000 invalid channel, group not found`
  （不带鉴权是 `401 APIG.0301`，路由与鉴权都在，**是后端那个 channel 分组没了**）。

**唯一容易看错的地方**：`activity.huaweicloud.com/codearts_agent.html` 还挂着「每日 1,000 万免费 Token」，
但那是 **2026-09-02 的缓存版本**、从未写结束日期 —— 营销页没下架，不代表活动还在。

**替代品是积分**，四个免费来源都有明确有效期（签到 1000/30 天、注册 4000/30 天、
学生认证 4000/90 天、邀请 1000+6000/1 个月），活动多在 2026-12-31 00:00 截止；
体验版套餐每月 500 积分且用尽后不可买积分包。README 的能力表与账本表已按此改写。

## 0.2.17（2026-10-21：签到/余额搬回 snap 侧，两本账分开展示）

**起因**：用户指出「每日签到领 1000 积分一直都在，我账户积分余额 12000 多」——0.2.16
把 opengw 福利网关下线当成了「签到活动结束」，结论完全错了。

**根因：码道有两本互不相通的账，插件把 token 池当成了积分。**

| 账 | 接口 | 前缀 | 实测数值 |
|---|---|---|---|
| **积分账** | `GET /snap-manager/v1/statistics/plugin` | **必须带** `snap-manager` | 12500 总额 / 12162.78 剩余 |
| 每日 token 池 | `GET opengw /api/v1/user/tokens/balance` | —— | 2026-10-20 起 `4000 invalid channel, group not found` |

**实测（本机两账号，2026-10-21）**：

| 请求 | 结果 |
|---|---|
| `GET /snap-manager/v1/statistics/plugin`（头 `agent-type: PromptCenter`） | **200**，`metrics[]` 里 `usageTotalPackageCredit` = 12500 / 已用 337.22 / **剩 12162.78**，另有 `usageBasicPackageCredit` 500、`usageBonusPackageCredit` 12000 两个分项；`end_date` 2026-11-12 是**套餐到期日**（积分用不完作废） |
| `GET /snap-manager/v1/current/user` | 200，`domain_name: xi930214890` |
| `GET /v1/ops/delivery?channel=IDE` | **200**，`campaignId:1 "每日签到领1000积分"` type `USER_LOGIN`，账号 A `status:CONFIRMED`（今天已签）、账号 B `status:ELIGIBLE` `claimable:true` `pendingTotalAmount:1000`（今天还没签） |
| 同路径**不带** `snap-manager`（`/v1/statistics/plugin`、`/v1/current/user`） | 404 `APIG.0101 The API does not exist or has not been published` |
| `/v1/ops/*` **带上** `snap-manager` | 同上 404（两套前缀方向相反） |
| 可选头写成大写 `Agent-Type` 且不入签名 | 401 `APIG.0301 verify ak sk signature fail`；小写 `agent-type` **入签名或不发**都能过 |
| `POST /v1/ops/claim {campaignId:987654, channel:"IDE", idempotentKey:…}` | 200 `{"code":40401,"message":"运营事件不存在: 987654"}` —— 形状对，业务上不存在 |
| 同请求**不带** `channel` | 400 `PROMPTCENTER.00000001 "channel : 参数无效"` —— `channel` 是必填 body 字段 |
| `POST /v1/ops/confirm {campaignId:987654}` | 200 `{"code":40001,"message":"该活动没有可确认的权益记录"}` |

**修法**：

1. **签到改为 snap 侧三步**：`GET /v1/ops/delivery?channel=IDE` 预检 → 按四态决动作
   （`ELIGIBLE` claim、`CLAIMED` 只补 confirm、`CONFIRMED`/`CONSUMED` 不动、`null` 不在期）
   → `POST /v1/ops/claim` → 服务端要求时 `POST /v1/ops/confirm`。`credit` 报上游给的
   `benefitAmount`（1000），不再是「不编造所以不报」。
2. **顺带补确认**其它卡在 `CLAIMED` 的活动（新用户注册 4000 积分是 `AUTO_GRANT`，发放后
   停在 CLAIMED 等确认）。claim 时积分即到账，confirm 只推进状态 —— 不会多发也不会少发。
3. **`auth.usage` 改读积分账**：窗口 `积分`，`amount/limit` = 已用/总额，`aside` 写
   「体验版 · 到期 2026-11-12」。token 池降级为**可选**窗口（拿得到才画），两本账不折算、
   不混进一个数字里。
4. **新增 `snapEnvelope`**：认两种信封（`/v1/ops/*` 是 `{code,message,data}`，统计接口是
   **裸对象**），把 APIG 的 `error_code` 与业务 `code` 都带成 `errorCode` 抛出去；
   401 `APIG.0301` 时去掉 `agent-type` 可选头自动重发一次。
5. **`checkinOutcome` → `checkinPlan` + `checkinErrorOutcome`**（都是纯函数，写请求由
   `checkinFlow` 按 action 发起）：业务码走 HTTP 200，所以判定看 `code`——
   `40001` 按 `done`（今天这轮已领）、`4006`/`40401` → `ineligible`、`APIG.0602` 提示重新登录。
   **`40001` 是同一个码两种含义**，按 claim/confirm 分开判（claim 那侧是「未到刷新时间」，
   confirm 那侧是「没有待确认记录」）；confirm 的其它错误报 `failed` 让宿主下一轮补，
   否则状态会卡在 CLAIMED 而没人再试。
6. `claimToday` / `claimStatus` 两个 opengw 函数从签到路径上摘掉（`fetchBalance` 仍保留，
   喂 token 池那个可选窗口）。

**对抗式复核（4 个维度独立找茬 + 逐条反驳）修掉的几处**：

- **不再拿 `data.id` 猜「要不要 confirm」**：领到之后**一律**补一次 confirm，失败就忽略
  （没有待确认记录时上游回 40001，属正常）。原写法把 `id` 当唯一依据，字段缺失时活动就
  卡在 CLAIMED（积分已到账但状态非终态）。
- **活动号必须是正整数**：`campaignId` 为 `undefined` 时 `JSON.stringify` 会把那个键整个
  丢掉，`null` 时会发出 `{"campaignId":null}` —— 两种都是我们自己造的畸形写请求。
  `usableCampaignId()` 在 `pickDailyCampaign` 与 `opsClaim`/`opsConfirm` 三层都挡。
- **积分窗口也做夹取**：上游退积分/统计回滚会给负已用或「剩余 > 总额」，不夹的话宿主
  会画成 `-0.1%` 和倒欠（token 池那段本来就有这个防守，新路径漏了）。
- **预算**：`SNAP_TIMEOUT_MS = 6s`（实测这一侧 p50 40ms、最慢 1.4s），usage 的两本账**并行**
  取，签到内部 17s 预算用完就不再「顺手补确认」—— 宿主给钩子只有 20s，原来的
  12s × 3 串行最坏 36s，会先被宿主放弃。

**实测（0.2.17 通过 magpie 网关）**：`auth.usage` 返回
`balance: 12162.8 积分`、窗口 `{"name":"积分","used":2.7,"amount":337.2,"limit":12500,"aside":"体验版 · 到期 2026-11-12"}`；
第二个账号 `7475.7 积分`（到期 2026-11-17）。`magpie accounts checkin codearts` 实跑：

```
✓ CodeArts 码道 (Huawei) API key …1XCY checked in today +1000
✓ CodeArts 码道 (Huawei) API key …BJ0C checked in today +1000 · already
```

第二个账号余额 7475.7 → **8475.7**（额度上限 7500 → 8500），`plugin-checkin.json` 记
`outcome: claimed, credit: 1000`。测试 193 条。

## 0.2.16（2026-10-20 晚：上游把福利通道摘了）

**现象**：所有福利模型（`deepseek-v4.1-flash` / `deepseek-v4-pro-0813` /
`glm-5.3-flash` / `deepseek-v4-flash-0731`）突然 400：

```
{"code":"InferHub.4004.200","message":"CodeArts 码道 (Huawei): benefit not found", …}
```

**根因**（直连实测，两个账号四模型全复现）：上游把「限时福利」分组整个下线了。

| 请求 | 结果 |
|---|---|
| 带 `maas_type: benefit` + `model-id` + `model-name`（三个头参与签名） | **四个福利模型全部** `4004 benefit not found` |
| 不带这三个头 | `deepseek-v4.1-flash` 正常推理（非流式 / 流式 / 带工具 / `max_tokens=65536` 全 200）；其余三个回 `InferHub.002002009.404 model is not registered` |
| `opengw` 的 `/gateway/config`、`/user/tokens/balance`、`/benefit/claim` | 一律 `4000 invalid channel, group not found`（权益网关本身下线，签到与余额一并失效） |

**修法**：

- 撞到 `benefit not found`（非流式 `4004`、流式首帧 `InferHub.4004.200`）就**去掉那三个头重发一次**（同一 body，签名随头重算）。普通通道能跑就用它；跑不了（`model is not registered`）就把「福利没了」这条可行动的错误报给调用方，而不是把两个错误都糊掉。
- 加 `benefitDown` 熔断表（按 **账号+模型**，10 分钟）：撞过一次之后 TTL 内直接走普通通道，不再每次先撞一次白花一倍延迟；TTL 过后自动重试福利通道，活动恢复后能自己切回去。
- `auth.checkin`：`invalid channel / group not found` → `ineligible`（不是 `failed`），否则宿主每 30 分钟重试一次必死的请求；`usage` 卡片给出可读原因。
- **退役模型**（`RETIRED_MODELS`）：`deepseek-v4-pro-0813` / `glm-5.3-flash` / `deepseek-v4-flash-0731` 福利头没了之后，不带头的普通通道回 `404 model is not registered` —— **两条通道都不通**。它们仍留在清单里的话，magpie 轮询到就得到一个不带额度关键词的 400，而 magpie 对这种 400 **不 failover**（实测 `group/auto-deepseek-v4-pro` 4 次挂 1 次）。所以从清单里摘掉，云端清单里出现时也同样过滤。
- 名单钩子在「权益网关永久下线」时**静默退回静态清单**，不再每次刷新都刷一条 `listError`；网络类临时错误仍照旧上抛。

**同时修掉的两个流式缺陷**（都不是这次引入的，是压测时才暴露）：

| # | 问题 | 修法 |
|---|---|---|
| ㉘ | `streamWithErrorEvents` 的 `pull()` 在下游缓冲区里**还没有完整一行**时直接返回。上游把 `data:` 和后面的内容分成两个 chunk 时（实测很常见），这一轮什么都没入队就返回 → Node 的 `ReadableStream` 在 `pull` 空手而归后**不会再调用 `pull`**，而客户端的那次 read 永远挂着：**20 次压测挂 3~4 次**，表现是「回答永远不结束」（0.2.15 也有，只是此前没压测到） | `pull` 里循环读到**至少一整行**才返回；`done`/出错时置 `closed`，避免重复收尾 |
| ㉙ | 用 `res.clone()` 窥探首帧会 tee 上游流：取消窥探那一支时另一支一起卡死（实测 `reader.cancel()` 永不返回） | 窥探只用**一个** reader，判定完把「已读字节 + reader + 还没回来的那次 read」一并交给转发层，全程只有一层流 |

测试 140 条。

## 0.2.4 – 0.2.15（本 fork）

在 0.2.3 基础上的改动，逐条都有单测覆盖：

| # | 问题 | 修法 |
|---|---|---|
| ① | 不带 `x-ot-session-id`，撞上游「每账号 3 个并发会话」上限 → `TM.00001041` → 被 magpie 判成**额度用尽**并休息 15 分钟 | 所有对话请求带稳定会话 ID（由 AK 派生） |
| ② | `amount` 填的是**剩余**，宿主当**已用**渲染 → 「只用了 21.8%」显示成 `7819948 / 10000000` | `amount` 改填已用 |
| ③ | 窗口把每日免费 **Token** 标成「积分」，与控制台积分是两种货币 | 改名「每日免费 Token」、`unit: "tokens"` |
| ④ | 静态兜底的 `context: 200000 / output: 32000` 是猜的，而 `limit` 是**硬上限**，会截断长上下文 | 兜底一律 0（不设限），真实值取云端 |
| ⑤ | 签到窗口未签到时 `used: 1 / limit: 1` = 恰好 100%，满格红条像「用尽」 | 改成不带 `limit` 的纯状态行 |
| ⑥ | 天界按**机器本地时区**算，机器不在东八区时「今日已签」判定差一天 | 固定按 UTC+8（上游 24:00 清零） |
| ⑦ | loader 里 `init.body` 非字符串时被 `String()` 成 `"[object Object]"`，签名与实际 body 不一致；`Request` 对象的 method/body 被忽略；调用方的 `accept: text/event-stream` 等头被丢弃 | 按实际 URL/方法/body 签名，保留调用方其它头，非本 provider 地址原样转发 |
| ⑧ | 云端 `channel` 缓存跨账号串用 | 改为**按账号**分层缓存（`AK → modelId → channel`），只替换本账号那一层，键统一小写 |
| ⑨ | **对话端点少一段 `/api/v2`**：宿主 `pluginFetch` 用 `baseURL + TrimPrefix("/v1/chat/completions","/v1")` 拼地址，`baseURL` 只写主机名就会打到 `…/chat/completions`，上游返回 `APIG.0101 The API does not exist or has not been published` | `baseURL` / `config.api` 都改为 **base** `…/api/v2`；loader 另加 `resolveTarget()` 兜底，来地址只有 `…/chat/completions` 时补回 `/api/v2` |
| ⑩ | 同主机判断用 `startsWith`：`https://…myhuaweicloud.com.evil.example/` 会被当成自家地址，**AK/SK 签名外泄** | 改用 `new URL().origin` 精确比较 |
| ⑪ | 宿主给插件读的 `x-magpie-work-dir` / `x-magpie-work-git`（工作目录、仓库地址）被原样转给上游厂商 | loader 转发前显式删除；不依赖宿主自己擦 |
| ⑫ | 探针脚本打印 AK 首尾各 4 位（仍是凭据片段） | 改用不可逆指纹 |
| ⑬ | 模型清单拉取失败被 `catch` 吞成空数组 → 缓存被清空、静默退回静态清单，提供商页也不报错 | 拉取失败**不清缓存、向上抛**，由宿主记 `listError` 显示出来 |
| ⑭ | 上游 `models[]` 里有 `null` / 非对象元素时读 `.model_id` 抛错，**整份清单作废** | 逐项过滤非对象元素 |
| ⑮ | 签到 POST 成功后回读状态失败 → 被判成 `ineligible`；宿主把非 `failed` 的 outcome 当作「今天已结算」，**当天再也不重试** | 回读失败报 `failed`（30 分钟后由宿主重试确认）；只有「回读成功且时间戳确实没推进」才判 `ineligible` |
| ⑯ | 把云端 `max_tokens`（393216 / 384000）直接发布成 `limit.output`，而上游**参数**上限是 65536：客户端照着要 393216 → 上游 400 `RANGE_VALIDATOR` → magpie 包成 **HTTP 200 的空流**，看起来「成功但没内容」 | 新增 `MAX_OUTPUT_TOKENS = 65536`（实测值，非猜测），云端值与静态兜底都收敛到它 |
| ⑰ | 签到只看 POST 之后那次 GET：POST 自己带回的 `create_time` 被丢弃，GET 若返回 200 但没有 `result` 就判成**终局 `ineligible`**（宿主当天不再重试、UI 显示「不参与活动」，而积分其实已到账） | POST 的返回体作为第一手证据；GET 仅作回退；两者都拿不到时间戳时报 `failed`（可重试） |
| ⑱ | 上游错误体会**回显 Access Key**（`the access key LTAI5t… is malformed`），而这条消息会进登录失败提示、提供商页 `listError` 与 magpie 日志 | 新增 `redact()`，所有错误路径出站前把 AK/SK 换成 `***`；原因（malformed / 业务码）保留 |
| ⑲ | 宿主只在**路由组内**按成员上限收敛 `max_tokens`，组外只有用户手设「Max output」才下降。所以裸模型 `codearts/x` 收到 393216 时上游照旧 400 → 200 空流 | loader 在**签名前**把 `max_tokens` / `max_completion_tokens` / `max_output_tokens` 收敛到 65536，签名对应改写后的 body |
| ⑳ | 请求体**不带 `stream` 字段**时，上游默认按 **SSE** 应答；而 SSE 里的错误是 `{"error_code","error_msg"}`，magpie 嗅探器只认 OpenAI 的 `{"error"}`，于是「模型不存在」「参数非法」全被吞成 **HTTP 200 + `content:null` + 0 tokens**，客户端看到的是「成功但没有回答」 | loader 在签名前补 `stream: false`（OpenAI 语义里缺省就是 false）；已经写了 `stream` 的请求一律不动，避免破坏 magpie 的流式翻译路径 |
| ㉑ | 即使带了 `stream: false`，`unsupported model` 这类错误上游仍返回 **HTTP 200 + `error_code`**（实测），同样会被当成空回答 | loader 看响应：JSON 200 里认出 `error_code` → 改成 **400 + OpenAI 错误形态**；流式则窥探首事件，是错误就整条改 400，途中的错误事件改写成 `{"error":…}`（magpie 认这个）。正常流**逐字节透传**（有单测保证） |
| ㉒ | 宿主 `save()` 的实现是 `md = { ...inputs, ...result.metadata }`，prompt 收集的原始 `AK:SK` 组合串会落到 `metadata.credential`，与 `key`、`metadata.sk` **重复三份**明文凭据 | `authorize` 返回 `metadata: { sk, credential: "" }` 覆盖掉它（同名键、result 优先合并） |
| ㉓ | `usage()` 的 `catch` 引用了 `try` 块内的 `const ak/sk`：凭据不完整时 `creds()` 抛错 → catch 再抛 `ReferenceError`，宿主拿到异常而非「额度查询失败」 | `ak/sk` 提到 `try` 外声明，catch 照常脱敏并返回 error |
| ㉔ | 流式窥探若直接 `await reader.read()`：上游长思考时可能数秒不发一个字节，宿主就一直拿不到响应头（只判时间戳是拦不住的） | 窥探与 3 秒定时器竞速；超时放弃窥探，把那次**未完成**的 read 交给后续转发，一个字节都不丢 |

| ㉕ | 插件从不声明模型收不收图，magpie 只能记成**「没说」**（`imageSaid:false`）→ 带图请求照样被发给空文本成员，上游 406 `The request model is not multimodal`、账号被 backoff 60 秒（额度一个 token 没动，所以卡片照旧满格） | 给每个模型**明确**声明收不收图：配置钩子路径写 `modalities`、`provider.models` 钩子路径写 `capabilities` —— 宿主对这两条路的处理**不同**，写错会被静默丢掉 |
| ㉖ | 云端路径把「明确说不收图」写成了 `capabilities: { input: { text: true } }` —— **省掉值为 `false` 的键**。而宿主的 `imageSaid` 判的是 `typeof m.capabilities?.input?.image === "boolean"`，`undefined` 不是布尔 → 又退回「没说」，等于㉕白修（配置钩子那 3 个模型是对的，只有云端那 4 个没生效） | `capabilitiesField()` 照抄宿主自己的 `modalities()`：**每个模态键都在、值都是布尔**。补一条断言 `typeof input.image === "boolean"` 的单测钉死 —— 这条断言就是原来缺的那一条 |
| ㉗ | **㉕㉖ 的方向整体判错了**：探针绕过了插件自己的通道判定（benefit 通道要 `maas_type: benefit` + `model-id`/`model-name` 三个头并参与签名），于是把「模型未注册」的 404 和「格式不对」的 406 误读成能力差异，给 `deepseek-v4-pro-0813` 标了 `image: true` —— 等于**请宿主把图片发给一个必然 406 的模型** | 用正确通道头重测：codearts **全线不收图**。改为默认全 `false`，例外走 `VISION_MODELS` 名单（当前为空）。清单里没有的模型也明确声明 `false`（原来是「不写键」，会被照发图片） |

测试从 45 条增到 129 条，覆盖上述每一条以及「`used` 永不为 NaN」「空响应不抛错」
「余额字段为 0 不被 `||` 吞掉」等边界。

### 图片能力（0.2.15 定论：codearts 全线不收图）

**结论：codearts 没有任何模型能通过 magpie 的图片格式收图**，所以插件给每一个模型
（包括云端新上、清单里没有的）都**明确声明** `image: false`。这样 magpie 在带图请求里
会跳过 codearts，改派给路由组里能看图的成员（workbuddy / loomy / qoder 等），
你最初遇到的 406 和随之而来的 60 秒 backoff 就不会再出现。

**三个独立证据**（2026-10-20）：

1. **直连实测**（同一端点、同一 benefit 通道头，只改有没有图）：

   | 请求 | 结果 |
   |---|---|
   | `deepseek-v4-pro-0813` 纯文本 | **200** ✓（说明端点与头都对） |
   | `deepseek-v4-pro-0813` 带图 | **406** `InferHub.001001020.406 The request model is not multimodal` |
   | `deepseek-v4.1-flash` 带图 | 406 |
   | `glm-5.3-flash` 带图 | 406 |

   试过 OpenAI 的 `image_url`(data URI / 裸 base64)、`input_image`、`image`、
   `source{base64}` 等多种形状，以及 64×64 纯色图与 512×512、256×256 噪声图，
   **没有一种被接受**。
2. **AgentCenter**（`/v1/agent-center/agents/detail`，老套餐通道）**确实提供
   `supports_images` 字段** —— 该账号下 5 个模型（`GLM-5.2` / `glm-5.2-sft-harmony` /
   `openpangu-2.0-pro` / `openpangu-2.0-flash` / `glm-5.3`）**全是 `false`**。
3. **免费额度网关**（`/api/v1/gateway/config`，本插件用的那条）**不含任何能力信息** ——
   只有 `model_id` / `model_name` / `context_window` / `max_tokens` / `sort` 五个字段；
   社区参考实现 codearts2api 对这条通道同样硬编码 `supports_images: False`。

⚠️ **凌晨日志里 `deepseek-v4-pro-0813`「成功服务 18 次带图请求」是假象**：那是第 30 轮的
长对话，图片出现在早前轮次，宿主已用「识图模型转文字描述」把原图换成了文字，模型收到
的是纯文本所以 200。不要去信「它接过带图请求且成功」这种二手证据 ——
**判定能力必须自己直连发一张图，并且要有纯文本对照**。

**为什么要声明成 `false` 而不是留空**：宿主 `internal/plugin/host.js` 把能力读成三态 ——

```js
image:     !!m.capabilities?.input?.image,                     // 会不会看图
imageSaid: typeof m.capabilities?.input?.image === "boolean",  // 厂商有没有说
```

| 怎么写 | 宿主读出 | 语义 | 带图请求 |
|---|---|---|---|
| 一个键都不写 | `image:false, imageSaid:false` | **没说** | 照发（会撞 406） |
| `input.image = false` | `image:false, imageSaid:true` | **明确说不收** | **跳过** ✓ |
| `input.image = true` | `image:true, imageSaid:true` | 收图 | 可以派给它 |

实测证据：同一个 `raccoon/sn-deepseek-v4-1-flash`（`image:false, imageSaid:true`）一天里
纯文本请求被尝试 160 次、**带图请求 0 次**；而「没说」的 codearts 被尝试了 20 次，
里面就有那两次 406。**`imageSaid` 要的是真的布尔，所以值为 `false` 的键不能省。**

⚠️ **两条路径写的字段不一样，这是最容易踩的坑**（都有单测盯着）：

| 产出模型的地方 | 走宿主的哪条路 | 要写的字段 |
|---|---|---|
| `codeartsModels()`（配置钩子） | 配置模型合并循环 —— 宿主**自己**用 `modalities` 重建 `capabilities`，模型对象里原生的 `capabilities` 键反而不被采纳 | `modalities: { input: [...], output: [...] }` |
| `provider.models` 钩子的云端清单 | 返回值被**原样采用**（`{ ...m, id, providerID }`），**不做**任何 `modalities` 转换 | `capabilities: { input: {…}, output: {…} }`，照抄宿主的 `modalities()` |

「照抄宿主的 `modalities()`」的意思是**五个模态键（`text/image/audio/video/pdf`）一个不落、
值全是布尔**。0.2.13 在云端路径上写成了 `{ text: true }`，少了 `image: false`，
于是一路静默失效到线上才被发现（㉖）。

**将来华为真支持了怎么办**：把模型 id 加进 `VISION_MODELS`（`index.mjs` 里那个集合），
两条路径会自动把它声明成 `image: true`。加之前**必须直连实测过**：同一端点、同一通道头、
只改有没有图，且**纯文本对照必须是 200**（否则你连端点选错了都不知道 —— ㉗ 就是这么翻车的）。

**维护提示**：`image` 和 `context: 0`、`MAX_OUTPUT_TOKENS` 一样是**实测值不是猜的** ——
上游模型能力变了（或新模型进清单）要跟着改；表里查不到的模型宁可保持「没说」
（行为退回 0.2.12），也不编一个可能错的 `false` 把模型从带图请求里踢掉。

### 第四轮实测（2026-10-19）

工具调用（流式 / 非流式）、5 万 token 长上下文、`max_tokens=1` 截断、错误分类、
两个账号的额度换算、七个模型的通道判定全部通过；上面 ⑳㉑㉒㉓ 就是这轮挖出来的。

修完后又复测了一轮（0.2.11）：8 并发流式 / 8 并发非流式全 200、流式工具调用
`{"city":"北京"}` 能正确拼回、未知模型与空 messages 在**非流式**下也如实返回 400、
Anthropic 协议（`/v1/messages`，流式与非流式）翻译路径不受影响。⑳ 修好后，
「思考型模型 + 小 `max_tokens` 时正文为空」仍然存在 —— 直连上游同样如此
（`max_tokens=1500` 时 2817 reasoning / 34 content），是模型把预算花在思考上，
不是插件缺陷；给足 `max_tokens`（实测 3000）即正常出正文。

> **为什么要改 `baseURL` 而不是在 fetch 里硬编码端点**：0.2.3 的 `fetch` 无视宿主给的
> 地址、直接打 `SNAP_HOST + /api/v2/chat/completions`，看着能用，但它同时把宿主的
> 路由语义（`plugin://<id>/v1`)绕开了：任何非对话路径、任何宿主拼法变更都会出错，
> 而且 `config.api` 里那条完整端点一旦被宿主当基址用，就会拼成
> `…/chat/completions/chat/completions`。现在的写法是「base 交给宿主拼、插件只做
> 签名与兜底补正」，两条路径都对。

## 致谢与免责声明

本插件的协议实现基于社区开源逆向成果（MIT）：

- [codearts2api](https://cnb.cool/itq5/codearts2api)（Go，多账号 OpenAI 兼容代理，签到/登录/额度架构）
- [Johnsheng1/codearts2api](https://github.com/Johnsheng1/codearts2api)（Python，`benefit.py` 签到实现与签名算法）

在此致谢。本项目为**非官方**社区插件，与华为云 / CodeArts 无任何关联；使用本插件产生的账号风险（含违反上游服务条款的限制）由使用者自行承担；上游协议变更可能导致插件随时失效。

本 fork（`xiyingruyi/magpie-codearts-auth`）同样以 MIT 发布，保留原作者署名。

## License

MIT
