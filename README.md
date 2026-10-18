# magpie-codearts-auth

[magpie](https://usemagpie.ai) / [OpenCode](https://opencode.ai) provider 插件：**华为云码道 CodeArts 代码智能体**。

| 能力 | 说明 |
|---|---|
| 授权 | 华为云访问密钥 **AK/SK**（华为云官方 SDK-HMAC-SHA256 签名），登录时自动验证有效性 |
| **每日签到** ⭐ | 实现 magpie 原生 `auth.checkin` 钩子（magpie ≥ v0.1.1083）——Settings → Usage → Plugins 打开 **Daily check-in**，每天每账号自动签到领取 **1000 积分**，Usage 卡片显示签到状态，也可 **Check in now** 手动签 |
| 免费额度 | `auth.usage` 显示**每日免费 Token** 的已用/总量与今日签到状态 |
| 对话 | `POST snap-access /api/v2/chat/completions`（OpenAI 形态），按模型自动选通道 |
| 模型 | 登录后自动同步云端模型清单（含 `channel` 字段），失败时回退内置列表 |

## 安装

```sh
magpie plugin add github:liuxigreen/magpie-codearts-auth   # 上游原版
magpie plugin add github:xiyingruyi/magpie-codearts-auth   # 本 fork（含 0.2.6 修复）
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

## 每日签到

- **协议**：`POST https://opengw.developer.huaweicloud.com/api/v1/benefit/claim`（空 body，AK/SK 签名，服务端按天幂等）
- **状态**：`GET` 同路径返回 `result.create_time`（最近签到毫秒时间戳），当天已签则 `outcome: done`
- **调度**：Settings → Usage → Plugins 的 Daily check-in 开关（默认关）打开后，每天每账号自动签一次（启动 2 分钟后首查、每 30 分钟轮询，`failed` 30 分钟后重试）
- **奖励**：官方活动每日签到 +1000 积分（积分自发放起 30 天有效；活动结束时间以官网为准）

插件向 magpie 返回的标准 outcome：

| outcome | 触发条件 |
|---|---|
| `claimed` | 签到成功且 `create_time` 落在今天 |
| `done` | 今天已经签过 |
| `ineligible` | 上游未推进签到时间（账号不参与签到活动 / 活动已结束） |
| `inactive` | 账号未开通该权益或未实名 / 未登录 |
| `captcha` | 需要人机验证，提示到控制台手动签到 |
| `failed` | 其它错误（宿主 30 分钟后重试） |

> **实测注意**：老套餐（AgentCenter）账号不参与签到活动 —— 上游对这类账号**不报错**，`POST /benefit/claim` 会原样返回旧的 `create_time`（余额也不变）。插件据此判定为 `ineligible`，避免宿主每 30 分钟无意义重试。

## Usage 卡片字段语义（实测定论）

magpie 的 `usage()` window 字段，本插件按宿主源码逐条对齐：

| 字段 | 含义 | magpie 如何渲染 |
|---|---|---|
| `used` | **已用百分比**（0~100+，可超 100） | 直接显示为 `N%`，`>=98` 染成「spent」红条 |
| `amount` | 该窗口的**已用**绝对量 | 与 `limit` 组合成 `amount / limit` |
| `limit` | 绝对值总量（0 / 缺省 = 不设限） | 同上；`limit > 0` 才显示括号数字 |
| `unit` | 计量单位文案 | 拼在数字后（这里是 `tokens`） |
| `aside` | `true` = 只展示，**不参与路由、不参与「用尽」判定** | 侧栏一行 |

**踩坑记录一（0.2.2）**：`used` 被填成绝对值 `299530`，`magpie quota` 显示成 `299530%`。
受控实验（`used:50 → 50%`）定论：**`used` 是百分比**。

**踩坑记录二（0.2.3，仍在）**：`amount` 被填成**剩余**（`total_balance`），而宿主
`quotaCount()` 是按 `amount / limit` 当「已用」渲染的。于是明明只用了 21.8%，
卡片却显示 `7819948 / 10000000`——看起来像「用掉了 78%」。0.2.4 改为填已用。

**踩坑记录三（0.2.3，仍在）**：`total_quota = 10,000,000` 是**每日免费 Token**
（官方口径：每位用户每日 1000 万 Tokens，当日 24:00 清零，**不与积分包互通**），
不是积分。控制台里那一万多积分是签到/邀请/学生认证等活动发的另一种货币（`CREDIT`），
插件没有接口去读它。0.2.4 起窗口名与单位改为 `每日免费 Token` / `tokens`，不再混称「积分」。

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

## 0.2.4 – 0.2.6（本 fork）

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

测试从 45 条增到 94 条，覆盖上述每一条以及「`used` 永不为 NaN」「空响应不抛错」
「余额字段为 0 不被 `||` 吞掉」等边界。

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
