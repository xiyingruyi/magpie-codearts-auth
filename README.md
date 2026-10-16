# magpie-codearts-auth

[magpie](https://usemagpie.ai) / [OpenCode](https://opencode.ai) provider 插件：**华为云码道 CodeArts 代码智能体**。

| 能力 | 说明 |
|---|---|
| 授权 | 华为云访问密钥 **AK/SK**（华为云官方 SDK-HMAC-SHA256 签名），登录时自动验证有效性 |
| **每日签到** ⭐ | 实现 magpie 原生 `auth.checkin` 钩子（magpie ≥ v0.1.1083）——Settings → Usage → Plugins 打开 **Daily check-in**，每天每账号自动签到领取 **1000 积分**，Usage 卡片显示签到状态，也可 **Check in now** 手动签 |
| 免费额度 | `auth.usage` 显示免费额度余额（已用/总量）与今日签到状态 |
| 对话 | `POST snap-access /api/v2/chat/completions`（OpenAI 形态），按模型自动选通道 |
| 模型 | 登录后自动同步云端模型清单（含 `channel` 字段），失败时回退内置列表 |

## 安装

```sh
magpie plugin add github:liuxigreen/magpie-codearts-auth   # 或本地文件夹 / .tgz
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
| `ineligible` | 当前不在签到活动期内（活动结束 / 未开始） |
| `inactive` | 账号未开通该权益或未实名 |
| `captcha` | 需要人机验证，提示到控制台手动签到 |
| `failed` | 其它错误（宿主 30 分钟后重试） |

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
node --test tests/index.test.mjs  # 纯函数单测（无网络，Node ≥ 18）
```

可测辅助函数经 `_internal` 导出；涉及上游交互的函数（`claimToday` / `fetchBalance` 等）需真实 AK/SK，不在 CI 覆盖范围。

## 与官方骨架版（0.1.0）的差异

本仓库起自一份社区骨架，修掉了三个会实际影响使用的问题：

1. **登录不可用（致命）** —— 骨架版 `authorize()` 读 `inputs.key`，而宿主从不把 key 框的值并进 `inputs`，导致 AK 永远为空、100% 登录失败。本版改为单框粘贴 `AK:SK` 并在插件内拆分，AK/SK 均经 `prompts` 进入 `inputs`。
2. **通道判定方向反了** —— 骨架版用硬编码白名单判定 benefit，与上游的黑名单语义相反，云端新模型会走错通道报 `unsupported model`。
3. **丢弃云端 `channel` 字段** —— 该字段正是上游构建 `AGENT_MODELS` 的依据；本版保留并写入运行期缓存。

此外补齐了 `ineligible` / `captcha` / `inactive` 三种签到 outcome（骨架版遇到会落到 `failed` 并每 30 分钟无意义重试）。

## 致谢与免责声明

本插件的协议实现基于社区开源逆向成果（MIT）：

- [codearts2api](https://cnb.cool/itq5/codearts2api)（Go，多账号 OpenAI 兼容代理，签到/登录/额度架构）
- [Johnsheng1/codearts2api](https://github.com/Johnsheng1/codearts2api)（Python，`benefit.py` 签到实现与签名算法）

在此致谢。本项目为**非官方**社区插件，与华为云 / CodeArts 无任何关联；使用本插件产生的账号风险（含违反上游服务条款的限制）由使用者自行承担；上游协议变更可能导致插件随时失效。

## License

MIT
