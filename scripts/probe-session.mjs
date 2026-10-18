/**
 * 实测探针（只读）：验证「稳定 x-ot-session-id」是否真能压掉上游的
 * `TM.00001041 并发会话数已达上限(3个)`。
 *
 * 这条错误会被 magpie 误判成「额度用尽」（宿主 internal/gateway/routing.go
 * 的 usedUpWords 含中文词 `上限`），把账号休息 15 分钟。带上稳定会话 ID 后，
 * 上游应把同一账号的所有请求算作同一个会话，这条错误就不再出现。
 *
 * 用法（凭据只从环境变量读，不落盘、不打印）：
 *
 *   CODEARTS_AK=... CODEARTS_SK=... node scripts/probe-session.mjs <模式> [并发数]
 *
 *   <模式> = nosid  不带会话头
 *            sid    带稳定会话头
 *            both   先 nosid 再 sid（中间有冷却；串行跑的对照更可靠）
 *
 * 一次只跑一种模式很重要：上游按*活跃*会话计数，上一轮的流式连接若还没被
 * 服务端回收，会把下一轮一起带进上限。
 *
 * 只发流式 chat 请求，max_tokens 很小，读完前 8KB 主动断开；
 * 不发签到、不写任何东西。
 */
import { _internal } from "../index.mjs";

const { sdkSignedHeaders, sessionHeaders, upstreamSessionId } = _internal;

const AK = process.env.CODEARTS_AK;
const SK = process.env.CODEARTS_SK;
if (!AK || !SK) {
  console.error("需要 CODEARTS_AK / CODEARTS_SK 环境变量");
  process.exit(2);
}

const MODE = String(process.argv[2] ?? "both");
const CONCURRENCY = Number(process.argv[3] ?? 3);
const COOLDOWN_MS = Number(process.env.CODEARTS_COOLDOWN_MS ?? 90_000);
const URL_ = "https://snap-access.cn-north-4.myhuaweicloud.com/api/v2/chat/completions";
const MODEL = process.env.CODEARTS_MODEL ?? "deepseek-v4.1-flash";

const body = JSON.stringify({
  model: MODEL,
  messages: [{ role: "user", content: "从 1 数到 3000，用逗号分隔，不要省略任何数字。" }],
  max_tokens: 2000,
  stream: true,
});

function headersFor(withSession) {
  const s = withSession ? sessionHeaders(AK) : {};
  return sdkSignedHeaders("POST", URL_, body, AK, SK, {
    ...s,
    maas_type: "benefit",
    "model-id": MODEL,
    "model-name": MODEL,
  });
}

async function call(i, t0, withSession) {
  try {
    const res = await fetch(URL_, {
      method: "POST",
      headers: headersFor(withSession),
      body,
      signal: AbortSignal.timeout(120_000),
    });
    if (res.status !== 200) {
      const text = await res.text();
      return { i, status: res.status, text: text.slice(0, 200), ms: Date.now() - t0 };
    }
    const reader = res.body.getReader();
    let bytes = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value?.length ?? 0;
      if (bytes > 8000) {
        await reader.cancel();
        break;
      }
    }
    return { i, status: 200, text: `streamed ${bytes}B`, ms: Date.now() - t0 };
  } catch (e) {
    return { i, status: 0, text: `ERR ${e?.message ?? e}`, ms: Date.now() - t0 };
  }
}

function tally(rs) {
  const out = {};
  for (const r of rs) {
    const k = /TM\.00001041|并发会话数已达上限/.test(r.text)
      ? "CONCURRENCY"
      : r.status === 200
        ? "ok"
        : /APIG\.0301|signature fail/i.test(r.text)
          ? "SIGNATURE_REJECTED"
          : /TM\.00001001/.test(r.text)
            ? "HEADER_REJECTED"
            : `other_${r.status}`;
    out[k] = (out[k] ?? 0) + 1;
  }
  return Object.entries(out).map(([k, v]) => `${k}×${v}`).join(" ") || "(none)";
}

const mask = (s) => `${String(s).slice(0, 4)}…${String(s).slice(-4)}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function burst(withSession) {
  const t = Date.now();
  const rs = await Promise.all(Array.from({ length: CONCURRENCY }, (_, i) => call(i, t, withSession)));
  const label = withSession ? "带稳定会话头" : "不带会话头  ";
  console.log(`${label} → ${tally(rs)}`);
  for (const r of rs.filter((x) => x.status !== 200).slice(0, 2)) {
    console.log(`  [${r.i}] ${r.status} ${r.text.replace(/\s+/g, " ")}`);
  }
}

console.log(`账号 ${mask(AK)} · 模型 ${MODEL} · 并发 ${CONCURRENCY} · 模式 ${MODE}`);
console.log(`稳定会话 ID = ${upstreamSessionId(AK)}`);

if (MODE === "nosid") {
  await burst(false);
} else if (MODE === "sid") {
  await burst(true);
} else {
  await burst(false);
  console.log(`\n冷却 ${Math.round(COOLDOWN_MS / 1000)}s，等上游回收上一轮的会话…\n`);
  await sleep(COOLDOWN_MS);
  await burst(true);
}
