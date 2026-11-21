
const URL = "https://mensura.cdn-apple.com/api/v1/gm/large";
const PING = "http://www.gstatic.com/generate_204";

const CHUNK = 1024 * 1024;
const CONCURRENCY = 4;
const DURATION = 10000;

function get(url, headers = {}) {
  return new Promise((resolve, reject) => {
    $httpClient.get({
      url,
      timeout: 20,
      headers
    }, (err, resp, body) => {
      if (err) return reject(new Error(String(err)));
      if (!resp) return reject(new Error("无响应"));
      resolve({ resp, body });
    });
  });
}

async function ping() {
  const start = Date.now();
  const r = await get(PING, {
    "Cache-Control": "no-cache"
  });
  if (r.resp.statusCode !== 204) {
    throw new Error("延迟 HTTP " + r.resp.statusCode);
  }
  return Date.now() - start;
}

async function latency() {
  await ping();
  const a = [];
  for (let i = 0; i < 8; i++) a.push(await ping());
  a.sort((x, y) => x - y);
  return (a[3] + a[4]) / 2;
}

async function download() {
  let offset = 0;
  let bytes = 0;
  let failed = "";
  const start = Date.now();
  const deadline = start + DURATION;

  async function worker() {
    while (Date.now() < deadline && !failed) {
      const pos = offset;
      offset += CHUNK;

      try {
        const r = await get(URL, {
          "Range": "bytes=" + pos + "-" + (pos + CHUNK - 1),
          "Accept-Encoding": "identity",
          "Cache-Control": "no-cache"
        });

        if (r.resp.statusCode !== 206) {
          failed = "HTTP " + r.resp.statusCode;
          break;
        }

        const n = typeof r.body === "string" ? r.body.length : 0;
        if (n !== CHUNK) {
          failed = "数据长度异常：" + n;
          break;
        }

        bytes += n;
      } catch (e) {
        failed = String(e.message || e);
        break;
      }
    }
  }

  await Promise.all(
    Array.from({ length: CONCURRENCY }, () => worker())
  );

  const elapsed = (Date.now() - start) / 1000;

  if (failed) throw new Error(failed);
  if (!bytes) throw new Error("下载数据为 0");

  return {
    speed: bytes * 8 / elapsed / 1000000,
    elapsed
  };
}

(async () => {
  try {
    const p = await latency();
    const d = await download();

    const icon = d.speed >= 300 ? "bolt" :
      d.speed >= 100 ? "hare" : "tortoise";

    $done({
      title: "NetSpeed",
      content:
        "下行速率：" + d.speed.toFixed(2) + " Mbps\n" +
        "网络延迟：" + (p < 100 ? "🟢" : "🟡") + " " + p + " ms\n" +
        "测试耗时：" + d.elapsed.toFixed(1) + " 秒",
      icon,
      "icon-color": p < 100 ? "#16A36A" : "#D69B28"
    });
  } catch (e) {
    $done({
      title: "NetSpeed",
      content: "测速失败：\n" + String(e.message || e),
      icon: "exclamationmark.triangle.fill",
      "icon-color": "#EF476F"
    });
  }
})();
