
const CF = "https://speed.cloudflare.com";
const PING_URL = "http://cp.cloudflare.com/generate_204";

// Cloudflare 官方测速风格的下载阶梯
const DOWNLOAD_STAGES = [
  { bytes: 1e5, count: 9 },
  { bytes: 1e6, count: 8 },
  { bytes: 1e7, count: 6 },
  { bytes: 2.5e7, count: 4 },
  { bytes: 1e8, count: 3 },
  { bytes: 2.5e8, count: 2 }
];

function median(values) {
  const a = values.slice().sort((x, y) => x - y);
  const n = a.length;
  if (!n) return 0;
  if (n % 2) return a[(n - 1) / 2];
  return (a[n / 2 - 1] + a[n / 2]) / 2;
}

function percentile(values, p) {
  const a = values.slice().sort((x, y) => x - y);
  if (!a.length) return 0;
  return a[Math.max(0, Math.ceil(p * a.length) - 1)];
}

function makeURL(bytes) {
  return CF + "/__down?bytes=" + bytes +
    "&measId=" + Date.now() +
    Math.random().toString(16).slice(2);
}

// HTTP 204 延迟测试
function pingOnce() {
  return new Promise((resolve, reject) => {
    const start = Date.now();

    $httpClient.get({
      url: PING_URL + "?ts=" + Date.now() +
        Math.random().toString(16).slice(2),
      timeout: 10,
      headers: {
        "Cache-Control": "no-cache"
      }
    }, (error, response) => {
      if (error) {
        reject(new Error("延迟请求失败：" + error));
        return;
      }

      if (!response) {
        reject(new Error("延迟服务器无响应"));
        return;
      }

      const status = response.statusCode || response.status || 0;

      if (status < 200 || status >= 300) {
        reject(new Error("延迟接口 HTTP " + status));
        return;
      }

      resolve(Date.now() - start);
    });
  });
}

async function latencyTest() {
  // 预热，不计入结果
  await pingOnce();

  const samples = [];

  for (let i = 0; i < 10; i++) {
    samples.push(await pingOnce());
  }

  return median(samples);
}

// 下载一个文件，利用 Resource Timing 计算传输时间
async function downloadOnce(bytes) {
  const url = makeURL(bytes);
  const start = performance.now();

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 45000);

  try {
    const response = await fetch(url, {
      method: "GET",
      cache: "no-store",
      credentials: "omit",
      mode: "cors",
      signal: controller.signal
    });

    if (!response.ok) {
      throw new Error("Cloudflare 下载 HTTP " + response.status);
    }

    if (!response.body || !response.body.getReader) {
      throw new Error("当前 WebView 不支持流式下载");
    }

    const reader = response.body.getReader();
    let received = 0;

    while (true) {
      const result = await reader.read();
      if (result.done) break;
      received += result.value.byteLength;
    }

    const elapsed = performance.now() - start;

    // 获取本次请求独立的 Resource Timing
    const entries = performance.getEntriesByName(url, "resource");
    const entry = entries.length
      ? entries[entries.length - 1]
      : null;

    if (!entry || !entry.responseEnd || !entry.responseStart) {
      throw new Error("无法取得 Cloudflare Resource Timing");
    }

    // 优先采用最终响应头时间，避免 1xx 响应影响计时
    const headerStart =
      entry.finalResponseHeadersStart > 0
        ? entry.finalResponseHeadersStart
        : entry.responseStart;

    const duration = entry.responseEnd - headerStart;

    if (duration <= 0 || received <= 0) {
      throw new Error("下载计时数据无效");
    }

    // 优先采用 Resource Timing 的实际传输字节数
    const transferBytes =
      entry.transferSize > 0
        ? entry.transferSize
        : received;

    return {
      bps: transferBytes * 8 / (duration / 1000),
      duration: duration,
      received: received,
      elapsed: elapsed
    };

  } finally {
    clearTimeout(timer);
  }
}

// 多连接下载测速
async function downloadTest() {
  const samples = [];

  for (const stage of DOWNLOAD_STAGES) {
    const batch = await Promise.all(
      Array.from(
        { length: stage.count },
        () => downloadOnce(stage.bytes)
      )
    );

    for (const item of batch) {
      // 排除过短请求，避免计时误差
      if (item.duration >= 10 && item.bps > 0) {
        samples.push(item.bps);
      }
    }

    if (!batch.length) {
      throw new Error("下载样本为空");
    }

    // 与 Cloudflare 默认的 1000ms 阶梯终止门槛接近
    const typicalDuration = median(
      batch.map(item => item.duration)
    );

    if (typicalDuration >= 1000) {
      break;
    }
  }

  if (!samples.length) {
    throw new Error("没有获得有效下载速度样本");
  }

  // 采用 90 百分位
  return percentile(samples, 0.9) / 1000000;
}

async function main() {
  const totalStart = Date.now();

  const ping = await latencyTest();
  const download = await downloadTest();

  const totalTime = (Date.now() - totalStart) / 1000;

  return {
    title: "NetSpeed",
    content:
      "下行速率：" + download.toFixed(2) + " Mbps\n" +
      "网络延迟：" + ping.toFixed(1) + " ms\n" +
      "测试耗时：" + totalTime.toFixed(1) + " 秒",
    icon: "speedometer",
    "icon-color": "#06D6A0"
  };
}

(async () => {
  try {
    const result = await main();
    $done(result);
  } catch (error) {
    $done({
      title: "NetSpeed",
      content: "测速失败：\n" +
        String(error.message || error),
      icon: "exclamationmark.triangle.fill",
      "icon-color": "#EF476F"
    });
  }
})();
