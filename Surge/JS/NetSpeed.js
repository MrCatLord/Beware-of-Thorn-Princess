
const BASE = "https://speed.cloudflare.com";
const TIMEOUT = 120000;

function percentile(values, p) {
  if (!values.length) return 0;
  const sorted = values.slice().sort((a, b) => a - b);
  const index = Math.max(0, Math.ceil(p * sorted.length) - 1);
  return sorted[index];
}

function median(values) {
  return percentile(values, 0.5);
}

function uniqueURL(path) {
  return BASE + path + "&measId=" +
    Date.now() + Math.random().toString(16).slice(2);
}

async function fetchWithTimeout(url, ms) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);

  try {
    return await fetch(url, {
      method: "GET",
      cache: "no-store",
      credentials: "omit",
      signal: controller.signal
    });
  } finally {
    clearTimeout(timer);
  }
}

async function latencyTest() {
  const values = [];

  for (let i = 0; i < 20; i++) {
    const url = uniqueURL("/__down?bytes=0");
    const start = performance.now();

    const response = await fetchWithTimeout(url, 15000);

    const elapsed = performance.now() - start;

    if (!response.ok) {
      throw new Error("延迟测试 HTTP " + response.status);
    }

    await response.arrayBuffer();

    const entries = performance.getEntriesByName(url);
    const entry = entries.length ? entries[entries.length - 1] : null;

    let ping = entry && entry.responseStart > 0
      ? entry.responseStart - entry.requestStart
      : elapsed;

    if (ping > 0 && ping < 10000) {
      values.push(ping);
    }
  }

  if (values.length < 5) {
    throw new Error("有效延迟样本不足");
  }

  return median(values);
}

async function downloadOne(bytes) {
  const url = uniqueURL("/__down?bytes=" + bytes);

  const start = performance.now();
  const response = await fetchWithTimeout(url, 30000);
  const headersTime = performance.now();

  if (!response.ok) {
    throw new Error("下载 HTTP " + response.status);
  }

  let received = 0;

  if (response.body && response.body.getReader) {
    const reader = response.body.getReader();

    while (true) {
      const result = await reader.read();
      if (result.done) break;
      received += result.value.byteLength;
    }
  } else {
    const buffer = await response.arrayBuffer();
    received = buffer.byteLength;
  }

  const end = performance.now();

  const entries = performance.getEntriesByName(url);
  const entry = entries.length ? entries[entries.length - 1] : null;

  let duration = entry &&
    entry.responseStart > 0 &&
    entry.responseEnd > entry.responseStart
      ? entry.responseEnd - entry.responseStart
      : end - headersTime;

  if (duration <= 0) {
    duration = end - start;
  }

  if (received <= 0 || duration <= 0) {
    throw new Error("下载数据无效");
  }

  return {
    bytes: received,
    duration: duration,
    bps: received * 8 / (duration / 1000)
  };
}

async function downloadTest() {
  const stages = [
    { bytes: 100000, count: 9 },
    { bytes: 1000000, count: 8 },
    { bytes: 10000000, count: 6 },
    { bytes: 25000000, count: 4 },
    { bytes: 100000000, count: 3 },
    { bytes: 250000000, count: 2 }
  ];

  const samples = [];

  for (const stage of stages) {
    const batch = await Promise.all(
      Array.from({ length: stage.count }, () =>
        downloadOne(stage.bytes)
      )
    );

    for (const item of batch) {
      if (item.duration >= 10) {
        samples.push(item.bps);
      }
    }

    const durations = batch.map(x => x.duration);
    const typicalDuration = median(durations);

    // 达到 Cloudflare 默认的 1 秒请求时长门槛后停止扩大文件
    if (typicalDuration >= 1000) {
      break;
    }
  }

  if (!samples.length) {
    throw new Error("没有获得有效下载样本");
  }

  return percentile(samples, 0.9) / 1000000;
}

async function main() {
  const start = performance.now();

  const ping = await latencyTest();
  const download = await downloadTest();

  const total = (performance.now() - start) / 1000;

  return {
    title: "NetSpeed",
    content:
      "下载：" + download.toFixed(2) + " Mbps\n" +
      "延迟：" + ping.toFixed(1) + " ms\n" +
      "耗时：" + total.toFixed(1) + " 秒",
    icon: "bolt",
    "icon-color": "#06D6A0"
  };
}

(async () => {
  let finished = false;

  const watchdog = setTimeout(() => {
    if (finished) return;
    finished = true;

    $done({
      title: "NetSpeed",
      content: "测速超时，请检查网络或 Cloudflare 接口",
      icon: "exclamationmark.triangle.fill",
      "icon-color": "#EF476F"
    });
  }, TIMEOUT);

  try {
    const result = await main();

    if (!finished) {
      finished = true;
      clearTimeout(watchdog);
      $done(result);
    }
  } catch (error) {
    if (!finished) {
      finished = true;
      clearTimeout(watchdog);

      $done({
        title: "NetSpeed",
        content: "测速失败：\n" + String(error.message || error),
        icon: "exclamationmark.triangle.fill",
        "icon-color": "#EF476F"
      });
    }
  }
})();
