
const APPLE_URL = "https://mensura.cdn-apple.com/api/v1/gm/large";
const PING_URL = "http://www.gstatic.com/generate_204";

const CONCURRENCY = 4;
const CHUNK_SIZE = 8 * 1024 * 1024;
const TEST_DURATION = 10000;

function median(arr) {
  const a = arr.slice().sort((x, y) => x - y);
  const n = a.length;
  if (!n) return 0;
  return n % 2 ? a[(n - 1) / 2] : (a[n / 2 - 1] + a[n / 2]) / 2;
}

function pingOnce() {
  return new Promise((resolve, reject) => {
    const start = Date.now();

    $httpClient.get({
      url: PING_URL,
      timeout: 10,
      headers: {
        "Cache-Control": "no-cache"
      }
    }, (error, response) => {
      if (error) {
        reject(new Error("Google 延迟请求失败：" + error));
        return;
      }

      if (!response) {
        reject(new Error("Google 延迟服务器无响应"));
        return;
      }

      const status = response.statusCode || response.status;

      if (status !== 204) {
        reject(new Error("Google HTTP 状态码：" + status));
        return;
      }

      resolve(Date.now() - start);
    });
  });
}

async function latencyTest() {
  await pingOnce(); // 预热

  const samples = [];

  for (let i = 0; i < 8; i++) {
    samples.push(await pingOnce());
  }

  return median(samples);
}

async function downloadTest() {
  let nextOffset = 0;
  let totalBytes = 0;
  let failure = null;

  const controllers = [];
  const start = performance.now();
  const deadline = start + TEST_DURATION;

  async function worker() {
    while (performance.now() < deadline && !failure) {
      const offset = nextOffset;
      nextOffset += CHUNK_SIZE;

      const end = offset + CHUNK_SIZE - 1;
      const controller = new AbortController();
      controllers.push(controller);

      try {
        const response = await fetch(APPLE_URL, {
          method: "GET",
          headers: {
            "Range": "bytes=" + offset + "-" + end,
            "Cache-Control": "no-cache"
          },
          cache: "no-store",
          credentials: "omit",
          signal: controller.signal
        });

        if (response.status !== 206) {
          controller.abort();
          throw new Error(
            "Apple CDN 不支持预期的分段下载，HTTP " +
            response.status
          );
        }

        const reader = response.body.getReader();

        while (true) {
          const result = await reader.read();

          if (result.done) break;

          totalBytes += result.value.byteLength;

          if (performance.now() >= deadline) {
            controller.abort();
            break;
          }
        }

      } catch (e) {
        if (e.name !== "AbortError" && !failure) {
          failure = e;
        }
      }
    }
  }

  const timer = setTimeout(() => {
    controllers.forEach(c => c.abort());
  }, TEST_DURATION);

  try {
    await Promise.all(
      Array.from({ length: CONCURRENCY }, () => worker())
    );
  } finally {
    clearTimeout(timer);
    controllers.forEach(c => c.abort());
  }

  const elapsed = (performance.now() - start) / 1000;

  if (failure) throw failure;

  if (totalBytes === 0) {
    throw new Error("Apple CDN 没有返回有效下载数据");
  }

  return {
    speed: totalBytes * 8 / elapsed / 1000000,
    elapsed: elapsed,
    bytes: totalBytes
  };
}

async function main() {
  const totalStart = Date.now();

  const ping = await latencyTest();
  const download = await downloadTest();

  const totalTime = (Date.now() - totalStart) / 1000;

  let icon = "tortoise";

  if (download.speed >= 300) {
    icon = "bolt";
  } else if (download.speed >= 100) {
    icon = "hare";
  }

  const latencyIcon = ping < 100 ? "🟢" : "🟡";

  return {
    title: "NetSpeed",
    content:
      "下行速率：" + download.speed.toFixed(2) + " Mbps\n" +
      "网络延迟：" + latencyIcon + " " + ping.toFixed(1) + " ms\n" +
      "测试耗时：" + totalTime.toFixed(1) + " 秒",
    icon: icon,
    "icon-color": ping < 100 ? "#16A36A" : "#D69B28"
  };
}

(async () => {
  try {
    const result = await main();
    $done(result);
  } catch (e) {
    $done({
      title: "NetSpeed",
      content: "测速失败：\n" + String(e.message || e),
      icon: "exclamationmark.triangle.fill",
      "icon-color": "#EF476F"
    });
  }
})();
