
const APPLE_URL = "https://mensura.cdn-apple.com/api/v1/gm/large";
const PING_URL = "http://www.gstatic.com/generate_204";

const CONCURRENCY = 4;
const CHUNK_SIZE = 4 * 1024 * 1024;
const TEST_DURATION = 10000;

function request(url, headers = {}) {
  return new Promise((resolve, reject) => {
    $httpClient.get({
      url,
      timeout: 20,
      headers
    }, (error, response, body) => {
      if (error) {
        reject(new Error(String(error)));
        return;
      }
      if (!response) {
        reject(new Error("服务器无响应"));
        return;
      }
      resolve({ response, body: body || "" });
    });
  });
}

async function pingOnce() {
  const start = Date.now();
  const result = await request(PING_URL, {
    "Cache-Control": "no-cache"
  });

  const status = result.response.statusCode;
  if (status !== 204) {
    throw new Error("延迟测试 HTTP 状态码：" + status);
  }
  return Date.now() - start;
}

async function latencyTest() {
  await pingOnce();
  const samples = [];

  for (let i = 0; i < 8; i++) {
    samples.push(await pingOnce());
  }

  samples.sort((a, b) => a - b);
  return (samples[3] + samples[4]) / 2;
}

async function downloadTest() {
  let offset = 0;
  let totalBytes = 0;
  let errorMessage = "";
  const start = Date.now();
  const deadline = start + TEST_DURATION;

  async function worker() {
    while (Date.now() < deadline && !errorMessage) {
      const current = offset;
      offset += CHUNK_SIZE;

      try {
        const result = await request(APPLE_URL, {
          "Range": "bytes=" + current + "-" +
            (current + CHUNK_SIZE - 1),
          "Accept-Encoding": "identity",
          "Cache-Control": "no-cache"
        });

        const status = result.response.statusCode;

        if (status !== 206) {
          errorMessage = "Apple CDN HTTP " + status +
            "，未返回预期的 206 分段数据";
          break;
        }

        const size = result.body.length;
        if (size > 0) {
          totalBytes += size;
        } else {
          errorMessage = "Apple CDN 返回了空数据";
          break;
        }
      } catch (e) {
        errorMessage = String(e.message || e);
        break;
      }
    }
  }

  await Promise.all(
    Array.from({ length: CONCURRENCY }, () => worker())
  );

  const elapsed = (Date.now() - start) / 1000;

  if (errorMessage) {
    throw new Error(errorMessage);
  }

  if (!totalBytes) {
    throw new Error("下载数据为 0，请检查 Apple CDN 分段请求");
  }

  return {
    speed: totalBytes * 8 / elapsed / 1000000,
    elapsed
  };
}

(async () => {
  try {
    const ping = await latencyTest();
    const download = await downloadTest();

    let icon = "tortoise";
    if (download.speed >= 300) {
      icon = "bolt";
    } else if (download.speed >= 100) {
      icon = "hare";
    }

    $done({
      title: "NetSpeed",
      content:
        "下行速率：" + download.speed.toFixed(2) + " Mbps\n" +
        "网络延迟：" + (ping < 100 ? "🟢" : "🟡") +
        " " + ping + " ms\n" +
        "测试耗时：" + download.elapsed.toFixed(1) + " 秒",
      icon,
      "icon-color": ping < 100 ? "#16A36A" : "#D69B28"
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