
const DOWNLOAD_URL = "https://mensura.cdn-apple.com/api/v1/gm/large";
const PING_URL = "http://www.gstatic.com/generate_204";

const MB = 4 * 1024 * 1024;
const PING_COUNT = 5;
const DOWNLOAD_COUNT = 3;

function httpGet(url, headers = {}) {
  return new Promise((resolve, reject) => {
    $httpClient.get({
      url: url,
      timeout: 30,
      headers: headers
    }, (error, response, body) => {
      if (error) {
        reject(new Error(String(error)));
        return;
      }

      if (!response) {
        reject(new Error("服务器无响应"));
        return;
      }

      resolve({
        response: response,
        body: body
      });
    });
  });
}

function median(arr) {
  const sorted = arr.slice().sort((a, b) => a - b);
  const n = sorted.length;

  if (n % 2 === 1) return sorted[(n - 1) / 2];

  return (sorted[n / 2 - 1] + sorted[n / 2]) / 2;
}

// Google HTTP 延迟
async function testPing() {
  async function once() {
    const start = Date.now();

    const result = await httpGet(PING_URL, {
      "Cache-Control": "no-cache"
    });

    const elapsed = Date.now() - start;
    const status = result.response.statusCode ||
                   result.response.status;

    if (status !== 204) {
      throw new Error("Google 延迟 HTTP " + status);
    }

    return elapsed;
  }

  await once();

  const samples = [];

  for (let i = 0; i < PING_COUNT; i++) {
    samples.push(await once());
  }

  return median(samples);
}

// Apple CDN 下载测速
async function testDownload() {
  const speeds = [];
  let totalBytes = 0;

  for (let i = 0; i < DOWNLOAD_COUNT; i++) {
    const startOffset = i * MB;
    const endOffset = startOffset + MB - 1;

    const start = Date.now();

    const result = await httpGet(DOWNLOAD_URL, {
      "Range": "bytes=" + startOffset + "-" + endOffset,
      "Accept-Encoding": "identity",
      "Cache-Control": "no-cache"
    });

    const elapsed = (Date.now() - start) / 1000;
    const status = result.response.statusCode ||
                   result.response.status;

    if (status !== 206) {
      throw new Error("Apple CDN HTTP " + status);
    }

    if (typeof result.body !== "string") {
      throw new Error("Apple CDN 返回的数据类型异常");
    }

    const bytes = result.body.length;

    if (bytes !== MB) {
      throw new Error(
        "Apple CDN 数据长度异常：" + bytes +
        "，预期：" + MB
      );
    }

    if (elapsed <= 0) {
      throw new Error("测速时间异常");
    }

    totalBytes += bytes;

    speeds.push(bytes * 8 / elapsed / 1000000);
  }

  return {
    speed: median(speeds),
    bytes: totalBytes
  };
}

(async () => {
  try {
    const totalStart = Date.now();

    const ping = await testPing();
    const download = await testDownload();

    const totalTime = (Date.now() - totalStart) / 1000;

    let icon = "tortoise";

    if (download.speed >= 300) {
      icon = "bolt";
    } else if (download.speed >= 100) {
      icon = "hare";
    }

    const latencyColor =
      ping < 100 ? "#16A36A" : "#D69B28";

    $done({
      title: "NetSpeed",
      content:
        "下行速率：" + download.speed.toFixed(2) + " Mbps\n" +
        "网络延迟：" +
        (ping < 100 ? "🟢" : "🟡") +
        " " + ping.toFixed(0) + " ms\n" +
        "测试耗时：" + totalTime.toFixed(1) + " 秒",
      icon: icon,
      "icon-color": latencyColor
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
