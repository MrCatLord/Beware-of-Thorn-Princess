
const $ = {
  http: {
    get: (options) => new Promise((resolve, reject) => {
      $httpClient.get({
        url: options.url,
        timeout: 30,
        headers: {
          "Cache-Control": "no-cache"
        }
      }, (error, response, body) => {
        if (error) return reject(new Error(String(error)));
        if (!response) return reject(new Error("服务器无响应"));
        resolve({ response, body });
      });
    })
  }
};

const DOWNLOAD_URL = "https://speed.cloudflare.com/__down";
const PING_URL = "http://cp.cloudflare.com/generate_204";

const DOWNLOAD_MB = 4;
const DOWNLOAD_COUNT = 3;
const PING_COUNT = 5;

function median(arr) {
  const sorted = arr.slice().sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)];
}

async function downloadTest() {
  let totalBytes = 0;
  let totalTime = 0;

  for (let i = 0; i < DOWNLOAD_COUNT; i++) {
    const bytes = DOWNLOAD_MB * 1024 * 1024;
    const start = Date.now();

    const result = await $.http.get({
      url: DOWNLOAD_URL + "?bytes=" + bytes +
        "&test=" + Date.now()
    });

    const elapsed = (Date.now() - start) / 1000;

    if (result.response.statusCode !== 200) {
      throw new Error(
        "Cloudflare 下载 HTTP " + result.response.statusCode
      );
    }

    if (!result.body || result.body.length === 0) {
      throw new Error("Cloudflare 下载数据为空");
    }

    totalBytes += result.body.length;
    totalTime += elapsed;
  }

  return {
    speed: totalBytes * 8 / totalTime / 1000000,
    bytes: totalBytes,
    elapsed: totalTime
  };
}

async function latencyTest() {
  async function once() {
    const start = Date.now();

    const result = await $.http.get({
      url: PING_URL + "?t=" + Date.now()
    });

    const elapsed = Date.now() - start;

    if (result.response.statusCode !== 204) {
      throw new Error(
        "Cloudflare 延迟 HTTP " + result.response.statusCode
      );
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

(async () => {
  try {
    const totalStart = Date.now();

    const ping = await latencyTest();
    const download = await downloadTest();

    const totalElapsed = (Date.now() - totalStart) / 1000;

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
        "测试耗时：" + totalElapsed.toFixed(1) + " 秒",
      icon: icon,
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
