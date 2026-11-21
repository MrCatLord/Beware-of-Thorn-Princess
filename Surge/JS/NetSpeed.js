

const BASE = "https://speed.cloudflare.com";

const HEADERS = {
  "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Version/18.0 Mobile/15E148 Safari/604.1",
  "Accept": "*/*",
  "Origin": BASE,
  "Referer": BASE + "/",
  "Cache-Control": "no-cache"
};

function request(method, url, body) {
  return new Promise((resolve, reject) => {
    const options = {
      url: url,
      timeout: 45,
      headers: Object.assign({}, HEADERS)
    };

    if (method === "POST") {
      options.body = body;
      options.headers["Content-Type"] = "application/octet-stream";
    }

    const callback = (error, response, data) => {
      if (error) {
        reject(new Error("网络请求失败：" + error + "\n" + url));
        return;
      }

      if (!response) {
        reject(new Error("服务器没有响应\n" + url));
        return;
      }

      const status = response.statusCode || response.status || 0;

      if (status < 200 || status >= 300) {
        reject(new Error(
          "HTTP错误：" + status +
          "\n请求地址：" + url +
          "\n服务器返回：" + String(data || "空").slice(0, 300)
        ));
        return;
      }

      resolve({
        data: data,
        status: status
      });
    };

    if (method === "POST") {
      $httpClient.post(options, callback);
    } else {
      $httpClient.get(options, callback);
    }
  });
}

function formatSpeed(mbps) {
  if (!isFinite(mbps)) return "0 Mbps";
  return mbps.toFixed(2) + " Mbps";
}

function formatMBps(mbps) {
  return (mbps / 8).toFixed(2) + " MB/s";
}

function median(arr) {
  const sorted = arr.slice().sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)];
}

async function main() {
  const startAll = Date.now();
  const latencies = [];
  const downloadSpeeds = [];
  const uploadSpeeds = [];

  // 1. 延迟测试
  for (let i = 0; i < 3; i++) {
    const url = BASE + "/__down?bytes=1000&cache=" + Date.now() + "_" + i;
    const start = Date.now();
    await request("GET", url);
    latencies.push(Date.now() - start);
  }

  const ping = median(latencies);

  const jitterValues = [];
  for (let i = 1; i < latencies.length; i++) {
    jitterValues.push(Math.abs(latencies[i] - latencies[i - 1]));
  }

  const jitter = jitterValues.length
    ? jitterValues.reduce((a, b) => a + b, 0) / jitterValues.length
    : 0;

  // 2. 下载测试：3 次，每次 1 MB
  for (let i = 0; i < 3; i++) {
    const bytes = 1024 * 1024;
    const url = BASE + "/__down?bytes=" + bytes + "&cache=" + Date.now() + "_" + i;

    const start = Date.now();
    await request("GET", url);
    const elapsed = Math.max((Date.now() - start) / 1000, 0.001);

    downloadSpeeds.push((bytes * 8) / elapsed / 1000000);
  }

  const download = downloadSpeeds.reduce((a, b) => a + b, 0) / downloadSpeeds.length;

  // 3. 上传测试：2 次，每次 256 KB
  const uploadBytes = 256 * 1024;
  const payload = "0123456789abcdef".repeat(uploadBytes / 16);

  for (let i = 0; i < 2; i++) {
    const url = BASE + "/__up?cache=" + Date.now() + "_" + i;

    const start = Date.now();
    await request("POST", url, payload);
    const elapsed = Math.max((Date.now() - start) / 1000, 0.001);

    uploadSpeeds.push((uploadBytes * 8) / elapsed / 1000000);
  }

  const upload = uploadSpeeds.reduce((a, b) => a + b, 0) / uploadSpeeds.length;

  const duration = ((Date.now() - startAll) / 1000).toFixed(1);

  let icon = "bolt";
  if (download < 80) icon = "tortoise";
  else if (download < 120) icon = "hare";

  let color = "#06D6A0";
  if (ping >= 300) color = "#EF476F";
  else if (ping >= 150) color = "#FFD166";

  return {
    title: "NetSpeed",
    content:
      "下载：" + formatSpeed(download) + "（" + formatMBps(download) + "）\n" +
      "上传：" + formatSpeed(upload) + "（" + formatMBps(upload) + "）\n" +
      "延迟：" + ping + " ms\n" +
      "抖动：" + jitter.toFixed(1) + " ms\n" +
      "下载样本：" + downloadSpeeds.map(x => x.toFixed(1)).join(" / ") + " Mbps\n" +
      "上传样本：" + uploadSpeeds.map(x => x.toFixed(1)).join(" / ") + " Mbps\n" +
      "耗时：" + duration + " 秒",
    icon: icon,
    "icon-color": color
  };
}

(async () => {
  try {
    const result = await main();
    $done(result);
  } catch (e) {
    $done({
      title: "NetSpeed",
      content: "测速失败：\n" + String(e),
      icon: "exclamationmark.triangle.fill",
      "icon-color": "#EF476F"
    });
  }
})();
