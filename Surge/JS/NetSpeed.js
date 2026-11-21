
/**
 * NetSpeed for Surge
 * Cloudflare Speed Test compatible implementation
 * Download / Upload / Latency / Jitter
 */

const BASE = "https://speed.cloudflare.com";
const MB = 1024 * 1024;

let args = {};

if (typeof $argument !== "undefined" && $argument) {
  $argument.split("&").forEach(item => {
    const i = item.indexOf("=");
    if (i < 0) return;

    const key = item.slice(0, i);
    const value = item.slice(i + 1);

    try {
      args[decodeURIComponent(key)] =
        decodeURIComponent(value);
    } catch (_) {
      args[key] = value;
    }
  });
}

const title = args.title || "NetSpeed";

function round(n, p = 2) {
  const m = Math.pow(10, p);
  return Math.round(n * m) / m;
}

function median(arr) {
  const sorted = [...arr].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);

  return sorted.length % 2
    ? sorted[mid]
    : (sorted[mid - 1] + sorted[mid]) / 2;
}

function httpRequest(method, url, body) {
  return new Promise((resolve, reject) => {
    const options = {
      url,
      timeout: 60,
      headers: {
        "Cache-Control": "no-cache"
      }
    };

    if (method === "POST") {
      options.body = body;
      options.headers["Content-Type"] =
        "application/octet-stream";
    }

    const callback = (error, response, data) => {
      if (error) {
        reject(new Error(String(error)));
        return;
      }

      if (!response) {
        reject(new Error("服务器没有返回响应"));
        return;
      }

      const status =
        response.statusCode || response.status || 0;

      if (status < 200 || status >= 300) {
        reject(new Error("HTTP错误：" + status));
        return;
      }

      resolve({
        response,
        data
      });
    };

    if (method === "POST") {
      $httpClient.post(options, callback);
    } else {
      $httpClient.get(options, callback);
    }
  });
}

// 延迟测试
async function testPing() {
  const samples = [];

  for (let i = 0; i < 5; i++) {
    const url =
      BASE + "/__down?bytes=0&measId=" +
      Date.now() + "-" + i;

    const start = Date.now();

    await httpRequest("GET", url);

    samples.push(Date.now() - start);
  }

  const ping = median(samples);

  let jitterTotal = 0;

  for (let i = 1; i < samples.length; i++) {
    jitterTotal += Math.abs(
      samples[i] - samples[i - 1]
    );
  }

  return {
    ping,
    jitter: jitterTotal / (samples.length - 1),
    samples
  };
}

// 下载测试
async function testDownload() {
  const sizes = [16, 24, 32];

  let totalBytes = 0;
  let totalTime = 0;
  const samples = [];

  for (let i = 0; i < sizes.length; i++) {
    const bytes = sizes[i] * MB;

    const url =
      BASE + "/__down?bytes=" + bytes +
      "&measId=" + Date.now() + "-" + i;

    const start = Date.now();

    let result = await httpRequest("GET", url);

    const duration = (Date.now() - start) / 1000;

    if (duration <= 0) {
      throw new Error("下载计时异常");
    }

    totalBytes += bytes;
    totalTime += duration;

    samples.push(
      round(bytes * 8 / duration / 1000000)
    );

    // 释放响应数据
    result.data = null;
    result = null;
  }

  return {
    speed: totalBytes * 8 / totalTime / 1000000,
    samples
  };
}

// 上传测试
async function testUpload() {
  const sizes = [16, 32];

  let totalBytes = 0;
  let totalTime = 0;
  const samples = [];

  // ASCII数据，避免UTF-8多字节长度误差
  const pattern = "0123456789abcdef".repeat(65536);

  for (let i = 0; i < sizes.length; i++) {
    const bytes = sizes[i] * MB;

    const payload = pattern.repeat(
      Math.ceil(bytes / pattern.length)
    ).slice(0, bytes);

    const url =
      BASE + "/__up?measId=" +
      Date.now() + "-" + i;

    const start = Date.now();

    let result = await httpRequest(
      "POST",
      url,
      payload
    );

    const duration = (Date.now() - start) / 1000;

    if (duration <= 0) {
      throw new Error("上传计时异常");
    }

    totalBytes += bytes;
    totalTime += duration;

    samples.push(
      round(bytes * 8 / duration / 1000000)
    );

    result.data = null;
    result = null;
  }

  return {
    speed: totalBytes * 8 / totalTime / 1000000,
    samples
  };
}

// 图标设置
function getIcon(speed) {
  if (speed < 80) {
    return args.iconslow || "tortoise";
  }

  if (speed < 120) {
    return args.iconmid || "hare";
  }

  return args.iconfast || "bolt";
}

// 颜色设置
function getColor(ping) {
  if (ping < 150) {
    return args.colorlow || "#06D6A0";
  }

  if (ping < 300) {
    return args.colormid || "#FFD166";
  }

  return args.colorhigh || "#EF476F";
}

// 主程序
(async () => {
  const startTime = Date.now();

  let down;
  let up;
  let latency;

  try {
    // 1. 延迟
    latency = await testPing();

    // 2. 下载
    down = await testDownload();

    // 3. 上传
    up = await testUpload();

    const download = round(down.speed);
    const upload = round(up.speed);

    const ping = round(latency.ping, 1);
    const jitter = round(latency.jitter, 1);

    const elapsed = round(
      (Date.now() - startTime) / 1000,
      1
    );

    const icon = getIcon(download);
    const color = getColor(ping);

    const content =
      "↓ 下载速度：" + download +
      " Mbps [" + round(download / 8) + " MB/s]\n" +

      "↑ 上传速度：" + upload +
      " Mbps [" + round(upload / 8) + " MB/s]\n" +

      "网络延迟：" + ping + " ms\n" +

      "网络抖动：" + jitter + " ms\n" +

      "下载样本：" + down.samples.join(" / ") +
      " Mbps\n" +

      "上传样本：" + up.samples.join(" / ") +
      " Mbps\n" +

      "测速耗时：" + elapsed + " s\n" +

      "执行时间：" +
      new Date().toTimeString().split(" ")[0];

    console.log(content);

    $done({
      title,
      content,
      icon,
      "icon-color": color
    });

  } catch (e) {
    console.log("NetSpeed Error:", e);

    $done({
      title: "❌ " + title,
      content:
        "测速失败：" +
        (e.message || String(e)),
      icon: "xmark",
      "icon-color": "#EF476F"
    });
  }
})();
