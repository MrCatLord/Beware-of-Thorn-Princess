/**
 * Surge Panel 节点测速脚本
 * 规则：
 * - 图标：< 200Mbps 乌龟 (tortoise) | 200-400Mbps 兔子 (hare) | > 400Mbps 闪电 (bolt.fill)
 * - 颜色：< 100ms 绿色 (#34C759) | >= 100ms 黄色 (#FFCC00)
 * - 规避单次响应体超限：默认单次 2MB (2097152 bytes)，支持多轮累加 (rounds)
 */

const DEFAULT_BYTES = 2097152; // 单次下载 2MB，避免触发 Surge $httpClient 响应体大小限制
const DEFAULT_ROUNDS = 3; // 默认连续测速 3 轮（共约 6MB）
const PING_URL = "https://cp.cloudflare.com/generate_204";

const args = parseArgs(typeof $argument !== "undefined" ? $argument : "");
const chunkBytes = Math.max(parseInt(args.bytes, 10) || DEFAULT_BYTES, 65536);
const rounds = Math.min(Math.max(parseInt(args.rounds, 10) || DEFAULT_ROUNDS, 1), 10);
const panelTitle = args.title || "Net Speed";
const baseUrl = args.url || "";

!(async () => {
  try {
    // 1. 测量网络延迟 (ms)
    const latency = await measureLatency(PING_URL);

    // 2. 多轮下行速率测试（规避单次大包被 Surge 中止）
    let totalBytes = 0;
    let totalMs = 0;

    for (let i = 0; i < rounds; i++) {
      const targetUrl = buildSpeedUrl(baseUrl, chunkBytes, i);
      const { bytes, elapsedMs } = await downloadOnce(targetUrl, chunkBytes);
      totalBytes += bytes;
      totalMs += elapsedMs;
    }

    const durationSec = Math.max(totalMs / 1000, 0.01);
    const mbs = totalBytes / (1024 * 1024) / durationSec;
    const mbps = ((totalBytes * 8) / (1000 * 1000)) / durationSec;

    // 3. 速率图标映射
    let iconName = "tortoise"; // < 200 Mbps
    if (mbps > 400) {
      iconName = "bolt.fill"; // > 400 Mbps
    } else if (mbps >= 200) {
      iconName = "hare"; // 200 - 400 Mbps
    }

    // 4. 延迟颜色映射 (< 100ms 绿，>= 100ms 黄)
    const iconColor = latency < 100 ? "#34C759" : "#FFCC00";

    // 5. 格式化执行时间 (HH:mm:ss)
    const execTime = formatTime(new Date());

    // 6. 面板内容（还原截图布局）
    const content = [
      `下行速率: ${mbps.toFixed(0)} Mbps [${mbs.toFixed(1)} MB/s]`,
      `测试耗时: ${durationSec.toFixed(2)}s`,
      `网络延迟: ${latency} ms`,
      `执行时间: ${execTime}`
    ].join("\n");

    $done({
      title: panelTitle,
      content: content,
      icon: iconName,
      "icon-color": iconColor
    });
  } catch (err) {
    const errMsg = err && err.message ? err.message : String(err || "未知错误");
    $done({
      title: panelTitle,
      content: `测速失败: ${errMsg}\n执行时间: ${formatTime(new Date())}`,
      icon: "exclamationmark.triangle.fill",
      "icon-color": "#FF3B30"
    });
  }
})();

/**
 * 构造测速 URL，附带防缓存参数
 */
function buildSpeedUrl(customUrl, bytes, index) {
  if (customUrl) {
    const sep = customUrl.includes("?") ? "&" : "?";
    return `${customUrl}${sep}_r=${index}&_t=${Date.now()}`;
  }
  return `https://speed.cloudflare.com/__down?bytes=${bytes}&_r=${index}&_t=${Date.now()}`;
}

/**
 * 测量单次 HTTP 延迟 (ms)
 */
function measureLatency(url) {
  return new Promise((resolve, reject) => {
    const startTime = Date.now();
    $httpClient.get({ url: url, timeout: 5 }, (error) => {
      if (error) {
        reject(`延迟测试失败 (${error})`);
        return;
      }
      resolve(Math.max(Date.now() - startTime, 1));
    });
  });
}

/**
 * 单轮下载测速
 */
function downloadOnce(url, expectedBytes) {
  return new Promise((resolve, reject) => {
    const startTime = Date.now();
    $httpClient.get({ url: url, timeout: 15 }, (error, response, data) => {
      if (error) {
        reject(`下载失败 (${error})`);
        return;
      }
      const elapsedMs = Math.max(Date.now() - startTime, 1);
      let bytes = expectedBytes;
      if (data) {
        if (typeof data === "string") {
          bytes = data.length;
        } else if (typeof data.byteLength === "number") {
          bytes = data.byteLength;
        }
      }
      resolve({ bytes, elapsedMs });
    });
  });
}

/**
 * 格式化时间为 HH:MM:SS
 */
function formatTime(date) {
  const pad = (n) => (n < 10 ? "0" + n : String(n));
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

/**
 * 解析 Surge $argument 参数
 */
function parseArgs(argStr) {
  const result = {};
  if (!argStr || typeof argStr !== "string") return result;
  argStr.split("&").forEach((item) => {
    const idx = item.indexOf("=");
    if (idx > 0) {
      const key = item.slice(0, idx).trim();
      const val = item.slice(idx + 1).trim();
      if (key) {
        try {
          result[key] = decodeURIComponent(val);
        } catch (_) {
          result[key] = val;
        }
      }
    }
  });
  return result;
}
