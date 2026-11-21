/**
 * Surge Panel 节点测速脚本 (修复延迟检测兼容性与错误提示)
 * 规则：
 * - 图标：< 200Mbps 乌龟 (tortoise) | 200-400Mbps 兔子 (hare) | > 400Mbps 闪电 (bolt.fill)
 * - 颜色：< 100ms 绿色 | >= 100ms 黄色
 */

const DEFAULT_BYTES = 10485760; // 默认下载 10MB (10 * 1024 * 1024)
const PING_URL = "https://cp.cloudflare.com/generate_204";

const args = parseArgs(typeof $argument !== "undefined" ? $argument : "");
const testBytes = parseInt(args.bytes) || DEFAULT_BYTES;
const panelTitle = args.title || "Net Speed";
const downloadUrl = args.url || `https://speed.cloudflare.com/__down?bytes=${testBytes}`;

!(async () => {
  try {
    // 1. 测量网络延迟
    const latency = await measureLatency(PING_URL);

    // 2. 测量下行速率
    const { mbps, mbs, durationSec } = await measureDownloadSpeed(downloadUrl, testBytes);

    // 3. 速率图标映射
    let iconName = "tortoise"; // < 200 Mbps
    if (mbps > 400) {
      iconName = "bolt.fill"; // > 400 Mbps
    } else if (mbps >= 200) {
      iconName = "hare"; // 200 - 400 Mbps
    }

    // 4. 延迟颜色映射
    const iconColor = latency < 100 ? "#34C759" : "#FFCC00";

    // 5. 执行时间
    const execTime = formatTime(new Date());

    // 6. 面板内容
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
 * 测量 HTTP 延迟 (ms) - 使用 GET 请求兼容性更好
 */
function measureLatency(url) {
  return new Promise((resolve, reject) => {
    const startTime = Date.now();
    $httpClient.get({ url: url, timeout: 5 }, (error, response) => {
      if (error) {
        reject(`延迟测试失败 (${error})`);
        return;
      }
      const latency = Math.max(Date.now() - startTime, 1);
      resolve(latency);
    });
  });
}

/**
 * 测量下行下载速率
 */
function measureDownloadSpeed(url, expectedBytes) {
  return new Promise((resolve, reject) => {
    const startTime = Date.now();
    $httpClient.get({ url: url, timeout: 15 }, (error, response, data) => {
      if (error) {
        reject(`下载测试失败 (${error})`);
        return;
      }
      const durationMs = Date.now() - startTime;
      const durationSec = Math.max(durationMs / 1000, 0.01);

      let actualBytes = expectedBytes;
      if (data) {
        if (typeof data === "string") {
          actualBytes = data.length;
        } else if (data.byteLength) {
          actualBytes = data.byteLength;
        }
      }

      const mbs = actualBytes / (1024 * 1024) / durationSec;
      const mbps = ((actualBytes * 8) / (1000 * 1000)) / durationSec;

      resolve({ mbps, mbs, durationSec });
    });
  });
}

/**
 * 格式化时间为 HH:MM:SS
 */
function formatTime(date) {
  const pad = (n) => (n < 10 ? "0" + n : n);
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

/**
 * 解析 Surge argument 字符串
 */
function parseArgs(argStr) {
  const result = {};
  if (!argStr) return result;
  argStr.split("&").forEach((item) => {
    const [key, val] = item.split("=");
    if (key) result[key.trim()] = decodeURIComponent((val || "").trim());
  });
  return result;
}
