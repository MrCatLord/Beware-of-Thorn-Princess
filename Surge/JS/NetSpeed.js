/**
 * Surge Panel 节点测速脚本
 * 规则：
 * - 图标：< 200Mbps 乌龟 (tortoise) | 200-400Mbps 兔子 (hare) | > 400Mbps 闪电 (bolt.fill)
 * - 颜色：< 100ms 绿色 | >= 100ms 黄色
 */

const DEFAULT_BYTES = 10485760; // 默认下载 10MB (10 * 1024 * 1024)，适合高速节点测速
const TEST_URL = `https://speed.cloudflare.com/__down?bytes=${DEFAULT_BYTES}`;
const PING_URL = "https://cp.cloudflare.com/generate_204";

// 解析外部传入参数 (例如: bytes=20971520&title=节点测速)
const args = parseArgs(typeof $argument !== "undefined" ? $argument : "");
const testBytes = parseInt(args.bytes) || DEFAULT_BYTES;
const panelTitle = args.title || "Net Speed";
const downloadUrl = args.url || `https://speed.cloudflare.com/__down?bytes=${testBytes}`;

!(async () => {
  try {
    // 1. 测试网络延迟 (HTTP 204 握手耗时)
    const latency = await measureLatency(PING_URL);

    // 2. 测试下行速率
    const { mbps, mbs, durationSec } = await measureDownloadSpeed(downloadUrl, testBytes);

    // 3. 根据速率决定 SF Symbols 图标
    let iconName = "tortoise"; // < 200 Mbps
    if (mbps > 400) {
      iconName = "bolt.fill"; // > 400 Mbps
    } else if (mbps >= 200) {
      iconName = "hare"; // 200 - 400 Mbps
    }

    // 4. 根据延迟决定图标颜色 (Apple 系统标准绿/黄)
    const iconColor = latency < 100 ? "#34C759" : "#FFCC00";

    // 5. 格式化当前执行时间 (HH:mm:ss)
    const execTime = formatTime(new Date());

    // 6. 组装完全还原截图样式的面板内容
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
    $done({
      title: panelTitle,
      content: `测速失败: ${err}\n执行时间: ${formatTime(new Date())}`,
      icon: "exclamationmark.triangle.fill",
      "icon-color": "#FF3B30"
    });
  }
})();

/**
 * 测量单次 HTTP 延迟 (ms)
 */
function measureLatency(url) {
  return new Promise((resolve, reject) => {
    const startTime = Date.now();
    $httpClient.head({ url: url, timeout: 5 }, (error, response) => {
      if (error) {
        reject("连接超时或节点不可用");
        return;
      }
      const latency = Date.now() - startTime;
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
        reject("下载测速超时");
        return;
      }
      const durationMs = Date.now() - startTime;
      const durationSec = Math.max(durationMs / 1000, 0.01); // 防止除以 0

      // 优先使用实际接收的数据长度，若框架未暴露则回退到预设字节数
      const actualBytes = (data && data.length) ? data.length : expectedBytes;

      const mbs = (actualBytes / (1024 * 1024)) / durationSec; // MB/s
      const mbps = (actualBytes * 8 / (1000 * 1000)) / durationSec; // Mbps (网络带宽标准采用 1000 进制)

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
