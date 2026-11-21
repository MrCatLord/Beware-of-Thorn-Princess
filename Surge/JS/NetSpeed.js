/**
 * Surge Panel 节点测速脚本（非 Cloudflare 测速源）
 * 规则：
 * - 图标：< 200Mbps 乌龟 (tortoise) | 200-400Mbps 兔子 (hare) | > 400Mbps 闪电 (bolt.fill)
 * - 颜色：< 100ms 绿色 (#34C759) | >= 100ms 黄色 (#FFCC00)
 */

const DEFAULT_PING_URL = "http://captive.apple.com/generate_204";
const DEFAULT_SPEED_URL = "https://testfile.to/5MB.bin";
const DEFAULT_FALLBACK_BYTES = 5242880; // 5MB

const args = parseArgs(typeof $argument !== "undefined" ? $argument : "");
const pingUrl = args.ping_url || DEFAULT_PING_URL;
const speedUrl = args.url || DEFAULT_SPEED_URL;
const fallbackBytes = Math.max(parseInt(args.bytes, 10) || DEFAULT_FALLBACK_BYTES, 65536);
const concurrency = Math.min(Math.max(parseInt(args.concurrency, 10) || 2, 1), 6);
const panelTitle = args.title || "Net Speed";

!(async () => {
  try {
    // 1. 测量网络延迟 (ms)
    const latency = await measureLatency(pingUrl);

    // 2. 测量下行速率（支持并发拉取直链，规避单次包体超限）
    const { mbps, mbs, durationSec } = await measureDownloadSpeed(
      speedUrl,
      fallbackBytes,
      concurrency
    );

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
 * 测量单次 HTTP 延迟 (ms)
 */
function measureLatency(url) {
  return new Promise((resolve, reject) => {
    const startTime = Date.now();
    $httpClient.get({ url: withCacheBust(url), timeout: 5 }, (error) => {
      if (error) {
        reject(`延迟测试失败 (${error})`);
        return;
      }
      resolve(Math.max(Date.now() - startTime, 1));
    });
  });
}

/**
 * 测量下行下载速率
 */
async function measureDownloadSpeed(baseUrl, expectedBytes, concurrency) {
  const startTime = Date.now();

  const tasks = Array.from({ length: concurrency }, () => {
    return new Promise((resolve, reject) => {
      $httpClient.get(
        {
          url: withCacheBust(baseUrl),
          timeout: 15,
          "binary-mode": true
        },
        (error, response, data) => {
          if (error) {
            reject(`下载失败 (${error})`);
            return;
          }
          let bytes = expectedBytes;
          if (data && typeof data.byteLength === "number") {
            bytes = data.byteLength;
          } else if (typeof data === "string") {
            bytes = data.length;
          }
          resolve(bytes);
        }
      );
    });
  });

  const results = await Promise.all(tasks);
  const totalBytes = results.reduce((sum, n) => sum + n, 0);
  const durationSec = Math.max((Date.now() - startTime) / 1000, 0.01);

  const mbs = totalBytes / (1024 * 1024) / durationSec;
  const mbps = ((totalBytes * 8) / (1000 * 1000)) / durationSec;

  return { mbps, mbs, durationSec };
}

/**
 * 追加防缓存查询参数
 */
function withCacheBust(rawUrl) {
  const sep = rawUrl.includes("?") ? "&" : "?";
  const nonce = `${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  return `${rawUrl}${sep}_t=${nonce}`;
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
