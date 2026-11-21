/**
 * 并发分片下载测速（规避单次包超限 + 提升高带宽跑分准确度）
 * @param {string} baseUrl 测速基础地址（若为空则使用 Cloudflare __down）
 * @param {number} chunkBytes 单片字节数（建议 1048576 = 1MB）
 * @param {number} concurrency 并发路数（建议 4）
 */
async function measureConcurrentSpeed(baseUrl, chunkBytes = 1048576, concurrency = 4) {
  const startTime = Date.now();

  const tasks = Array.from({ length: concurrency }, (_, idx) => {
    const url = buildChunkUrl(baseUrl, chunkBytes, idx);
    return new Promise((resolve, reject) => {
      $httpClient.get(
        {
          url: url,
          timeout: 15,
          "binary-mode": true
        },
        (error, response, data) => {
          if (error) {
            reject(`并发下载失败 (${error})`);
            return;
          }
          let bytes = chunkBytes;
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

  return { mbps, mbs, durationSec, totalBytes };
}

function buildChunkUrl(customUrl, bytes, index) {
  const stamp = `${Date.now()}_${index}_${Math.random().toString(36).slice(2, 7)}`;
  if (customUrl) {
    const sep = customUrl.includes("?") ? "&" : "?";
    return `${customUrl}${sep}bytes=${bytes}&_t=${stamp}`;
  }
  return `https://speed.cloudflare.com/__down?bytes=${bytes}&_t=${stamp}`;
}
