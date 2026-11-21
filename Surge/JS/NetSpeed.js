
const URL = "https://mensura.cdn-apple.com/api/v1/gm/large";

$httpClient.get({
  url: URL,
  timeout: 30,
  headers: {
    "Range": "bytes=0-1048575",
    "Accept-Encoding": "identity",
    "Cache-Control": "no-cache"
  }
}, (error, response, body) => {
  if (error) {
    $done({
      title: "Apple CDN诊断",
      content: "请求错误：\n" + String(error),
      icon: "exclamationmark.triangle.fill"
    });
    return;
  }

  if (!response) {
    $done({
      title: "Apple CDN诊断",
      content: "没有收到响应对象",
      icon: "exclamationmark.triangle.fill"
    });
    return;
  }

  const h = response.headers || {};
  const status = response.statusCode || response.status || "未知";
  const bodyType = typeof body;
  const bodyLength = body == null ? 0 :
    (typeof body === "string" ? body.length :
    (body.byteLength || body.length || 0));

  $done({
    title: "Apple CDN诊断",
    content:
      "HTTP状态码：" + status + "\n" +
      "Content-Range：" + (h["Content-Range"] || h["content-range"] || "无") + "\n" +
      "Content-Length：" + (h["Content-Length"] || h["content-length"] || "无") + "\n" +
      "Content-Encoding：" + (h["Content-Encoding"] || h["content-encoding"] || "无") + "\n" +
      "Body类型：" + bodyType + "\n" +
      "Body长度：" + bodyLength,
    icon: "info"
  });
});
