
/**
 * Surge iOS 6 - IP 检测面板
 * IPPure 类型与风险 + 入口/落地 IP 地区运营商
 */

const CONFIG = {
  timeout: 15000,
  pureAPI: "https://my.ippure.com/v1/info",
  ipAPI: "http://ip-api.com/json/",
  infoAPI: "https://ipinfo.io/"
};

function get(url) {
  return new Promise(resolve => {
    $httpClient.get({
      url,
      timeout: CONFIG.timeout,
      headers: { "User-Agent": "Surge IP Check" }
    }, (err, resp, body) => {
      if (err || !resp || resp.status < 200 || resp.status >= 300) {
        resolve(null);
        return;
      }
      resolve(body || null);
    });
  });
}

async function json(url) {
  const body = await get(url);
  if (!body) return null;
  try {
    return JSON.parse(body);
  } catch {
    return null;
  }
}

// IP 地址验证
function validIP(ip) {
  return typeof ip === "string" &&
    (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(ip) ||
     ip.includes(":"));
}

// 获取 IPPure 完整信息
async function getPureInfo() {
  return await json(CONFIG.pureAPI);
}

// 地区及运营商
async function getGeo(ip) {
  if (!ip) return null;

  const [a, b] = await Promise.all([
    json(CONFIG.ipAPI + encodeURIComponent(ip) +
      "?fields=status,country,city,isp,org"),
    json(CONFIG.infoAPI + encodeURIComponent(ip) + "/json")
  ]);

  const validA = a?.status === "success";

  if (!validA && !b) return null;

  return {
    country: validA ? a.country : b?.country || "",
    city: validA ? a.city : b?.city || "",
    isp: validA ? (a.isp || a.org) : b?.org || ""
  };
}

// 获取入口 IP
function getEntranceIP() {
  return new Promise(resolve => {
    $httpAPI("GET", "/v1/requests/recent", null, result => {
      const requests = result?.requests || [];

      const hit = requests.find(item =>
        /my\.ippure\.com\/v1\/info/i.test(item.URL || "") &&
        /\(Proxy\)/.test(item.remoteAddress || "")
      );

      if (!hit) {
        resolve(null);
        return;
      }

      let ip = hit.remoteAddress
        .replace(/\s*\(Proxy\)\s*/, "")
        .trim();

      if (ip.startsWith("[")) {
        ip = ip.replace(/^\[([^\]]+)\](?::\d+)?$/, "$1");
      } else if ((ip.match(/:/g) || []).length === 1) {
        ip = ip.replace(/:\d+$/, "");
      }

      resolve(validIP(ip) ? ip : null);
    });
  });
}

// 风险等级：分数越低越纯净
function riskLevel(score) {
  if (score <= 15) return "极度纯净";
  if (score <= 25) return "纯净";
  if (score <= 40) return "一般";
  if (score <= 50) return "微风险";
  if (score <= 70) return "一般风险";
  return "高风险";
}

// 地理信息显示：只保留国家和城市
function geoText(geo) {
  if (!geo) return "未知";
  return [geo.country, geo.city].filter(Boolean).join(" · ") || "未知";
}

// IP 信息区块
function ipSection(name, ip, geo) {
  return [
    `【${name}】`,
    `IP：${ip || "获取失败"}`,
    `地区：${geoText(geo)}`,
    `运营商：${geo?.isp || "未知"}`
  ].join("\n");
}

// 主程序
(async () => {
  try {
    // IPPure 同时获取落地 IP、类型、原生属性和风险值
    const pure = await getPureInfo();

    const pureIP = validIP(pure?.ip) ? pure.ip : null;

    // IPPure 失败时只回退获取 IP，不伪造类型和纯净度
    let outboundIP = pureIP;

    if (!outboundIP) {
      const fallback = await json("https://api.ipify.org?format=json");
      outboundIP = validIP(fallback?.ip) ? fallback.ip : null;
    }

    if (!outboundIP) {
      $done({
        content: "无法获取落地 IP，请检查网络连接。",
        icon: "bolt.fill",
        "icon-color": "#30D158"
      });
      return;
    }

    // 类型及风险检测
    const type = pureIP && typeof pure.isResidential === "boolean"
      ? (pure.isResidential ? "住宅 IP" : "机房 IP")
      : "检测失败";

    const native = pureIP && typeof pure.isBroadcast === "boolean"
      ? (pure.isBroadcast ? "广播 IP" : "原生 IP")
      : "检测失败";

    const score = pureIP &&
      Number.isFinite(Number(pure.fraudScore)) &&
      pure.fraudScore !== null &&
      pure.fraudScore !== ""
      ? Number(pure.fraudScore)
      : null;

    const purityText = score === null
      ? "检测失败"
      : `风险值 ${score}% · ${riskLevel(score)}`;

    // 并行查询入口和落地地区
    const [entranceIP, outboundGeo] = await Promise.all([
      getEntranceIP(),
      getGeo(outboundIP)
    ]);

    const entranceGeo = entranceIP
      ? await getGeo(entranceIP)
      : null;

    // 面板内容
    const content = [
      "【IP 类型与纯净度】",
      `类型：${type}`,
      `属性：${native}`,
      `纯净度：${purityText}`,
      "",
      ipSection("入口 IP", entranceIP, entranceGeo),
      "",
      ipSection("落地 IP", outboundIP, outboundGeo)
    ].join("\n");

    // 不设置 title，由 [Panel] 自定义名称
    $done({
      content,
      icon: "bolt.fill",
      "icon-color": "#30D158"
    });

  } catch (e) {
    $done({
      content: "检测异常：" + String(e),
      icon: "bolt.fill",
      "icon-color": "#30D158"
    });
  }
})();
