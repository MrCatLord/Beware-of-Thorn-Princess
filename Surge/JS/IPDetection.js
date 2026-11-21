
/**
 * Surge IP 检测面板
 * 功能：
 * 1. IP 类型及纯净度
 * 2. 入口 IP（中转）、地区、运营商
 * 3. 落地 IP、地区、运营商
 * Surge iOS 6
 */

const CONFIG = {
  timeout: 12000,
  ipAPI: "https://api.ipify.org?format=json",
  pureAPI: "https://my.ippure.com/v1/info",
  geoAPI: "http://ip-api.com/json/",
  infoAPI: "https://ipinfo.io/",
};

// HTTP 请求
function request(url, timeout = CONFIG.timeout) {
  return new Promise(resolve => {
    $httpClient.get({
      url,
      timeout,
      headers: {
        "User-Agent": "Surge IP Check"
      }
    }, (error, response, body) => {
      if (error || !response || response.status < 200 ||
          response.status >= 300) {
        resolve(null);
        return;
      }
      resolve(body || null);
    });
  });
}

// JSON 请求
async function getJSON(url) {
  const body = await request(url);
  if (!body) return null;
  try {
    return JSON.parse(body);
  } catch {
    return null;
  }
}

// 获取落地 IP
async function getOutboundIP() {
  const data = await getJSON(CONFIG.ipAPI);
  return data?.ip || null;
}

// 获取 IP 地区
async function getGeo(ip) {
  if (!ip) return null;

  const [geo, info] = await Promise.all([
    getJSON(CONFIG.geoAPI + encodeURIComponent(ip) +
      "?fields=status,country,regionName,city,isp,org,as"),
    getJSON(CONFIG.infoAPI + encodeURIComponent(ip) + "/json")
  ]);

  if (geo?.status !== "success" && !info) return null;

  return {
    country: geo?.country || info?.country || "",
    region: geo?.regionName || "",
    city: geo?.city || "",
    isp: info?.org || geo?.isp || geo?.org || "",
    asn: info?.org || geo?.as || ""
  };
}

// IP 类型与纯净度
async function getIPType(ip) {
  const data = await getJSON(CONFIG.pureAPI);

  if (!data) {
    return {
      type: "未知",
      source: "未知",
      score: null
    };
  }

  // IPPure 检测结果必须与当前落地 IP 一致
  if (data.ip && data.ip !== ip) {
    return {
      type: "未知",
      source: "未知",
      score: null
    };
  }

  const type = data.isResidential === undefined
    ? "未知"
    : data.isResidential ? "住宅 IP" : "机房 IP";

  const source = data.isBroadcast === undefined
    ? "未知"
    : data.isBroadcast ? "广播 IP" : "原生 IP";

  const score = Number.isFinite(Number(data.fraudScore))
    ? Number(data.fraudScore)
    : null;

  return { type, source, score };
}

// 风险等级
function getRisk(score) {
  if (score === null) return "暂无评分";
  if (score <= 15) return "极度纯净";
  if (score <= 25) return "纯净";
  if (score <= 40) return "一般";
  if (score <= 50) return "微风险";
  if (score <= 70) return "一般风险";
  return "高风险";
}

// 获取 Surge 入口 IP
function getEntranceIP() {
  return new Promise(resolve => {
    $httpAPI("GET", "/v1/requests/recent", null, result => {
      const requests = result?.requests || [];

      // 找到本次 IP 查询请求
      const hit = requests.find(item =>
        /api\.ipify\.org/i.test(item.URL || "")
      );

      if (!hit || !hit.remoteAddress ||
          !/\(Proxy\)/.test(hit.remoteAddress)) {
        resolve(null);
        return;
      }

      let address = hit.remoteAddress
        .replace(/\s*\(Proxy\)\s*/, "")
        .trim();

      // 去除端口
      if (address.startsWith("[")) {
        address = address.replace(/^\[([^\]]+)\](?::\d+)?$/, "$1");
      } else if ((address.match(/:/g) || []).length === 1) {
        address = address.replace(/:\d+$/, "");
      }

      resolve(address || null);
    });
  });
}

// 面板输出
function buildSection(title, ip, geo) {
  return [
    `【${title}】`,
    `IP：${ip || "获取失败"}`,
    `地区：${geo
      ? [geo.country, geo.region, geo.city].filter(Boolean).join(" ")
      : "未知"}`,
    `运营商：${geo?.isp || "未知"}`
  ].join("\n");
}

// 主程序
(async () => {
  try {
    // 先获取落地 IP
    const outboundIP = await getOutboundIP();

    if (!outboundIP) {
      $done({
        title: "IP 检测失败",
        content: "无法获取落地 IP，请检查网络或代理连接。"
      });
      return;
    }

    // 并行查询检测数据
    const [typeInfo, outboundGeo, entranceIP] =
      await Promise.all([
        getIPType(outboundIP),
        getGeo(outboundIP),
        getEntranceIP()
      ]);

    // 查询入口 IP 地理信息
    const entranceGeo = entranceIP
      ? await getGeo(entranceIP)
      : null;

    // 纯净度
    const risk = getRisk(typeInfo.score);

    const scoreText = typeInfo.score === null
      ? "暂无评分"
      : `${typeInfo.score}% · ${risk}`;

    const content = [
      "【IP 类型与纯净度】",
      `类型：${typeInfo.type}`,
      `来源：${typeInfo.source}`,
      `纯净度：${scoreText}`,
      "",
      buildSection("入口 IP（中转）", entranceIP, entranceGeo),
      "",
      buildSection("落地 IP（出口）", outboundIP, outboundGeo)
    ].join("\n");

    $done({
      title: "IP 检测",
      content,
      icon: "network",
      "icon-color": typeInfo.score === null
        ? "#9E9E9E"
        : typeInfo.score <= 25
          ? "#30A46C"
          : typeInfo.score <= 50
            ? "#E5A000"
            : "#E5484D"
    });

  } catch (error) {
    $done({
      title: "IP 检测异常",
      content: String(error)
    });
  }
})();
