
/**
 * Surge iOS 6 - IP Detection
 * IP 类型 / 纯净度 / 入口 IP / 落地 IP
 *
 * 优化：
 * 1. IPPure、Cloudflare、IP.SB 交叉确认落地 IP
 * 2. IPPure + ProxyCheck + Scamalytics 多源风险检测
 * 3. 所有评分必须对应同一个落地 IP
 * 4. 多源评分避免单一来源误判
 * 5. 住宅、机房、原生、广播分别判断
 * 6. 入口 IP 优先从 Surge 最近请求中提取
 * 7. 国家 + 城市，不显示省份
 */


/************************************************************
 * Surge iOS 6 - IP 信息检测 Panel
 *
 * 功能：
 * 1. 多源交叉验证出口 IP
 * 2. IPPure / ProxyCheck / Scamalytics 纯净度检测
 * 3. IP 类型、原生/广播属性识别
 * 4. 入口 IP、国家城市、运营商信息
 * 5. 支持自定义标题、图标、正常颜色
 * 6. 异常状态固定红色
 *
 * Surge 模块参数：
 * panel_title=IP信息
 * panel_icon=bolt.fill
 * panel_color=#30D158
 ************************************************************/


// ==================== 基础配置 ====================

const CFG = {
  timeout: 7000,
  totalTimeout: 25000,

  defaultTitle: "IP信息",
  icon: "bolt.fill",
  iconColor: "#30D158",
  errorColor: "#FF3B30",

  ippure: "https://my.ippure.com/v1/info",
  cfTrace: "https://1.1.1.1/cdn-cgi/trace",
  ipSB: "https://api-ipv4.ip.sb/geoip",

  proxyCheck: "https://proxycheck.io/v2/",
  scamalytics: "https://scamalytics.com/ip/",

  geoAPI: "https://ip-api.com/json/"
};


// ==================== 参数读取 ====================

function parseArguments(str) {
  const result = {};

  if (!str) return result;

  str.split("&").forEach(item => {
    const index = item.indexOf("=");

    if (index < 0) return;

    const key = item.slice(0, index);
    const value = item.slice(index + 1);

    try {
      result[decodeURIComponent(key)] =
        decodeURIComponent(value.replace(/\+/g, "%20"));
    } catch (_) {
      result[key] = value;
    }
  });

  return result;
}

const args = parseArguments($argument || "");

const PANEL_TITLE =
  args.panel_title || CFG.defaultTitle;

CFG.icon =
  args.panel_icon || CFG.icon;

CFG.iconColor =
  args.panel_color || CFG.iconColor;


// ==================== 通用工具 ====================

function isIPv4(ip) {
  if (!ip || typeof ip !== "string") return false;

  const parts = ip.trim().split(".");

  if (parts.length !== 4) return false;

  return parts.every(part => {
    if (!/^\d+$/.test(part)) return false;

    const n = Number(part);

    return n >= 0 && n <= 255;
  });
}

function isIPv6(ip) {
  if (!ip || typeof ip !== "string") return false;

  return ip.includes(":") &&
    /^[0-9a-fA-F:]+$/.test(ip) &&
    ip.split(":").length >= 3;
}

function isValidIP(ip) {
  return isIPv4(ip) || isIPv6(ip);
}

function cleanIP(value) {
  if (!value) return "";

  const str = String(value).trim();

  const ipv4Match = str.match(
    /(?:\d{1,3}\.){3}\d{1,3}/
  );

  if (ipv4Match && isIPv4(ipv4Match[0])) {
    return ipv4Match[0];
  }

  const ipv6Match = str.match(
    /(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}/
  );

  if (ipv6Match && isIPv6(ipv6Match[0])) {
    return ipv6Match[0];
  }

  return "";
}

function safeJSON(text) {
  try {
    return JSON.parse(text);
  } catch (_) {
    return null;
  }
}

function getNumber(value) {
  if (value === undefined || value === null || value === "") {
    return null;
  }

  const n = Number(value);

  if (!Number.isFinite(n)) return null;

  return Math.max(0, Math.min(100, n));
}

function firstValidNumber(obj, keys) {
  if (!obj) return null;

  for (const key of keys) {
    const value = getNumber(obj[key]);

    if (value !== null) return value;
  }

  return null;
}

function request(url, timeout) {
  return new Promise(resolve => {
    const options = {
      url: url,
      timeout: timeout || CFG.timeout,
      headers: {
        "User-Agent": "Mozilla/5.0 Surge-IP-Detection"
      }
    };

    $httpClient.get(options, (error, response, data) => {
      if (error || !response) {
        resolve({
          ok: false,
          status: 0,
          body: ""
        });
        return;
      }

      resolve({
        ok: response.statusCode >= 200 &&
            response.statusCode < 400,
        status: response.statusCode,
        body: data || ""
      });
    });
  });
}


// ==================== 出口 IP 多源检测 ====================

async function getCFIP() {
  const res = await request(CFG.cfTrace);

  if (!res.ok) return "";

  const match = res.body.match(/(?:^|\n)ip=([^\r\n]+)/);

  if (!match) return "";

  const ip = cleanIP(match[1]);

  return isValidIP(ip) ? ip : "";
}

async function getSBIP() {
  const res = await request(CFG.ipSB);

  if (!res.ok) return "";

  const data = safeJSON(res.body);

  if (!data) return "";

  const ip = cleanIP(data.ip);

  return isValidIP(ip) ? ip : "";
}

async function getIPPure() {
  const res = await request(CFG.ippure);

  if (!res.ok) return null;

  const data = safeJSON(res.body);

  if (!data || typeof data !== "object") {
    return null;
  }

  const ip = cleanIP(data.ip);

  if (!isValidIP(ip)) return null;

  return data;
}

async function getOutboundIP() {
  const results = await Promise.all([
    getCFIP(),
    getSBIP(),
    getIPPure()
  ]);

  const cfIP = results[0];
  const sbIP = results[1];
  const pureData = results[2];

  const pureIP = pureData ? cleanIP(pureData.ip) : "";

  const sources = [
    cfIP,
    sbIP,
    pureIP
  ].filter(ip => isValidIP(ip));

  if (sources.length === 0) {
    return {
      ip: "",
      pureData: pureData,
      conflict: false,
      sourceCount: 0
    };
  }

  // 统计各 IP 出现次数
  const counts = {};

  sources.forEach(ip => {
    counts[ip] = (counts[ip] || 0) + 1;
  });

  const sorted = Object.keys(counts).sort((a, b) => {
    return counts[b] - counts[a];
  });

  // 至少两个来源一致时，采用多数结果
  if (sorted.length === 1 || counts[sorted[0]] >= 2) {
    return {
      ip: sorted[0],
      pureData: pureData,
      conflict: false,
      sourceCount: sources.length
    };
  }

  // 三个来源都不一致时，按 CF > IP.SB > IPPure 回退
  return {
    ip: cfIP || sbIP || pureIP,
    pureData: pureData,
    conflict: true,
    sourceCount: sources.length
  };
}


// ==================== 纯净度检测 ====================

async function getProxyCheck(ip) {
  if (!ip) return null;

  const url =
    CFG.proxyCheck +
    encodeURIComponent(ip) +
    "?vpn=1&risk=1";

  const res = await request(url);

  if (!res.ok) return null;

  const data = safeJSON(res.body);

  if (!data || data.status !== "ok") {
    return null;
  }

  const item = data[ip];

  if (!item) return null;

  return {
    risk: getNumber(item.risk),
    type: item.type || "",
    proxy: item.proxy || ""
  };
}

async function getScamalytics(ip) {
  if (!ip) return null;

  const res = await request(
    CFG.scamalytics + encodeURIComponent(ip)
  );

  if (!res.ok) return null;

  const html = res.body || "";

  // 优先匹配 Fraud Score
  let match = html.match(
    /Fraud Score[^0-9]{0,80}(\d{1,3})/i
  );

  if (!match) {
    match = html.match(
      /fraud_score[^0-9]{0,80}(\d{1,3})/i
    );
  }

  if (!match) return null;

  return getNumber(match[1]);
}

function getIPPureRisk(data, currentIP) {
  if (!data || !currentIP) return null;

  const dataIP = cleanIP(data.ip);

  // IPPure 返回的 IP 必须与当前出口 IP 一致
  if (!dataIP || dataIP !== currentIP) {
    return null;
  }

  return firstValidNumber(data, [
    "risk",
    "fraudScore",
    "fraud_score",
    "score"
  ]);
}

function calculateRisk(pureData, proxyData, scamRisk, currentIP) {
  const pureRisk = getIPPureRisk(pureData, currentIP);

  // 显示优先级：IPPure > ProxyCheck > Scamalytics
  if (pureRisk !== null) {
    return {
      score: pureRisk,
      source: "IPPure"
    };
  }

  if (proxyData && proxyData.risk !== null) {
    return {
      score: proxyData.risk,
      source: "ProxyCheck"
    };
  }

  if (scamRisk !== null) {
    return {
      score: scamRisk,
      source: "Scamalytics"
    };
  }

  return {
    score: null,
    source: ""
  };
}

function getRiskLabel(score) {
  if (score === null) return "暂无数据";

  if (score <= 24) return "低风险";

  if (score <= 49) return "较低风险";

  if (score <= 74) return "中风险";

  return "高风险";
}


// ==================== IP 类型判断 ====================

function getIPType(pureData, proxyData, currentIP) {
  if (
    pureData &&
    cleanIP(pureData.ip) === currentIP &&
    typeof pureData.isResidential === "boolean"
  ) {
    return pureData.isResidential ?
      "住宅 IP" :
      "机房 IP";
  }

  if (proxyData && proxyData.type) {
    const type = String(proxyData.type).toLowerCase();

    if (
      type.includes("residential") ||
      type.includes("mobile") ||
      type.includes("wireless")
    ) {
      return "住宅 IP";
    }

    if (
      type.includes("hosting") ||
      type.includes("datacenter") ||
      type.includes("business")
    ) {
      return "机房 IP";
    }
  }

  return "未知";
}

function getIPAttribute(pureData, currentIP) {
  if (
    !pureData ||
    cleanIP(pureData.ip) !== currentIP
  ) {
    return "未知";
  }

  if (typeof pureData.isBroadcast === "boolean") {
    return pureData.isBroadcast ?
      "广播 IP" :
      "原生 IP";
  }

  return "未知";
}


// ==================== 入口 IP 检测 ====================

function getEntranceIP() {
  return new Promise(resolve => {
    $httpAPI(
      "GET",
      "/v1/requests/recent",
      null,
      data => {
        try {
          let requests = [];

          if (Array.isArray(data)) {
            requests = data;
          } else if (data && Array.isArray(data.requests)) {
            requests = data.requests;
          }

          const candidates = requests.filter(item => {
            const url = String(item.URL || item.url || "");

            return (
              /ippure|ip-api|ipinfo|ip\.sb|cloudflare/i.test(url) &&
              String(item.remoteAddress || "").includes("(Proxy)")
            );
          });

          if (candidates.length === 0) {
            resolve("");
            return;
          }

          const remote = candidates[0].remoteAddress || "";

          const ip = cleanIP(remote);

          resolve(ip || "");
        } catch (_) {
          resolve("");
        }
      }
    );
  });
}


// ==================== 地理位置与运营商 ====================

async function getGeoInfo(ip) {
  if (!ip) return null;

  const url =
    CFG.geoAPI +
    encodeURIComponent(ip) +
    "?lang=zh-CN&fields=status,country,regionName,city,isp,org,query";

  const res = await request(url);

  if (!res.ok) return null;

  const data = safeJSON(res.body);

  if (!data || data.status !== "success") {
    return null;
  }

  return data;
}


// ==================== 面板内容 ====================

function formatGeo(data) {
  if (!data) return "未知";

  const country = data.country || "";
  const city = data.city || "";

  const location = [country, city]
    .filter(Boolean)
    .join(" · ");

  return location || "未知";
}

function formatISP(data) {
  if (!data) return "未知";

  return data.isp || data.org || "未知";
}

function formatIP(ip) {
  return ip || "检测失败";
}

function buildContent(info) {
  const lines = [];

  lines.push("【IP 信息】");

  lines.push(
    "出口 IP：" + formatIP(info.ip)
  );

  lines.push(
    "入口 IP：" + (info.entranceIP || "未知")
  );

  lines.push(
    "IP 类型：" + info.ipType
  );

  lines.push(
    "IP 属性：" + info.ipAttribute
  );

  if (info.risk.score !== null) {
    lines.push(
      "纯净度：" +
      info.risk.score +
      "/100 · " +
      getRiskLabel(info.risk.score)
    );
  } else {
    lines.push("纯净度：暂无数据");
  }

  lines.push(
    "地理位置：" + formatGeo(info.geo)
  );

  lines.push(
    "运营商：" + formatISP(info.geo)
  );

  if (info.conflict) {
    lines.push("⚠️ 出口 IP 来源存在分歧");
  }

  return lines.join("\n");
}


// ==================== 主程序 ====================

let finished = false;
let timeoutTimer = null;

function finish(result) {
  if (finished) return;

  finished = true;

  if (timeoutTimer) {
    clearTimeout(timeoutTimer);
  }

  $done(result);
}

function finishError(message) {
  finish({
    title: PANEL_TITLE,
    content: message || "IP 检测失败，请稍后重试",
    icon: CFG.icon,
    "icon-color": CFG.errorColor
  });
}

async function main() {
  try {
    // 第一步：检测出口 IP
    const outbound = await getOutboundIP();

    const ip = outbound.ip;

    if (!ip) {
      finishError("IP 检测失败\n无法获取有效出口 IP");
      return;
    }

    // 第二步：并行获取风险、类型、入口、地理信息
    const results = await Promise.all([
      getProxyCheck(ip),
      getScamalytics(ip),
      getEntranceIP(),
      getGeoInfo(ip)
    ]);

    const proxyData = results[0];
    const scamRisk = results[1];
    const entranceIP = results[2];
    const geo = results[3];

    const pureData = outbound.pureData;

    // 第三步：汇总结果
    const risk = calculateRisk(
      pureData,
      proxyData,
      scamRisk,
      ip
    );

    const ipType = getIPType(
      pureData,
      proxyData,
      ip
    );

    const ipAttribute = getIPAttribute(
      pureData,
      ip
    );

    const info = {
      ip: ip,
      entranceIP: entranceIP,
      ipType: ipType,
      ipAttribute: ipAttribute,
      risk: risk,
      geo: geo,
      conflict: outbound.conflict
    };

    const content = buildContent(info);

    // 出口 IP 来源冲突也视为异常，面板固定红色
    const isError =
      outbound.conflict ||
      !geo ||
      risk.score === null;

    finish({
      title: PANEL_TITLE,
      content: content,
      icon: CFG.icon,
      "icon-color": isError ?
        CFG.errorColor :
        CFG.iconColor
    });

  } catch (error) {
    finishError("IP 检测异常\n" + String(error));
  }
}


// ==================== 超时保护 ====================

timeoutTimer = setTimeout(() => {
  finishError("IP 检测超时\n请检查网络或稍后重试");
}, CFG.totalTimeout);


// ==================== 启动 ====================

main();
