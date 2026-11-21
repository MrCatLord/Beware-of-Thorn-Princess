
/**
 * Surge iOS 6 - IP Detection
 * IP 类型 / 纯净度 / 入口 IP / 落地 IP
 *
 * 优化：
 * 1. IPPure、Cloudflare、IP.SB 交叉确认落地 IP
 * 2. IPPure + ProxyCheck + Scamalytics 多源风险检测
 * 3. 所有评分必须对应同一个落地 IP
 * 4. 多源评分采用中位数，避免单一来源误判
 * 5. 住宅、机房、原生、广播分别判断
 * 6. 入口 IP 优先从 Surge 最近请求中提取
 * 7. 国家 + 城市，不显示省份
 */

const CFG = {
  timeout: 6,
  totalTimeout: 23,

  icon: "bolt.fill",
  iconColor: "#30D158",
  errorColor: "#EF476F",

  ippure: "https://my.ippure.com/v1/info",
  cfTrace: "https://1.1.1.1/cdn-cgi/trace",
  ipSB: "https://api-ipv4.ip.sb/geoip",

  proxyCheck: "https://proxycheck.io/v2/",
  scamalytics: "https://scamalytics.com/ip/",

  geoAPI: "http://ip-api.com/json/",
  ipInfo: "https://ipinfo.io/"
};

let finished = false;

const DEFAULT_TITLE = "IP 信息";
const args = new URLSearchParams(
  typeof $argument !== "undefined" ? $argument : ""
);
const PANEL_TITLE = args.get("panel_title") || DEFAULT_TITLE;
    
// 读取模块参数
function parseArguments(raw) {
  const result = {};

  if (!raw) return result;

  raw.split("&").forEach(item => {
    const index = item.indexOf("=");
    if (index < 0) return;

    try {
      const key = decodeURIComponent(item.slice(0, index));
      const value = decodeURIComponent(item.slice(index + 1));
      result[key] = value;
    } catch (e) {}
  });

  return result;
}

const args = parseArguments(
  typeof $argument === "string" ? $argument : ""
);

CFG.icon = args.panel_icon || CFG.icon;
CFG.iconColor = args.panel_color || CFG.iconColor;

// 统一结束面板
function finish(content, isError) {
  if (finished) return;

  finished = true;

  $done({
    title: PANEL_TITLE,
    content: content,
    icon: CFG.icon,
    "icon-color": isError ? CFG.errorColor : CFG.iconColor
  });
}

// HTTP 请求
function request(url) {
  return new Promise(resolve => {
    try {
      $httpClient.get({
        url: url,
        timeout: CFG.timeout,
        headers: {
          "User-Agent":
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Version/18.0 Mobile/15E148 Safari/604.1"
        }
      }, (error, response, body) => {
        if (
          error ||
          !response ||
          response.status < 200 ||
          response.status >= 300
        ) {
          resolve(null);
          return;
        }

        resolve(body || null);
      });
    } catch (e) {
      resolve(null);
    }
  });
}

async function getJSON(url) {
  const body = await request(url);
  if (!body) return null;

  try {
    return JSON.parse(body);
  } catch (e) {
    return null;
  }
}

// IPv4 / IPv6 校验
function validIP(value) {
  if (typeof value !== "string") return false;

  const ip = value.trim();

  const ipv4 = ip.split(".");

  if (
    ipv4.length === 4 &&
    ipv4.every(part =>
      /^\d{1,3}$/.test(part) &&
      Number(part) >= 0 &&
      Number(part) <= 255
    )
  ) {
    return true;
  }

  if (
    ip.includes(":") &&
    /^[0-9a-f:.]+$/i.test(ip) &&
    !ip.includes(":::")
  ) {
    const groups = ip.split("::");

    if (groups.length > 2) return false;

    const left = groups[0] ? groups[0].split(":") : [];
    const right =
      groups.length === 2 && groups[1]
        ? groups[1].split(":")
        : [];

    const all = left.concat(right);

    if (all.some(x => x && !/^[0-9a-f]{1,4}$/i.test(x))) {
      return false;
    }

    if (groups.length === 1 && all.length !== 8) {
      return false;
    }

    if (groups.length === 2 && all.length >= 8) {
      return false;
    }

    return true;
  }

  return false;
}

function parseTrace(body) {
  if (!body || typeof body !== "string") return null;

  const match = body.match(/^ip=(.+)$/m);
  const ip = match ? match[1].trim() : null;

  return validIP(ip) ? ip : null;
}

// 获取出口 IP
async function getOutboundSources() {
  const [pure, traceBody, sb] = await Promise.all([
    getJSON(CFG.ippure),
    request(CFG.cfTrace),
    getJSON(CFG.ipSB)
  ]);

  const cfIP = parseTrace(traceBody);
  const sbIP = validIP(sb?.ip) ? sb.ip : null;
  const pureIP = validIP(pure?.ip) ? pure.ip : null;

  return {
    ip: cfIP || sbIP || pureIP,
    pure: pure
  };
}

// IPPure 数据必须匹配当前出口 IP
function pureMatchesIP(pure, ip) {
  return !!(
    pure &&
    validIP(pure.ip) &&
    pure.ip === ip
  );
}

function validScore(value) {
  if (
    value === null ||
    value === undefined ||
    value === ""
  ) return null;

  const n = Number(value);

  return Number.isFinite(n) && n >= 0 && n <= 100
    ? n
    : null;
}

// IPPure
async function getIPPureData(ip, pure) {
  let data = pureMatchesIP(pure, ip) ? pure : null;

  if (!data) {
    const other = await getJSON(CFG.ippure);

    if (pureMatchesIP(other, ip)) {
      data = other;
    }
  }

  if (!data) return null;

  return {
    source: "IPPure",
    ip: data.ip,
    score: validScore(data.fraudScore),
    residential:
      typeof data.isResidential === "boolean"
        ? data.isResidential
        : null,
    broadcast:
      typeof data.isBroadcast === "boolean"
        ? data.isBroadcast
        : null
  };
}

// ProxyCheck
async function getProxyCheck(ip) {
  const data = await getJSON(
    CFG.proxyCheck +
    encodeURIComponent(ip) +
    "?vpn=1&risk=1"
  );

  if (!data || data.status !== "ok" || !data[ip]) {
    return null;
  }

  const item = data[ip];

  const type = String(item.type || "");
  const proxy = String(item.proxy || "").toLowerCase();

  let residential = null;

  if (/residential|wireless|mobile/i.test(type)) {
    residential = true;
  } else if (/hosting|datacenter|business/i.test(type)) {
    residential = false;
  }

  return {
    source: "ProxyCheck",
    ip: ip,
    score: validScore(item.risk),
    proxy:
      proxy === "yes" ? true :
      proxy === "no" ? false : null,
    type: type || "未知",
    residential: residential
  };
}

// Scamalytics
async function getScamalytics(ip) {
  const html = await request(
    CFG.scamalytics + encodeURIComponent(ip)
  );

  if (!html) return null;

  let score = null;

  const patterns = [
    /Fraud Score[\s\S]{0,100}?([0-9]{1,3})\s*(?:\/\s*100)?/i,
    /scamalytics\.com[\s\S]{0,300}?fraud[\s\S]{0,100}?([0-9]{1,3})/i,
    /class=["'][^"']*score[^"']*["'][^>]*>\s*([0-9]{1,3})/i
  ];

  for (const pattern of patterns) {
    const match = html.match(pattern);

    if (match) {
      score = validScore(match[1]);
      if (score !== null) break;
    }
  }

  if (score === null) return null;

  return {
    source: "Scamalytics",
    ip: ip,
    score: score
  };
}

// IP 类型
function getIPType(pureData, proxyData) {
  let residential = pureData?.residential;

  if (residential === null || residential === undefined) {
    residential = proxyData?.residential;
  }

  let type = "未知";

  if (residential === true) type = "住宅 IP";
  if (residential === false) type = "机房/非住宅 IP";

  let broadcast = pureData?.broadcast;
  let source = "未知";

  if (broadcast === true) source = "广播 IP";
  if (broadcast === false) source = "原生 IP";

  return { type, source };
}

// 多源综合风险评分
function calculateRisk(results) {
  const valid = results.filter(item =>
    item &&
    item.ip &&
    item.score !== null &&
    item.score !== undefined
  );

  if (valid.length === 0) {
    return {
      text: "无法判断",
      score: null,
      sources: []
    };
  }

  const scores = valid
    .map(item => item.score)
    .sort((a, b) => a - b);

  let median;

  if (scores.length % 2 === 1) {
    median = scores[Math.floor(scores.length / 2)];
  } else {
    const middle = scores.length / 2;
    median = (scores[middle - 1] + scores[middle]) / 2;
  }

  let level = "一般";

  if (median <= 10) level = "极低风险";
  else if (median <= 25) level = "低风险";
  else if (median <= 40) level = "较低风险";
  else if (median <= 60) level = "中等风险";
  else if (median <= 80) level = "较高风险";
  else level = "高风险";

  const spread = scores[scores.length - 1] - scores[0];

  if (valid.length >= 2 && spread >= 35) {
    level = "来源结果不一致";
  }

  return {
    text: `${median.toFixed(0)} / 100 · ${level}`,
    score: median,
    sources: valid
  };
}

// 地区与运营商
async function getGeo(ip) {
  if (!ip) return null;

  const [a, b] = await Promise.all([
    getJSON(
      CFG.geoAPI +
      encodeURIComponent(ip) +
      "?lang=zh-CN&fields=status,country,city,isp,org"
    ),
    getJSON(
      CFG.ipInfo +
      encodeURIComponent(ip) +
      "/json"
    )
  ]);

  const ok = a?.status === "success";

  if (!ok && !b) return null;

  let isp = ok ? (a.isp || "") : "";

  if (!isp && b?.org) {
    isp = b.org.replace(/^AS\d+\s*/i, "");
  }

  return {
    country: ok ? a.country : b?.country || "",
    city: ok ? a.city : b?.city || "",
    isp: isp || "未知"
  };
}

// 入口 IP 识别
function cleanRemoteIP(value) {
  if (!value || typeof value !== "string") return null;

  let ip = value.replace(/\s*\(Proxy\)\s*/i, "").trim();

  if (ip.startsWith("[")) {
    ip = ip.replace(/^\[([^\]]+)\](?::\d+)?$/, "$1");
  } else if ((ip.match(/:/g) || []).length === 1) {
    ip = ip.replace(/:\d+$/, "");
  }

  return validIP(ip) ? ip : null;
}

function getEntranceIP() {
  return new Promise(resolve => {
    if (typeof $httpAPI !== "function") {
      resolve(null);
      return;
    }

    try {
      $httpAPI(
        "GET",
        "/v1/requests/recent",
        null,
        result => {
          const requests = result?.requests || [];

          const pattern =
            /(my\.ippure\.com|1\.1\.1\.1|api-ipv4\.ip\.sb|ip-api\.com|ipinfo\.io|scamalytics\.com|proxycheck\.io)/i;

          for (const item of requests) {
            if (!pattern.test(item.URL || "")) continue;

            const remote = item.remoteAddress || "";

            if (!/\(Proxy\)/i.test(remote)) continue;

            const ip = cleanRemoteIP(remote);

            if (ip) {
              resolve(ip);
              return;
            }
          }

          resolve(null);
        }
      );
    } catch (e) {
      resolve(null);
    }
  });
}

// 地区格式
function formatLocation(geo) {
  if (!geo) return "未知";

  return [geo.country, geo.city]
    .filter(Boolean)
    .join(" · ") || "未知";
}

// IP 信息块
function buildIPBlock(name, ip, geo) {
  return [
    `【${name}】`,
    `IP：${ip || "获取失败"}`,
    `地区：${formatLocation(geo)}`,
    `运营商：${geo?.isp || "未知"}`
  ].join("\n");
}

// 总超时保护
setTimeout(() => {
  finish("检测超时，请手动刷新重试。", true);
}, CFG.totalTimeout * 1000);

// 主程序
(async () => {
  try {
    const sources = await getOutboundSources();
    const outboundIP = sources.ip;

    if (!outboundIP) {
      finish("落地 IP 获取失败，请检查网络。", true);
      return;
    }

    const matchedPure = pureMatchesIP(sources.pure, outboundIP)
      ? sources.pure
      : null;

    const [
      pureData,
      proxyData,
      scamData,
      entranceIP,
      outboundGeo
    ] = await Promise.all([
      getIPPureData(outboundIP, matchedPure),
      getProxyCheck(outboundIP),
      getScamalytics(outboundIP),
      getEntranceIP(),
      getGeo(outboundIP)
    ]);

    const riskResults = [
      pureData,
      proxyData,
      scamData
    ].filter(item => item && item.ip === outboundIP);

    const risk = calculateRisk(riskResults);
    const type = getIPType(pureData, proxyData);

    const entranceGeo = entranceIP
      ? await getGeo(entranceIP)
      : null;

    // 最终展示：不显示风险数据源明细
    const content = [
      "【IP 类型与纯净度】",
      `类型：${type.type}`,
      `属性：${type.source}`,
      `纯净度：${risk.text}`,
      "",
      buildIPBlock("入口 IP", entranceIP, entranceGeo),
      "",
      buildIPBlock("落地 IP", outboundIP, outboundGeo)
    ].join("\n");

    finish(content, false);

  } catch (e) {
    finish("检测异常：" + String(e), true);
  }
})();
