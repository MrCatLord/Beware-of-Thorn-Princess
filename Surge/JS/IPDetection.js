
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
  timeout: 7,
  totalTimeout: 23,

  ippure: "https://my.ippure.com/v1/info",
  ippureCard: "https://my.ippure.com/v1/card",

  cfTrace: "https://1.1.1.1/cdn-cgi/trace",
  ipSB: "https://api-ipv4.ip.sb/geoip",

  proxyCheck: "https://proxycheck.io/v2/",
  scamalytics: "https://scamalytics.com/ip/",

  geoAPI: "http://ip-api.com/json/",
  ipInfo: "https://ipinfo.io/",

  icon: "bolt.fill",
  iconColor: "#30D158"
};

let finished = false;
let startTime = Date.now();

const PANEL_TITLE =
  typeof $input !== "undefined" && $input.panelName
    ? $input.panelName
    : "IP 信息";

function finish(content, color) {
  if (finished) return;
  finished = true;

  $done({
    title: PANEL_TITLE,
    content: content,
    icon: CFG.icon,
    "icon-color": color || CFG.iconColor
  });
}

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

// IPv4 / IPv6 验证
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
    const right = groups.length === 2 && groups[1]
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

// 同时获取多个出口检测结果
async function getOutboundSources() {
  const [pure, traceBody, sb] = await Promise.all([
    getJSON(CFG.ippure),
    request(CFG.cfTrace),
    getJSON(CFG.ipSB)
  ]);

  const cfIP = parseTrace(traceBody);
  const sbIP = validIP(sb?.ip) ? sb.ip : null;
  const pureIP = validIP(pure?.ip) ? pure.ip : null;

  // Cloudflare 优先，IP.SB 次之，IPPure 作为回退
  const outboundIP = cfIP || sbIP || pureIP;

  return {
    ip: outboundIP,
    pure: pure,
    pureIP: pureIP,
    cfIP: cfIP,
    sbIP: sbIP
  };
}

// 只有与当前落地 IP 一致才接受 IPPure 结果
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

// IPPure 评分和属性
async function getIPPureData(ip, pure) {
  let data = pureMatchesIP(pure, ip) ? pure : null;

  if (!data) {
    const other = await getJSON(CFG.ippure);
    if (pureMatchesIP(other, ip)) data = other;
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

// ProxyCheck 风险与代理类型
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
    proxy: proxy === "yes" ? true :
      proxy === "no" ? false : null,
    type: type || "未知",
    residential: residential
  };
}

// Scamalytics 网页评分
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

// IP 类型：优先 IPPure，ProxyCheck 辅助
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

// 多源风险评分
function calculateRisk(results) {
  const valid = results.filter(item =>
    item &&
    item.ip &&
    item.score !== null &&
    item.score !== undefined &&
    item.score >= 0 &&
    item.score <= 100
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

  // 来源间差异
  const spread = scores[scores.length - 1] - scores[0];

  if (valid.length >= 2 && spread >= 35) {
    level = "来源结果不一致";
  }

  return {
    text: `${median.toFixed(0)} / 100 · ${level}`,
    score: median,
    sources: valid,
    spread: spread
  };
}

// 风险来源简要展示
function formatRiskSources(results) {
  const names = ["IPPure", "ProxyCheck", "Scamalytics"];

  return names.map(name => {
    const item = results.find(x => x && x.source === name);

    if (!item) return `${name}：无结果`;

    if (item.score === null || item.score === undefined) {
      return `${name}：未提供评分`;
    }

    return `${name}：${item.score}`;
  }).join("\n");
}

// 获取地区与运营商
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

// 解析 Surge 最近请求的远端代理地址
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

          // recent 通常按时间倒序，优先选择最新的代理请求
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

function formatLocation(geo) {
  if (!geo) return "未知";

  return [geo.country, geo.city]
    .filter(Boolean)
    .join(" · ") || "未知";
}

function buildIPBlock(name, ip, geo) {
  return [
    `【${name}】`,
    `IP：${ip || "获取失败"}`,
    `地区：${formatLocation(geo)}`,
    `运营商：${geo?.isp || "未知"}`
  ].join("\n");
}

// 主程序
(async () => {
  try {
    const sources = await getOutboundSources();
    const outboundIP = sources.ip;

    if (!outboundIP) {
      finish("落地 IP 获取失败，请检查网络。", "#E5484D");
      return;
    }

    // 如果 IPPure 返回 IP 与实际出口不一致，丢弃其结果
    const matchedPure = pureMatchesIP(sources.pure, outboundIP)
      ? sources.pure
      : null;

    // 所有风险查询都明确指定同一个落地 IP
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

    // 再次核验 IP，避免错配
    const riskResults = [
      pureData,
      proxyData,
      scamData
    ].filter(item => item && item.ip === outboundIP);

    const risk = calculateRisk(riskResults);
    const type = getIPType(pureData, proxyData);

    // 入口地区
    const entranceGeo = entranceIP
      ? await getGeo(entranceIP)
      : null;

    const riskDetails = formatRiskSources(riskResults);

    const content = [
      "【IP 类型与纯净度】",
      `类型：${type.type}`,
      `属性：${type.source}`,
      `纯净度：${risk.text}`,
      `有效数据源：${riskResults.length} / 3`,
      "",
      "【风险数据源】",
      riskDetails,
      "",
      buildIPBlock("入口 IP", entranceIP, entranceGeo),
      "",
      buildIPBlock("落地 IP", outboundIP, outboundGeo)
    ].join("\n");

    finish(content);

  } catch (e) {
    finish("检测异常：" + String(e), "#E5484D");
  }
})();
