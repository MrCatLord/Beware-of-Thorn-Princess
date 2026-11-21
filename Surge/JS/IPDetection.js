/**
 * Surge Panel 节点检测脚本
 * 实现：入口（中转）、落地、纯净度、IP 类型
 */

const TIMEOUT_MS = 10000;
const args = parseArgs(typeof $argument !== "undefined" ? $argument : "");
const panelTitle = args.title || "IP Check";

let doneCalled = false;
function finish(obj) {
  if (doneCalled) return;
  doneCalled = true;
  $done(obj);
}

const watchdog = typeof setTimeout === "function"
  ? setTimeout(() => {
      finish({
        title: panelTitle,
        content: [
          "入口: 检测超时",
          "落地: 检测超时",
          "纯净度: 未知",
          "IP 类型: 未知"
        ].join("\n"),
        icon: "exclamationmark.shield.fill",
        "icon-color": "#FF3B30"
      });
    }, TIMEOUT_MS)
  : null;

function done(obj) {
  if (watchdog && typeof clearTimeout === "function") clearTimeout(watchdog);
  finish(obj);
}

!(async () => {
  try {
    // 1. 获取落地 IP
    const outIP = await getOutboundIP();
    if (!outIP) {
      return done({
        title: panelTitle,
        content: [
          "入口: 未知",
          "落地: 获取失败",
          "纯净度: 未知",
          "IP 类型: 未知"
        ].join("\n"),
        icon: "xmark.shield.fill",
        "icon-color": "#FF3B30"
      });
    }

    // 2. 并行检测落地归属、IP 类型、纯净度
    const [outGeoRes, typeRes, riskRes] = await Promise.allSettled([
      getGeo(outIP),
      getIPType(outIP),
      getRiskScore(outIP)
    ]);

    const outGeo = outGeoRes.status === "fulfilled" ? outGeoRes.value : null;
    const ipTypeInfo = typeRes.status === "fulfilled"
      ? typeRes.value
      : { ipType: "未知", ipSrc: "未知" };
    const risk = riskRes.status === "fulfilled"
      ? riskRes.value
      : { score: null, source: "未知" };

    // 3. 尝试从 Surge 最近请求获取入口（中转）IP，并查其归属（若与落地不同）
    const entryIP = await getEntryIPWithRetry();
    let entryGeo = null;
    if (entryIP && entryIP !== outIP) {
      entryGeo = await getGeo(entryIP);
    }

    // 4. 拼接四项展示文本
    const entryLoc = entryGeo ? [entryGeo.country, entryGeo.city, entryGeo.isp].filter(Boolean).join(" ") : "";
    const entryText = entryIP
      ? (entryLoc ? `${entryIP} (${entryLoc})` : entryIP)
      : "未检测到";

    const outLoc = outGeo ? [outGeo.country, outGeo.city].filter(Boolean).join(" ") : "";
    const exitText = outLoc ? `${outIP} (${outLoc})` : outIP;

    const purityText = risk.score !== null && risk.score !== undefined
      ? `${risk.score}% ${riskLabel(risk.score)} (${risk.source})`
      : "未知";

    const typeText = `${ipTypeInfo.ipType} | ${ipTypeInfo.ipSrc}`;

    const style = pickStyle(risk.score, ipTypeInfo.ipType);

    done({
      title: panelTitle,
      content: [
        `入口: ${entryText}`,
        `落地: ${exitText}`,
        `纯净度: ${purityText}`,
        `IP 类型: ${typeText}`
      ].join("\n"),
      icon: style.icon,
      "icon-color": style.color
    });
  } catch (err) {
    const msg = err && err.message ? err.message : String(err || "未知错误");
    done({
      title: panelTitle,
      content: [
        `入口: 异常`,
        `落地: 异常 (${msg})`,
        `纯净度: 未知`,
        `IP 类型: 未知`
      ].join("\n"),
      icon: "xmark.shield.fill",
      "icon-color": "#FF3B30"
    });
  }
})();

// --- 入口（中转）获取（带短暂重试，提高命中 recent 记录的概率）---
async function getEntryIPWithRetry() {
  if (typeof $httpAPI !== "function") return null;
  const targetPattern = /(1\.1\.1\.1|ip\.sb|ip-api\.com|ippure\.com|proxycheck\.io)/i;

  const findEntry = async (limit) => {
    const res = await httpAPI("GET", "/v1/requests/recent");
    const list = Array.isArray(res?.requests) ? res.requests.slice(0, limit) : [];
    const hit = list.find(item => item && targetPattern.test(item.URL || ""));
    if (hit && typeof hit.remoteAddress === "string" && /\(Proxy\)/.test(hit.remoteAddress)) {
      const ip = hit.remoteAddress.replace(/\s*\(Proxy\)\s*/, "").replace(/:\d+$/, "").trim();
      return ip || null;
    }
    return null;
  };

  let ip = await findEntry(50);
  if (ip) return ip;

  await sleep(400);
  ip = await findEntry(80);
  return ip || null;
}

// --- 落地 IP 获取 ---
async function getOutboundIP() {
  const trace = await httpGet("https://1.1.1.1/cdn-cgi/trace", 5);
  if (trace) {
    const match = trace.match(/^ip=(.+)$/m);
    if (match && match[1]) return match[1].trim();
  }
  const sb = await httpGetJSON("https://api-ipv4.ip.sb/geoip", 5);
  return sb?.ip ? String(sb.ip).trim() : null;
}

// --- IP 归属查询 ---
async function getGeo(ip) {
  const encoded = encodeURIComponent(ip);
  const api = await httpGetJSON(`http://ip-api.com/json/${encoded}?lang=zh-CN&fields=status,country,city,isp`, 5);
  if (api && api.status === "success") {
    return {
      country: api.country || "",
      city: api.city || "",
      isp: api.isp || ""
    };
  }
  const sb = await httpGetJSON(`https://api.ip.sb/geoip/${encoded}`, 5);
  if (sb && sb.ip) {
    return {
      country: sb.country || sb.country_code || "",
      city: sb.city || "",
      isp: sb.organization || ""
    };
  }
  return null;
}

// --- IP 类型检测 ---
async function getIPType(ip) {
  const pure = await httpGetJSON("https://my.ippure.com/v1/info", 6);
  if (pure && typeof pure.isResidential === "boolean") {
    return {
      ipType: pure.isResidential ? "住宅 IP" : "机房 IP",
      ipSrc: pure.isBroadcast ? "广播 IP" : "原生 IP"
    };
  }
  const pc = await httpGetJSON(`https://proxycheck.io/v2/${encodeURIComponent(ip)}?risk=1&vpn=1`, 6);
  const rawType = pc?.[ip]?.type;
  if (rawType) {
    return {
      ipType: /residential|wireless|mobile/i.test(rawType) ? "住宅 IP" : "机房 IP",
      ipSrc: "未知"
    };
  }
  return { ipType: "未知", ipSrc: "未知" };
}

// --- 纯净度（风险分）检测 ---
async function getRiskScore(ip) {
  if (args.ipqs_key) {
    const qs = await httpGetJSON(
      `https://ipqualityscore.com/api/json/ip/${encodeURIComponent(args.ipqs_key)}/${encodeURIComponent(ip)}?strictness=1`,
      6
    );
    if (qs && qs.success && typeof qs.fraud_score === "number") {
      return { score: qs.fraud_score, source: "IPQS" };
    }
  }
  const pc = await httpGetJSON(`https://proxycheck.io/v2/${encodeURIComponent(ip)}?risk=1&vpn=1`, 6);
  if (pc && pc[ip] && typeof pc[ip].risk === "number") {
    return { score: pc[ip].risk, source: "ProxyCheck" };
  }
  const pure = await httpGetJSON("https://my.ippure.com/v1/info", 6);
  if (pure && typeof pure.fraudScore === "number") {
    return { score: pure.fraudScore, source: "IPPure" };
  }
  return { score: null, source: "未知" };
}

function riskLabel(score) {
  if (score <= 25) return "纯净";
  if (score <= 50) return "微风险";
  if (score <= 70) return "一般风险";
  return "高风险";
}

function pickStyle(score, ipType) {
  if (score === null || score === undefined) {
    return { icon: "shield.lefthalf.filled", color: "#9E9E9E" };
  }
  if (score <= 25) {
    return { icon: "checkmark.shield.fill", color: "#34C759" };
  }
  if (score <= 50) {
    return {
      icon: ipType === "住宅 IP" ? "checkmark.shield.fill" : "shield.lefthalf.filled",
      color: "#FFCC00"
    };
  }
  return { icon: "exclamationmark.shield.fill", color: "#FF3B30" };
}

// --- 辅助工具 ---
function sleep(ms) {
  return typeof setTimeout === "function"
    ? new Promise(resolve => setTimeout(resolve, ms))
    : Promise.resolve();
}

function httpGet(url, timeoutSec = 5) {
  return new Promise(resolve => {
    try {
      $httpClient.get({ url, timeout: timeoutSec }, (err, resp, data) => {
        if (err || !data) return resolve(null);
        resolve(typeof data === "string" ? data : String(data));
      });
    } catch (_) {
      resolve(null);
    }
  });
}

async function httpGetJSON(url, timeoutSec = 5) {
  const raw = await httpGet(url, timeoutSec);
  if (!raw) return null;
  try { return JSON.parse(raw); } catch (_) { return null; }
}

function httpAPI(method, path) {
  if (typeof $httpAPI !== "function") return Promise.resolve(null);
  return new Promise(resolve => {
    try {
      $httpAPI(method, path, null, res => resolve(res || null));
    } catch (_) {
      resolve(null);
    }
  });
}

function parseArgs(str) {
  const out = {};
  if (!str || typeof str !== "string") return out;
  str.split("&").forEach(pair => {
    const idx = pair.indexOf("=");
    if (idx > 0) {
      out[pair.slice(0, idx).trim()] = decodeURIComponent(pair.slice(idx + 1).trim());
    }
  });
  return out;
}
