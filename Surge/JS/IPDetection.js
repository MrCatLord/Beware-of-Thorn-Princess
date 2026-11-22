

/**
 * Surge iOS 6 - IP Detection
 * IP 类型 / 纯净度 / 入口 IP / 落地 IP
 *
 * 1. Cloudflare / IP.SB / IPPure 多源出口 IP 检测
 * 2. 多源一致性验证，异常分歧识别
 * 3. CleanIP / IPPure / ProxyCheck / Scamalytics 纯净度与类型/属性融合
 */

// =====================================
// 1. 基础配置
// =====================================

const CFG = {
  timeout: 5,
  totalTimeout: 16,

  icon: "bolt.fill",
  iconColor: "#30D158",
  errorColor: "#EF476F",

  ippure: "https://my.ippure.com/v1/info",
  cfTrace: "https://1.1.1.1/cdn-cgi/trace",
  ipSB: "https://api-ipv4.ip.sb/geoip",

  cleanIP: "https://api.cleanip.io/api/v2/",
  proxyCheck: "https://proxycheck.io/v2/",
  scamalytics: "https://scamalytics.com/ip/",

  geoAPI: "http://ip-api.com/json/",
  ipInfo: "https://ipinfo.io/"
};

const DEFAULT_TITLE = "IP信息";

let PANEL_TITLE = DEFAULT_TITLE;
let CLEANIP_KEY = "";
let finished = false;
let totalTimer = null;

// =====================================
// 2. 模块参数
// =====================================

function parseArguments(raw) {
  const result = {};

  if (!raw || typeof raw !== "string") {
    return result;
  }

  raw.split("&").forEach(item => {
    const index = item.indexOf("=");

    if (index < 0) return;

    try {
      const key = decodeURIComponent(
        item.slice(0, index).replace(/\+/g, " ")
      );

      const value = decodeURIComponent(
        item.slice(index + 1).replace(/\+/g, " ")
      );

      result[key] = value;
    } catch (e) {}
  });

  return result;
}

const args = parseArguments(
  typeof $argument === "string" ? $argument : ""
);

PANEL_TITLE = args.panel_title || DEFAULT_TITLE;
CLEANIP_KEY = (args.cleanip_key || "").trim();

CFG.icon = args.panel_icon || CFG.icon;
CFG.iconColor = args.panel_color || CFG.iconColor;

if (args.timeout && Number(args.timeout) > 0) {
  CFG.timeout = Math.min(Number(args.timeout), 15);
}

if (args.total_timeout && Number(args.total_timeout) > 0) {
  CFG.totalTimeout = Math.min(Number(args.total_timeout), 30);
}

// =====================================
// 3. 统一结束面板
// =====================================

function finish(content, isError) {
  if (finished) return;

  finished = true;

  if (totalTimer) {
    clearTimeout(totalTimer);
    totalTimer = null;
  }

  $done({
    title: PANEL_TITLE,
    content: content,
    icon: CFG.icon,
    "icon-color": isError
      ? CFG.errorColor
      : CFG.iconColor
  });
}

// =====================================
// 4. HTTP 请求
// =====================================

function request(url, extraHeaders) {
  return new Promise(resolve => {
    try {
      const headers = Object.assign(
        {
          "User-Agent":
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Version/18.0 Mobile/15E148 Safari/604.1"
        },
        extraHeaders || {}
      );

      $httpClient.get(
        {
          url: url,
          timeout: CFG.timeout,
          headers: headers
        },
        (error, response, body) => {
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
        }
      );
    } catch (e) {
      resolve(null);
    }
  });
}

async function getJSON(url, extraHeaders) {
  const body = await request(url, extraHeaders);

  if (!body) return null;

  try {
    return JSON.parse(body);
  } catch (e) {
    return null;
  }
}

// =====================================
// 5. IP 地址校验与标准化
// =====================================

function normalizeIP(value) {
  if (typeof value !== "string") return null;

  let ip = value.trim().toLowerCase();

  // IPv4
  const ipv4 = ip.split(".");

  if (ipv4.length === 4) {
    if (
      !ipv4.every(
        part =>
          /^\d{1,3}$/.test(part) &&
          Number(part) >= 0 &&
          Number(part) <= 255
      )
    ) {
      return null;
    }

    return ipv4.map(part => String(Number(part))).join(".");
  }

  // IPv6
  if (!ip.includes(":")) return null;

  if (!/^[0-9a-f:.]+$/i.test(ip)) {
    return null;
  }

  if (ip.includes(".")) {
    return null;
  }

  if ((ip.match(/::/g) || []).length > 1) {
    return null;
  }

  const compressed = ip.includes("::");
  const parts = ip.split("::");

  const left = parts[0] ? parts[0].split(":") : [];
  const right = compressed && parts[1] ? parts[1].split(":") : [];

  const all = left.concat(right);

  if (all.some(group => !/^[0-9a-f]{1,4}$/.test(group))) {
    return null;
  }

  if (
    (!compressed && all.length !== 8) ||
    (compressed && all.length > 7)
  ) {
    return null;
  }

  const groups = compressed
    ? left.concat(Array(8 - all.length).fill("0"), right)
    : all;

  const normalized = groups.map(group =>
    parseInt(group || "0", 16).toString(16)
  );

  // IPv4-mapped IPv6
  if (
    normalized.slice(0, 5).every(x => x === "0") &&
    normalized[5] === "ffff"
  ) {
    const a = parseInt(normalized[6], 16);
    const b = parseInt(normalized[7], 16);

    return [a >> 8, a & 255, b >> 8, b & 255].join(".");
  }

  return normalized.join(":");
}

function isPrivateOrLoopbackIP(ip) {
  if (!ip) return true;

  if (ip === "127.0.0.1" || ip === "::1" || ip === "0:0:0:0:0:0:0:1") {
    return true;
  }

  if (ip.includes(".")) {
    const parts = ip.split(".").map(Number);
    if (parts[0] === 10) return true;
    if (parts[0] === 127) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 169 && parts[1] === 254) return true;
  } else {
    const first = ip.split(":")[0];
    if (first.startsWith("fc") || first.startsWith("fd") || first.startsWith("fe80")) {
      return true;
    }
  }

  return false;
}

// =====================================
// 6. Cloudflare Trace
// =====================================

function parseTrace(body) {
  if (!body || typeof body !== "string") {
    return null;
  }

  const match = body.match(/^ip=(.+)$/m);

  return match ? normalizeIP(match[1]) : null;
}

// =====================================
// 7. 出口 IP 多源检测
// =====================================

async function getOutboundSources() {
  const [pure, traceBody, sb] = await Promise.all([
    getJSON(CFG.ippure),
    request(CFG.cfTrace),
    getJSON(CFG.ipSB)
  ]);

  const results = {
    cf: parseTrace(traceBody),
    sb: normalizeIP(sb?.ip),
    pure: normalizeIP(pure?.ip),
    pureData: pure
  };

  const candidates = [results.cf, results.sb, results.pure].filter(Boolean);

  if (!candidates.length) {
    return {
      ip: null,
      conflict: false,
      count: 0,
      sources: results
    };
  }

  const counts = {};

  candidates.forEach(ip => {
    counts[ip] = (counts[ip] || 0) + 1;
  });

  let selected = null;
  let maxCount = 0;

  Object.keys(counts).forEach(ip => {
    if (counts[ip] > maxCount) {
      maxCount = counts[ip];
      selected = ip;
    }
  });

  // 多数一致优先；无多数时按 CF > IP.SB > IPPure
  if (maxCount < 2) {
    selected = results.cf || results.sb || results.pure;
  }

  return {
    ip: selected,
    conflict: Object.keys(counts).length > 1,
    count: candidates.length,
    sources: results
  };
}

// =====================================
// 8. 评分与布尔解析
// =====================================

function pureMatchesIP(pure, ip) {
  return !!(
    pure &&
    normalizeIP(pure.ip) &&
    normalizeIP(pure.ip) === normalizeIP(ip)
  );
}

function validScore(value) {
  if (value === null || value === undefined || value === "") {
    return null;
  }

  const n = Number(value);

  return Number.isFinite(n) && n >= 0 && n <= 100 ? n : null;
}

function parseBooleanFlag(value) {
  if (value === true || value === 1) {
    return true;
  }

  if (value === false || value === 0) {
    return false;
  }

  if (typeof value === "string") {
    const v = value.trim().toLowerCase();

    if (["true", "1", "yes"].includes(v)) {
      return true;
    }

    if (["false", "0", "no"].includes(v)) {
      return false;
    }
  }

  return null;
}

function mapIPCategory(rawType) {
  const s = String(rawType || "").toLowerCase();

  if (!s) return { category: "未知", residential: null };

  if (/residential|home|broadband|住宅/.test(s)) {
    return { category: "住宅 IP", residential: true };
  }
  if (/mobile|wireless|cellular|移动|蜂窝/.test(s)) {
    return { category: "移动/无线 IP", residential: true };
  }
  if (/hosting|datacenter|idc|cloud|机房|数据中心/.test(s)) {
    return { category: "机房 IP", residential: false };
  }
  if (/business|commercial|corporate|商业|企业/.test(s)) {
    return { category: "商业 IP", residential: false };
  }

  return { category: "未知", residential: null };
}

// =====================================
// 9. CleanIP (https://api.cleanip.io)
// =====================================

async function getCleanIP(ip) {
  const headers = {};
  if (CLEANIP_KEY) {
    headers["X-API-Key"] = CLEANIP_KEY;
  }

  const url =
    CFG.cleanIP +
    encodeURIComponent(ip) +
    "?lang=zh&detail=full";

  const data = await getJSON(url, headers);

  if (!data || data.ok === false) {
    return null;
  }

  const payload = data.data || data;

  // CleanIP 评分通常为 0-100（越高越纯净）；若字段名为 fraudScore/riskScore 则按风险分处理
  let riskScore = null;

  if (payload.fraudScore !== undefined || payload.riskScore !== undefined) {
    riskScore = validScore(payload.fraudScore ?? payload.riskScore);
  } else {
    const purity = validScore(
      payload.score ??
        payload.purityScore ??
        payload.purity?.score
    );
    if (purity !== null) {
      riskScore = Math.max(0, Math.min(100, 100 - purity));
    }
  }

  const rawType =
    payload.ipType ||
    payload.type ||
    payload.network?.type ||
    payload.classification?.type ||
    "";

  const mapped = mapIPCategory(rawType);

  const isResidential =
    parseBooleanFlag(
      payload.isResidential ??
        payload.residential ??
        payload.network?.isResidential
    ) ?? mapped.residential;

  const isBroadcast = parseBooleanFlag(
    payload.isBroadcast ??
      payload.broadcast ??
      payload.isNative === false ??
      payload.network?.isBroadcast
  );

  const geoObj = payload.geo || payload.location || {};
  const netObj = payload.network || payload.asn || {};

  return {
    source: "CleanIP",
    ip: normalizeIP(payload.ip || ip),
    score: riskScore,
    type: mapped.category,
    residential: isResidential,
    broadcast: isBroadcast,
    geo: {
      countryCode: String(
        geoObj.countryCode || geoObj.country_code || payload.countryCode || ""
      ).toUpperCase(),
      country: geoObj.country || payload.country || "",
      region: geoObj.region || geoObj.regionName || payload.region || "",
      city: geoObj.city || payload.city || "",
      isp:
        netObj.isp ||
        netObj.org ||
        netObj.asName ||
        payload.isp ||
        payload.org ||
        ""
    }
  };
}

// =====================================
// 10. IPPure
// =====================================

function getIPPureData(ip, pure) {
  if (!pureMatchesIP(pure, ip)) {
    return null;
  }

  return {
    source: "IPPure",
    ip: normalizeIP(pure.ip),
    score: validScore(pure.fraudScore),
    residential: parseBooleanFlag(pure.isResidential),
    broadcast: parseBooleanFlag(pure.isBroadcast)
  };
}

// =====================================
// 11. ProxyCheck
// =====================================

async function getProxyCheck(ip) {
  const data = await getJSON(
    CFG.proxyCheck + encodeURIComponent(ip) + "?vpn=1&risk=1"
  );

  if (!data || data.status !== "ok" || !data[ip]) {
    return null;
  }

  const item = data[ip];
  const mapped = mapIPCategory(item.type);

  return {
    source: "ProxyCheck",
    ip: normalizeIP(ip),
    score: validScore(item.risk),
    type: mapped.category,
    residential: mapped.residential,
    broadcast: null
  };
}

// =====================================
// 12. Scamalytics
// =====================================

async function getScamalytics(ip) {
  const html = await request(CFG.scamalytics + encodeURIComponent(ip));

  if (!html) return null;

  let score = null;

  const patterns = [
    /Fraud\s*Score\s*<\/[^>]+>\s*<[^>]+>\s*([0-9]{1,3})\s*(?:\/\s*100)?/i,
    /Fraud\s*Score[\s\S]{0,60}?([0-9]{1,3})\s*\/\s*100/i,
    /Fraud\s*Score\s*[:：]\s*([0-9]{1,3})\b/i
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
    ip: normalizeIP(ip),
    score: score
  };
}

// =====================================
// 13. 纯净度计算（CleanIP > IPPure > ProxyCheck > Scamalytics）
// =====================================

function calculateRisk(results) {
  const priority = ["CleanIP", "IPPure", "ProxyCheck", "Scamalytics"];

  for (const source of priority) {
    const item = results.find(
      result =>
        result &&
        result.source === source &&
        result.score !== null &&
        result.score !== undefined
    );

    if (!item) continue;

    const score = item.score;
    let level = "一般";

    if (score <= 10) {
      level = "极低风险";
    } else if (score <= 25) {
      level = "低风险";
    } else if (score <= 40) {
      level = "较低风险";
    } else if (score <= 60) {
      level = "中等风险";
    } else if (score <= 80) {
      level = "较高风险";
    } else {
      level = "高风险";
    }

    return {
      text: `${score.toFixed(0)} / 100 · ${level}`,
      score: score,
      source: source
    };
  }

  return {
    text: "无法判断",
    score: null,
    source: null
  };
}

// =====================================
// 14. IP 类型与原生 / 广播属性
// =====================================

function getIPType(cleanData, pureData, proxyData) {
  let type = "未知";

  const candidates = [cleanData, pureData, proxyData].filter(Boolean);

  for (const item of candidates) {
    if (typeof item.residential === "boolean") {
      if (item.residential) {
        type = item.type && item.type !== "未知" ? item.type : "住宅 IP";
        break;
      } else if (item.type && item.type !== "未知") {
        type = item.type;
        break;
      } else {
        type = "非住宅 IP";
        break;
      }
    }
    if (item.type && item.type !== "未知") {
      type = item.type;
      break;
    }
  }

  let attribute = "无法确认";

  const broadcastSource = [cleanData, pureData, proxyData].find(
    item => item && typeof item.broadcast === "boolean"
  );

  if (broadcastSource) {
    attribute = broadcastSource.broadcast ? "广播 IP" : "原生 IP";
  }

  return {
    type: type,
    attribute: attribute
  };
}

// =====================================
// 15. 地区名称标准化
// =====================================

function cleanAreaName(value) {
  if (!value || typeof value !== "string") {
    return "";
  }

  return value.trim().replace(/\s+/g, " ").trim();
}

function getMunicipality(value) {
  const name = cleanAreaName(value).toLowerCase();

  const map = {
    "北京": "北京",
    "北京市": "北京",
    "beijing": "北京",
    "beijing shi": "北京",

    "上海": "上海",
    "上海市": "上海",
    "shanghai": "上海",
    "shanghai shi": "上海",

    "天津": "天津",
    "天津市": "天津",
    "tianjin": "天津",
    "tianjin shi": "天津",

    "重庆": "重庆",
    "重庆市": "重庆",
    "chongqing": "重庆",
    "chongqing shi": "重庆"
  };

  return map[name] || "";
}

const HK_DISTRICTS = {
  "central and western": "中西区",
  "central and western district": "中西区",
  "eastern": "东区",
  "eastern district": "东区",
  "southern": "南区",
  "southern district": "南区",
  "wan chai": "湾仔",
  "wan chai district": "湾仔",
  "kowloon city": "九龙城",
  "kowloon city district": "九龙城",
  "kwun tong": "观塘",
  "kwun tong district": "观塘",
  "sham shui po": "深水埗",
  "sham shui po district": "深水埗",
  "wong tai sin": "黄大仙",
  "wong tai sin district": "黄大仙",
  "yau tsim mong": "油尖旺",
  "yau tsim mong district": "油尖旺",
  "islands": "离岛",
  "islands district": "离岛",
  "kwai tsing": "葵青",
  "kwai tsing district": "葵青",
  "north": "北区",
  "north district": "北区",
  "sai kung": "西贡",
  "sai kung district": "西贡",
  "sha tin": "沙田",
  "sha tin district": "沙田",
  "tai po": "大埔",
  "tai po district": "大埔",
  "tsuen wan": "荃湾",
  "tsuen wan district": "荃湾",
  "tuen mun": "屯门",
  "tuen mun district": "屯门",
  "yuen long": "元朗",
  "yuen long district": "元朗"
};

const MO_DISTRICTS = {
  "nossa senhora de fatima": "花地玛",
  "nossa senhora de fátima": "花地玛",
  "santo antonio": "圣安多尼",
  "santo antónio": "圣安多尼",
  "sao lazaro": "望德堂",
  "são lázaro": "望德堂",
  "se": "大堂",
  "sé": "大堂",
  "sao lourenco": "风顺堂",
  "são lourenço": "风顺堂",
  "nossa senhora do carmo": "嘉模",
  "cotai": "路氹",
  "coloane": "路环"
};

function stripCitySuffix(value) {
  return cleanAreaName(value)
    .replace(/市$/, "")
    .replace(/地区$/, "")
    .replace(/自治州$/, "")
    .replace(/盟$/, "");
}

function normalizeSpecialArea(value, code) {
  const name = cleanAreaName(value);

  if (!name) return "";

  if (code === "HK") {
    const key = name.toLowerCase();
    if (HK_DISTRICTS[key]) return HK_DISTRICTS[key];
    return name.replace(/\s+district$/i, "").replace(/区$/, "");
  }

  if (code === "MO") {
    const key = name.toLowerCase();
    if (MO_DISTRICTS[key]) return MO_DISTRICTS[key];
    return name.replace(/\s+(parish|district)$/i, "").replace(/堂区$/, "").replace(/区$/, "");
  }

  if (code === "TW") {
    return name.replace(/\s+(county|city)$/i, "").replace(/县$/, "").replace(/市$/, "");
  }

  return name;
}

// =====================================
// 16. 地区信息查询（ip-api + ipinfo + CleanIP 兜底）
// =====================================

function getISP(a, b, fallbackGeo) {
  let isp = "";

  if (a?.status === "success") {
    isp = a.isp || "";
  }

  if (!isp && b?.org) {
    isp = b.org.replace(/^AS\d+\s*/i, "");
  }

  if (!isp && a?.status === "success") {
    isp = a.org || a.asname || "";
  }

  if (!isp && fallbackGeo?.isp) {
    isp = fallbackGeo.isp.replace(/^AS\d+\s*/i, "");
  }

  return isp || "未知";
}

async function getGeo(ip, fallbackGeo) {
  if (!ip) return null;

  const [a, b] = await Promise.all([
    getJSON(
      CFG.geoAPI +
        encodeURIComponent(ip) +
        "?lang=zh-CN&fields=status,country,countryCode,city,regionName,isp,org,as,asname"
    ),
    getJSON(CFG.ipInfo + encodeURIComponent(ip) + "/json")
  ]);

  const geoOK = a?.status === "success";

  if (!geoOK && !b && !fallbackGeo) return null;

  const countryCode = String(
    (geoOK && a.countryCode) ||
      b?.country ||
      fallbackGeo?.countryCode ||
      ""
  ).toUpperCase();

  let country =
    (geoOK && a.country) ||
    b?.country ||
    fallbackGeo?.country ||
    "";

  const city =
    cleanAreaName(geoOK ? a.city : "") ||
    cleanAreaName(b?.city || "") ||
    cleanAreaName(fallbackGeo?.city || "");

  const region =
    cleanAreaName(geoOK ? a.regionName : "") ||
    cleanAreaName(b?.region || "") ||
    cleanAreaName(fallbackGeo?.region || "");

  const countryNames = {
    CN: "中国",
    HK: "香港",
    MO: "澳门",
    TW: "台湾"
  };

  if (countryNames[countryCode]) {
    country = countryNames[countryCode];
  }

  if (countryCode === "CN") {
    const municipality = getMunicipality(region) || getMunicipality(city);
    return {
      country: "中国",
      city: municipality || stripCitySuffix(city),
      area: "",
      isp: getISP(a, b, fallbackGeo)
    };
  }

  if (countryCode === "HK" || countryCode === "MO" || countryCode === "TW") {
    const genericByCode = {
      HK: ["hong kong", "hong kong sar", "香港", "香港特别行政区"],
      MO: ["macau", "macao", "澳门", "澳门特别行政区"],
      TW: ["taiwan", "taiwan province", "台湾", "台湾省"]
    };

    const generics = genericByCode[countryCode] || [];
    let area = "";

    if (region && !generics.includes(region.toLowerCase())) {
      area = normalizeSpecialArea(region, countryCode);
    }

    if (!area && city && !generics.includes(city.toLowerCase())) {
      area = normalizeSpecialArea(city, countryCode);
    }

    return {
      country: countryNames[countryCode],
      city: "",
      area: area,
      isp: getISP(a, b, fallbackGeo)
    };
  }

  return {
    country: country,
    city: city,
    area: "",
    isp: getISP(a, b, fallbackGeo)
  };
}

function formatLocation(geo) {
  if (!geo) return "未知";

  if (
    geo.country === "香港" ||
    geo.country === "澳门" ||
    geo.country === "台湾"
  ) {
    return [geo.country, geo.area].filter(Boolean).join(" · ") || "未知";
  }

  return [geo.country, geo.city, geo.area].filter(Boolean).join(" · ") || "未知";
}

// =====================================
// 17. 入口 IP 识别
// =====================================

function cleanRemoteIP(value) {
  if (!value || typeof value !== "string") {
    return null;
  }

  let ip = value.replace(/\s*\(Proxy\)\s*/ig, "").trim();

  if (ip.startsWith("[")) {
    const match = ip.match(/^\[([^\]]+)\](?::\d+)?$/);
    if (!match) return null;
    ip = match[1];
  } else {
    const match = ip.match(/^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/);
    if (match) {
      ip = match[1];
    }
  }

  const normalized = normalizeIP(ip);
  if (!normalized || isPrivateOrLoopbackIP(normalized)) {
    return null;
  }

  return normalized;
}

function queryRecentRequests() {
  return new Promise(resolve => {
    if (typeof $httpAPI !== "function") {
      resolve([]);
      return;
    }

    try {
      $httpAPI("GET", "/v1/requests/recent", null, result => {
        resolve(Array.isArray(result?.requests) ? result.requests : []);
      });
    } catch (e) {
      resolve([]);
    }
  });
}

function pickEntranceFromRequests(requests) {
  const pattern =
    /(my\.ippure\.com|1\.1\.1\.1|api-ipv4\.ip\.sb|api\.cleanip\.io|ip-api\.com|ipinfo\.io|scamalytics\.com|proxycheck\.io)/i;

  for (const item of requests) {
    if (!pattern.test(item?.URL || "")) {
      continue;
    }

    const remote = item?.remoteAddress || "";
    if (!/\(Proxy\)/i.test(remote)) {
      continue;
    }

    const ip = cleanRemoteIP(remote);
    if (ip) {
      return ip;
    }
  }

  return null;
}

async function getEntranceIP() {
  let ip = pickEntranceFromRequests(await queryRecentRequests());
  if (ip) return ip;

  // 若首次查询时请求日志尚未落盘，短暂停顿后再查一次
  await new Promise(resolve => setTimeout(resolve, 250));
  ip = pickEntranceFromRequests(await queryRecentRequests());
  return ip || null;
}

// =====================================
// 18. 面板信息块
// =====================================

function buildIPBlock(name, ip, geo) {
  return [
    `【${name}】`,
    `IP：${ip || "获取失败"}`,
    `地区：${formatLocation(geo)}`,
    `运营商：${geo?.isp || "未知"}`
  ].join("\n");
}

// =====================================
// 19. 总超时保护与主程序
// =====================================

totalTimer = setTimeout(() => {
  finish("检测超时，请手动刷新重试。", true);
}, CFG.totalTimeout * 1000);

(async () => {
  try {
    const sources = await getOutboundSources();
    const outboundIP = sources.ip;

    if (!outboundIP) {
      finish("落地 IP 获取失败，请检查网络。", true);
      return;
    }

    const pureData = getIPPureData(outboundIP, sources.sources.pureData);

    const [cleanData, proxyData, scamData, outboundGeo] = await Promise.all([
      getCleanIP(outboundIP),
      getProxyCheck(outboundIP),
      getScamalytics(outboundIP),
      getGeo(outboundIP, null)
    ]);

    // 若 ip-api 与 ipinfo 均未命中，用 CleanIP 附带的归属地做补充
    const resolvedOutboundGeo =
      outboundGeo || (cleanData?.geo ? await getGeo(outboundIP, cleanData.geo) : null);

    const entranceIP = await getEntranceIP();
    const entranceGeo = entranceIP ? await getGeo(entranceIP, null) : null;

    const riskResults = [cleanData, pureData, proxyData, scamData].filter(
      item => item && normalizeIP(item.ip) === normalizeIP(outboundIP)
    );

    const risk = calculateRisk(riskResults);
    const type = getIPType(cleanData, pureData, proxyData);

    // 面板保持你指定的简洁字段
    const content = [
      "【IP 信息】",
      `类型：${type.type}`,
      `属性：${type.attribute}`,
      `纯净度：${risk.text}`,
      "",
      buildIPBlock("入口 IP", entranceIP, entranceGeo),
      "",
      buildIPBlock("落地 IP", outboundIP, resolvedOutboundGeo)
    ].join("\n");

    const isError = sources.conflict || risk.score === null;

    finish(content, isError);
  } catch (e) {
    finish("检测异常：" + String(e), true);
  }
})();
