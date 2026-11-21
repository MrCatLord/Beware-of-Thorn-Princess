
/**
 * Surge iOS 6 - IP Detection
 * IP 类型 / 纯净度 / 入口 IP / 落地 IP
 *
 * 1. Cloudflare / IP.SB / IPPure 多源出口 IP 检测
 * 2. 多源一致性验证，异常分歧识别
 * 3. IPPure > ProxyCheck > Scamalytics 纯净度优先级
 */

// =====================================
// 1. 基础配置
// =====================================

const CFG = {
  timeout: 6,
  totalTimeout: 28,

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

const DEFAULT_TITLE = "IP信息";

let PANEL_TITLE = DEFAULT_TITLE;
let finished = false;

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

CFG.icon = args.panel_icon || CFG.icon;
CFG.iconColor = args.panel_color || CFG.iconColor;

// =====================================
// 3. 统一结束面板
// =====================================

function finish(content, isError) {
  if (finished) return;

  finished = true;

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

// =====================================
// 5. IP 地址校验与标准化
// =====================================

function normalizeIP(value) {
  if (typeof value !== "string") return null;

  let ip = value.trim().toLowerCase();

  // IPv4
  const ipv4 = ip.split(".");

  if (ipv4.length === 4) {
    if (!ipv4.every(part =>
      /^\d{1,3}$/.test(part) &&
      Number(part) >= 0 &&
      Number(part) <= 255
    )) {
      return null;
    }

    return ipv4.map(part =>
      String(Number(part))
    ).join(".");
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

  const left = parts[0]
    ? parts[0].split(":")
    : [];

  const right = compressed && parts[1]
    ? parts[1].split(":")
    : [];

  const all = left.concat(right);

  if (
    all.some(group =>
      !/^[0-9a-f]{1,4}$/.test(group)
    )
  ) {
    return null;
  }

  if (
    (!compressed && all.length !== 8) ||
    (compressed && all.length >= 8)
  ) {
    return null;
  }

  const groups = compressed
    ? left.concat(
        Array(8 - all.length).fill("0"),
        right
      )
    : all;

  const normalized = groups.map(group =>
    parseInt(group || "0", 16)
      .toString(16)
  );

  // IPv4-mapped IPv6
  if (
    normalized.slice(0, 5).every(x => x === "0") &&
    normalized[5] === "ffff"
  ) {
    const a = parseInt(normalized[6], 16);
    const b = parseInt(normalized[7], 16);

    return [
      a >> 8,
      a & 255,
      b >> 8,
      b & 255
    ].join(".");
  }

  return normalized.join(":");
}

function validIP(value) {
  return normalizeIP(value) !== null;
}

// =====================================
// 6. Cloudflare Trace
// =====================================

function parseTrace(body) {
  if (!body || typeof body !== "string") {
    return null;
  }

  const match = body.match(/^ip=(.+)$/m);

  return match
    ? normalizeIP(match[1])
    : null;
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

  const candidates = [
    results.cf,
    results.sb,
    results.pure
  ].filter(Boolean);

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

  // 多数一致优先
  // 无多数时：CF > IP.SB > IPPure
  if (maxCount < 2) {
    selected =
      results.cf ||
      results.sb ||
      results.pure;
  }

  return {
    ip: selected,
    conflict: Object.keys(counts).length > 1,
    count: candidates.length,
    sources: results
  };
}

// =====================================
// 8. IP 匹配
// =====================================

function pureMatchesIP(pure, ip) {
  return !!(
    pure &&
    normalizeIP(pure.ip) &&
    normalizeIP(pure.ip) === normalizeIP(ip)
  );
}

// =====================================
// 9. 评分校验
// =====================================

function validScore(value) {
  if (
    value === null ||
    value === undefined ||
    value === ""
  ) {
    return null;
  }

  const n = Number(value);

  return Number.isFinite(n) &&
    n >= 0 &&
    n <= 100
      ? n
      : null;
}

// =====================================
// 10. 布尔属性兼容解析
// =====================================

function parseBooleanFlag(value) {
  if (value === true || value === 1) {
    return true;
  }

  if (value === false || value === 0) {
    return false;
  }

  if (typeof value === "string") {
    const v = value.trim().toLowerCase();

    if (
      ["true", "1", "yes"].includes(v)
    ) {
      return true;
    }

    if (
      ["false", "0", "no"].includes(v)
    ) {
      return false;
    }
  }

  return null;
}

// =====================================
// 11. IPPure
// =====================================

function getIPPureData(ip, pure) {
  if (!pureMatchesIP(pure, ip)) {
    return null;
  }

  return {
    source: "IPPure",
    ip: normalizeIP(pure.ip),

    score: validScore(pure.fraudScore),

    residential: parseBooleanFlag(
      pure.isResidential
    ),

    broadcast: parseBooleanFlag(
      pure.isBroadcast
    )
  };
}

// =====================================
// 12. ProxyCheck
// =====================================

async function getProxyCheck(ip) {
  const data = await getJSON(
    CFG.proxyCheck +
    encodeURIComponent(ip) +
    "?vpn=1&risk=1"
  );

  if (
    !data ||
    data.status !== "ok" ||
    !data[ip]
  ) {
    return null;
  }

  const item = data[ip];

  const type = String(item.type || "")
    .toLowerCase();

  const proxy = String(item.proxy || "")
    .toLowerCase();

  let category = "未知";
  let residential = null;

  if (/residential/.test(type)) {
    category = "住宅 IP";
    residential = true;
  } else if (/mobile|wireless/.test(type)) {
    category = "移动/无线 IP";
    residential = true;
  } else if (/hosting|datacenter/.test(type)) {
    category = "机房 IP";
    residential = false;
  } else if (/business/.test(type)) {
    category = "商业 IP";
    residential = false;
  }

  return {
    source: "ProxyCheck",
    ip: normalizeIP(ip),

    score: validScore(item.risk),

    proxy:
      proxy === "yes" ? true :
      proxy === "no" ? false : null,

    type: category,
    residential: residential
  };
}

// =====================================
// 13. Scamalytics
// =====================================

async function getScamalytics(ip) {
  const html = await request(
    CFG.scamalytics + encodeURIComponent(ip)
  );

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
// 14. 纯净度优先级
// IPPure > ProxyCheck > Scamalytics
// =====================================

function calculateRisk(results) {
  const priority = [
    "IPPure",
    "ProxyCheck",
    "Scamalytics"
  ];

  for (const source of priority) {
    const item = results.find(result =>
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
// 15. IP 类型与原生 / 广播属性
// =====================================

function getIPType(pureData, proxyData) {
  let type = "未知";

  if (
    pureData &&
    typeof pureData.residential === "boolean"
  ) {
    if (pureData.residential) {
      type = "住宅 IP";
    } else if (
      proxyData &&
      proxyData.residential === false &&
      proxyData.type !== "未知"
    ) {
      type = proxyData.type;
    } else {
      type = "非住宅 IP";
    }
  } else if (
    proxyData &&
    proxyData.type !== "未知"
  ) {
    type = proxyData.type;
  }

  let attribute = "无法确认";

  if (
    pureData &&
    typeof pureData.broadcast === "boolean"
  ) {
    attribute = pureData.broadcast
      ? "广播 IP"
      : "原生 IP";
  }

  return {
    type: type,
    attribute: attribute
  };
}

// =====================================
// 16. 地区名称标准化
// =====================================

function cleanAreaName(value) {
  if (!value || typeof value !== "string") {
    return "";
  }

  return value
    .trim()
    .replace(/\s+/g, " ")
    .trim();
}

// 直辖市名称兼容
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

// 香港英文区名兼容
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

// 澳门英文堂区兼容
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

// 中国大陆城市后缀清理
function stripCitySuffix(value) {
  let name = cleanAreaName(value);

  return name
    .replace(/市$/, "")
    .replace(/地区$/, "")
    .replace(/自治州$/, "")
    .replace(/盟$/, "");
}

// 港澳台下一级地区清理
function normalizeSpecialArea(value, code) {
  let name = cleanAreaName(value);

  if (!name) return "";

  if (code === "HK") {
    const key = name.toLowerCase();

    if (HK_DISTRICTS[key]) {
      return HK_DISTRICTS[key];
    }

    return name
      .replace(/\s+district$/i, "")
      .replace(/区$/, "");
  }

  if (code === "MO") {
    const key = name.toLowerCase();

    if (MO_DISTRICTS[key]) {
      return MO_DISTRICTS[key];
    }

    return name
      .replace(/\s+(parish|district)$/i, "")
      .replace(/堂区$/, "")
      .replace(/区$/, "");
  }

  if (code === "TW") {
    return name
      .replace(/\s+(county|city)$/i, "")
      .replace(/县$/, "")
      .replace(/市$/, "");
  }

  return name;
}

// =====================================
// 17. 地区信息查询
// =====================================

async function getGeo(ip) {
  if (!ip) return null;

  const [a, b] = await Promise.all([
    getJSON(
      CFG.geoAPI +
      encodeURIComponent(ip) +
      "?lang=zh-CN&fields=status,country,countryCode,city,regionName,isp,org,as,asname"
    ),

    getJSON(
      CFG.ipInfo +
      encodeURIComponent(ip) +
      "/json"
    )
  ]);

  const geoOK = a?.status === "success";

  if (!geoOK && !b) return null;

  const countryCode = String(
    (geoOK && a.countryCode) ||
    b?.country ||
    ""
  ).toUpperCase();

  let country =
    (geoOK && a.country) ||
    b?.country ||
    "";

  const cityA = cleanAreaName(
    geoOK ? a.city : ""
  );

  const cityB = cleanAreaName(
    b?.city || ""
  );

  const regionA = cleanAreaName(
    geoOK ? a.regionName : ""
  );

  const regionB = cleanAreaName(
    b?.region || ""
  );

  let city = cityA || cityB;
  let region = regionA || regionB;

  const countryNames = {
    CN: "中国",
    HK: "香港",
    MO: "澳门",
    TW: "台湾"
  };

  if (countryNames[countryCode]) {
    country = countryNames[countryCode];
  }

  // 中国大陆
  if (countryCode === "CN") {
    const municipality =
      getMunicipality(region) ||
      getMunicipality(city);

    if (municipality) {
      city = municipality;
    } else {
      city = stripCitySuffix(city);
    }

    return {
      country: "中国",
      city: city,
      area: "",
      isp: getISP(a, b)
    };
  }

  // 香港
  if (countryCode === "HK") {
    const genericNames = [
      "hong kong",
      "hong kong sar",
      "香港",
      "香港特别行政区"
    ];

    let area = "";

    if (
      region &&
      !genericNames.includes(region.toLowerCase())
    ) {
      area = normalizeSpecialArea(region, "HK");
    }

    if (
      !area &&
      city &&
      !genericNames.includes(city.toLowerCase())
    ) {
      area = normalizeSpecialArea(city, "HK");
    }

    return {
      country: "香港",
      city: "",
      area: area,
      isp: getISP(a, b)
    };
  }

  // 澳门
  if (countryCode === "MO") {
    const genericNames = [
      "macau",
      "macao",
      "澳门",
      "澳门特别行政区"
    ];

    let area = "";

    if (
      region &&
      !genericNames.includes(region.toLowerCase())
    ) {
      area = normalizeSpecialArea(region, "MO");
    }

    if (
      !area &&
      city &&
      !genericNames.includes(city.toLowerCase())
    ) {
      area = normalizeSpecialArea(city, "MO");
    }

    return {
      country: "澳门",
      city: "",
      area: area,
      isp: getISP(a, b)
    };
  }

  // 台湾
  if (countryCode === "TW") {
    const genericNames = [
      "taiwan",
      "taiwan province",
      "台湾",
      "台湾省"
    ];

    let area = "";

    if (
      region &&
      !genericNames.includes(region.toLowerCase())
    ) {
      area = normalizeSpecialArea(region, "TW");
    }

    if (
      !area &&
      city &&
      !genericNames.includes(city.toLowerCase())
    ) {
      area = normalizeSpecialArea(city, "TW");
    }

    return {
      country: "台湾",
      city: "",
      area: area,
      isp: getISP(a, b)
    };
  }

  // 其他国家和地区
  return {
    country: country,
    city: city,
    area: "",
    isp: getISP(a, b)
  };
}

// =====================================
// 18. 运营商逐字段回退
// =====================================

function getISP(a, b) {
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

  return isp || "未知";
}

// =====================================
// 19. 地区格式
// =====================================

function formatLocation(geo) {
  if (!geo) return "未知";

  // 港澳台：直接显示地区名称 + 下辖地区
  if (
    geo.country === "香港" ||
    geo.country === "澳门" ||
    geo.country === "台湾"
  ) {
    return [
      geo.country,
      geo.area
    ].filter(Boolean).join(" · ");
  }

  return [
    geo.country,
    geo.city,
    geo.area
  ].filter(Boolean).join(" · ") || "未知";
}

// =====================================
// 20. 入口 IP 识别
// =====================================

function cleanRemoteIP(value) {
  if (!value || typeof value !== "string") {
    return null;
  }

  let ip = value
    .replace(/\s*\(Proxy\)\s*/ig, "")
    .trim();

  // IPv6 [地址]:端口
  if (ip.startsWith("[")) {
    const match = ip.match(/^\[([^\]]+)\](?::\d+)?$/);

    if (!match) return null;

    ip = match[1];
  } else {
    // IPv4:端口
    const match = ip.match(
      /^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/
    );

    if (match) {
      ip = match[1];
    }
  }

  return normalizeIP(ip);
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
            if (!pattern.test(item.URL || "")) {
              continue;
            }

            const remote = item.remoteAddress || "";

            if (!/\(Proxy\)/i.test(remote)) {
              continue;
            }

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

// =====================================
// 21. IP 信息块
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
// 22. 总超时保护
// =====================================

setTimeout(() => {
  finish(
    "检测超时，请手动刷新重试。",
    true
  );
}, CFG.totalTimeout * 1000);

// =====================================
// 23. 主程序
// =====================================

(async () => {
  try {
    // 获取出口 IP
    const sources = await getOutboundSources();

    const outboundIP = sources.ip;

    if (!outboundIP) {
      finish(
        "落地 IP 获取失败，请检查网络。",
        true
      );
      return;
    }

    // IPPure 必须与落地 IP 匹配
    const pureData = getIPPureData(
      outboundIP,
      sources.sources.pureData
    );

    // 并行执行检测
    const [
      proxyData,
      scamData,
      entranceIP,
      outboundGeo
    ] = await Promise.all([
      getProxyCheck(outboundIP),
      getScamalytics(outboundIP),
      getEntranceIP(),
      getGeo(outboundIP)
    ]);

    // 评分必须对应相同 IP
    const riskResults = [
      pureData,
      proxyData,
      scamData
    ].filter(item =>
      item &&
      normalizeIP(item.ip) === normalizeIP(outboundIP)
    );

    // 纯净度
    const risk = calculateRisk(riskResults);

    // IP 类型与属性
    const type = getIPType(
      pureData,
      proxyData
    );

    // 入口地区
    const entranceGeo = entranceIP
      ? await getGeo(entranceIP)
      : null;

    // 最终面板内容
    const content = [
      "【IP信息】",
      `类型：${type.type}`,
      `属性：${type.attribute}`,
      `纯净度：${risk.text}`,
      "",
      buildIPBlock(
        "入口 IP",
        entranceIP,
        entranceGeo
      ),
      "",
      buildIPBlock(
        "落地 IP",
        outboundIP,
        outboundGeo
      )
    ].join("\n");

    // 异常状态始终红色
    const isError =
      sources.conflict ||
      risk.score === null;

    finish(content, isError);

  } catch (e) {
    finish(
      "检测异常：" + String(e),
      true
    );
  }
})();
