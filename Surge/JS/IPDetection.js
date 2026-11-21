
/**
 * Surge iOS 6 - IP 检测
 * 入口 IP / 落地 IP / 地区 / 运营商
 * IPPure 类型 / 风险评分
 */

const CFG = {
  timeout: 8,
  trace: "https://1.1.1.1/cdn-cgi/trace",
  fallbackIP: "https://api.ip.sb/geoip",
  ippure: "https://my.ippure.com/v1/info",
  ippureCard: "https://my.ippure.com/v1/card"
};

// 防止重复结束
let isDone = false;

function done(content) {
  if (isDone) return;
  isDone = true;

  $done({
    content: content,
    icon: "bolt.fill",
    "icon-color": "#30D158"
  });
}

// HTTP 请求
function get(url) {
  return new Promise(resolve => {
    try {
      $httpClient.get({
        url: url,
        timeout: CFG.timeout,
        headers: {
          "User-Agent": "Surge/6 IP-Panel"
        }
      }, (error, response, body) => {
        if (error || !response ||
            response.status < 200 ||
            response.status >= 300) {
          resolve(null);
        } else {
          resolve(body || null);
        }
      });
    } catch (e) {
      resolve(null);
    }
  });
}

// JSON
async function getJSON(url) {
  const body = await get(url);
  if (!body) return null;

  try {
    return JSON.parse(body);
  } catch (e) {
    return null;
  }
}

// 验证 IP
function validIP(ip) {
  if (typeof ip !== "string") return false;

  ip = ip.trim();

  const v4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(ip) &&
    ip.split(".").every(x => Number(x) <= 255);

  const v6 = ip.includes(":") &&
    /^[0-9a-f:]+$/i.test(ip) &&
    !ip.includes(":::");

  return v4 || v6;
}

// 获取 Cloudflare Trace
async function getTrace() {
  const body = await get(CFG.trace);
  if (!body) return null;

  const match = body.match(/^ip=(.+)$/m);
  const ip = match ? match[1].trim() : null;

  return validIP(ip) ? ip : null;
}

// 获取出口 IP
async function getOutboundIP() {
  let ip = await getTrace();

  if (!ip) {
    const data = await getJSON(CFG.fallbackIP);
    ip = data?.ip || null;
  }

  return validIP(ip) ? ip : null;
}

// IPPure 数据
async function getPure() {
  return await getJSON(CFG.ippure);
}

// IPPure 类型及评分
async function getPureInfo(ip, pure) {
  let residential = pure?.isResidential;
  let broadcast = pure?.isBroadcast;
  let score = pure?.fraudScore;

  // IPPure info 缺少类型或评分时，读取 card
  if (typeof residential !== "boolean" ||
      typeof broadcast !== "boolean" ||
      score === undefined || score === null) {

    const html = await get(CFG.ippureCard);

    if (html) {
      if (typeof residential !== "boolean") {
        if (/住宅|residential/i.test(html)) residential = true;
        else if (/机房|数据中心|datacenter|hosting/i.test(html))
          residential = false;
      }

      if (typeof broadcast !== "boolean") {
        if (/广播|broadcast|announced/i.test(html))
          broadcast = true;
        else if (/原生|native/i.test(html))
          broadcast = false;
      }

      if (score === undefined || score === null) {
        const match = html.match(
          /(\d{1,3})\s*%\s*(?:极度纯净|纯净|一般|微风险|一般风险|极度风险)/
        );
        if (match) score = Number(match[1]);
      }
    }
  }

  // 确认 IPPure 检测 IP 与当前出口一致
  const sameIP = validIP(pure?.ip) &&
    pure.ip.toLowerCase() === ip.toLowerCase();

  if (!sameIP) {
    return {
      type: "未知",
      source: "未知",
      risk: "检测失败"
    };
  }

  const type = typeof residential === "boolean"
    ? residential ? "住宅 IP" : "机房 IP"
    : "未知";

  const source = typeof broadcast === "boolean"
    ? broadcast ? "广播 IP" : "原生 IP"
    : "未知";

  const n = Number(score);

  let risk = "检测失败";

  if (score !== null && score !== undefined &&
      score !== "" && Number.isFinite(n) &&
      n >= 0 && n <= 100) {

    let level = "高风险";

    if (n <= 15) level = "极度纯净";
    else if (n <= 25) level = "纯净";
    else if (n <= 40) level = "一般";
    else if (n <= 50) level = "微风险";
    else if (n <= 70) level = "一般风险";

    risk = `风险值 ${n}% · ${level}`;
  }

  return { type, source, risk };
}

// 地区和运营商
async function getGeo(ip) {
  if (!ip) return null;

  const url = "http://ip-api.com/json/" +
    encodeURIComponent(ip) +
    "?fields=status,country,city,isp,org";

  const [a, b] = await Promise.all([
    getJSON(url),
    getJSON("https://ipinfo.io/" +
      encodeURIComponent(ip) + "/json")
  ]);

  const ok = a?.status === "success";

  if (!ok && !b) return null;

  let isp = ok ? (a.isp || a.org) : "";

  if (!isp && b?.org) {
    isp = b.org.replace(/^AS\d+\s*/i, "");
  }

  return {
    country: ok ? a.country : b?.country || "",
    city: ok ? a.city : b?.city || "",
    isp: isp || "未知"
  };
}

// 获取入口 IP
function getEntranceIP() {
  return new Promise(resolve => {
    if (typeof $httpAPI !== "function") {
      resolve(null);
      return;
    }

    try {
      $httpAPI("GET", "/v1/requests/recent", null, result => {
        const requests = result?.requests || [];

        const pattern =
          /(1\.1\.1\.1|api\.ip\.sb|my\.ippure\.com|ip-api\.com|ipinfo\.io)/i;

        const hit = requests.find(item =>
          pattern.test(item.URL || "") &&
          /\(Proxy\)/.test(item.remoteAddress || "")
        );

        if (!hit) {
          resolve(null);
          return;
        }

        let ip = hit.remoteAddress
          .replace(/\s*\(Proxy\)\s*/, "")
          .trim();

        // IPv6 带端口
        if (ip.startsWith("[")) {
          ip = ip.replace(/^\[([^\]]+)\](?::\d+)?$/, "$1");
        } else if ((ip.match(/:/g) || []).length === 1) {
          ip = ip.replace(/:\d+$/, "");
        }

        resolve(validIP(ip) ? ip : null);
      });
    } catch (e) {
      resolve(null);
    }
  });
}

// 显示地区，只保留国家和城市
function location(geo) {
  if (!geo) return "未知";

  return [geo.country, geo.city]
    .filter(Boolean)
    .join(" · ") || "未知";
}

// IP 信息区块
function ipBlock(title, ip, geo) {
  return [
    `【${title}】`,
    `IP：${ip || "获取失败"}`,
    `地区：${location(geo)}`,
    `运营商：${geo?.isp || "未知"}`
  ].join("\n");
}

// 主程序
(async () => {
  try {
    // 同时请求出口 IP 和 IPPure
    const [outboundIP, pure] = await Promise.all([
      getOutboundIP(),
      getPure()
    ]);

    if (!outboundIP) {
      done("出口 IP 获取失败，请检查代理连接。");
      return;
    }

    // IPPure 信息
    const pureInfo = await getPureInfo(outboundIP, pure);

    // 同时查询入口及出口地区
    const [entranceIP, outboundGeo] = await Promise.all([
      getEntranceIP(),
      getGeo(outboundIP)
    ]);

    // 入口地区
    const entranceGeo = entranceIP
      ? await getGeo(entranceIP)
      : null;

    const content = [
      "【IP 类型与纯净度】",
      `类型：${pureInfo.type}`,
      `属性：${pureInfo.source}`,
      `纯净度：${pureInfo.risk}`,
      "",
      ipBlock("入口 IP", entranceIP, entranceGeo),
      "",
      ipBlock("落地 IP", outboundIP, outboundGeo)
    ].join("\n");

    done(content);

  } catch (e) {
    done("检测异常：" + String(e));
  }
})();
