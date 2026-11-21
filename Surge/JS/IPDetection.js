
/**
 * Surge iOS 6 - IP 检测
 * 入口 IP / 落地 IP / 地区 / 运营商
 * IPPure 类型 / 风险评分
 */

const CONFIG = {
  timeout: 8,
  ippure: "https://my.ippure.com/v1/info",
  ippureCard: "https://my.ippure.com/v1/card",
  ipify: "https://api.ipify.org?format=json",
  ipapi: "http://ip-api.com/json/",
  ipinfo: "https://ipinfo.io/",
  apiTimeout: 2500
};

let finished = false;
let watchdog = null;

function finish(data) {
  if (finished) return;
  finished = true;

  if (watchdog) clearTimeout(watchdog);

  $done({
    ...data,
    icon: "bolt.fill",
    "icon-color": "#30D158"
  });
}

// 总超时保护
watchdog = setTimeout(() => {
  finish({
    content: "检测超时，请检查网络或代理连接。"
  });
}, 18000);

// HTTP 请求
function request(url, timeout = CONFIG.timeout) {
  return new Promise(resolve => {
    let settled = false;

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      resolve(null);
    }, (timeout + 1) * 1000);

    try {
      $httpClient.get({
        url: url,
        timeout: timeout,
        headers: {
          "User-Agent": "Surge IP Check"
        }
      }, (error, response, body) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);

        if (error || !response ||
            response.status < 200 ||
            response.status >= 300) {
          resolve(null);
          return;
        }

        resolve(body || null);
      });
    } catch (e) {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        resolve(null);
      }
    }
  });
}

// JSON 请求
async function getJSON(url, timeout) {
  const body = await request(url, timeout);
  if (!body) return null;

  try {
    return JSON.parse(body);
  } catch (e) {
    return null;
  }
}

// IP 地址检查
function validIP(ip) {
  return typeof ip === "string" &&
    (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(ip) ||
     /^[0-9a-f:]+$/i.test(ip) && ip.includes(":"));
}

// 获取出口 IP
async function getOutbound(pure) {
  if (validIP(pure?.ip)) return pure.ip;

  const data = await getJSON(CONFIG.ipify);
  return validIP(data?.ip) ? data.ip : null;
}

// 获取 IP 地区与运营商
async function getGeo(ip) {
  if (!ip) return null;

  const [a, b] = await Promise.all([
    getJSON(
      CONFIG.ipapi + encodeURIComponent(ip) +
      "?fields=status,country,city,isp,org"
    ),
    getJSON(
      CONFIG.ipinfo + encodeURIComponent(ip) + "/json"
    )
  ]);

  const geoA = a?.status === "success";

  if (!geoA && !b) return null;

  let isp = geoA ? (a.isp || a.org) : "";

  if (!isp && b?.org) {
    isp = b.org.replace(/^AS\d+\s*/i, "");
  }

  return {
    country: geoA ? a.country : b?.country || "",
    city: geoA ? a.city : b?.city || "",
    isp: isp || "未知"
  };
}

// 获取入口 IP
function getEntranceIP() {
  return new Promise(resolve => {
    let settled = false;

    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        resolve(null);
      }
    }, CONFIG.apiTimeout);

    try {
      $httpAPI("GET", "/v1/requests/recent", null, result => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);

        const requests = result?.requests || [];

        const patterns =
          /(my\.ippure\.com|api\.ipify\.org|ip-api\.com|ipinfo\.io)/i;

        const hit = requests.find(item =>
          patterns.test(item.URL || "") &&
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
    } catch (e) {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        resolve(null);
      }
    }
  });
}

// IPPure 类型检测
async function getIPType(info) {
  let residential = info?.isResidential;
  let broadcast = info?.isBroadcast;

  // /v1/info 没有返回类型时，尝试官方卡片
  if (typeof residential !== "boolean" ||
      typeof broadcast !== "boolean") {

    const html = await request(CONFIG.ippureCard);

    if (html) {
      if (typeof residential !== "boolean") {
        if (/住宅|residential/i.test(html)) {
          residential = true;
        } else if (/机房|数据中心|datacenter|hosting/i.test(html)) {
          residential = false;
        }
      }

      if (typeof broadcast !== "boolean") {
        if (/广播|broadcast|announced/i.test(html)) {
          broadcast = true;
        } else if (/原生|native/i.test(html)) {
          broadcast = false;
        }
      }
    }
  }

  return {
    type: typeof residential === "boolean"
      ? residential ? "住宅 IP" : "机房 IP"
      : "未知",

    source: typeof broadcast === "boolean"
      ? broadcast ? "广播 IP" : "原生 IP"
      : "未知"
  };
}

// 风险等级
function riskLevel(score) {
  if (score <= 15) return "极度纯净";
  if (score <= 25) return "纯净";
  if (score <= 40) return "一般";
  if (score <= 50) return "微风险";
  if (score <= 70) return "一般风险";
  return "高风险";
}

// 地区只显示国家与城市
function formatGeo(geo) {
  if (!geo) return "未知";

  return [geo.country, geo.city]
    .filter(Boolean)
    .join(" · ") || "未知";
}

// IP 信息
function ipSection(name, ip, geo) {
  return [
    `【${name}】`,
    `IP：${ip || "获取失败"}`,
    `地区：${formatGeo(geo)}`,
    `运营商：${geo?.isp || "未知"}`
  ].join("\n");
}

// 主程序
(async () => {
  try {
    // 1. 获取 IPPure 原始数据
    const pure = await getJSON(CONFIG.ippure);

    // 2. 获取落地 IP
    const outboundIP = await getOutbound(pure);

    if (!outboundIP) {
      finish({
        content: "落地 IP 获取失败，请检查网络连接。"
      });
      return;
    }

    // 3. IPPure 类型及评分
    const typeInfo = await getIPType(pure);

    const scoreValue = pure?.fraudScore;
    const score = scoreValue !== null &&
      scoreValue !== undefined &&
      scoreValue !== "" &&
      Number.isFinite(Number(scoreValue)) &&
      Number(scoreValue) >= 0 &&
      Number(scoreValue) <= 100
        ? Number(scoreValue)
        : null;

    const risk = score === null
      ? "检测失败"
      : `风险值 ${score}% · ${riskLevel(score)}`;

    // 4. 查询地理信息
    const outboundGeoPromise = getGeo(outboundIP);

    // 5. 获取入口 IP
    const entranceIPPromise = getEntranceIP();

    const [outboundGeo, entranceIP] = await Promise.all([
      outboundGeoPromise,
      entranceIPPromise
    ]);

    // 6. 查询入口地区
    const entranceGeo = entranceIP
      ? await getGeo(entranceIP)
      : null;

    // 7. 最终面板
    const content = [
      "【IP 类型与纯净度】",
      `类型：${typeInfo.type}`,
      `属性：${typeInfo.source}`,
      `纯净度：${risk}`,
      "",
      ipSection("入口 IP", entranceIP, entranceGeo),
      "",
      ipSection("落地 IP", outboundIP, outboundGeo)
    ].join("\n");

    finish({ content });

  } catch (e) {
    finish({
      content: "检测异常：" + String(e)
    });
  }
})();
