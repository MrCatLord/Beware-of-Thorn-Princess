
/**
 * Surge iOS 6 - IP 检测
 * 入口 IP / 落地 IP / 地区 / 运营商
 * IPPure 类型 / 风险评分
 */

const CFG = {
  timeout: 6,
  ippure: "https://my.ippure.com/v1/info",
  ippureCard: "https://my.ippure.com/v1/card",
  cfTrace: "https://1.1.1.1/cdn-cgi/trace",
  ipSB: "https://api-ipv4.ip.sb/geoip"
};

let finished = false;

// 面板标题：由 [Panel] 左侧名称控制
const PANEL_TITLE =
  typeof $input !== "undefined" && $input.panelName
    ? $input.panelName
    : "IP 信息";

// 统一结束
function finish(content, color) {
  if (finished) return;
  finished = true;

  $done({
    title: PANEL_TITLE,
    content: content,
    icon: "bolt.fill",
    "icon-color": color || "#30D158"
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
          "User-Agent": "Surge/6 IP Security Panel"
        }
      }, (error, response, body) => {
        if (error || !response ||
            response.status < 200 ||
            response.status >= 300) {
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

// JSON 请求
async function getJSON(url) {
  const body = await request(url);
  if (!body) return null;

  try {
    return JSON.parse(body);
  } catch (e) {
    return null;
  }
}

// IP 验证
function validIP(ip) {
  if (typeof ip !== "string") return false;
  ip = ip.trim();

  const ipv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(ip) &&
    ip.split(".").every(x => Number(x) >= 0 && Number(x) <= 255);

  const ipv6 = ip.includes(":") &&
    /^[0-9a-f:]+$/i.test(ip) &&
    !ip.includes(":::");

  return ipv4 || ipv6;
}

// 解析 Cloudflare Trace
function parseTrace(body) {
  if (!body || typeof body !== "string") return null;

  const match = body.match(/^ip=(.+)$/m);
  const ip = match ? match[1].trim() : null;

  return validIP(ip) ? ip : null;
}

// 获取落地 IP
async function getOutboundIP(pure) {
  // 优先采用 IPPure 返回的 IP
  if (validIP(pure?.ip)) return pure.ip;

  // Cloudflare 回退
  const trace = await request(CFG.cfTrace);
  const cfIP = parseTrace(trace);

  if (cfIP) return cfIP;

  // IP.SB 回退
  const sb = await getJSON(CFG.ipSB);
  return validIP(sb?.ip) ? sb.ip : null;
}

// 获取 IPPure 信息
async function getPure() {
  return await getJSON(CFG.ippure);
}

// IP 类型及风险评分
async function getIPSecurity(ip, pure) {
  let residential = pure?.isResidential;
  let broadcast = pure?.isBroadcast;
  let score = pure?.fraudScore;

  let card = null;

  // IPPure info 缺失时回退 card
  if (typeof residential !== "boolean" ||
      typeof broadcast !== "boolean" ||
      score === undefined || score === null) {

    card = await request(CFG.ippureCard);
  }

  // 类型回退
  if (typeof residential !== "boolean" && card) {
    if (/住宅|residential/i.test(card)) residential = true;
    else if (/机房|数据中心|datacenter|hosting/i.test(card))
      residential = false;
  }

  if (typeof broadcast !== "boolean" && card) {
    if (/广播|broadcast|announced/i.test(card)) broadcast = true;
    else if (/原生|native/i.test(card)) broadcast = false;
  }

  // IPPure 评分回退
  if ((score === undefined || score === null) && card) {
    const match = card.match(
      /(\d{1,3})\s*%\s*(极度纯净|纯净|一般|微风险|一般风险|极度风险)/
    );
    if (match) score = Number(match[1]);
  }

  // 类型再回退到 ProxyCheck
  if (typeof residential !== "boolean") {
    const pc = await getJSON(
      "https://proxycheck.io/v2/" +
      encodeURIComponent(ip) + "?vpn=1"
    );

    const type = pc?.[ip]?.type;

    if (type) {
      residential = /residential|wireless|mobile/i.test(type);
    }
  }

  // 风险评分最后回退 Scamalytics
  if (score === undefined || score === null) {
    const html = await request(
      "https://scamalytics.com/ip/" + encodeURIComponent(ip)
    );

    const match = html?.match(/Fraud Score[^0-9]*([0-9]{1,3})/i);

    if (match) score = Number(match[1]);
  }

  const type = typeof residential === "boolean"
    ? residential ? "住宅 IP" : "机房 IP"
    : "未知";

  const source = typeof broadcast === "boolean"
    ? broadcast ? "广播 IP" : "原生 IP"
    : "未知";

  let risk = "检测失败";

  const n = Number(score);

  if (score !== null && score !== undefined &&
      score !== "" && Number.isFinite(n) &&
      n >= 0 && n <= 100) {

    let level = "极度风险";

    if (n <= 15) level = "极度纯净";
    else if (n <= 25) level = "纯净";
    else if (n <= 40) level = "一般";
    else if (n <= 50) level = "微风险";
    else if (n <= 70) level = "一般风险";

    risk = `风险值 ${n}% · ${level}`;
  }

  return { type, source, risk };
}

// 查询地区及运营商
async function getGeo(ip) {
  if (!ip) return null;

  const [a, b] = await Promise.all([
    getJSON(
      "http://ip-api.com/json/" +
      encodeURIComponent(ip) +
      "?lang=zh-CN&fields=status,country,city,isp,org"
    ),
    getJSON(
      "https://ipinfo.io/" +
      encodeURIComponent(ip) + "/json"
    )
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

// 获取 Surge 入口 IP
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
          /(my\.ippure\.com|1\.1\.1\.1|api-ipv4\.ip\.sb|ip-api\.com|ipinfo\.io|scamalytics\.com|proxycheck\.io)/i;

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

        // IPv6 地址处理
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

// 地区格式：国家 + 城市
function formatLocation(geo) {
  if (!geo) return "未知";

  return [geo.country, geo.city]
    .filter(Boolean)
    .join(" · ") || "未知";
}

// IP 显示区块
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
    // 第一步：获取 IPPure 信息
    const pure = await getPure();

    // 第二步：获取落地 IP
    const outboundIP = await getOutboundIP(pure);

    if (!outboundIP) {
      finish("落地 IP 获取失败，请检查网络。", "#E5484D");
      return;
    }

    // 第三步：并行检测类型、风险、入口及落地地区
    const [security, entranceIP, outboundGeo] =
      await Promise.all([
        getIPSecurity(outboundIP, pure),
        getEntranceIP(),
        getGeo(outboundIP)
      ]);

    // 第四步：入口地区
    const entranceGeo = entranceIP
      ? await getGeo(entranceIP)
      : null;

    // 第五步：生成面板
    const content = [
      "【IP 类型与纯净度】",
      `类型：${security.type}`,
      `属性：${security.source}`,
      `纯净度：${security.risk}`,
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
