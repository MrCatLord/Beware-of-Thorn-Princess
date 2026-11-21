/**
 * Surge Panel 入口 + 落地 IP 类型与纯净度检测脚本
 * 支持通过 $argument 配置国内入口中转信息（如 entry=上海入口 1.2.3.4）
 */

const args = parseArgs(typeof $argument !== "undefined" ? $argument : "");
const panelTitle = args.title || "IP Purity";
const configuredEntry = args.entry || ""; // 国内入口中转（可填 IP、城市或线路名称）

!(async () => {
  try {
    // 1. 尝试获取代理策略/节点名称（若 Surge 环境暴露了相关上下文）
    const policyName = detectPolicyName();

    // 2. 并发查询落地 IP 信息
    const [ipApiRes, ipWhoisRes] = await Promise.allSettled([
      httpGetJson("http://ip-api.com/json/?fields=status,message,country,regionName,city,isp,org,as,hosting,query", 6),
      httpGetJson("https://ipwho.is/", 6)
    ]);

    const main = ipApiRes.status === "fulfilled" && ipApiRes.value && ipApiRes.value.status === "success"
      ? ipApiRes.value
      : null;
    const backup = ipWhoisRes.status === "fulfilled" && ipWhoisRes.value && ipWhoisRes.value.success !== false
      ? ipWhoisRes.value
      : null;

    if (!main && !backup) {
      throw new Error("无法获取落地 IP 信息");
    }

    const exitIp = (main && main.query) || (backup && backup.ip) || "未知";
    const country = (main && main.country) || (backup && backup.country) || "";
    const city = (main && main.city) || (backup && backup.city) || "";
    const loc = [country, city].filter(Boolean).join(" ") || "未知地区";

    const orgRaw = (main && (main.isp || main.org)) || (backup && backup.connection && backup.connection.isp) || "未知";
    const asn = (main && main.as) || (backup && backup.connection && backup.connection.asn ? `AS${backup.connection.asn}` : "");

    // 3. 确定“入口”显示文本（优先用 argument 传入的 entry；否则提示未配置或显示策略名）
    const entryDisplay = configuredEntry
      ? configuredEntry
      : policyName
        ? `未填入口 (策略: ${policyName})`
        : "未配置 (可在参数填 entry)";

    // 4. 判断落地 IP 类型（机房/托管 vs 住宅/宽带）
    const isHosting = Boolean(
      (main && main.hosting === true) ||
      (backup && backup.connection && (backup.connection.type === "hosting" || backup.connection.type === "datacenter")) ||
      /cloud|hosting|datacenter|data center|server|vps|amazon|aws|google|microsoft|azure|digitalocean|linode|ovh|hetzner|vultr|cloudflare/i.test(orgRaw)
    );

    const ipType = isHosting ? "机房 / 托管 (Hosting)" : "住宅 / 宽带 (ISP)";
    const purity = evaluatePurity({ isHosting, orgRaw, asn });

    // 5. 图标与颜色
    let iconName = "checkmark.shield.fill";
    let iconColor = "#34C759";
    if (purity.level === "high_risk") {
      iconName = "exclamationmark.shield.fill";
      iconColor = "#FF3B30";
    } else if (purity.level === "medium_risk" || isHosting) {
      iconName = "shield.lefthalf.filled";
      iconColor = "#FFCC00";
    }

    const timeStr = formatTime(new Date());
    const content = [
      `入口中转: ${entryDisplay}`,
      `落地 IP: ${exitIp} (${loc})`,
      `所属网络: ${orgRaw}${asn ? ` [${asn}]` : ""}`,
      `IP 类型: ${ipType}`,
      `纯净度: ${purity.label} (${purity.detail})`,
      `更新时间: ${timeStr}`
    ].join("\n");

    $done({
      title: panelTitle,
      content,
      icon: iconName,
      "icon-color": iconColor
    });
  } catch (err) {
    const msg = err && err.message ? err.message : String(err || "未知错误");
    $done({
      title: panelTitle,
      content: `检测失败: ${msg}\n更新时间: ${formatTime(new Date())}`,
      icon: "xmark.shield.fill",
      "icon-color": "#FF3B30"
    });
  }
})();

function detectPolicyName() {
  try {
    if (typeof $environment !== "undefined" && $environment) {
      return $environment.policy || $environment.proxy || "";
    }
  } catch (_) {}
  return "";
}

function evaluatePurity({ isHosting, orgRaw, asn }) {
  const text = `${orgRaw} ${asn}`.toLowerCase();
  const highRiskKeywords = ["vpn", "proxy", "tor", "hosting", "datacenter", "colocation", "m247", "tzulo", "zenlayer", "datapacket"];
  const hitHigh = highRiskKeywords.some((k) => text.includes(k));

  if (!isHosting && !hitHigh) {
    return { level: "clean", label: "较高", detail: "非明显机房段" };
  }
  if (hitHigh && isHosting) {
    return { level: "medium_risk", label: "一般", detail: "机房/代理特征明显" };
  }
  return { level: "medium_risk", label: "中等", detail: "数据中心/托管 IP" };
}

function httpGetJson(url, timeoutSec = 6) {
  return new Promise((resolve, reject) => {
    $httpClient.get({ url, timeout: timeoutSec }, (error, response, data) => {
      if (error) {
        reject(error);
        return;
      }
      try {
        const parsed = typeof data === "string" ? JSON.parse(data) : data;
        resolve(parsed);
      } catch (e) {
        reject(e);
      }
    });
  });
}

function formatTime(date) {
  const pad = (n) => (n < 10 ? "0" + n : String(n));
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

function parseArgs(argStr) {
  const res = {};
  if (!argStr || typeof argStr !== "string") return res;
  argStr.split("&").forEach((pair) => {
    const idx = pair.indexOf("=");
    if (idx > 0) {
      res[pair.slice(0, idx).trim()] = decodeURIComponent(pair.slice(idx + 1).trim());
    }
  });
  return res;
}
