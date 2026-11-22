/**
* Surge iOS 6 - IP Detection
* IP 类型 / 纯净度 / 入口 IP / 落地 IP
* 
* 1. 多源出口 IP 探测与一致性交叉验证，CleanIP 参与投票；
* 无多数分歧时用全新连接复测 IPPure + CF 定案（已弃用频繁失败的 ipwho.is）
* 2. IPPure > ProxyCheck > Scamalytics 纯净度优先级，
* 面板显示按用户指定版式，内部改进不增加显示项
* 3. IP 类型引入 ip-api 的 mobile / proxy / hosting 强标志加权投票，
* 再由 CleanIP + IPPure + ProxyCheck 交叉辅助判断
* 4. 归属地：接入经真实 IP 实测挑选的来源阵容（ip-api + IPPure + ipquery +
* ipapi.is + db-ip + geojs 为主，ipinfo 降为弱参考），加权投票定国家，
* 地名只从国家一致的来源记录里取（不再跨源拼凑）：
* - 中国：直辖市只显示直辖市；其他显示 省份 + 城市
* - 香港 / 澳门 / 台湾：国家/地区名 + 下辖地区（泛称如 臺灣省 自动忽略）
* - 其他国家：国家 + 州/省 + 城市，国家名以任何语言重复出现时自动去重
* - 双语并列值（如“臺灣省 or 台灣省”）自动只取第一种写法
* 5. 入口 IP 在脚本启动时先等基线快照拍完再发探测，只对本轮新增请求投票，避免滞留上一轮入口；
*    且与落地详情并发检测，不再串行等待
* 6. 入口 IP 与落地 IP 相同时复用归属地结果，不重复查询
* 7. 节点名：出口探测请求带本轮唯一标记，节点名只认带标记的请求记录
*/


// =====================================
// 1. 基础配置
// =====================================

const CFG = {
timeout: 5,
totalTimeout: 16,

icon: "bolt.fill",
iconColor: "#30D158",
warnColor: "#FF9F0A",
errorColor: "#EF476F",

ippure: "https://my.ippure.com/v1/info",
cfTrace: "https://1.1.1.1/cdn-cgi/trace",
ipSB: "https://api-ipv4.ip.sb/geoip",

cleanIP: "https://api.cleanip.io/api/v2/",
proxyCheck: "https://proxycheck.io/v2/",
scamalytics: "https://scamalytics.com/ip/",

geoAPI: "http://ip-api.com/json/",
ipInfo: "https://ipinfo.io/",
ipQuery: "https://api.ipquery.io/",
ipapiIs: "https://api.ipapi.is/?ip=",
dbip: "https://api.db-ip.com/v2/free/",
geojs: "https://get.geojs.io/v1/ip/geo/"
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
if (!raw || typeof raw!== "string") return result;

raw.split("&").forEach(item => {
const index = item.indexOf("=");
if (index < 0) return;
try {
const key = decodeURIComponent(item.slice(0, index).replace(/\+/g, " "));
const value = decodeURIComponent(item.slice(index + 1).replace(/\+/g, " "));
result[key] = value;
} catch (e) {}
});

return result;
}

const args = parseArguments(typeof $argument === "string"? $argument: "");

PANEL_TITLE = args.panel_title || DEFAULT_TITLE;
CLEANIP_KEY = (args.cleanip_key || "").trim();

// 调试模式（模块参数加 debug=1 时开启）：把节点名解析过程附在面板末尾，定位用，平时不显示
const PANEL_DEBUG = args.debug === "1";
const DEBUG_LINES = [];
let probeFieldLogged = false;
function dbg(line) {
if (!PANEL_DEBUG) return;
DEBUG_LINES.push(String(line).slice(0, 110));
}

CFG.icon = args.panel_icon || CFG.icon;
CFG.iconColor = args.panel_color || CFG.iconColor;

if (args.timeout && Number(args.timeout) > 0) {
CFG.timeout = Math.min(Number(args.timeout), 15);
}
if (args.total_timeout && Number(args.total_timeout) > 0) {
CFG.totalTimeout = Math.min(Number(args.total_timeout), 30);
}

// =====================================
// 3. 统一结束面板（ok / warn / error 三态）
// =====================================

function finish(content, mode) {
if (finished) return;
finished = true;

if (totalTimer) {
clearTimeout(totalTimer);
totalTimer = null;
}

// 兼容旧调用：true = error，false/undefined = ok
const state = mode === true? "error": mode === "warn"? "warn": mode === "error"? "error": "ok";
const color = state === "error"? CFG.errorColor: state === "warn"? CFG.warnColor: CFG.iconColor;

$done({
title: PANEL_TITLE,
content: content,
icon: CFG.icon,
"icon-color": color
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
"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Version/18.0 Mobile/15E148 Safari/604.1",
"Cache-Control": "no-cache",
Connection: "close",
Pragma: "no-cache"
},
extraHeaders || {}
);

$httpClient.get({ url: url, timeout: CFG.timeout, headers: headers}, (error, response, body) => {
if (error ||!response || response.status < 200 || response.status >= 300) {
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
if (typeof value!== "string") return null;

let ip = value.trim().toLowerCase();
if (!ip) return null;

// IPv4 嵌入式 IPv6，如::ffff:1.2.3.4 / 64:ff9b::1.2.3.4
if (ip.includes(".") && ip.includes(":")) {
const match = ip.match(/(\d{1,3}(?:\.\d{1,3}){3})$/);
if (!match) return null;
const v4 = match[1].split(".").map(Number);
if (v4.some(n =>!Number.isFinite(n) || n < 0 || n > 255)) return null;

// IPv4-mapped 直接还原为 IPv4
const prefix = ip.slice(0, ip.length - match[1].length);
if (prefix === "::ffff:" || prefix === "0:0:0:0:0:ffff:") {
return v4.join(".");
}
const hi = ((v4[0] << 8) | v4[1]).toString(16);
const lo = ((v4[2] << 8) | v4[3]).toString(16);
ip = ip.slice(0, ip.length - match[1].length) + hi + ":" + lo;
}

// IPv4
const ipv4 = ip.split(".");
if (ipv4.length === 4 &&!ip.includes(":")) {
if (!ipv4.every(part => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255)) {
return null;
}
return ipv4.map(part => String(Number(part))).join(".");
}

// IPv6
if (!ip.includes(":")) return null;
if (!/^[0-9a-f:.]+$/i.test(ip)) return null;
if ((ip.match(/::/g) || []).length > 1) return null;

const compressed = ip.includes("::");
const parts = ip.split("::");
const left = parts[0]? parts[0].split(":"): [];
const right = compressed && parts[1]? parts[1].split(":"): [];
const all = left.concat(right);

if (all.some(group =>!/^[0-9a-f]{1,4}$/.test(group))) return null;
if ((!compressed && all.length!== 8) || (compressed && all.length > 7)) return null;

const groups = compressed? left.concat(Array(8 - all.length).fill("0"), right): all;
const normalized = groups.map(group => parseInt(group || "0", 16).toString(16));

// IPv4-mapped IPv6（十六进制形式）
if (normalized.slice(0, 5).every(x => x === "0") && normalized[5] === "ffff") {
const a = parseInt(normalized[6], 16);
const b = parseInt(normalized[7], 16);
return [a >> 8, a & 255, b >> 8, b & 255].join(".");
}

return normalized.join(":");
}

function isPrivateOrLoopbackIP(ip) {
if (!ip) return true;

if (ip.includes(".")) {
const p = ip.split(".").map(Number);
if (p[0] === 10 || p[0] === 127) return true;
if (p[0] === 192 && p[1] === 168) return true;
if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
if (p[0] === 169 && p[1] === 254) return true;
if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return true; // CGNAT 100.64.0.0/10
if (p[0] === 192 && p[1] === 0 && p[2] === 0) return true;
return false;
}

if (ip === "::1" || ip === "0:0:0:0:0:0:0:1") return true;
const first = parseInt(ip.split(":")[0] || "0", 16);
if (first >= 0xfe80 && first <= 0xfebf) return true; // fe80::/10 链路本地
if (first >= 0xfc00 && first <= 0xfdff) return true; // fc00::/7 唯一本地
return false;
}

// =====================================
// 6. Cloudflare Trace（IP + 国家码）
// =====================================

function parseTrace(body) {
if (!body || typeof body!== "string") return { ip: null, loc: ""};
const ipMatch = body.match(/^ip=(.+)$/m);
const locMatch = body.match(/^loc=(.+)$/m);
return {
ip: ipMatch? normalizeIP(ipMatch[1]): null,
loc: locMatch? locMatch[1].trim().toUpperCase(): ""
};
}

// =====================================
// 7. 多源出口 IP 检测与一致性交叉验证
// =====================================

function buildCleanIPHeaders() {
const headers = {};
if (CLEANIP_KEY) headers["X-API-Key"] = CLEANIP_KEY;
return headers;
}

function extractCleanIPAddress(raw) {
if (!raw || raw.ok === false) return null;
const payload = raw.data || raw;
return normalizeIP(payload?.ip || payload?.query);
}

function verifyOutboundConsistency(entries) {
const validEntries = entries.filter(e => e && e.ip);
if (!validEntries.length) {
return { ip: null, conflict: false, consensus: "none", count: 0, topCount: 0, votes: {}};
}

const sourceRank = { pure: 5, cf: 3, sb: 2, clean: 1};
const voteMap = {};

for (const item of validEntries) {
if (!voteMap[item.ip]) voteMap[item.ip] = { ip: item.ip, count: 0, sources: [], bestRank: 0};
voteMap[item.ip].count += 1;
voteMap[item.ip].sources.push(item.key);
const rank = sourceRank[item.key] || 0;
if (rank > voteMap[item.ip].bestRank) voteMap[item.ip].bestRank = rank;
}

const groups = Object.values(voteMap).sort((a, b) => {
if (b.count!== a.count) return b.count - a.count;
return b.bestRank - a.bestRank;
});

const top = groups[0];
const uniqueIPCount = groups.length;
const hasMajority = top.count >= 2 && top.count > validEntries.length / 2;
const isUnanimous = uniqueIPCount === 1 && validEntries.length >= 2;

return {
ip: top.ip,
conflict: uniqueIPCount > 1,
consensus: isUnanimous? "unanimous": hasMajority? "majority": "split",
count: validEntries.length,
topCount: top.count,
votes: voteMap
};
}

// 本轮唯一标记：拼到 IPPure / CF 两个探测请求的 URL 上。最近请求记录写入有
// 延迟，上一轮的记录会迟到混进列表，且与本轮记录 URL 完全相同、无从分辨——
// 这正是节点名总慢一拍的原因。带上每轮不同的标记后，只认带本轮标记的记录，
// 迟到的旧记录再像也不是本轮的。
let RUN_TAG = "";
function ensureRunTag() {
if (!RUN_TAG) {
RUN_TAG = "rt" + Date.now().toString(36) + Math.floor(Math.random() * 1679616).toString(36);
}
return RUN_TAG;
}
function tagged(url) {
return url + (url.includes("?") ? "&" : "?") + "v=" + ensureRunTag();
}

async function getOutboundSources() {
const [pure, traceBody, sb, cleanRaw] = await Promise.all([
getJSON(tagged(CFG.ippure)),
request(tagged(CFG.cfTrace)),
getJSON(CFG.ipSB),
getJSON(CFG.cleanIP + "?lang=zh", buildCleanIPHeaders())
]);

const trace = parseTrace(traceBody);

const results = {
cf: trace.ip,
cfLoc: trace.loc,
sb: normalizeIP(sb?.ip),
pure: normalizeIP(pure?.ip),
clean: extractCleanIPAddress(cleanRaw),
pureData: pure,
sbData: sb,
cleanRaw: cleanRaw
};

let entries = [
{ key: "cf", ip: results.cf},
{ key: "sb", ip: results.sb},
{ key: "pure", ip: results.pure},
{ key: "clean", ip: results.clean}
].filter(item => item.ip);

let verification = verifyOutboundConsistency(entries);

// 无多数分歧（split）时，用全新连接复测 IPPure + CF 两个高可信源，合并投票定案，
// 避免某一条探测被旧连接/旧路由带偏时把落地 IP 选错
if (verification.consensus === "split") {
const [pure2, traceBody2] = await Promise.all([getJSON(tagged(CFG.ippure)), request(tagged(CFG.cfTrace))]);
const trace2 = parseTrace(traceBody2);
const extra = [
{ key: "pure", ip: normalizeIP(pure2?.ip) },
{ key: "cf", ip: trace2.ip }
].filter(e => e.ip);
if (extra.length) {
entries = entries.concat(extra);
verification = verifyOutboundConsistency(entries);
}
}

return {
ip: verification.ip,
conflict: verification.conflict,
consensus: verification.consensus,
count: verification.count,
topCount: verification.topCount,
votes: verification.votes,
sources: results
};
}

// =====================================
// 8. 评分与布尔解析
// =====================================

function pureMatchesIP(pure, ip) {
return!!(pure && normalizeIP(pure.ip) && normalizeIP(pure.ip) === normalizeIP(ip));
}

function validScore(value) {
if (value === null || value === undefined || value === "") return null;
const n = Number(value);
return Number.isFinite(n) && n >= 0 && n <= 100? n: null;
}

function parseBooleanFlag(value) {
if (value === true || value === 1) return true;
if (value === false || value === 0) return false;
if (typeof value === "string") {
const v = value.trim().toLowerCase();
if (["true", "1", "yes"].includes(v)) return true;
if (["false", "0", "no"].includes(v)) return false;
}
return null;
}

function mapIPCategory(rawType) {
const s = String(rawType || "").toLowerCase();
if (!s) return { category: "未知", residential: null};
if (/residential|home|broadband|住宅/.test(s)) return { category: "住宅 IP", residential: true};
if (/mobile|wireless|cellular|移动|蜂窝/.test(s)) return { category: "移动/无线 IP", residential: true};
if (/hosting|datacenter|idc|cloud|机房|数据中心/.test(s)) return { category: "机房 IP", residential: false};
if (/business|commercial|corporate|商业|企业/.test(s)) return { category: "商业 IP", residential: false};
return { category: "未知", residential: null};
}

// =====================================
// 9. CleanIP（类型/属性与归属地兜底，不参与纯净度评分）
// =====================================

function parseCleanIPPayload(raw, targetIP) {
if (!raw || raw.ok === false) return null;

const payload = raw.data || raw;
const resolvedIP = normalizeIP(payload?.ip || payload?.query || targetIP);
if (!resolvedIP || (targetIP && resolvedIP!== normalizeIP(targetIP))) return null;

const rawType = payload.ipType || payload.type || payload.network?.type || payload.classification?.type || "";
const mapped = mapIPCategory(rawType);

const isResidential =
parseBooleanFlag(payload.isResidential?? payload.residential?? payload.network?.isResidential)?? mapped.residential;

const isBroadcast = parseBooleanFlag(payload.isBroadcast?? payload.broadcast?? payload.network?.isBroadcast);

const geoObj = payload.geo || payload.location || {};
const netObj = payload.network || payload.asn || {};

return {
source: "CleanIP",
ip: resolvedIP,
type: mapped.category,
residential: isResidential,
broadcast: isBroadcast,
geo: {
countryCode: String(geoObj.countryCode || geoObj.country_code || payload.countryCode || "").toUpperCase(),
country: geoObj.country || payload.country || "",
region: geoObj.region || geoObj.regionName || payload.region || "",
city: geoObj.city || payload.city || "",
isp: netObj.isp || netObj.org || netObj.asName || payload.isp || payload.org || ""
}
};
}

async function getCleanIP(ip, cachedRaw) {
const cached = parseCleanIPPayload(cachedRaw, ip);
if (cached) return cached;
const url = CFG.cleanIP + encodeURIComponent(ip) + "?lang=zh&detail=full";
const data = await getJSON(url, buildCleanIPHeaders());
return parseCleanIPPayload(data, ip);
}

// =====================================
// 10. IPPure
// =====================================

function getIPPureData(ip, pure) {
if (!pureMatchesIP(pure, ip)) return null;
return {
source: "IPPure",
ip: normalizeIP(pure.ip),
score: validScore(pure.fraudScore),
residential: parseBooleanFlag(pure.isResidential),
broadcast: parseBooleanFlag(pure.isBroadcast),
geo: {
countryCode: String(pure.countryCode || pure.country_code || pure.countrycode || "").toUpperCase(),
country: pure.country || "",
region: pure.region || pure.regionName || pure.state || "",
city: pure.city || "",
isp: pure.isp || pure.org || pure.organization || pure.asnName || ""
}
};
}

// =====================================
// 11. ProxyCheck
// =====================================

async function getProxyCheck(ip) {
const data = await getJSON(CFG.proxyCheck + encodeURIComponent(ip) + "?vpn=1&risk=1");
if (!data || data.status!== "ok") return null;

// 键名以查询 IP 为准；个别 IPv6 规范化差异时退回取唯一结果项
let item = data[ip];
if (!item) {
const keys = Object.keys(data).filter(k => normalizeIP(k));
if (keys.length === 1) item = data[keys[0]];
}
if (!item) return null;

const mapped = mapIPCategory(item.type);
return {
source: "ProxyCheck",
ip: normalizeIP(ip),
score: validScore(item.risk),
type: mapped.category,
residential: mapped.residential,
broadcast: null,
proxy: parseBooleanFlag(item.proxy),
vpn: parseBooleanFlag(item.vpn)
};
}

// =====================================
// 12. Scamalytics（先校验页面确含目标 IP，再提取分数）
// =====================================

async function getScamalytics(ip) {
const html = await request(CFG.scamalytics + encodeURIComponent(ip));
if (!html) return null;
if (!html.includes(ip)) return null;

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
if (score!== null) break;
}
}
if (score === null) return null;

return { source: "Scamalytics", ip: normalizeIP(ip), score: score};
}

// =====================================
// 13. 纯净度计算（IPPure > ProxyCheck > Scamalytics，标注来源与分歧）
// =====================================

function calculateRisk(results) {
const scored = results.filter(r => r && r.score!== null && r.score!== undefined);
const scores = scored.map(r => r.score);
const divergent = scores.length >= 2 && Math.max(...scores) - Math.min(...scores) > 30;

const priority = ["IPPure", "ProxyCheck", "Scamalytics"];
for (const source of priority) {
const item = scored.find(r => r.source === source);
if (!item) continue;

const score = item.score;
let level = "一般";
if (score <= 10) level = "极低风险";
else if (score <= 25) level = "低风险";
else if (score <= 40) level = "较低风险";
else if (score <= 60) level = "中等风险";
else if (score <= 80) level = "较高风险";
else level = "高风险";

return {
text: `${score.toFixed(0)} / 100 · ${level}`,
score: score,
source: source,
divergent: divergent
};
}

return { text: "无法判断", score: null, source: null, divergent: false};
}

// =====================================
// 14. 多源交叉验证：IP 类型与原生 / 广播属性
// 新增 ip-api 强标志：hosting / mobile / proxy（权重最高）
// =====================================

function getIPType(pureData, proxyData, cleanData, apiFlags) {
const flags = apiFlags || {};
let resScore = 0;
let nonResScore = 0;

const vote = (residential, weight) => {
if (residential === true) resScore += weight;
else if (residential === false) nonResScore += weight;
};

// ip-api 强标志权重 3
if (flags.mobile === true) resScore += 3;
if (flags.hosting === true) nonResScore += 3;

vote(pureData?.residential, 2); // IPPure 权重 2
vote(cleanData?.residential, 1.5); // CleanIP 权重 1.5
vote(proxyData?.residential, 1.5); // ProxyCheck 权重 1.5

let type = "未知";
if (flags.mobile === true && flags.hosting!== true) {
type = "移动/无线 IP";
} else if (resScore > nonResScore) {
const detailed = [cleanData, proxyData].find(s => s && s.residential === true && s.type && s.type!== "未知");
type = detailed? detailed.type: "住宅 IP";
} else if (nonResScore > resScore) {
if (flags.hosting === true) {
type = "机房 IP";
} else {
const detailed = [cleanData, proxyData].find(s => s && s.residential === false && s.type && s.type!== "未知");
type = detailed? detailed.type: "非住宅 IP";
}
} else {
const fallbackType = [cleanData, proxyData].find(s => s && s.type && s.type!== "未知");
if (fallbackType) type = fallbackType.type;
else if (pureData && typeof pureData.residential === "boolean") type = pureData.residential? "住宅 IP": "非住宅 IP";
}

// 原生 / 广播属性（IPPure 优先，CleanIP 印证/补全）
let attribute = "无法确认";
const pureBroadcast = pureData && typeof pureData.broadcast === "boolean"? pureData.broadcast: null;
const cleanBroadcast = cleanData && typeof cleanData.broadcast === "boolean"? cleanData.broadcast: null;
if (pureBroadcast!== null) attribute = pureBroadcast? "广播 IP": "原生 IP";
else if (cleanBroadcast!== null) attribute = cleanBroadcast? "广播 IP": "原生 IP";

return { type: type, attribute: attribute};
}

// =====================================
// 15. 地区名称标准化
// =====================================

function cleanAreaName(value) {
if (!value || typeof value!== "string") return "";
return value.trim().replace(/\s+/g, " ");
}

const MUNICIPALITIES = {
北京: "北京", 北京市: "北京", beijing: "北京", "beijing shi": "北京",
上海: "上海", 上海市: "上海", shanghai: "上海", "shanghai shi": "上海",
天津: "天津", 天津市: "天津", tianjin: "天津", "tianjin shi": "天津",
重庆: "重庆", 重庆市: "重庆", chongqing: "重庆", "chongqing shi": "重庆"
};

function getMunicipality(value) {
return MUNICIPALITIES[cleanAreaName(value).toLowerCase()] || "";
}

// 中国省份英文名 -> 中文名（ipinfo 等英文源兜底用）
const CN_PROVINCE_EN = {
anhui: "安徽", fujian: "福建", gansu: "甘肃", guangdong: "广东", guizhou: "贵州",
hainan: "海南", hebei: "河北", heilongjiang: "黑龙江", henan: "河南", hubei: "湖北",
hunan: "湖南", jiangsu: "江苏", jiangxi: "江西", jilin: "吉林", liaoning: "辽宁",
qinghai: "青海", shaanxi: "陕西", shandong: "山东", shanxi: "山西", sichuan: "四川",
yunnan: "云南", zhejiang: "浙江",
"guangxi": "广西", "inner mongolia": "内蒙古", "nei mongol": "内蒙古",
ningxia: "宁夏", xinjiang: "新疆", xizang: "西藏", tibet: "西藏"
};

function normalizeProvinceCN(value) {
let name = cleanAreaName(value);
if (!name) return "";
const en = CN_PROVINCE_EN[name.toLowerCase()];
if (en) return en;
// 去行政后缀（长后缀优先）
name = name
.replace(/维吾尔自治区$/, "")
.replace(/壮族自治区$/, "")
.replace(/回族自治区$/, "")
.replace(/特别行政区$/, "")
.replace(/自治区$/, "")
.replace(/省$/, "");
return name;
}

function stripCitySuffix(value) {
return cleanAreaName(value)
.replace(/市$/, "")
.replace(/地区$/, "")
.replace(/自治州$/, "")
.replace(/盟$/, "");
}

const HK_DISTRICTS = {
"central and western": "中西区", "central and western district": "中西区",
"eastern": "东区", "eastern district": "东区",
"southern": "南区", "southern district": "南区",
"wan chai": "湾仔", "wan chai district": "湾仔",
"kowloon city": "九龙城", "kowloon city district": "九龙城",
"kwun tong": "观塘", "kwun tong district": "观塘",
"sham shui po": "深水埗", "sham shui po district": "深水埗",
"wong tai sin": "黄大仙", "wong tai sin district": "黄大仙",
"yau tsim mong": "油尖旺", "yau tsim mong district": "油尖旺",
"islands": "离岛", "islands district": "离岛",
"kwai tsing": "葵青", "kwai tsing district": "葵青",
"north": "北区", "north district": "北区",
"sai kung": "西贡", "sai kung district": "西贡",
"sha tin": "沙田", "sha tin district": "沙田",
"tai po": "大埔", "tai po district": "大埔",
"tsuen wan": "荃湾", "tsuen wan district": "荃湾",
"tuen mun": "屯门", "tuen mun district": "屯门",
"yuen long": "元朗", "yuen long district": "元朗"
};

const MO_DISTRICTS = {
"nossa senhora de fatima": "花地玛", "nossa senhora de fátima": "花地玛",
"santo antonio": "圣安多尼", "santo antónio": "圣安多尼",
"sao lazaro": "望德堂", "são lázaro": "望德堂",
"se": "大堂", "sé": "大堂",
"sao lourenco": "风顺堂", "são lourenço": "风顺堂",
"nossa senhora do carmo": "嘉模", "cotai": "路氹", "coloane": "路环"
};

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
const TW_CITIES_EN = {
taipei: "台北", "new taipei": "新北", taoyuan: "桃园", taichung: "台中",
tainan: "台南", kaohsiung: "高雄", keelung: "基隆", hsinchu: "新竹", chiayi: "嘉义"
};
const en = TW_CITIES_EN[name.toLowerCase()];
if (en) return en;
return name.replace(/\s+(county|city)$/i, "").replace(/县$/, "").replace(/市$/, "");
}
return name;
}

// =====================================
// 16. 多源归属地交叉验证
// 来源阵容（均经真实 IP 实测挑选）：ip-api（中文名+类型标志）、IPPure（探测响应）、
// ipquery、ipapi.is、db-ip、geojs（实测型，对中转/广播 IP 更准）、ipinfo（弱参考）、
// CleanIP / ip.sb / CF（已抓数据兜底）。
// 每个来源先整理成一条独立记录 {code, country, region, city, isp}；
// 国家代码投票定下国家后，地名只从“国家一致”的记录里按优先级取，
// 不再跨来源拼凑（杜绝 香港 + 臺灣省 这类混合结果）；显示时统一去重
// （杜绝 新加坡 · North West · 新加坡 这类国家名重复）。
// =====================================

// 加权投票：IPPure 是实测出口的服务、权重最高（3）；ip-api / ipquery / ipapi.is（2）；
// db-ip / geojs / ipinfo / CF 权重 1；CleanIP / ip.sb 只提供字段兜底、不参与国家
// 投票（权重 0）——按号段注册地判定的库会把中转节点的落地 IP 误判到注册国
// （如 Kirino 的台湾出口被 ipinfo 判香港），实测类来源必须能压过它们。
// 同分时由支持方里的最高权重决定。
function voteCountryCode(records) {
const tally = {};
for (const r of records || []) {
const c = String(r?.code || "").trim().toUpperCase();
if (!/^[A-Z]{2}$/.test(c)) continue;
const w = typeof r.weight === "number"? r.weight: 1;
if (!tally[c]) tally[c] = { score: 0, best: 0 };
tally[c].score += w;
if (w > tally[c].best) tally[c].best = w;
}
const sorted = Object.entries(tally).sort((a, b) => b[1].score - a[1].score || b[1].best - a[1].best);
return sorted.length? sorted[0][0]: "";
}

// 繁体 -> 简体（地名常用字）：部分来源对港澳台及海外地区返回繁体名
// （如 臺北 / 桃園 / 觀塘），显示前统一转简体。
const TRAD_TO_SIMP = {
"臺": "台", "灣": "湾", "廣": "广", "東": "东", "門": "门", "區": "区", "縣": "县",
"鄉": "乡", "鎮": "镇", "島": "岛", "嶼": "屿", "龍": "龙", "鳳": "凤", "馬": "马",
"雲": "云", "蘭": "兰", "蓮": "莲", "園": "园", "義": "义", "橋": "桥", "頭": "头",
"圍": "围", "溝": "沟", "漁": "渔", "興": "兴", "榮": "荣", "華": "华", "萬": "万",
"豐": "丰", "樂": "乐", "寶": "宝", "樹": "树", "葉": "叶", "蘆": "芦", "崙": "仑",
"嶺": "岭", "岡": "冈", "場": "场", "廠": "厂", "廟": "庙", "宮": "宫", "濱": "滨",
"澤": "泽", "潤": "润", "滬": "沪", "長": "长", "慶": "庆", "壽": "寿", "強": "强",
"寧": "宁", "龜": "龟", "鹽": "盐", "鐵": "铁", "銅": "铜", "銀": "银", "錦": "锦",
"鏡": "镜", "鐘": "钟", "關": "关", "陽": "阳", "陰": "阴", "陳": "陈", "鄭": "郑",
"劉": "刘", "楊": "杨", "黃": "黄", "蕭": "萧", "賴": "赖", "謝": "谢", "鍾": "钟",
"盧": "卢", "顏": "颜", "許": "许", "鄧": "邓", "馮": "冯", "於": "于", "餘": "余",
"單": "单", "雙": "双", "壢": "坜", "楓": "枫", "機": "机", "國": "国", "際": "际",
"學": "学", "醫": "医", "館": "馆", "廳": "厅", "處": "处", "線": "线", "號": "号",
"樓": "楼", "層": "层", "棟": "栋", "鄰": "邻", "愛": "爱", "恆": "恒", "舊": "旧",
"遠": "远", "內": "内", "圓": "圆", "後": "后", "魚": "鱼", "鳥": "鸟", "鷹": "鹰",
"鶴": "鹤", "鴨": "鸭", "鵝": "鹅", "雞": "鸡", "豬": "猪", "貓": "猫", "貝": "贝",
"蝦": "虾", "蠔": "蚝", "鑽": "钻", "貴": "贵", "麗": "丽", "觀": "观", "賞": "赏",
"遊": "游", "舖": "铺", "礦": "矿", "電": "电", "燈": "灯", "車": "车", "飛": "飞",
"風": "风", "霧": "雾", "峽": "峡", "灘": "滩", "碼": "码", "徑": "径", "莊": "庄",
"將": "将", "軍": "军", "調": "调", "顯": "显", "烏": "乌", "環": "环", "來": "来",
"亞": "亚", "檳": "槟", "靂": "雳", "繩": "绳", "韓": "韩", "圖": "图", "書": "书",
"體": "体", "運": "运", "動": "动", "購": "购", "業": "业", "農": "农", "聽": "听",
"濤": "涛", "鰂": "鲗", "廈": "厦", "匯": "汇", "瀋": "沈", "魯": "鲁", "遼": "辽",
"連": "连", "營": "营", "盤": "盘", "鋼": "钢", "順": "顺", "蓋": "盖", "綏": "绥",
"啟": "启", "瓊": "琼", "瑪": "玛", "爾": "尔", "齊": "齐", "澀": "涩", "澁": "涩"
};

function toSimplified(s) {
if (!s || typeof s !== "string") return s || "";
let out = "";
for (const ch of s) out += TRAD_TO_SIMP[ch] || ch;
return out;
}

function sanitizeAreaName(value) {
let s = cleanAreaName(value);
if (!s) return "";
// 个别数据库返回“臺灣省 or 台灣省”这类双语并列值，只取第一种写法
if (s.includes(" or ")) s = s.split(" or ")[0].trim();
return toSimplified(s);
}

// 各来源整理成统一记录；prio 越小优先级越高：
// ip-api（中文名）> 已抓兜底（IPPure 等）> ipquery > ipapi.is > db-ip > geojs > ipinfo
function buildGeoRecords(a, b, extras, fallbacks) {
const records = [];
if (a?.status === "success") {
records.push({
code: String(a.countryCode || "").toUpperCase(),
country: a.country || "",
region: a.regionName || "",
city: a.city || "",
isp: a.isp || a.org || a.asname || "",
prio: 0,
weight: 2
});
}
for (const f of fallbacks || []) {
if (!f) continue;
records.push({
code: String(f.countryCode || "").toUpperCase(),
country: f.country || "",
region: f.region || "",
city: f.city || "",
isp: f.isp || "",
prio: 1,
weight: typeof f.w === "number"? f.w: 1
});
}
for (const r of extras || []) {
if (r) records.push(r);
}
if (b) {
records.push({
code: String(b.country || "").toUpperCase(),
country: "",
region: b.region || "",
city: b.city || "",
isp: b.org? String(b.org).replace(/^AS\d+\s*/i, ""): "",
prio: 6,
weight: 1
});
}
return records;
}


const GEO_COUNTRY_NAMES = {
CN: "中国", HK: "香港", MO: "澳门", TW: "台湾", SG: "新加坡",
JP: "日本", KR: "韩国", US: "美国", GB: "英国", DE: "德国",
FR: "法国", AU: "澳大利亚", CA: "加拿大", NL: "荷兰", CH: "瑞士",
IT: "意大利", ES: "西班牙", RU: "俄罗斯", IN: "印度", TH: "泰国",
VN: "越南", MY: "马来西亚", ID: "印度尼西亚", PH: "菲律宾", TR: "土耳其"
};

// 同一国家的其他语言写法（用于识别“城市名其实就是国家名”的重复）
const GEO_COUNTRY_ALIASES = {
CN: ["china"], HK: ["hong kong"], MO: ["macau", "macao"], TW: ["taiwan"],
SG: ["singapore"], JP: ["japan"], KR: ["south korea", "korea", "republic of korea"],
US: ["united states", "united states of america", "usa"],
GB: ["united kingdom", "uk", "great britain"], DE: ["germany"], FR: ["france"],
AU: ["australia"], CA: ["canada"], NL: ["netherlands", "holland"],
CH: ["switzerland"], IT: ["italy"], ES: ["spain"], RU: ["russia", "russian federation"],
IN: ["india"], TH: ["thailand"], VN: ["vietnam"], MY: ["malaysia"],
ID: ["indonesia"], PH: ["philippines"], TR: ["turkey", "türkiye"]
};

// ipapi.is 只返回国家英文名，用别名表反查国家代码
const EN_NAME_TO_CODE = {};
for (const [code, names] of Object.entries(GEO_COUNTRY_ALIASES)) {
for (const n of names) EN_NAME_TO_CODE[n] = code;
}
Object.assign(EN_NAME_TO_CODE, {
china: "CN", "hong kong": "HK", taiwan: "TW", singapore: "SG", japan: "JP",
"south korea": "KR", "united states": "US", "united kingdom": "GB"
});

async function getGeo(ip, fallbackGeos) {
if (!ip) return null;
const fallbacks = (fallbackGeos || []).filter(Boolean);

const [a, b, ipq, iis, dbi, gjs] = await Promise.all([
getJSON(
CFG.geoAPI +
encodeURIComponent(ip) +
"?lang=zh-CN&fields=status,country,countryCode,city,regionName,isp,org,as,asname,mobile,proxy,hosting"
),
getJSON(CFG.ipInfo + encodeURIComponent(ip) + "/json"),
getJSON(CFG.ipQuery + encodeURIComponent(ip)),
getJSON(CFG.ipapiIs + encodeURIComponent(ip)),
getJSON(CFG.dbip + encodeURIComponent(ip)),
getJSON(CFG.geojs + encodeURIComponent(ip) + ".json")
]);

// 新增实测型来源（对中转/广播 IP 的实际使用地判定明显更准）：
// ipquery（权重 2）、ipapi.is（权重 2）、db-ip（权重 1）、geojs（权重 1）
const extras = [
ipq?.location?.country_code
? {
code: String(ipq.location.country_code).toUpperCase(),
country: ipq.location.country || "",
region: ipq.location.state || "",
city: ipq.location.city || "",
isp: ipq.isp?.isp || ipq.isp?.org || "",
prio: 2,
weight: 2
}
: null,
iis?.country
? {
code: EN_NAME_TO_CODE[String(iis.country).trim().toLowerCase()] || "",
country: iis.country || "",
region: iis.region || "",
city: iis.city || "",
isp: iis.company || iis.asn || "",
prio: 3,
weight: 2
}
: null,
dbi?.countryCode
? {
code: String(dbi.countryCode).toUpperCase(),
country: dbi.countryName || "",
region: dbi.stateProv || "",
city: dbi.city || "",
isp: "",
prio: 4,
weight: 1
}
: null,
gjs?.country_code
? {
code: String(gjs.country_code).toUpperCase(),
country: gjs.country || "",
region: gjs.region || "",
city: gjs.city || "",
isp: gjs.organization_name || "",
prio: 5,
weight: 1
}
: null
];

const apiOK = a?.status === "success";
const records = buildGeoRecords(apiOK? a: null, b, extras, fallbacks);
if (!records.length) return null;

// 国家：用代码加权投票，避免中英文字符串对不上
const countryCode = voteCountryCode(records);

// 一致性过滤：地名只取国家代码与胜出代码相同的记录；
// 没有代码的记录仅在无一致记录时兜底，再不行才用全部记录。
let consistent = records.filter(r => r.code && r.code === countryCode);
if (!consistent.length) consistent = records.filter(r =>!r.code);
if (!consistent.length) consistent = records.slice();
consistent.sort((x, y) => x.prio - y.prio);

const country =
GEO_COUNTRY_NAMES[countryCode] ||
sanitizeAreaName((consistent.find(r => r.country) || {}).country || "") ||
countryCode;

const pickField = field => {
for (const r of consistent) {
const v = sanitizeAreaName(r[field]);
if (v) return v;
}
return "";
};

const regionRaw = pickField("region");
const cityRaw = pickField("city");
const isp = pickField("isp") || "未知";

const flags = {
mobile: apiOK? parseBooleanFlag(a.mobile): null,
proxy: apiOK? parseBooleanFlag(a.proxy): null,
hosting: apiOK? parseBooleanFlag(a.hosting): null
};

// ---- 中国 ----
if (countryCode === "CN") {
const municipality = getMunicipality(regionRaw) || getMunicipality(cityRaw);
if (municipality) {
// 直辖市：只显示直辖市本身
return { country: "中国", countryCode, province: municipality, city: municipality, area: "", isp, flags};
}
// 其他：省份 + 城市
const province = normalizeProvinceCN(regionRaw);
let city = stripCitySuffix(cityRaw);
if (city && province && city === province) city = ""; // 省会同名等去重
return { country: "中国", countryCode, province, city, area: "", isp, flags};
}

// ---- 香港 / 澳门 / 台湾：地区名 + 下辖地区 ----
if (countryCode === "HK" || countryCode === "MO" || countryCode === "TW") {
const generics = {
HK: ["hong kong", "hong kong sar", "hong kong special administrative region", "香港", "香港特别行政区", "香港特別行政區"],
MO: ["macau", "macao", "macao sar", "澳门", "澳門", "澳门特别行政区", "澳門特別行政區"],
TW: ["taiwan", "taiwan province", "taiwan province of china", "台湾", "台灣", "台湾省", "臺灣省"]
}[countryCode];

// 台湾优先取城市（台北/新北等本身就是下辖市），港澳优先取地区
const ordered = countryCode === "TW"? [cityRaw, regionRaw]: [regionRaw, cityRaw];
let area = "";
for (const cand of ordered) {
if (cand &&!generics.includes(cand.toLowerCase())) {
area = normalizeSpecialArea(cand, countryCode);
if (area) break;
}
}
return { country: GEO_COUNTRY_NAMES[countryCode], countryCode, province: "", city: "", area, isp, flags};
}

// ---- 其他国家：国家 + 州/省 + 城市（重复项在 formatLocation 统一去掉） ----
return {
country: country || countryCode,
countryCode,
province: regionRaw,
city: cityRaw,
area: "",
isp,
flags
};
}

function formatLocation(geo) {
if (!geo) return "未知";

const code = geo.countryCode || "";
const aliases = new Set(
[geo.country, ...(GEO_COUNTRY_ALIASES[code] || [])]
.filter(Boolean)
.map(s => String(s).toLowerCase())
);
const parts = [];
const pushPart = value => {
const s = toSimplified(cleanAreaName(value));
if (!s) return;
const lower = s.toLowerCase();
if (parts.some(p => p.toLowerCase() === lower)) return; // 与已显示部分完全重复
if (parts.length && aliases.has(lower)) return; // 国家名又以地区/城市形式重复出现
parts.push(s);
};

pushPart(geo.country);
if (code === "CN") {
pushPart(geo.province);
if (geo.city && geo.city!== geo.province) pushPart(geo.city);
} else if (code === "HK" || code === "MO" || code === "TW") {
pushPart(geo.area);
} else {
pushPart(geo.province);
pushPart(geo.city);
}

return parts.join(" · ") || "未知";
}

// =====================================
// 17. 入口 IP 识别（基线快照剔除上一轮记录，只对本轮新增代理请求投票）
// =====================================

function cleanRemoteIP(value) {
if (!value || typeof value!== "string") return null;

let ip = value.replace(/\s*\(Proxy\)\s*/gi, "").trim();

if (ip.startsWith("[")) {
const match = ip.match(/^\[([^\]]+)\](?::\d+)?$/);
if (!match) return null;
ip = match[1];
} else {
const match = ip.match(/^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/);
if (match) ip = match[1];
}

const normalized = normalizeIP(ip);
if (!normalized || isPrivateOrLoopbackIP(normalized)) return null;
return normalized;
}

function httpAPIGet(path, body) {
return new Promise(resolve => {
if (typeof $httpAPI !== "function") {
resolve(null);
return;
}
try {
$httpAPI("GET", path, body || null, result => {
resolve(result || null);
});
} catch (e) {
resolve(null);
}
});
}

function queryRecentRequests() {
return httpAPIGet("/v1/requests/recent").then(result =>
Array.isArray(result?.requests) ? result.requests : []
);
}

const DETECTOR_PATTERN =
/(my\.ippure\.com|1\.1\.1\.1|api-ipv4\.ip\.sb|api\.cleanip\.io|ip-api\.com|ipinfo\.io|scamalytics\.com|proxycheck\.io)/i;

// 出口探测请求（真正产生落地 IP 的那四个）：节点名候选优先只认它们，
// 保证显示的节点与落地 IP 出自同一批请求、同一个出口
const OUTBOUND_PROBE_PATTERN = /(my\.ippure\.com|1\.1\.1\.1|api-ipv4\.ip\.sb|api\.cleanip\.io)/i;

function requestSignature(item) {
return [
item?.id ?? item?.requestId ?? "",
item?.URL || "",
item?.remoteAddress || "",
item?.startDate ?? item?.startTime ?? item?.date ?? item?.time ?? ""
].join("|");
}

function buildBaselineCounts(requests) {
const counts = {};
for (const item of requests || []) {
if (!DETECTOR_PATTERN.test(item?.URL || "")) continue;
const remote = item?.remoteAddress || "";
if (!/\(Proxy\)/i.test(remote)) continue;
const sig = requestSignature(item);
counts[sig] = (counts[sig] || 0) + 1;
}
return counts;
}

async function snapshotEntranceBaseline() {
try {
return buildBaselineCounts(await queryRecentRequests());
} catch (e) {
return {};
}
}

// 从一条请求记录里深挖所有可能表示“实际使用策略”的字段：
// policyName / policy / finalPolicy 等直接字段优先，其余递归扫描键名带
// policy / proxy / node 的字符串值（包括嵌套的策略组决策链）。
function collectPolicyStrings(node, out, depth) {
if (!node || depth > 4 || typeof node !== "object") return;
if (Array.isArray(node)) {
node.forEach(n => collectPolicyStrings(n, out, depth + 1));
return;
}
for (const key of Object.keys(node)) {
const v = node[key];
if (typeof v === "string" && /policy|proxy|node/i.test(key)) out.push(v);
else if (v && typeof v === "object") collectPolicyStrings(v, out, depth + 1);
}
}

// 主字段（Surge 自己标注的 policyName 等）与深挖字段（决策链/中转链里的名字）分开：
// 主字段才是这条请求实际用的策略，深挖到的名字可能来自链路上的其他环节，只能兜底。
function extractPolicyCandidates(item) {
const primary = [];
const extra = [];
const makePush = list => v => {
if (typeof v !== "string") return;
const s = v.trim();
if (!s || s.length > 120) return;
if (s.includes("://") || /^(true|false)$/i.test(s) || /^\d+$/.test(s)) return;
if (!list.includes(s)) list.push(s);
};
const pushPrimary = makePush(primary);
const pushExtra = makePush(extra);
pushPrimary(item?.policyName);
if (typeof item?.policy === "string") pushPrimary(item.policy);
pushPrimary(item?.policy?.name);
pushPrimary(item?.finalPolicy);
pushPrimary(item?.effectivePolicy);
pushPrimary(item?.selectedPolicy);
pushPrimary(item?.proxyName);
pushPrimary(item?.nodeName);
const deep = [];
collectPolicyStrings(item, deep, 0);
for (const v of deep) {
const s = typeof v === "string"? v.trim(): "";
if (s &&!primary.includes(s)) pushExtra(v);
}
return { primary, extra };
}

function pickEntranceFromRequests(requests, baseline) {
// 基线多重集扣减：本轮开始前已存在的请求逐个扣掉，只统计本轮新增的。
// 这样入口没变时新增请求照样计票，入口变了时旧入口不会滞留。
const remaining = Object.assign({}, baseline || {});
const counts = {};
const candidateMap = new Map();
const probeMap = new Map();
for (const item of requests) {
if (!DETECTOR_PATTERN.test(item?.URL || "")) continue;
const sig = requestSignature(item);
if (remaining[sig] > 0) {
remaining[sig] -= 1;
continue;
}
const remote = item?.remoteAddress || "";
const isProxy = /\(Proxy\)/i.test(remote);
// 本轮新增探测请求的实际策略候选：走代理的请求权重更高（直连请求也会带策略名，避免喧宾夺主）；
// 出口探测请求的候选单独计票并优先采用，与落地 IP 保持同源
const weight = isProxy ? 2 : 1;
const target = OUTBOUND_PROBE_PATTERN.test(item?.URL || "") ? probeMap : candidateMap;
if (PANEL_DEBUG && !probeFieldLogged && target === probeMap) {
probeFieldLogged = true;
dbg("记录键：" + Object.keys(item).join(","));
const f0 = extractPolicyCandidates(item);
dbg("主字段：" + (f0.primary.join(" | ") || "（无）"));
dbg("深挖：" + (f0.extra.join(" | ") || "（无）"));
}
const found = extractPolicyCandidates(item);
// 主字段权重 ×10：请求记录里只要 Surge 标注了实际策略，就不许链路里的其他名字压过它
for (const name of found.primary) {
target.set(name, (target.get(name) || 0) + weight * 10);
}
for (const name of found.extra) {
target.set(name, (target.get(name) || 0) + weight);
}
if (!isProxy) continue;
const ip = cleanRemoteIP(remote);
if (ip) counts[ip] = (counts[ip] || 0) + 1;
}

const effectiveMap = probeMap.size ? probeMap : candidateMap;
const candidates = Array.from(effectiveMap.entries())
.map(([name, votes]) => ({ name, votes }))
.sort((a, b) => b.votes - a.votes);
const policyName = candidates.length ? candidates[0].name : "";
const groups = Object.entries(counts).sort((a, b) => b[1] - a[1]);
if (!groups.length) return { ip: null, distinct: 0, votes: 0, policyName: policyName, candidates: candidates };
return { ip: groups[0][0], distinct: groups.length, votes: groups[0][1], policyName: policyName, candidates: candidates };
}


const SELECTED_FIELDS = ["selected", "selectedPolicy", "selected_policy", "now", "current", "currentPolicy", "policy", "value", "choice"];

function firstStringField(obj, fields) {
if (!obj || typeof obj !== "object") return null;
for (const f of fields) {
if (typeof obj[f] === "string" && obj[f]) return obj[f];
}
return null;
}

// 官方接口 $surge.selectGroupDetails()：decisions 给出 select 组当前选中的策略，
// groups 给出每个组的成员名单——后者用来校验前者：decisions 里的值若根本不是
// 该组成员（实测出现过同名组串扰，把别的订阅的节点报成智能组的选择），直接拒绝。
function getSelectGroupDetails() {
try {
if (typeof $surge !== "undefined" && $surge && typeof $surge.selectGroupDetails === "function") {
const details = $surge.selectGroupDetails();
if (details && typeof details === "object") {
const decisions = details.decisions && typeof details.decisions === "object"? details.decisions: {};
const groups = details.groups && typeof details.groups === "object"? details.groups: {};
dbg("decisions：共 " + Object.keys(decisions).length + " 组");
return { decisions, groups };
}
dbg("decisions：返回为空");
return null;
}
dbg("decisions：接口不可用");
} catch (e) {
dbg("decisions：调用异常");
}
return null;
}

// 从 /v1/policy_groups 提取每个组的成员名单（policies / availablePolicyNames 等数组字段）
function buildGroupMembersMap(data) {
const map = {};
const visit = (node, keyHint) => {
if (!node || typeof node !== "object") return;
if (Array.isArray(node)) {
node.forEach(item => visit(item, keyHint));
return;
}
const name = typeof node.name === "string" && node.name ? node.name : (typeof node.group === "string" && node.group ? node.group : (keyHint || ""));
for (const key of Object.keys(node)) {
const v = node[key];
if (Array.isArray(v) && v.length && v.every(x => typeof x === "string") && /polic|member|prox/i.test(key)) {
if (name && !map[name]) map[name] = v.slice();
} else if (v && typeof v === "object") {
visit(v, key);
}
}
};
visit(data, "");
return map;
}

// 深度遍历 /v1/policy_groups 的返回：不管外层包装键名是什么（policy-groups 等），
// 把所有带 name/group 的条目按其选中字段收成 name -> 选中策略 的映射；
// 同时兼容 {组名: "策略"} / {组名: {selected: ...}} 的对象映射形式
function buildGroupSelectedMap(data) {
const map = {};
const visit = (node, keyHint) => {
if (!node || typeof node !== "object") return;
if (Array.isArray(node)) {
node.forEach(item => visit(item, keyHint));
return;
}
const name = typeof node.name === "string" && node.name ? node.name : (typeof node.group === "string" && node.group ? node.group : "");
const selected = firstStringField(node, SELECTED_FIELDS);
if (name && selected && !map[name]) map[name] = selected;
if (!name && keyHint && selected && !map[keyHint]) map[keyHint] = selected;
for (const key of Object.keys(node)) {
const v = node[key];
if (typeof v === "string") {
if (!name && v && !SELECTED_FIELDS.includes(key) && !["type", "name", "group"].includes(key) && !map[key]) map[key] = v;
} else {
visit(v, key);
}
}
};
visit(data, "");
return map;
}

// url-test / fallback / load-balance 等自动组没有手动选中项，从 test_results 里取当前生效策略
function extractAutoGroupPolicy(data, groupName) {
let found = null;
const visit = node => {
if (found || !node || typeof node !== "object") return;
if (Array.isArray(node)) {
for (const item of node) {
visit(item);
if (found) return;
}
return;
}
const name = typeof node.name === "string" ? node.name : (typeof node.group === "string" ? node.group : "");
if (name === groupName) {
found = firstStringField(node, SELECTED_FIELDS);
if (found) return;
}
if (Object.prototype.hasOwnProperty.call(node, groupName)) {
const v = node[groupName];
if (typeof v === "string" && v) {
found = v;
return;
}
if (v && typeof v === "object") {
found = firstStringField(v, SELECTED_FIELDS);
if (found) return;
}
}
for (const key of Object.keys(node)) visit(node[key]);
};
visit(data);
return found;
}

async function resolveNodeName(policyName) {
const name = String(policyName || "").trim();
if (!name) return "";
if (name === "DIRECT") return "DIRECT（直连）";
if (name === "REJECT" || name === "REJECT-DROP") return name;
let current = name;
const details = getSelectGroupDetails();
const decisions = details?.decisions || null;
const sgGroups = details?.groups || {};
const pgData = await httpAPIGet("/v1/policy_groups");
const groupMap = buildGroupSelectedMap(pgData);
const pgMembers = buildGroupMembersMap(pgData);
let testResults = null;
let testResultsLoaded = false;

// 成员校验：任何来源给出的解析结果，必须是该组的真实成员才采信——
// 实测同名组串扰会让 decisions 把别的订阅的节点报成智能组的选择，
// 那种值根本不在本组成员名单里，一验即穿。成员名单以本地
// /v1/policy_groups 为准，其次 selectGroupDetails 的 groups；
// 两处都查不到成员名单时不拦（保持原有行为）。
const memberOK = (group, candidate) => {
let list = null;
if (Array.isArray(pgMembers[group]) && pgMembers[group].length) list = pgMembers[group];
else if (Array.isArray(sgGroups[group]) && sgGroups[group].length) list = sgGroups[group];
if (!list) return true;
return list.includes(candidate);
};
const topMembers = Array.isArray(pgMembers[name]) && pgMembers[name].length ? pgMembers[name]
: (Array.isArray(sgGroups[name]) && sgGroups[name].length ? sgGroups[name] : null);
if (topMembers) dbg("成员[" + name + "]：" + topMembers.join(" | "));

for (let i = 0; i < 5; i++) {
if (current === "DIRECT") return "DIRECT（直连）";
if (current === "REJECT" || current === "REJECT-DROP") return current;
let next = null;
let via = "";
const gate = (value, source) => {
if (!value) return null;
if (!memberOK(current, value)) {
dbg("拒绝非成员[" + source + "] " + current + " → " + value);
return null;
}
via = source;
return value;
};
// 1) select 组：官方 decisions 映射（经成员校验后才采信）
if (decisions && typeof decisions[current] === "string" && decisions[current]) {
next = gate(decisions[current], "decisions");
}
// 2) /v1/policy_groups 全量数据深度解析
if (!next) next = gate(groupMap[current], "policy_groups");
// 3) 按组名单查 select 接口：GET /v1/policy_groups/select?group_name=xxx -> {"policy": "..."}
if (!next) {
const sel = await httpAPIGet("/v1/policy_groups/select", { group_name: current });
const v = sel ? firstStringField(sel, ["policy", "selected", "now"]) : null;
next = gate(v, "select接口");
if (!next && !v) dbg("select接口：" + current + " 无结果");
}
// 4) 自动组 / 智能组：test_results 里的当前生效策略
if (!next) {
if (!testResultsLoaded) {
testResults = await httpAPIGet("/v1/policy_groups/test_results");
testResultsLoaded = true;
}
next = gate(extractAutoGroupPolicy(testResults, current), "test_results");
}
dbg("解析[" + (via || "无") + "] " + current + " → " + (next || "（无）"));
if (!next || next === current) break;
current = next;
}
return current;
}

// 节点名最终裁决：候选来自本轮请求记录，再用 /v1/policies 的清单校验——
// proxies 是真实节点名单、policy-groups 是组名单。候选本身已是真实节点就直接用；
// 是组名才走 resolveNodeName 翻译，且翻译结果也要在真实节点名单里才采信，
// 避免再把组名或接口错误值显示到面板上。
async function resolveNodeFromCandidates(candidates) {
if (!candidates || !candidates.length) return "";
const policies = (await httpAPIGet("/v1/policies?include_external=true")) || (await httpAPIGet("/v1/policies"));
const proxies = new Set(Array.isArray(policies?.proxies) ? policies.proxies : []);
const groups = new Set(Array.isArray(policies?.["policy-groups"]) ? policies["policy-groups"] : []);
// 外部订阅策略组里的节点在记录里可能只是 identifier，先翻译回真实节点名
const extMap = {};
if (Array.isArray(policies?.["external-policies"])) {
for (const p of policies["external-policies"]) {
if (p && typeof p.identifier === "string" && typeof p.name === "string") extMap[p.identifier] = p.name;
}
}
const translate = n => (typeof n === "string" && extMap[n]) || n;
candidates = candidates.map(c => ({ name: translate(c.name), votes: c.votes }));
dbg("候选：" + candidates.map(c => c.name + "(" + c.votes + ")").join(" | "));
dbg("清单：节点 " + proxies.size + " · 组 " + groups.size + " · 外部 " + Object.keys(extMap).length);
const done = v => {
dbg("节点结果：" + (v || "（空）"));
return v;
};
const hasLists = proxies.size > 0 || groups.size > 0;
for (const c of candidates) {
if (proxies.has(c.name) && !groups.has(c.name)) return done(c.name);
}
const resolvedList = [];
for (const c of candidates) {
const r = translate(await resolveNodeName(c.name));
if (r && !resolvedList.includes(r)) resolvedList.push(r);
if (r && proxies.has(r) && !groups.has(r)) return done(r);
}
if (hasLists) {
const nonGroup = resolvedList.find(r => !groups.has(r));
if (nonGroup) return done(nonGroup);
const nonGroupCandidate = candidates.find(c => !groups.has(c.name));
if (nonGroupCandidate) return done(nonGroupCandidate.name);
}
return done(resolvedList[0] || candidates[0].name || "");
}

async function getEntranceIP(baseline) {
let result = pickEntranceFromRequests(await queryRecentRequests(), baseline);
// 请求记录写入有延迟：入口 IP 或策略候选任一缺失时，再等一会儿重读两次；
// 仍无候选时，从正在进行的请求（/v1/requests/active）里补找策略候选。
for (const wait of [150, 300]) {
if (result.ip && result.candidates.length) break;
await new Promise(resolve => setTimeout(resolve, wait));
const next = pickEntranceFromRequests(await queryRecentRequests(), baseline);
if (next.ip) result.ip = next.ip;
if (next.candidates.length) {
result.candidates = next.candidates;
result.policyName = next.policyName;
}
}
if (!result.candidates.length) {
try {
const active = await httpAPIGet("/v1/requests/active");
const list = Array.isArray(active?.requests) ? active.requests : [];
const act = pickEntranceFromRequests(list, {});
if (act.candidates.length) {
result.candidates = act.candidates;
result.policyName = act.policyName;
}
} catch (e) {}
}
return result;
}

// =====================================
// 18. 面板信息块
// =====================================


// 对齐说明：全角冒号占 1 个汉字宽，英文冒号只占约 1/4 宽。
// 纯净度 / 运营商 按用户指定用英文冒号，冒号后补 3 个空格，
// 使所有行的值都从同一位置开始（按实测截图：值起点差 36px ≈ 3 个空格宽）。
function buildIPBlock(name, ip, geo) {
return [
`${name}：${ip || "获取失败"}`,
`IP地区：${formatLocation(geo)}`,
`运营商： ${geo?.isp || "未知"}`
].join("\n");
}

// 节点名（新实现）：只认带本轮标记的探测请求记录。标记是每轮随机生成的，
// 出现在记录 URL 里即证明这条记录属于本轮——上一轮迟到刷入的记录没有本轮
// 标记，再新也直接忽略，从根上杜绝节点名慢一拍。记录写入有延迟，轮询几次
// 等它刷入（探测响应都已返回，记录通常在头两次读取内出现）；实在等不到
// 才返回空，由调用方退回旧候选逻辑兜底。
async function resolveCurrentNodeName() {
const tag = ensureRunTag();
const waits = [0, 200, 400, 700, 1000, 1200];
for (let attempt = 0; attempt < waits.length; attempt++) {
if (waits[attempt]) await new Promise(r => setTimeout(r, waits[attempt]));
let list = await queryRecentRequests();
if (attempt >= 2) {
try {
const active = await httpAPIGet("/v1/requests/active");
if (Array.isArray(active?.requests)) list = list.concat(active.requests);
} catch (e) {}
}
const taggedRecords = list.filter(item => (item?.URL || "").includes(tag));
if (!taggedRecords.length) continue;
const map = new Map();
for (const item of taggedRecords) {
const found = extractPolicyCandidates(item);
const w = /\(Proxy\)/i.test(item?.remoteAddress || "") ? 2 : 1;
for (const n of found.primary) map.set(n, (map.get(n) || 0) + w * 10);
for (const n of found.extra) map.set(n, (map.get(n) || 0) + w);
}
const candidates = Array.from(map.entries())
.map(([name, votes]) => ({ name, votes }))
.sort((a, b) => b.votes - a.votes);
dbg("本轮标记请求：" + taggedRecords.length + " 条");
if (candidates.length) return await resolveNodeFromCandidates(candidates);
}
dbg("本轮标记请求：未找到，退回旧候选");
return "";
}

// =====================================
// 19. 总超时保护与主程序
// =====================================

totalTimer = setTimeout(() => {
finish("检测超时，请手动刷新重试。", "error");
}, CFG.totalTimeout * 1000);

async function buildPanelAttempt(sources, entranceBaseline) {
const outboundIP = sources.ip;
const pureData = getIPPureData(outboundIP, sources.sources.pureData);

// 入口检测与下面的落地详情查询并发进行：入口记录在出口探测时已经产生，无需等全部查完
const entrancePromise = (async () => {
try {
// 入口检测与节点名解析并发：节点名的标记记录轮询越早开始，越容易在记录
// 刷入的第一时间抓到，不必排在入口检测后面白白消耗时间预算
const [ent, taggedName] = await Promise.all([
getEntranceIP(entranceBaseline),
resolveCurrentNodeName()
]);
let nodeName = taggedName;
if (!nodeName) nodeName = await resolveNodeFromCandidates(ent.candidates);
if (!ent.ip || ent.ip === outboundIP) return { ip: ent.ip, geo: null, nodeName: nodeName };
return { ip: ent.ip, geo: await getGeo(ent.ip, []), nodeName: nodeName };
} catch (e) {
return { ip: null, geo: null, nodeName: "" };
}
})();
const cleanParsed = parseCleanIPPayload(sources.sources.cleanRaw, outboundIP);

// 已抓到数据的归属地兜底（不额外发请求）：CleanIP / ip.sb / IPPure / CF 国家码
const sbGeo = sources.sources.sbData
? {
countryCode: String(sources.sources.sbData.country_code || sources.sources.sbData.countryCode || "").toUpperCase(),
country: sources.sources.sbData.country || "",
region: sources.sources.sbData.region || "",
city: sources.sources.sbData.city || "",
isp: sources.sources.sbData.isp || sources.sources.sbData.organization || sources.sources.sbData.asn_organization || ""
}
: null;

// 国家投票权重：IPPure 原始响应（w=3）——直接取探测响应本身，不要求它与最终落地 IP
// 逐字一致：落地 IP 在同段内轮换（如 .194/.196）时 IPPure 的国家判定仍然有效；
// CF（w=1）只作弱参考；CleanIP / ip.sb（w=0）只供字段兜底，不参与国家投票。
const rawPure = sources.sources.pureData;
const rawPureGeo = rawPure
? {
countryCode: String(rawPure.countryCode || rawPure.country_code || rawPure.countrycode || "").toUpperCase(),
country: rawPure.country || "",
region: rawPure.region || rawPure.regionName || rawPure.state || "",
city: rawPure.city || "",
isp: rawPure.isp || rawPure.org || rawPure.organization || rawPure.asnName || ""
}
: null;

const outboundFallbacks = [
cleanParsed?.geo? Object.assign({}, cleanParsed.geo, { w: 0 }): null,
sbGeo? Object.assign({}, sbGeo, { w: 0 }): null,
rawPureGeo? Object.assign({}, rawPureGeo, { w: 3 }): null,
sources.sources.cfLoc? { countryCode: sources.sources.cfLoc, country: "", region: "", city: "", isp: "", w: 1 }: null
];

const [cleanData, proxyData, scamData, outboundGeo] = await Promise.all([
getCleanIP(outboundIP, sources.sources.cleanRaw),
getProxyCheck(outboundIP),
// IPPure 已有评分时 Scamalytics 只是优先级最低的兜底，跳过以省时并减少被限流概率；
pureData && pureData.score!== null? Promise.resolve(null): getScamalytics(outboundIP),
getGeo(outboundIP, outboundFallbacks)
]);

const entranceResult = await entrancePromise;
const entranceIP = entranceResult.ip;

// 入口与落地相同则复用归属地，避免重复查询
const entranceGeo = entranceIP && entranceIP === outboundIP ? outboundGeo : entranceResult.geo;

const riskResults = [pureData, proxyData, scamData].filter(
item => item && normalizeIP(item.ip) === normalizeIP(outboundIP)
);

const risk = calculateRisk(riskResults);
const type = getIPType(pureData, proxyData, cleanData, outboundGeo?.flags);

const content = [
entranceResult.nodeName || "未知",
"",
`IP类型：${type.type}`,
`IP属性：${type.attribute}`,
`纯净度： ${risk.text}`,
"",
buildIPBlock("入口IP", entranceIP, entranceGeo),
"",
buildIPBlock("落地IP", outboundIP, outboundGeo)
].join("\n");

const isError = sources.consensus === "split" || risk.score === null;

const finalContent = PANEL_DEBUG && DEBUG_LINES.length
? content + "\n\n[调试]\n" + DEBUG_LINES.join("\n")
: content;

return { content: finalContent, isError: isError };
}

(async () => {
try {
const startedAt = Date.now();
// 脚本一启动先给最近请求拍基线快照（本地接口，毫秒级），用于剔除上一轮的旧入口记录
// 必须 await 等快照拍完再发探测请求：只发起不等待的话，快照回调可能在探测请求
// 已经进入最近请求列表之后才返回，那样本轮请求会被误当成旧记录扣掉，入口变空。
const entranceBaseline = await snapshotEntranceBaseline();
let sources = await getOutboundSources();

if (!sources.ip) {
finish("落地 IP 获取失败，请检查网络。", "error");
return;
}

let panel = await buildPanelAttempt(sources, entranceBaseline);

// 异常自动复检一次：切节点后常有旧连接或旧路由残留，首轮出现无多数分歧或无评分时，
// 隔 800ms 用全新连接再测一轮；第二轮仍异常才报红。超时预算不够时不复检。
if (panel.isError && Date.now() - startedAt < 9000) {
await new Promise(resolve => setTimeout(resolve, 800));
const sources2 = await getOutboundSources();
if (sources2.ip) {
panel = await buildPanelAttempt(sources2, entranceBaseline);
}
}

finish(panel.content, panel.isError);
} catch (e) {
finish("检测异常：" + String(e), "error");
}
})();
