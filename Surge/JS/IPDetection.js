/**
* Surge iOS 6 - IP Detection
* IP 类型 / 纯净度 / 入口 IP / 落地 IP
*
* 1. 多源出口 IP 探测与一致性交叉验证，CleanIP 参与投票，
* 三/四源分歧（无多数）时用 ipwho.is 作决胜源再投一次
* 2. IPPure > ProxyCheck > Scamalytics 纯净度优先级，
* 面板显示格式与原版完全一致，内部改进不增加显示项
* 3. IP 类型引入 ip-api 的 mobile / proxy / hosting 强标志加权投票，
* 再由 CleanIP + IPPure + ProxyCheck 交叉辅助判断
* 4. 归属地按国家代码投票（不再用不同语言的字符串硬凑票数）：
* - 中国：直辖市只显示直辖市；其他显示 省份 + 城市
* - 香港 / 澳门 / 台湾：国家/地区名 + 下辖地区
* - 其他国家：国家 + 州/省 + 城市
* 5. 入口 IP 在脚本启动时拍基线快照，只对本轮新增的代理请求投票，避免滞留上一轮入口；
*    且与落地详情并发检测，不再串行等待
* 6. 入口 IP 与落地 IP 相同时复用归属地结果，不重复查询
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
ipWho: "https://ipwho.is/",

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

const sourceRank = { pure: 5, who: 4, cf: 3, sb: 2, clean: 1};
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

async function getOutboundSources() {
const [pure, traceBody, sb, cleanRaw] = await Promise.all([
getJSON(CFG.ippure),
request(CFG.cfTrace),
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

// 无多数分歧（split）时，用 ipwho.is 作决胜源再投一次
if (verification.consensus === "split") {
const who = await getJSON(CFG.ipWho);
const whoIP = normalizeIP(who?.ip);
if (whoIP) {
entries = entries.concat([{ key: "who", ip: whoIP}]);
verification = verifyOutboundConsistency(entries);
results.whoData = who;
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

// 中国省份英文名 -> 中文名（ipinfo / ipwho 等英文源兜底用）
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
return name.replace(/\s+(county|city)$/i, "").replace(/县$/, "").replace(/市$/, "");
}
return name;
}

// =====================================
// 16. 多源归属地交叉验证
// 国家用国家代码投票；地名优先中文源，英文源只兜底
// 来源：ip-api（中文）+ ipinfo + ipwho.is + 已抓到的 CleanIP/ip.sb/IPPure/CF
// =====================================

function voteCountryCode(candidates) {
const counts = {};
for (const code of candidates) {
const c = String(code || "").trim().toUpperCase();
if (!/^[A-Z]{2}$/.test(c)) continue;
counts[c] = (counts[c] || 0) + 1;
}
const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);
return sorted.length? sorted[0][0]: "";
}

function firstNonEmpty(values) {
for (const v of values) {
const s = cleanAreaName(v);
if (s) return s;
}
return "";
}

function getISP(api, info, who, fallbacks) {
const stripAS = s => cleanAreaName(String(s || "").replace(/^AS\d+\s*/i, ""));
return (
firstNonEmpty([
api?.status === "success"? api.isp: "",
who?.connection?.isp || who?.connection?.org || "",
info?.org? stripAS(info.org): "",
api?.status === "success"? api.org || api.asname: "",
...(fallbacks || []).map(f => (f? stripAS(f.isp): ""))
]) || "未知"
);
}

async function getGeo(ip, fallbackGeos) {
if (!ip) return null;
const fallbacks = (fallbackGeos || []).filter(Boolean);

const [a, b, who] = await Promise.all([
getJSON(
CFG.geoAPI +
encodeURIComponent(ip) +
"?lang=zh-CN&fields=status,country,countryCode,city,regionName,isp,org,as,asname,mobile,proxy,hosting"
),
getJSON(CFG.ipInfo + encodeURIComponent(ip) + "/json"),
getJSON(CFG.ipWho + encodeURIComponent(ip))
]);

const apiOK = a?.status === "success";
const whoOK = who && who.success!== false && (who.ip || who.country_code);

if (!apiOK &&!b &&!whoOK &&!fallbacks.length) return null;

// 国家：用代码投票，避免中英文字符串对不上
const countryCode = voteCountryCode([
apiOK? a.countryCode: "",
b?.country || "",
whoOK? who.country_code: "",
...fallbacks.map(f => f.countryCode || "")
]);

const countryNames = { CN: "中国", HK: "香港", MO: "澳门", TW: "台湾"};
const country =
countryNames[countryCode] ||
firstNonEmpty([apiOK? a.country: "",...fallbacks.map(f => f.country), whoOK? who.country: "", b?.country || ""]);

// 地名候选：中文源优先（ip-api > CleanIP 等 fallback），英文源兜底
const regionCandidates = [
apiOK? a.regionName: "",
...fallbacks.map(f => f.region),
whoOK? who.region: "",
b?.region || ""
];
const cityCandidates = [
apiOK? a.city: "",
...fallbacks.map(f => f.city),
whoOK? who.city: "",
b?.city || ""
];
const regionRaw = firstNonEmpty(regionCandidates);
const cityRaw = firstNonEmpty(cityCandidates);

const flags = {
mobile: apiOK? parseBooleanFlag(a.mobile): null,
proxy: apiOK? parseBooleanFlag(a.proxy): null,
hosting: apiOK? parseBooleanFlag(a.hosting): null
};

const isp = getISP(apiOK? a: null, b, whoOK? who: null, fallbacks);

// ---- 中国 ----
if (countryCode === "CN") {
const municipality = getMunicipality(regionRaw) || getMunicipality(cityRaw);
if (municipality) {
// 直辖市：只显示直辖市本身，保持原有格式
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
HK: ["hong kong", "hong kong sar", "香港", "香港特别行政区"],
MO: ["macau", "macao", "澳门", "澳门特别行政区"],
TW: ["taiwan", "taiwan province", "taiwan province of china", "台湾", "台湾省"]
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
return { country: countryNames[countryCode], countryCode, province: "", city: "", area, isp, flags};
}

// ---- 其他国家：国家 + 州/省 + 城市 ----
const region = cleanAreaName(regionRaw);
const city = cleanAreaName(cityRaw);
return {
country: country || countryCode,
countryCode,
province: region && region.toLowerCase()!== city.toLowerCase()? region: "",
city,
area: "",
isp,
flags
};
}

function formatLocation(geo) {
if (!geo) return "未知";

if (geo.countryCode === "CN") {
if (geo.province && geo.city && geo.province === geo.city) {
return [geo.country, geo.province].join(" · ");
}
return [geo.country, geo.province, geo.city].filter(Boolean).join(" · ") || "未知";
}

if (geo.countryCode === "HK" || geo.countryCode === "MO" || geo.countryCode === "TW") {
return [geo.country, geo.area].filter(Boolean).join(" · ") || "未知";
}

return [geo.country, geo.province, geo.city].filter(Boolean).join(" · ") || "未知";
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

function httpAPIGet(path) {
return new Promise(resolve => {
if (typeof $httpAPI !== "function") {
resolve(null);
return;
}
try {
$httpAPI("GET", path, null, result => {
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
/(my\.ippure\.com|1\.1\.1\.1|api-ipv4\.ip\.sb|api\.cleanip\.io|ip-api\.com|ipinfo\.io|ipwho\.is|scamalytics\.com|proxycheck\.io)/i;

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

function pickEntranceFromRequests(requests, baseline) {
// 基线多重集扣减：本轮开始前已存在的请求逐个扣掉，只统计本轮新增的。
// 这样入口没变时新增请求照样计票，入口变了时旧入口不会滞留。
const remaining = Object.assign({}, baseline || {});
const counts = {};
const policyCounts = {};
for (const item of requests) {
if (!DETECTOR_PATTERN.test(item?.URL || "")) continue;
const sig = requestSignature(item);
if (remaining[sig] > 0) {
remaining[sig] -= 1;
continue;
}
// 本轮新增探测请求实际使用的策略名（即当前节点/策略组），多数票为准
const pname = item?.policyName || (typeof item?.policy === "string" ? item.policy : item?.policy?.name) || "";
if (pname) policyCounts[pname] = (policyCounts[pname] || 0) + 1;
const remote = item?.remoteAddress || "";
if (!/\(Proxy\)/i.test(remote)) continue;
const ip = cleanRemoteIP(remote);
if (ip) counts[ip] = (counts[ip] || 0) + 1;
}

const policyGroups = Object.entries(policyCounts).sort((a, b) => b[1] - a[1]);
const policyName = policyGroups.length ? policyGroups[0][0] : "";
const groups = Object.entries(counts).sort((a, b) => b[1] - a[1]);
if (!groups.length) return { ip: null, distinct: 0, votes: 0, policyName: policyName };
return { ip: groups[0][0], distinct: groups.length, votes: groups[0][1], policyName: policyName };
}


function lookupGroupSelected(groupsData, name) {
if (!groupsData || !name) return null;
if (Array.isArray(groupsData)) {
const item = groupsData.find(g => g && (g.name === name || g.group === name));
if (!item) return null;
const v = item.selected || item.policy || item.now || item.selectedPolicy || null;
return typeof v === "string" ? v : null;
}
if (typeof groupsData === "object") {
const v = groupsData[name];
if (typeof v === "string") return v;
if (v && typeof v === "object") {
const inner = v.selected || v.policy || v.now || v.selectedPolicy || null;
return typeof inner === "string" ? inner : null;
}
}
return null;
}

async function resolveNodeName(policyName) {
const name = String(policyName || "").trim();
if (!name) return "";
if (name === "DIRECT") return "DIRECT（直连）";
if (name === "REJECT" || name === "REJECT-DROP") return name;
let current = name;
const groups = await httpAPIGet("/v1/policy_groups");
for (let i = 0; i < 3; i++) {
const next = lookupGroupSelected(groups, current);
if (!next || next === current) break;
current = next;
}
return current;
}

async function getEntranceIP(baseline) {
let result = pickEntranceFromRequests(await queryRecentRequests(), baseline);
if (result.ip) return result;
await new Promise(resolve => setTimeout(resolve, 100));
result = pickEntranceFromRequests(await queryRecentRequests(), baseline);
return result;
}

// =====================================
// 18. 面板信息块
// =====================================


function buildIPBlock(name, ip, geo) {
return [
`${name} ：${ip || "获取失败"}`,
`IP地区 ：${formatLocation(geo)}`,
`运营商 :${geo?.isp || "未知"}`
].join("\n");
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
const ent = await getEntranceIP(entranceBaseline);
const nodeName = await resolveNodeName(ent.policyName);
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

const outboundFallbacks = [
cleanParsed?.geo,
sbGeo,
pureData?.geo,
sources.sources.cfLoc? { countryCode: sources.sources.cfLoc, country: "", region: "", city: "", isp: ""}: null
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
" ".repeat(19) + (entranceResult.nodeName || "未知"),
"",
`IP类型 ：${type.type}`,
`IP属性 ：${type.attribute}`,
`纯净度 :${risk.text}`,
"",
buildIPBlock("入口IP", entranceIP, entranceGeo),
"",
buildIPBlock("落地IP", outboundIP, outboundGeo)
].join("\n");

const isError = sources.consensus === "split" || risk.score === null;

return { content: content, isError: isError };
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
