/**
* 感谢@congcong大佬提供的js，原文件地址：https://github.com/congcong0806/surge-list/blob/master/Script/ipcheck.js
* 用法
* [Panel]
* #节点检测
* ipcheck = script-name=ipcheck, title="节点详情", content="请刷新", style=info, update-interval=1
* ...
* [Script]
* #节点检测
* ipcheck = type=generic,timeout=3,script-path=https://raw.githubusercontent.com/LucaLin233/Luca_Conf/main/Surge/JS/ipcheck.js
*/

let url = "http://ip-api.com/json/?lang=zh-CN"

$httpClient.get(url, function(error, response, data){
    let jsonData = JSON.parse(data)
    let country = jsonData.country
    let emoji = getFlagEmoji(jsonData.countryCode)
    let city = jsonData.city
    let isp = jsonData.isp
    let ip = jsonData.query
  body = {
    title: "𝑰𝑷 𝑪𝒉𝒆𝒄𝒌",
    content: `IP信息：${ip}\n运营商：${isp}\nIP位置：${country} - ${city}`,
    icon: "globe.asia.australia.fill"
  }
  $done(body);
});


function getFlagEmoji(countryCode) {
    const codePoints = countryCode
      .toUpperCase()
      .split('')
      .map(char =>  127397 + char.charCodeAt());
    return String.fromCodePoint(...codePoints);
}