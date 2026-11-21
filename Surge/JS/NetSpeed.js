
const $ = new Env('network-speed')

$.isPanel = () =>
  $.isSurge() &&
  typeof $input !== 'undefined' &&
  $.lodash_get($input, 'purpose') === 'panel'

let arg = {}
if (typeof $argument !== 'undefined' && $argument) {
  arg = Object.fromEntries(
    $argument.split('&').map(item => {
      const i = item.indexOf('=')
      return i < 0
        ? [decodeURIComponent(item), '']
        : [
            decodeURIComponent(item.slice(0, i)),
            decodeURIComponent(item.slice(i + 1))
          ]
    })
  )
}

let title = 'NetSpeed'
let content = ''
let icon = ''
let color = ''

const BASE = 'https://speed.cloudflare.com'
const MB = 1024 * 1024

// 测速参数：下载 70MB，上传 45MB
const DOWN_SIZES = [10, 10, 25, 25]
const UP_SIZES = [10, 10, 25]

// 四舍五入
function round(n, p = 0) {
  const m = Math.pow(10, p)
  return Math.round(n * m) / m
}

// 中位数
function median(arr) {
  const a = [...arr].sort((x, y) => x - y)
  const mid = Math.floor(a.length / 2)
  return a.length % 2
    ? a[mid]
    : (a[mid - 1] + a[mid]) / 2
}

// HTTP 请求
async function request(method, url, body) {
  const options = {
    url,
    timeout: 30
  }

  if (method === 'POST') {
    options.body = body
    options.headers = {
      'Content-Type': 'application/octet-stream'
    }
    return await $.http.post(options)
  }

  return await $.http.get(options)
}

// 检查 HTTP 状态
function checkResponse(res) {
  const status = res?.statusCode || res?.status || 0
  if (status < 200 || status >= 300) {
    throw new Error(`HTTP 请求失败：${status || '无响应'}`)
  }
}

// 单次延迟测试
async function testPing() {
  const times = []

  for (let i = 0; i < 5; i++) {
    const start = Date.now()

    const res = await request(
      'GET',
      `${BASE}/__down?bytes=0&measId=${Date.now()}-${i}`
    )

    checkResponse(res)
    times.push(Date.now() - start)
  }

  return {
    ping: median(times),
    jitter: times.length > 1
      ? times.slice(1).reduce(
          (sum, v, i) => sum + Math.abs(v - times[i]), 0
        ) / (times.length - 1)
      : 0
  }
}

// 下载测速
async function testDownload() {
  let totalBytes = 0
  let totalTime = 0
  const samples = []

  for (let i = 0; i < DOWN_SIZES.length; i++) {
    const size = DOWN_SIZES[i] * MB
    const url =
      `${BASE}/__down?bytes=${size}&measId=${Date.now()}-${i}`

    const start = Date.now()
    const res = await request('GET', url)
    checkResponse(res)

    const duration = (Date.now() - start) / 1000

    if (duration <= 0) continue

    const speed = size * 8 / duration / 1000000

    samples.push(speed)
    totalBytes += size
    totalTime += duration

    // 释放响应引用
    res.body = null
  }

  if (!totalTime) {
    throw new Error('下载测速没有获得有效数据')
  }

  return {
    speed: totalBytes * 8 / totalTime / 1000000,
    samples
  }
}

// 上传测速
async function testUpload() {
  let totalBytes = 0
  let totalTime = 0
  const samples = []

  for (let i = 0; i < UP_SIZES.length; i++) {
    const size = UP_SIZES[i] * MB

    // 生成实际上传数据
    const payload = '0'.repeat(size)

    const url =
      `${BASE}/__up?measId=${Date.now()}-${i}`

    const start = Date.now()
    const res = await request('POST', url, payload)
    checkResponse(res)

    const duration = (Date.now() - start) / 1000

    if (duration <= 0) continue

    const speed = size * 8 / duration / 1000000

    samples.push(speed)
    totalBytes += size
    totalTime += duration

    res.body = null
  }

  if (!totalTime) {
    throw new Error('上传测速没有获得有效数据')
  }

  return {
    speed: totalBytes * 8 / totalTime / 1000000,
    samples
  }
}

// 图标与颜色
function setAppearance(download, ping) {
  const iconKey =
    download < 80 ? 'iconslow' :
    download < 120 ? 'iconmid' : 'iconfast'

  const colorKey =
    ping < 150 ? 'colorlow' :
    ping < 300 ? 'colormid' : 'colorhigh'

  icon = arg[iconKey] || ''
  color = arg[colorKey] || ''
}

// 主程序
;(async () => {
  const startTime = Date.now()

  // 1. 延迟
  const latency = await testPing()

  // 2. 下载
  const down = await testDownload()

  // 3. 上传
  let upSpeed = null
  let upError = ''

  try {
    const up = await testUpload()
    upSpeed = up.speed
  } catch (e) {
    upError = e.message || String(e)
  }

  const download = round(down.speed, 2)
  const upload = upSpeed === null ? null : round(upSpeed, 2)
  const ping = round(latency.ping)
  const jitter = round(latency.jitter, 1)

  setAppearance(download, ping)

  const downMB = download / 8
  const upMB = upload === null ? null : upload / 8

  title = 'NetSpeed'

  content =
    `↓ 下载速度：${download} Mbps [${round(downMB, 2)} MB/s]\n` +
    `↑ 上传速度：${upload === null ? '测试失败' : `${upload} Mbps [${round(upMB, 2)} MB/s]`}\n` +
    `网络延迟：${ping} ms\n` +
    `网络抖动：${jitter} ms\n` +
    `下载样本：${DOWN_SIZES.join(' + ')} MB\n` +
    `上传样本：${UP_SIZES.join(' + ')} MB\n` +
    `测速耗时：${round((Date.now() - startTime) / 1000, 1)} s` +
    (upError ? `\n上传错误：${upError}` : '')

  if (arg.notify) {
    await notify('网络速率', title, content)
  }

})()
.catch(async e => {
  title = '❌ 网络测速失败'
  content = e.message || String(e)

  if (arg.notify) {
    await notify('网络速率', title, content)
  }

  $.logErr(e)
})
.finally(() => {
  const result = {
    title,
    content,
    icon,
    'icon-color': color,
    ...arg
  }

  $.log($.toStr(result))
  $.done(result)
})

// 通知
async function notify(title, subt, desc, opts) {
  if (arg.notify) {
    $.msg(title, subt, desc, opts)
  }
}
