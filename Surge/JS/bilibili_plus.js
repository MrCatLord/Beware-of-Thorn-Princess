#!name=Bilibili_CC
#!desc=Bilibili_CC繁体转简体

[Script]

# > 哔哩哔哩繁体CC字幕转中文简体
bilibili_cc_16 = type=http-response, pattern=^https?:\/\/aisubtitle\.hdslb\.com\/bfs\/subtitle\/.+\.json, requires-body=true, max-size=3145728, script-path=https://github.com/ddgksf2013/Scripts/raw/master/bilibili_cc.js, timeout=60, script-update-interval=0

[MITM]

hostname = %APPEND% aisubtitle.hdslb.com
