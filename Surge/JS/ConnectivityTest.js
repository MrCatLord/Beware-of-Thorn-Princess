let $ = {
Bilibili:'https://www.bilibili.com',
Baidu:'https://www.baidu.com',
Youtube:'https://www.youtube.com/',
Google:'https://www.google.com/generate_204',
Github:'https://www.github.com'
}

!(async () => {
await Promise.all([http('Baidu'),http('Bilibili'),http('Github'),http('Google'),http('Youtube')]).then((x)=>{
	$done({
    title: '𝑵𝒆𝒕𝒘𝒐𝒓𝒌 𝑪𝒐𝒏𝒏𝒆𝒄𝒕𝒊𝒗𝒊𝒕𝒚 𝑻𝒆𝒔𝒕',
    content: x.join('\n'),
    icon: 'timer',
    'icon-color': '#66CDAA',
  })
})
})();

function http(req) {
    return new Promise((r) => {
			let time = Date.now();
        $httpClient.post($[req], (err, resp, data) => {
            r(req +
						'\xa0\xa0\xa0\t: ' +
						(Date.now() - time)+' ms');
        });
    });
}
