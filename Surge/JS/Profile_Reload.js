$httpAPI("POST", "/v1/profiles/reload", {}, data => {
   var now = new Date();
   var month = now.getMonth();
   var date = now.getDate();
   var hour = now.getHours();
   var minutes = now.getMinutes();
   var seconds = now.getSeconds();
   var monthArray=new Array("Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec");
   hour = hour > 9 ? hour : "0" + hour;
   minutes = minutes > 9 ? minutes : "0" + minutes;
   seconds = seconds > 9 ? seconds : "0" + seconds;
    $done({
        title:"Profile Reload",
        content:"Last runtime:  "+monthArray[month]+" "+date+"  "+hour+":"+minutes+":"+seconds,
        icon:"pencil.and.outline",
        "icon-color": "#FF9500",
     })
    }); 
