
console.log("NetSpeed Panel Test");
console.log("Trigger: " + $trigger);
console.log("Input: " + JSON.stringify($input));

$done({
  title: "NetSpeed 测试",
  content: "Panel 调用成功！\nSurge 脚本运行正常。",
  icon: "checkmark.circle.fill",
  "icon-color": "#06D6A0"
});
