function requestConfig(branch) {
  return fetch("/api?branch=" + branch);
}
function childSend() {
  return requestConfig("crossframe");
}
function scheduleFromParent() {
  return Promise.resolve().then(function () {
    setTimeout(function () {
      childSend();
    }, 30);
  });
}
