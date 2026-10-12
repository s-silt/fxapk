function requestConfig(branch) {
  return fetch("/api?branch=" + branch);
}
function workerSend() {
  return requestConfig("worker");
}
self.onmessage = function () {
  workerSend();
};
