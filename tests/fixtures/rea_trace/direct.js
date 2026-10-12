function requestConfig(branch) {
  return fetch("/api?branch=" + branch);
}
function loadConfig() {
  return requestConfig("direct");
}
document.getElementById("load").addEventListener("click", function () {
  loadConfig();
});
