function requestConfig(branch) {
  return fetch("/api?branch=" + branch);
}
function independentDecoy() {
  return requestConfig("decoy");
}
function initProbe() {
  setTimeout(independentDecoy, 50);
}
function clickSend() {
  return requestConfig("clicked");
}
function loadConfig() {
  setTimeout(clickSend, 50);
}
initProbe();
document.getElementById("load").addEventListener("click", function () {
  loadConfig();
});
