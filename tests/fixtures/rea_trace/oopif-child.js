var parentOrigin = location.hostname === "localhost"
  ? "http://127.0.0.1:" + location.port
  : "http://localhost:" + location.port;
function requestConfig() {
  return fetch(location.origin + "/api?branch=oopif");
}
window.addEventListener("message", function (ev) {
  if (ev.origin !== parentOrigin) {
    return;
  }
  if (!ev.data || ev.data.type !== "fxapk-load") {
    return;
  }
  requestConfig();
});
parent.postMessage({type: "fxapk-ready"}, parentOrigin);
