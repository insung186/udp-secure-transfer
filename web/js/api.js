(function () {
  async function request(path, options = {}) {
    const init = {
      method: options.method || "GET",
      headers: {"Content-Type": "application/json"},
    };
    if (options.body) {
      init.body = JSON.stringify(options.body);
    }
    const response = await fetch(path, init);
    const text = await response.text();
    let data;
    try {
      data = text ? JSON.parse(text) : {};
    } catch (error) {
      data = {ok: false, raw: text, error: error.message};
    }
    if (!response.ok) {
      data.ok = false;
      data.error = data.error || response.statusText;
    }
    return data;
  }

  window.Api = {
    status: () => request("/api/status"),
    logs: () => request("/api/logs"),
    clearLogs: () => request("/api/logs/clear", {method: "POST"}),
    reset: () => request("/api/reset", {method: "POST"}),
    startServer: (body) => request("/api/server/start", {method: "POST", body}),
    stopServer: () => request("/api/server/stop", {method: "POST"}),
    startClient: (body) => request("/api/client/start", {method: "POST", body}),
    stopClient: () => request("/api/client/stop", {method: "POST"}),
    sendPassword: (password) => request("/api/client/send-password", {method: "POST", body: {password}}),
    runTests: () => request("/api/test/run", {method: "POST"}),
    testResult: () => request("/api/test/result"),
  };
})();
