// Runs only against the isolated real Web artifact through Chrome DevTools.
// It imports no product module and writes one canonical mode-0600 report.
import crypto from "node:crypto";
import fs from "node:fs";

const cdpBase = process.env.CONTROL_CHROME_CDP_URL;
const resetUrl = process.env.CONTROL_RESET_BROWSER_URL;
const output = process.env.CONTROL_RESET_BROWSER_OUTPUT;
if (!cdpBase || !resetUrl || !output) {
  throw new Error("browser contract variables are unavailable");
}

const token = "A".repeat(64);
const password = "Contract-Reset-2026!";
const targetResponse = await fetch(
  `${cdpBase.replace(/\/$/, "")}/json/new?${encodeURIComponent(
    `${resetUrl}#token=${token}`,
  )}`,
  { method: "PUT" },
);
if (!targetResponse.ok) throw new Error("Chrome target is unavailable");
const target = await targetResponse.json();
const socket = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((resolve, reject) => {
  socket.addEventListener("open", resolve, { once: true });
  socket.addEventListener("error", reject, { once: true });
});

let sequence = 0;
const pending = new Map();
socket.addEventListener("message", (event) => {
  const message = JSON.parse(String(event.data));
  if (message.id && pending.has(message.id)) {
    const { resolve, reject } = pending.get(message.id);
    pending.delete(message.id);
    if (message.error) reject(new Error(message.error.message));
    else resolve(message.result);
  }
});

function command(method, params = {}) {
  const id = ++sequence;
  socket.send(JSON.stringify({ id, method, params }));
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
  });
}

async function evaluate(expression) {
  const result = await command("Runtime.evaluate", {
    expression,
    awaitPromise: true,
    returnByValue: true,
  });
  if (result.exceptionDetails) throw new Error("browser contract exception");
  return result.result.value;
}

await command("Runtime.enable");
await command("Page.enable");
await command("Page.addScriptToEvaluateOnNewDocument", {
  source: `
    (() => {
      const captured = [];
      Object.defineProperty(window, "__controlContractRequests", {
        value: captured,
        configurable: false,
        writable: false,
      });
      const originalOpen = XMLHttpRequest.prototype.open;
      const originalSend = XMLHttpRequest.prototype.send;
      XMLHttpRequest.prototype.open = function(method, url, ...rest) {
        this.__contractMethod = String(method);
        this.__contractUrl = String(url);
        return originalOpen.call(this, method, url, ...rest);
      };
      XMLHttpRequest.prototype.send = function(body) {
        captured.push({
          method: this.__contractMethod,
          url: this.__contractUrl,
          body: typeof body === "string" ? body : "",
        });
        return originalSend.call(this, body);
      };
      const originalFetch = window.fetch.bind(window);
      window.fetch = function(input, init = {}) {
        const url =
          typeof input === "string" ? input : String(input && input.url);
        if (url.includes("/auth/redefinir-senha")) {
          captured.push({
            method: String(init.method || "GET"),
            url,
            body: typeof init.body === "string" ? init.body : "",
          });
        }
        return originalFetch(input, init);
      };
    })();
  `,
});
await command("Page.navigate", { url: `${resetUrl}#token=${token}` });

let ready = false;
for (let index = 0; index < 100; index += 1) {
  ready = await evaluate(
    `location.hash === "" && document.querySelector("#senha") !== null`,
  );
  if (ready) break;
  await new Promise((resolve) => setTimeout(resolve, 100));
}
if (!ready) throw new Error("reset form did not consume the fragment");

await evaluate(`
  (() => {
    const set = Object.getOwnPropertyDescriptor(
      HTMLInputElement.prototype,
      "value",
    ).set;
    for (const [id, value] of [
      ["senha", ${JSON.stringify(password)}],
      ["confirma", ${JSON.stringify(password)}],
    ]) {
      const input = document.getElementById(id);
      set.call(input, value);
      input.dispatchEvent(new Event("input", { bubbles: true }));
    }
    document.querySelector("form").requestSubmit();
  })()
`);

let captured = [];
for (let index = 0; index < 100; index += 1) {
  captured = await evaluate(`window.__controlContractRequests`);
  if (captured.length) break;
  await new Promise((resolve) => setTimeout(resolve, 100));
}
if (captured.length !== 1) throw new Error("reset POST was not unique");
const request = captured[0];
const parsedUrl = new URL(request.url, resetUrl);
const body = JSON.parse(request.body);
if (
  request.method !== "POST" ||
  parsedUrl.pathname !== "/api/auth/redefinir-senha" ||
  body.token !== token ||
  body.senha_nova !== password
) {
  throw new Error("reset POST contract diverged");
}
const currentUrl = await evaluate(`location.href`);
if (currentUrl.includes(token) || request.url.includes(token)) {
  throw new Error("reset token remained observable in a URL");
}
const legacyStatus = await evaluate(`
  fetch("/redefinir-senha/token-legado", { redirect: "manual" })
    .then((response) => response.status)
`);
const report = {
  fragment_removed_before_submit: true,
  legacy_path_status: legacyStatus,
  request_body_keys: Object.keys(body).sort(),
  request_method: request.method,
  request_path: parsedUrl.pathname,
  request_token_sha256: crypto
    .createHash("sha256")
    .update(token)
    .digest("hex"),
  schema_version: 1,
  token_observed_in_url: false,
};
const canonical = {};
for (const key of Object.keys(report).sort()) canonical[key] = report[key];
fs.writeFileSync(output, `${JSON.stringify(canonical)}\n`, {
  mode: 0o600,
  flag: "wx",
});
socket.close();
