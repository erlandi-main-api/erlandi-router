#!/usr/bin/env node
var __defProp = Object.defineProperty;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __require = /* @__PURE__ */ ((x) => typeof require !== "undefined" ? require : typeof Proxy !== "undefined" ? new Proxy(x, {
  get: (a, b) => (typeof require !== "undefined" ? require : a)[b]
}) : x)(function(x) {
  if (typeof require !== "undefined") return require.apply(this, arguments);
  throw Error('Dynamic require of "' + x + '" is not supported');
});
var __esm = (fn, res, err) => function __init() {
  if (err) throw err[0];
  try {
    return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
  } catch (e) {
    throw err = [e], e;
  }
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// src/security/policy.ts
import { BlockList, isIP } from "node:net";
function normalizeSecurityConfig(raw) {
  const mode = normalizedMode(raw?.mode) === "strict" ? "strict" : "normal";
  const allowedUpstreams = Array.isArray(raw?.allowedUpstreams) ? [...new Set(raw.allowedUpstreams.filter((value) => typeof value === "string").map((value) => value.trim()).filter(Boolean))] : [];
  return {
    mode,
    allowedUpstreams,
    // strict mode stays fail-closed even if a stale config says otherwise
    allowCrossProviderFailover: mode === "strict" ? false : raw?.allowCrossProviderFailover !== false,
    unsafeAllowNonLoopbackBind: raw?.unsafeAllowNonLoopbackBind === true,
    dlp: normalizedMode(raw?.dlp) === "block" ? "block" : "redact"
  };
}
function normalizedMode(value) {
  return typeof value === "string" ? value.trim().toLowerCase() : void 0;
}
function securityConfigWarnings(raw) {
  if (raw === void 0 || raw === null) return [];
  if (typeof raw !== "object" || Array.isArray(raw)) {
    return [`security must be an object such as {"mode": "strict"}, got ${JSON.stringify(raw)}; running in normal mode (secret guard and strict protections are OFF).`];
  }
  const { mode: rawMode, dlp: rawDlp } = raw;
  const warnings = [];
  const mode = normalizedMode(rawMode);
  if (rawMode !== void 0 && mode !== "strict" && mode !== "normal") {
    warnings.push(
      `security.mode ${JSON.stringify(rawMode)} is not recognized; running in normal mode (secret guard and strict protections are OFF). Use "strict" or "normal".`
    );
  }
  const dlp = normalizedMode(rawDlp);
  if (mode === "strict" && rawDlp !== void 0 && dlp !== "redact" && dlp !== "block") {
    warnings.push(`security.dlp ${JSON.stringify(rawDlp)} is not recognized; using "redact". Use "redact" or "block".`);
  }
  return warnings;
}
function isStrictSecurity(config) {
  return config.mode === "strict";
}
function isLoopbackBind(bind) {
  const normalized = bind.trim().toLowerCase();
  if (normalized === "localhost") return true;
  const address = normalized.startsWith("[") && normalized.endsWith("]") ? normalized.slice(1, -1) : normalized;
  if (isIP(address) === 4) {
    return address.split(".")[0] === "127";
  }
  const mappedIpv4 = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(address);
  if (mappedIpv4) return isLoopbackBind(mappedIpv4[1]);
  return isIP(address) === 6 && IPV6_LOOPBACK.check(address, "ipv6");
}
function assertBindAllowed(bind, security, cliUnsafeOverride = false) {
  if (!isStrictSecurity(security) || isLoopbackBind(bind)) return;
  if (security.unsafeAllowNonLoopbackBind || cliUnsafeOverride) return;
  throw new Error(
    `strict security mode refuses non-loopback bind "${bind}"; use 127.0.0.1 or pass --unsafe-allow-non-loopback explicitly`
  );
}
function isUpstreamAllowed(security, upstreamId) {
  return !isStrictSecurity(security) || security.allowedUpstreams.includes(upstreamId);
}
function isCrossProviderFailoverAllowed(security) {
  return !isStrictSecurity(security) && security.allowCrossProviderFailover;
}
function isRelayAllowed(security) {
  return !isStrictSecurity(security);
}
function isSensitiveNetworkHost(hostname) {
  const normalized = hostname.trim().toLowerCase();
  const address = normalized.startsWith("[") && normalized.endsWith("]") ? normalized.slice(1, -1) : normalized;
  if (isIP(address) === 4) {
    return SENSITIVE_IPV4.check(address, "ipv4");
  }
  if (isIP(address) === 6) {
    const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(address);
    if (mapped) return SENSITIVE_IPV4.check(mapped[1], "ipv4");
    return SENSITIVE_IPV6.check(address, "ipv6");
  }
  return false;
}
var DEFAULT_SECURITY_CONFIG, IPV6_LOOPBACK, SENSITIVE_IPV4, SENSITIVE_IPV6;
var init_policy = __esm({
  "src/security/policy.ts"() {
    "use strict";
    DEFAULT_SECURITY_CONFIG = {
      mode: "normal",
      allowedUpstreams: [],
      allowCrossProviderFailover: true,
      unsafeAllowNonLoopbackBind: false,
      dlp: "redact"
    };
    IPV6_LOOPBACK = new BlockList();
    IPV6_LOOPBACK.addAddress("::1", "ipv6");
    SENSITIVE_IPV4 = new BlockList();
    SENSITIVE_IPV4.addSubnet("0.0.0.0", 8, "ipv4");
    SENSITIVE_IPV4.addSubnet("10.0.0.0", 8, "ipv4");
    SENSITIVE_IPV4.addSubnet("100.64.0.0", 10, "ipv4");
    SENSITIVE_IPV4.addSubnet("127.0.0.0", 8, "ipv4");
    SENSITIVE_IPV4.addSubnet("169.254.0.0", 16, "ipv4");
    SENSITIVE_IPV4.addSubnet("172.16.0.0", 12, "ipv4");
    SENSITIVE_IPV4.addSubnet("192.0.0.0", 24, "ipv4");
    SENSITIVE_IPV4.addSubnet("192.0.2.0", 24, "ipv4");
    SENSITIVE_IPV4.addSubnet("192.168.0.0", 16, "ipv4");
    SENSITIVE_IPV4.addSubnet("198.18.0.0", 15, "ipv4");
    SENSITIVE_IPV4.addSubnet("198.51.100.0", 24, "ipv4");
    SENSITIVE_IPV4.addSubnet("203.0.113.0", 24, "ipv4");
    SENSITIVE_IPV4.addSubnet("224.0.0.0", 4, "ipv4");
    SENSITIVE_IPV4.addSubnet("240.0.0.0", 4, "ipv4");
    SENSITIVE_IPV6 = new BlockList();
    SENSITIVE_IPV6.addAddress("::", "ipv6");
    SENSITIVE_IPV6.addAddress("::1", "ipv6");
    SENSITIVE_IPV6.addSubnet("fc00::", 7, "ipv6");
    SENSITIVE_IPV6.addSubnet("fe80::", 10, "ipv6");
    SENSITIVE_IPV6.addSubnet("2001:db8::", 32, "ipv6");
  }
});

// src/daemon/state.ts
var state_exports = {};
__export(state_exports, {
  BANSOS_DIR: () => BANSOS_DIR,
  CONFIG_FILE: () => CONFIG_FILE,
  DEFAULT_BODY_BYTES: () => DEFAULT_BODY_BYTES,
  DEFAULT_CONFIG: () => DEFAULT_CONFIG,
  LOG_DIR: () => LOG_DIR,
  LOG_FILE: () => LOG_FILE,
  MAX_BODY_BYTES: () => MAX_BODY_BYTES,
  MIN_BODY_BYTES: () => MIN_BODY_BYTES,
  RELAY_STATE_FILE: () => RELAY_STATE_FILE,
  STATE_FILE: () => STATE_FILE,
  effectiveBind: () => effectiveBind,
  effectivePort: () => effectivePort,
  ensureBansosDir: () => ensureBansosDir,
  loadConfig: () => loadConfig,
  loadConfigWarnings: () => loadConfigWarnings,
  normalizeBodyBytes: () => normalizeBodyBytes,
  readJson: () => readJson,
  readRawConfig: () => readRawConfig,
  runningDaemonUrl: () => runningDaemonUrl,
  startArgs: () => startArgs,
  writeJsonAtomic: () => writeJsonAtomic
});
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
function normalizeBodyBytes(value) {
  const n = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(n) || n <= 0) return DEFAULT_BODY_BYTES;
  return Math.min(Math.max(Math.round(n), MIN_BODY_BYTES), MAX_BODY_BYTES);
}
function ensureBansosDir() {
  fs.mkdirSync(BANSOS_DIR, { recursive: true });
}
function effectivePort() {
  const state = readJson(STATE_FILE);
  return typeof state?.port === "number" ? state.port : loadConfig().port;
}
function effectiveBind() {
  const state = readJson(STATE_FILE);
  return typeof state?.bind === "string" ? state.bind : loadConfig().bind;
}
function startArgs(flags = {}) {
  return [
    ...flags.port !== void 0 ? ["--port", String(flags.port)] : [],
    ...flags.bind !== void 0 ? ["--bind", flags.bind] : [],
    ...flags.unsafeAllowNonLoopback ? ["--unsafe-allow-non-loopback"] : []
  ];
}
async function runningDaemonUrl(port) {
  if (port !== void 0 && port !== effectivePort()) return null;
  const base = `http://${effectiveBind()}:${effectivePort()}`;
  try {
    const res = await fetch(`${base}/healthz`, { signal: AbortSignal.timeout(800) });
    return res.ok ? base : null;
  } catch {
    return null;
  }
}
function readRawConfig(file = CONFIG_FILE) {
  let text;
  try {
    text = fs.readFileSync(file, "utf8");
  } catch {
    return { raw: null, invalid: false };
  }
  try {
    const raw = JSON.parse(text);
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return { raw: null, invalid: true };
    return { raw, invalid: false };
  } catch {
    return { raw: null, invalid: true };
  }
}
function loadConfigWarnings(file = CONFIG_FILE) {
  const { raw, invalid } = readRawConfig(file);
  if (invalid) {
    return [`${file} is not a valid JSON object; using defaults (normal mode, strict protections OFF).`];
  }
  return securityConfigWarnings(raw?.security);
}
function loadConfig(file = CONFIG_FILE) {
  const { raw } = readRawConfig(file);
  if (!raw) return { ...DEFAULT_CONFIG };
  return {
    ...DEFAULT_CONFIG,
    ...raw,
    security: normalizeSecurityConfig(raw.security),
    maxBodyBytes: normalizeBodyBytes(raw.maxBodyBytes),
    localUpstreams: raw.localUpstreams ?? []
  };
}
function writeJsonAtomic(file, data) {
  ensureBansosDir();
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, `${JSON.stringify(data, null, 2)}
`, { mode: 384 });
  fs.renameSync(tmp, file);
}
function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return null;
  }
}
var BANSOS_DIR, CONFIG_FILE, STATE_FILE, RELAY_STATE_FILE, LOG_DIR, LOG_FILE, DEFAULT_BODY_BYTES, MIN_BODY_BYTES, MAX_BODY_BYTES, DEFAULT_CONFIG;
var init_state = __esm({
  "src/daemon/state.ts"() {
    "use strict";
    init_policy();
    BANSOS_DIR = process.env.BANSOS_DIR || path.join(os.homedir(), ".bansos");
    CONFIG_FILE = path.join(BANSOS_DIR, "config.json");
    STATE_FILE = path.join(BANSOS_DIR, "state.json");
    RELAY_STATE_FILE = path.join(BANSOS_DIR, "relay-state.json");
    LOG_DIR = path.join(BANSOS_DIR, "logs");
    LOG_FILE = path.join(LOG_DIR, "bansosd.log");
    DEFAULT_BODY_BYTES = 10 * 1024 * 1024;
    MIN_BODY_BYTES = 1024 * 1024;
    MAX_BODY_BYTES = 256 * 1024 * 1024;
    DEFAULT_CONFIG = {
      port: 17070,
      bind: "127.0.0.1",
      refreshIntervalMs: 30 * 6e4,
      security: { ...DEFAULT_SECURITY_CONFIG },
      maxBodyBytes: DEFAULT_BODY_BYTES,
      localUpstreams: []
    };
  }
});

// src/cli/index.ts
import fs14 from "node:fs";
import os8 from "node:os";
import path13 from "node:path";
import { execFileSync as execFileSync2, spawn as spawn2, spawnSync as spawnSync5 } from "node:child_process";

// src/cli/autostart.ts
init_state();
import fs2 from "node:fs";
import os2 from "node:os";
import path2 from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
var UNIT = "bansos-router.service";
var LABEL = "io.github.ihsan-ramadhan.bansos-router";
function defaultAutostartEnv() {
  const script = process.argv[1] ? path2.resolve(process.argv[1]) : "";
  const home = os2.homedir();
  const bunPath = (() => {
    try {
      const which = spawnSync("which", ["bun"], { encoding: "utf8", timeout: 1e3 });
      if (which.status === 0 && which.stdout.trim() && fs2.existsSync(which.stdout.trim())) {
        return which.stdout.trim();
      }
    } catch {
    }
    const candidates = [
      path2.join(home, ".bun", "bin", "bun"),
      "/usr/local/bin/bun",
      "/usr/bin/bun"
    ];
    for (const c of candidates) {
      if (fs2.existsSync(c)) return c;
    }
    return null;
  })();
  const execPath = bunPath ?? process.execPath;
  return {
    platform: process.platform,
    home,
    appData: process.env.APPDATA,
    uid: typeof process.getuid === "function" ? process.getuid() : void 0,
    command: [execPath, ...process.execArgv, script],
    run(cmd, args) {
      try {
        return { ok: true, stdout: execFileSync(cmd, args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }) };
      } catch {
        return { ok: false, stdout: "" };
      }
    }
  };
}
function managerFor(platform) {
  if (platform === "linux") return "systemd";
  if (platform === "darwin") return "launchd";
  if (platform === "win32") return "startup-folder";
  return null;
}
function autostartPath(env) {
  switch (managerFor(env.platform)) {
    case "systemd":
      return path2.join(env.home, ".config", "systemd", "user", UNIT);
    case "launchd":
      return path2.join(env.home, "Library", "LaunchAgents", `${LABEL}.plist`);
    case "startup-folder":
      return path2.join(env.appData ?? path2.join(env.home, "AppData", "Roaming"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup", "bansos-router.cmd");
    default:
      return void 0;
  }
}
var systemdQuote = (a) => `"${a.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/%/g, "%%").replace(/\$/g, "$$$$")}"`;
var xmlEscape = (a) => a.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
var xmlUnescape = (a) => a.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
function renderAutostart(env) {
  switch (managerFor(env.platform)) {
    case "systemd":
      const extraPaths = [
        path2.join(env.home, ".bun", "bin"),
        path2.join(env.home, ".npm-global", "bin"),
        path2.join(env.home, ".local", "bin"),
        "/usr/local/bin",
        "/usr/bin"
      ].join(":");
      return [
        "[Unit]",
        "Description=bansos-router daemon",
        "",
        "[Service]",
        `Environment="PATH=${extraPaths}"`,
        `ExecStart=${[...env.command, "daemon"].map(systemdQuote).join(" ")}`,
        "Restart=on-failure",
        "RestartSec=5",
        "",
        "[Install]",
        "WantedBy=default.target",
        ""
      ].join("\n");
    case "launchd":
      return [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
        '<plist version="1.0">',
        "<dict>",
        `  <key>Label</key><string>${LABEL}</string>`,
        "  <key>ProgramArguments</key>",
        "  <array>",
        ...[...env.command, "daemon"].map((a) => `    <string>${xmlEscape(a)}</string>`),
        "  </array>",
        "  <key>RunAtLoad</key><true/>",
        "  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>",
        "</dict>",
        "</plist>",
        ""
      ].join("\n");
    case "startup-folder":
      return ["@echo off", `${[...env.command].map((a) => `"${a.replace(/%/g, "%%")}"`).join(" ")} start --bg`, ""].join("\r\n");
    default:
      return "";
  }
}
function parseCommand(manager, text) {
  if (manager === "systemd") {
    const line = text.split("\n").find((l) => l.startsWith("ExecStart=")) ?? "";
    return [...line.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map(
      (m) => m[1].replace(/\\(.)/g, "$1").replace(/%%/g, "%").replace(/\$\$/g, "$")
    );
  }
  if (manager === "launchd") {
    const array = /<key>ProgramArguments<\/key>\s*<array>([\s\S]*?)<\/array>/.exec(text)?.[1] ?? "";
    return [...array.matchAll(/<string>([\s\S]*?)<\/string>/g)].map((m) => xmlUnescape(m[1]));
  }
  return [...text.matchAll(/"([^"]*)"/g)].map((m) => m[1].replace(/%%/g, "%"));
}
function unsupportedReason(env) {
  const manager = managerFor(env.platform);
  if (!manager) return `starting at login is not supported on ${env.platform}`;
  if (manager === "systemd" && !env.run("systemctl", ["--user", "show-environment"]).ok) {
    return "systemd user services are not available here; add `bansos start --bg` to your desktop's startup applications instead";
  }
  return void 0;
}
function autostartStatus(env = defaultAutostartEnv()) {
  const manager = managerFor(env.platform);
  const file = autostartPath(env);
  const reason = unsupportedReason(env);
  const installed = Boolean(file && fs2.existsSync(file));
  const command = installed && manager ? parseCommand(manager, fs2.readFileSync(file, "utf8")) : void 0;
  const enabled = manager === "systemd" && !reason ? env.run("systemctl", ["--user", "is-enabled", UNIT]).stdout.trim() === "enabled" : installed;
  const broken = Boolean(command?.some((a) => path2.isAbsolute(a) && !fs2.existsSync(a)));
  return { manager, supported: !reason, ...reason ? { reason } : {}, enabled, path: file, ...command ? { command } : {}, broken };
}
function enableAutostart(startNow, env = defaultAutostartEnv()) {
  const reason = unsupportedReason(env);
  if (reason) throw new Error(reason);
  const file = autostartPath(env);
  fs2.mkdirSync(path2.dirname(file), { recursive: true });
  fs2.writeFileSync(file, renderAutostart(env));
  const manager = managerFor(env.platform);
  if (manager === "systemd") {
    env.run("systemctl", ["--user", "daemon-reload"]);
    if (!env.run("systemctl", ["--user", "enable", ...startNow ? ["--now"] : [], UNIT]).ok) {
      fs2.rmSync(file, { force: true });
      throw new Error(`systemctl --user enable ${UNIT} failed; check: systemctl --user status ${UNIT}`);
    }
  } else if (manager === "launchd" && startNow && env.uid !== void 0) {
    env.run("launchctl", ["bootstrap", `gui/${env.uid}`, file]);
  }
  return autostartStatus(env);
}
function restartManaged(env = defaultAutostartEnv()) {
  const manager = managerFor(env.platform);
  if (manager === "systemd") {
    if (unsupportedReason(env) || !env.run("systemctl", ["--user", "is-active", UNIT]).ok) return null;
    if (!env.run("systemctl", ["--user", "restart", UNIT]).ok) {
      throw new Error(`systemctl --user restart ${UNIT} failed; check: systemctl --user status ${UNIT}`);
    }
    return manager;
  }
  if (manager === "launchd" && env.uid !== void 0) {
    const target = `gui/${env.uid}/${LABEL}`;
    const printed = env.run("launchctl", ["print", target]);
    if (!printed.ok || !/^\s*state = running$/m.test(printed.stdout)) return null;
    if (!env.run("launchctl", ["kickstart", "-k", target]).ok) throw new Error(`launchctl kickstart -k ${target} failed`);
    return manager;
  }
  return null;
}
function disableAutostart(env = defaultAutostartEnv()) {
  const file = autostartPath(env);
  if (managerFor(env.platform) === "systemd" && !unsupportedReason(env)) {
    env.run("systemctl", ["--user", "disable", UNIT]);
  }
  if (file) fs2.rmSync(file, { force: true });
  if (managerFor(env.platform) === "systemd" && !unsupportedReason(env)) {
    env.run("systemctl", ["--user", "daemon-reload"]);
  }
  return autostartStatus(env);
}
function printStatus(s) {
  if (!s.supported) {
    console.log(`autostart: unsupported (${s.reason})`);
    return;
  }
  console.log(`autostart: ${s.enabled ? "on" : "off"} (${s.manager})`);
  if (s.path) console.log(`file:      ${s.path}${s.enabled || s.command ? "" : " (not installed)"}`);
  if (s.command) console.log(`command:   ${s.command.join(" ")}`);
  if (s.broken) console.log(`warning:   the command points at a path that no longer exists; run "bansos autostart on" again`);
}
async function runAutostart(argv, json = false) {
  const cmd = argv[0] ?? "status";
  try {
    if (cmd === "status") {
      const s = autostartStatus();
      if (json) console.log(JSON.stringify(s, null, 2));
      else printStatus(s);
      return 0;
    }
    if (cmd === "on") {
      const running = await runningDaemonUrl() !== null;
      const s = enableAutostart(!running);
      if (json) {
        console.log(JSON.stringify(s, null, 2));
        return 0;
      }
      printStatus(s);
      if (s.manager === "startup-folder") {
        console.log(running ? "bansos will start at your next login." : 'bansos will start at your next login; run "bansos start --bg" to start it now.');
      } else if (running) {
        console.log("the daemon you are running now keeps going; the service takes over at your next login.");
      } else {
        console.log("started now, and at every login.");
      }
      if (s.manager === "systemd") console.log("to start before you log in: loginctl enable-linger $USER");
      return 0;
    }
    if (cmd === "off") {
      const s = disableAutostart();
      if (json) {
        console.log(JSON.stringify(s, null, 2));
        return 0;
      }
      printStatus(s);
      console.log('a daemon that is running now keeps going; stop it with "bansos stop".');
      return 0;
    }
  } catch (err) {
    console.error(`bansos autostart: ${err.message}`);
    return 1;
  }
  console.error(`bansos autostart: unknown subcommand "${cmd}" (use on, off or status)`);
  return 1;
}

// src/cli/doctor.ts
import fs5 from "node:fs";
import os4 from "node:os";
import path5 from "node:path";
import { spawnSync as spawnSync2 } from "node:child_process";

// src/adapters/types.ts
var START_MARKER = "bansos-router:start";
var END_MARKER = "bansos-router:end";

// src/upstreams/types.ts
var ZERO_COST = {
  input: 0,
  output: 0,
  cacheRead: 0,
  cacheWrite: 0
};
function modelDef(partial) {
  return { cost: ZERO_COST, ...partial };
}
function compareModelsByCapacity(a, b) {
  if (b.contextWindow !== a.contextWindow) return b.contextWindow - a.contextWindow;
  return b.maxTokens - a.maxTokens;
}
var PREFERRED_DEFAULT_MODELS = ["deepseek-v4.1-flash-free", "big-pickle"];
function pickSmartDefaultModel(models, fallback = "big-pickle") {
  const valid = models.filter((m) => !m.id.toLowerCase().includes("safety"));
  for (const id of PREFERRED_DEFAULT_MODELS) {
    if (valid.some((m) => m.id === id)) return id;
  }
  const reasoning = valid.filter((m) => m.reasoning).sort(compareModelsByCapacity);
  if (reasoning.length > 0) return reasoning[0].id;
  const nonReasoning = [...valid].sort(compareModelsByCapacity);
  if (nonReasoning.length > 0) return nonReasoning[0].id;
  return fallback;
}

// src/cli/write.ts
import fs3 from "node:fs";
import os3 from "node:os";
import path3 from "node:path";
function expandHome(p) {
  if (p === "~") {
    return os3.homedir();
  }
  if (p.startsWith("~/") || p.startsWith("~\\")) {
    return path3.join(os3.homedir(), p.slice(2));
  }
  return p;
}
function parseJsonc(text) {
  const clean = text.replace(/^\uFEFF/, "");
  const out = [];
  let inString = false;
  let quoteChar = "";
  let isEscaped = false;
  for (let i = 0; i < clean.length; i++) {
    const ch = clean[i];
    const next = clean[i + 1];
    if (inString) {
      out.push(ch);
      if (isEscaped) {
        isEscaped = false;
      } else if (ch === "\\") {
        isEscaped = true;
      } else if (ch === quoteChar) {
        inString = false;
      }
    } else {
      if (ch === '"' || ch === "'") {
        inString = true;
        quoteChar = ch;
        out.push(ch);
      } else if (ch === "/" && next === "/") {
        while (i < clean.length && clean[i] !== "\n") i++;
        if (i < clean.length) out.push(clean[i]);
      } else if (ch === "/" && next === "*") {
        i += 2;
        while (i < clean.length && !(clean[i] === "*" && clean[i + 1] === "/")) i++;
        i++;
      } else if (ch === "}" || ch === "]") {
        let j = out.length - 1;
        while (j >= 0 && /\s/.test(out[j])) j--;
        if (out[j] === ",") out.splice(j, 1);
        out.push(ch);
      } else {
        out.push(ch);
      }
    }
  }
  return JSON.parse(out.join(""));
}
function markerBlock(content, markers) {
  if (content.includes(markers[0])) return `${content.replace(/\s+$/, "")}
`;
  return `${markers[0]}
${content.replace(/\s+$/, "")}
${markers[1]}
`;
}
function findBlock(lines, start, end) {
  const si = lines.findIndex((l) => l.includes(start));
  const ei = lines.findIndex((l) => l.includes(end));
  if (si === -1 || ei === -1 || ei < si) return null;
  return [si, ei];
}
function applyBlockWrite(existing, content, markers) {
  const block = markerBlock(content, markers);
  const lines = existing.split("\n");
  const span = findBlock(lines, markers[0], markers[1]);
  if (span) {
    const [si, ei] = span;
    const head = lines.slice(0, si).join("\n").replace(/\s+$/, "");
    const tail = lines.slice(ei + 1).join("\n").replace(/^\s+/, "");
    const parts = [head, block.replace(/\s+$/, ""), tail].filter((s) => s !== "");
    return `${parts.join("\n\n")}
`;
  }
  const base = existing.replace(/\s+$/, "");
  return base ? `${base}

${block}` : block;
}
var TOML_ROOT_TAG = "# bansos-router";
var TOML_PREV_TAG = "# bansos-router-prev: ";
var TOML_TAGGED_RE = /#\s*bansos-router\s*$/;
function tomlKeyRe(key) {
  return new RegExp(`^\\s*${key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*=`);
}
function upsertTomlRootKeys(lines, rootKeys) {
  for (const raw of rootKeys) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const key = line.split("=", 1)[0].trim();
    const keyRe = tomlKeyRe(key);
    let rootEnd = lines.findIndex((l) => /^\s*\[/.test(l));
    if (rootEnd === -1) rootEnd = lines.length;
    const tagged = `${line}  ${TOML_ROOT_TAG}`;
    const idx = lines.slice(0, rootEnd).findIndex((l) => keyRe.test(l));
    if (idx === -1) {
      let at = rootEnd;
      while (at > 0 && lines[at - 1].trim() === "") at--;
      lines.splice(at, 0, tagged);
      if (lines[at + 1] !== void 0 && /^\s*\[/.test(lines[at + 1])) lines.splice(at + 1, 0, "");
    } else if (TOML_TAGGED_RE.test(lines[idx]) || lines[idx].trim() === line) {
      lines[idx] = tagged;
    } else {
      lines.splice(idx, 1, `${TOML_PREV_TAG}${lines[idx].trim()}`, tagged);
    }
  }
}
function applyTomlBlockWrite(existing, content, markers, tableName, fillOnly = false) {
  const stripped = removeBlock(existing, markers).replace(/\s+$/, "");
  const lines = stripped === "" ? [] : stripped.split("\n");
  const contentLines = content.replace(/\s+$/, "").split("\n");
  const tblIdx = contentLines.findIndex((l) => /^\[/.test(l.trim()));
  const rootKeys = tblIdx === -1 ? contentLines : contentLines.slice(0, tblIdx);
  const tableBody = tblIdx === -1 ? [] : contentLines.slice(tblIdx + 1);
  const tableSection = tblIdx === -1 ? [] : contentLines.slice(tblIdx);
  upsertTomlRootKeys(lines, rootKeys);
  const headerRe = new RegExp(`^\\[${tableName.replace(/\./g, "\\.")}\\]\\s*$`);
  const headerIdx = lines.findIndex((l) => headerRe.test(l.trim()));
  if (headerIdx === -1) {
    const base = lines.join("\n").replace(/\s+$/, "");
    if (tableSection.length === 0) return `${base}
`;
    const block = markerBlock(tableSection.join("\n"), markers);
    return base ? `${base}

${block}` : block;
  }
  let sectionEnd = lines.length;
  for (let i = headerIdx + 1; i < lines.length; i++) {
    if (/^\s*\[/.test(lines[i])) {
      sectionEnd = i;
      break;
    }
  }
  for (const line of tableBody) {
    if (!line.trim() || /^#/.test(line.trim())) continue;
    const keyRe = tomlKeyRe(line.split("=", 1)[0].trim());
    let replaced = false;
    for (let i = headerIdx + 1; i < sectionEnd; i++) {
      if (keyRe.test(lines[i])) {
        if (!fillOnly) lines[i] = line;
        replaced = true;
        break;
      }
    }
    if (!replaced) {
      lines.splice(sectionEnd, 0, line);
      sectionEnd++;
    }
  }
  return `${lines.join("\n").replace(/\s+$/, "")}
`;
}
function removeTomlSection(content, table) {
  const esc = table.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const headerRe = new RegExp(`^\\[\\[?${esc}(\\.[^\\]]+)?\\]\\]?\\s*$`);
  const out = [];
  let skipping = false;
  for (const line of content.split("\n")) {
    if (/^\s*\[/.test(line)) skipping = headerRe.test(line.trim());
    if (!skipping) out.push(line);
  }
  return `${out.join("\n").replace(/\n{3,}/g, "\n\n").replace(/\s+$/, "")}
`;
}
function stripJcodeDefaults(content) {
  const out = [];
  let inProvider = false;
  for (const line of removeTomlSection(content, "providers.bansos").split("\n")) {
    const header = /^\s*\[([^\]]+)\]\s*$/.exec(line);
    if (header) inProvider = header[1] === "provider";
    if (inProvider && /^\s*default_(provider|model)\s*=/.test(line)) continue;
    out.push(line);
  }
  return `${out.join("\n").replace(/\n{3,}/g, "\n\n").replace(/\s+$/, "")}
`;
}
function removeTomlBlock(existing, markers) {
  const lines = removeBlock(existing, markers).split("\n");
  const out = [];
  for (const l of lines) {
    if (TOML_TAGGED_RE.test(l)) continue;
    out.push(l.startsWith(TOML_PREV_TAG) ? l.slice(TOML_PREV_TAG.length) : l);
  }
  return `${out.join("\n").replace(/\s+$/, "")}
`.replace(/^\n+/, "");
}
function applyYamlBlockWrite(existing, content, markers, parentKey) {
  const key = parentKey.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const stripped = removeBlock(existing, markers).replace(/\s+$/, "");
  const lines = stripped === "" ? [] : stripped.split("\n");
  const parentRe = new RegExp(`^${key}:\\s*(#.*)?$`);
  const inlineRe = new RegExp(`^${key}:\\s*\\S`);
  if (lines.some((l) => inlineRe.test(l) && !parentRe.test(l))) {
    throw new Error(`cannot merge under inline "${parentKey}:"; edit the file by hand`);
  }
  const body = content.replace(/\s+$/, "").split("\n");
  const parentIdx = lines.findIndex((l) => parentRe.test(l));
  if (parentIdx === -1) {
    const inner = body.map((l) => l ? `  ${l}` : l);
    const block2 = [markers[0], `${parentKey}:`, ...inner, markers[1]].join("\n");
    return stripped ? `${stripped}

${block2}
` : `${block2}
`;
  }
  let childIndent = 2;
  for (let i = parentIdx + 1; i < lines.length; i++) {
    if (lines[i].trim() === "") continue;
    const indent = lines[i].length - lines[i].trimStart().length;
    if (indent > 0) childIndent = indent;
    break;
  }
  const pad2 = " ".repeat(childIndent);
  const block = [`${pad2}${markers[0]}`, ...body.map((l) => l ? `${pad2}${l}` : l), `${pad2}${markers[1]}`];
  let insertAt = lines.length;
  for (let i = parentIdx + 1; i < lines.length; i++) {
    if (lines[i].trim() === "") continue;
    const indent = lines[i].length - lines[i].trimStart().length;
    if (indent === 0) {
      insertAt = i;
      break;
    }
  }
  lines.splice(insertAt, 0, ...block);
  return `${lines.join("\n").replace(/\s+$/, "")}
`;
}
var CONTINUE_ITEM_RE = /^\s*-\s*name:\s*['"]?Bansos - /m;
function removeContinueModels(content) {
  const out = [];
  let inItem = false;
  for (const line of content.split("\n")) {
    if (CONTINUE_ITEM_RE.test(line)) {
      inItem = true;
      continue;
    }
    if (inItem && (/^\s*-\s/.test(line) || /^\S/.test(line))) inItem = false;
    if (!inItem) out.push(line);
  }
  return `${out.join("\n").replace(/\n{3,}/g, "\n\n").replace(/\s+$/, "")}
`;
}
function removeBlock(existing, markers) {
  const lines = existing.split("\n");
  const span = findBlock(lines, markers[0], markers[1]);
  if (!span) return existing;
  const [si, ei] = span;
  const head = lines.slice(0, si).join("\n").replace(/\s+$/, "");
  const tail = lines.slice(ei + 1).join("\n").replace(/^[ \t]*\n/, "");
  return `${[head, tail].filter((s) => s !== "").join("\n\n")}
`;
}
function getItemKey(item) {
  if (item && typeof item === "object") {
    const rec = item;
    if (typeof rec.id === "string") return rec.id;
    if (typeof rec.title === "string") return rec.title;
    if (typeof rec.model === "string") return rec.model;
  }
  return void 0;
}
function deepMerge(target, patch) {
  for (const [k, v] of Object.entries(patch)) {
    if (v !== null && typeof v === "object" && !Array.isArray(v) && target[k] !== null && typeof target[k] === "object" && !Array.isArray(target[k])) {
      deepMerge(target[k], v);
    } else if (Array.isArray(v) && Array.isArray(target[k])) {
      const targetArr = target[k];
      for (const item of v) {
        const itemKey = getItemKey(item);
        if (itemKey !== void 0) {
          const idx = targetArr.findIndex((t) => getItemKey(t) === itemKey);
          if (idx >= 0) {
            targetArr[idx] = item;
          } else {
            targetArr.push(item);
          }
        } else {
          targetArr.push(item);
        }
      }
    } else {
      target[k] = v;
    }
  }
}
function applyMergeWrite(existing, content, replace = []) {
  const patch = parseJsonc(content);
  const base = existing && existing.trim().length > 0 ? parseJsonc(existing) : {};
  removeKeys(base, replace);
  deepMerge(base, patch);
  return `${JSON.stringify(base, null, 2)}
`;
}
function removeKeys(obj, keys) {
  for (const kp of keys) {
    const parts = kp.split(".");
    let cur = obj;
    for (let i = 0; i < parts.length - 1; i++) {
      const p = parts[i];
      cur = cur?.[p];
      if (!cur || typeof cur !== "object") break;
    }
    if (cur && typeof cur === "object") {
      const last = parts[parts.length - 1];
      const matches = last.endsWith("*") ? (k) => k !== void 0 && k.startsWith(last.slice(0, -1)) : (k) => k === last;
      if (Array.isArray(cur)) {
        for (let idx = cur.length - 1; idx >= 0; idx--) {
          if (matches(getItemKey(cur[idx]))) cur.splice(idx, 1);
        }
      } else {
        for (const k of Object.keys(cur)) if (matches(k)) delete cur[k];
      }
    }
  }
}
function writeConfig(p, content) {
  const full = expandHome(p);
  fs3.mkdirSync(path3.dirname(full), { recursive: true });
  fs3.writeFileSync(full, content);
}

// src/adapters/index.ts
var yamlBlock = () => ({
  mode: "overwrite-block",
  markers: [`# ${START_MARKER}`, `# ${END_MARKER}`]
});
function claudeCodeAdapter() {
  return {
    id: "claude-code",
    name: "Claude Code",
    wire: "anthropic",
    modelMode: "tiered",
    configPaths: ["~/.claude/settings.json"],
    render(ctx) {
      const validModels = ctx.models.filter(
        (m) => !m.id.toLowerCase().includes("safety")
      );
      const nonReasoning = validModels.filter((m) => !m.reasoning);
      const reasoningModels = validModels.filter((m) => m.reasoning);
      const sortedReasoning = [...reasoningModels].sort(compareModelsByCapacity);
      const sortedNonReasoning = [...nonReasoning].sort(compareModelsByCapacity);
      const defaultModelDef = ctx.models.find((m) => m.id === ctx.defaultModel);
      const haikuModel = ctx.specificModel ? ctx.defaultModel : sortedNonReasoning[0]?.id ?? ctx.defaultModel;
      const opusModel = ctx.specificModel ? ctx.defaultModel : sortedReasoning[0]?.id ?? reasoningModels[0]?.id ?? ctx.defaultModel;
      let sonnetModel = ctx.defaultModel;
      if (!ctx.specificModel) {
        if (defaultModelDef?.reasoning) {
          sonnetModel = defaultModelDef.id;
        } else {
          sonnetModel = sortedReasoning[1]?.id ?? sortedReasoning[0]?.id ?? ctx.defaultModel;
        }
      }
      const env = {
        ANTHROPIC_BASE_URL: ctx.baseUrl.replace(/\/v1$/, ""),
        ANTHROPIC_AUTH_TOKEN: "bansos",
        ANTHROPIC_DEFAULT_HAIKU_MODEL: haikuModel,
        ANTHROPIC_DEFAULT_SONNET_MODEL: sonnetModel,
        ANTHROPIC_DEFAULT_OPUS_MODEL: opusModel,
        CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS: "1"
      };
      return [
        {
          path: "~/.claude/settings.json",
          content: `${JSON.stringify({ env }, null, 2)}
`,
          mode: "merge"
        }
      ];
    },
    undo() {
      return ["~/.claude/settings.json"];
    },
    // keys bansos adds to settings.json (--undo removes only these)
    undoKeys: [
      "env.ANTHROPIC_BASE_URL",
      "env.ANTHROPIC_AUTH_TOKEN",
      "env.ANTHROPIC_DEFAULT_HAIKU_MODEL",
      "env.ANTHROPIC_DEFAULT_SONNET_MODEL",
      "env.ANTHROPIC_DEFAULT_OPUS_MODEL",
      "env.CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS"
    ]
  };
}
function aiderAdapter() {
  return {
    id: "aider",
    name: "Aider",
    wire: "chat",
    modelMode: "single",
    configPaths: ["~/.aider.conf.yml", ".aider.conf.yml"],
    render(ctx) {
      const lines = [
        `# ${START_MARKER}`,
        `openai_api_base: ${ctx.baseUrl}`,
        `openai_api_key: bansos`,
        `model: ${ctx.defaultModel}`,
        `# ${END_MARKER}`
      ];
      return [
        {
          path: "~/.aider.conf.yml",
          content: `${lines.join("\n")}
`,
          ...yamlBlock()
        }
      ];
    },
    undo() {
      return ["~/.aider.conf.yml"];
    }
  };
}
function opencodeAdapter() {
  return {
    id: "opencode",
    name: "OpenCode",
    wire: "chat",
    modelMode: "list",
    configPaths: [
      "~/.config/opencode/opencode.json",
      "~/.config/opencode/opencode.jsonc",
      "opencode.json",
      "opencode.jsonc"
    ],
    render(ctx) {
      const modelEntries = {};
      if (ctx.specificModel) {
        modelEntries[ctx.defaultModel] = {};
      } else {
        const list = ctx.models.length > 0 ? ctx.models : [{ id: ctx.defaultModel }];
        for (const m of list) {
          modelEntries[m.id] = {};
        }
      }
      const provider = {
        bansos: {
          npm: "@ai-sdk/openai-compatible",
          options: { baseURL: ctx.baseUrl, apiKey: "bansos", headers: { "x-bansos-client": "opencode" } },
          models: modelEntries
        }
      };
      return [
        {
          path: "~/.config/opencode/opencode.json",
          content: `${JSON.stringify({ provider }, null, 2)}
`,
          mode: "merge",
          replace: ["provider.bansos.models"]
        }
      ];
    },
    undo() {
      return [
        "~/.config/opencode/opencode.json",
        "~/.config/opencode/opencode.jsonc",
        "opencode.json",
        "opencode.jsonc"
      ];
    },
    undoKeys: ["provider.bansos"]
  };
}
function codexAdapter() {
  return {
    id: "codex",
    name: "Codex CLI",
    wire: "responses",
    modelMode: "single",
    configPaths: ["~/.codex/config.toml", ".codex/config.toml"],
    render(ctx) {
      const toml = [
        `model = "${ctx.defaultModel}"`,
        `model_provider = "bansos"`,
        "",
        `[model_providers.bansos]`,
        `name = "Bansos Router"`,
        `base_url = "${ctx.baseUrl}"`,
        `experimental_bearer_token = "bansos"`,
        `wire_api = "responses"`,
        `http_headers = { "x-bansos-client" = "codex" }`
      ];
      return [
        {
          path: "~/.codex/config.toml",
          content: `${toml.join("\n")}
`,
          mode: "toml-block",
          markers: [`# ${START_MARKER}`, `# ${END_MARKER}`],
          tomlTable: "model_providers.bansos"
        }
      ];
    },
    undo() {
      return ["~/.codex/config.toml", ".codex/config.toml"];
    }
  };
}
function hermesAdapter() {
  return {
    id: "hermes",
    name: "Hermes (Nous)",
    wire: "chat",
    // one live model as the default, every picked model as a /model alias
    modelMode: "list",
    configPaths: ["~/.hermes/config.yaml"],
    render(ctx) {
      const aliases = (ctx.specificModel ? [] : ctx.models).filter((m) => m.id !== ctx.defaultModel);
      const yaml = [
        `# ${START_MARKER}`,
        `model:`,
        `  provider: custom`,
        `  default: "${ctx.defaultModel}"`,
        `  base_url: "${ctx.baseUrl}"`,
        `  api_key: bansos`,
        ...aliases.length > 0 ? [
          `model_aliases:`,
          ...aliases.flatMap((m) => [
            `  ${m.id}:`,
            `    model: ${m.id}`,
            `    provider: custom`,
            `    base_url: "${ctx.baseUrl}"`,
            `    api_key: bansos`
          ])
        ] : [],
        `# ${END_MARKER}`
      ];
      return [
        {
          path: "~/.hermes/config.yaml",
          content: `${yaml.join("\n")}
`,
          ...yamlBlock()
        }
      ];
    },
    undo() {
      return ["~/.hermes/config.yaml"];
    }
  };
}
function gooseAdapter() {
  return {
    id: "goose",
    name: "Goose",
    wire: "chat",
    modelMode: "list",
    configPaths: ["~/.config/goose/custom_providers/bansos.json"],
    render(ctx) {
      const models = ctx.specificModel ? [{ name: ctx.defaultModel, context_limit: 256e3 }] : (ctx.models.length > 0 ? ctx.models : [{ id: ctx.defaultModel, contextWindow: 256e3 }]).map((m) => ({
        name: m.id,
        context_limit: m.contextWindow || 256e3
      }));
      const provider = {
        name: "bansos",
        engine: "openai",
        display_name: "Bansos Router",
        description: "Free keyless models via bansos-router",
        api_key_env: "BANSOS_API_KEY",
        base_url: ctx.baseUrl,
        headers: { "x-bansos-client": "goose" },
        models
      };
      return [
        {
          path: "~/.config/goose/custom_providers/bansos.json",
          content: `${JSON.stringify(provider, null, 2)}
`,
          mode: "merge",
          replace: ["models"]
        }
      ];
    },
    undo() {
      return ["~/.config/goose/custom_providers/bansos.json"];
    },
    // file is dedicated to bansos; undo removes it entirely
    undoKeys: ["name", "engine", "display_name", "description", "api_key_env", "base_url", "headers", "models"]
  };
}
function openclawAdapter() {
  return {
    id: "openclaw",
    name: "OpenClaw",
    wire: "chat",
    modelMode: "list",
    configPaths: [
      "~/.openclaw/config.json",
      "~/.openclaw/openclaw.json",
      "openclaw.json"
    ],
    render(ctx) {
      const models = ctx.specificModel ? [{ id: ctx.defaultModel }] : (ctx.models.length > 0 ? ctx.models : [{ id: ctx.defaultModel }]).map((m) => ({
        id: m.id
      }));
      const config = {
        models: {
          providers: {
            bansos: {
              baseUrl: ctx.baseUrl,
              apiKey: "bansos",
              api: "openai-completions",
              models
            }
          }
        }
      };
      return [
        {
          path: "~/.openclaw/config.json",
          content: `${JSON.stringify(config, null, 2)}
`,
          mode: "merge",
          replace: ["models.providers.bansos.models"]
        }
      ];
    },
    undo() {
      return [
        "~/.openclaw/config.json",
        "~/.openclaw/openclaw.json",
        "openclaw.json"
      ];
    },
    undoKeys: ["models.providers.bansos"]
  };
}
function jcodeConfigPath() {
  return `${process.env.JCODE_HOME?.trim().replace(/\/+$/, "") || "~/.jcode"}/config.toml`;
}
function jcodeAdapter() {
  return {
    id: "jcode",
    name: "JCode",
    wire: "chat",
    modelMode: "discovery",
    configPaths: [jcodeConfigPath()],
    render(ctx) {
      const path14 = jcodeConfigPath();
      const markers = [`# ${START_MARKER}`, `# ${END_MARKER}`];
      const defaultMarkers = [
        "# bansos-router:provider-start",
        "# bansos-router:provider-end"
      ];
      const models = ctx.specificModel ? [{ id: ctx.defaultModel }] : ctx.models.length > 0 ? ctx.models.map((m) => ({ id: m.id })) : [{ id: ctx.defaultModel }];
      const profile = [
        `[providers.bansos]`,
        `type = "openai-compatible"`,
        `base_url = "${ctx.baseUrl}"`,
        // the router accepts any key; naming one only sends jcode looking for a file
        `auth = "none"`,
        `requires_api_key = false`,
        `model_catalog = true`,
        `default_model = "${ctx.defaultModel}"`,
        `models = [${models.map((m) => `{ id = "${m.id}" }`).join(", ")}]`
      ].join("\n");
      return [
        {
          path: path14,
          content: [`[provider]`, `default_provider = "bansos"`, `default_model = "${ctx.defaultModel}"`].join("\n"),
          mode: "toml-block",
          markers: defaultMarkers,
          tomlTable: "provider",
          fillOnly: true
        },
        {
          path: path14,
          content: profile,
          mode: "toml-block",
          markers,
          tomlTable: "providers.bansos"
        }
      ];
    },
    undo() {
      return [jcodeConfigPath()];
    },
    // jcode rewrites config.toml from its own model and drops comments, so the markers do not survive
    detect: (content) => /^\[providers\.bansos\]\s*$/m.test(content),
    undoContent: stripJcodeDefaults
  };
}
function nineRouterAdapter() {
  return {
    id: "9router",
    name: "9Router",
    wire: "chat",
    modelMode: "discovery",
    configPaths: ["~/.9router/db.json", "~/.9router/db/data.sqlite"],
    render(ctx) {
      const db = {
        providerNodes: [
          {
            id: "openai-compatible-chat-bansos",
            name: "Bansos Router",
            type: "openai-compatible",
            prefix: "bansos",
            apiType: "chat",
            baseUrl: ctx.baseUrl
          }
        ],
        providerConnections: [
          {
            id: "bansos-default",
            provider: "openai-compatible-chat-bansos",
            authType: "api_key",
            name: "Bansos Router",
            priority: 1,
            isActive: true,
            apiKey: "bansos"
          }
        ]
      };
      return [
        {
          path: "~/.9router/db.json",
          content: `${JSON.stringify(db, null, 2)}
`,
          mode: "merge"
        }
      ];
    },
    undo() {
      return ["~/.9router/db.json", "~/.9router/db/data.sqlite"];
    },
    undoKeys: [
      "providerNodes.openai-compatible-chat-bansos",
      "providerConnections.bansos-default",
      "providerNodes.bansos",
      "providerConnections.bansos-default"
    ]
  };
}
function continueAdapter() {
  return {
    id: "continue",
    name: "Continue (VS Code / JetBrains)",
    wire: "chat",
    modelMode: "list",
    // continue v1 reads config.yaml only; config.json is deprecated and ignored
    configPaths: ["~/.continue/config.yaml", ".continue/config.yaml"],
    render(ctx) {
      const list = ctx.specificModel ? [{ id: ctx.defaultModel, name: ctx.defaultModel }] : ctx.models.length > 0 ? ctx.models : [{ id: ctx.defaultModel, name: ctx.defaultModel }];
      const content = list.map(
        (m) => [
          `- name: Bansos - ${m.name ?? m.id}`,
          "  provider: openai",
          `  model: ${m.id}`,
          `  apiBase: ${ctx.baseUrl}`,
          "  apiKey: bansos",
          "  roles: [chat, edit, apply]"
        ].join("\n")
      ).join("\n");
      return [
        {
          path: "~/.continue/config.yaml",
          content,
          mode: "yaml-block",
          markers: [`# ${START_MARKER}`, `# ${END_MARKER}`],
          yamlParent: "models"
        }
      ];
    },
    undo(ctx) {
      return ["~/.continue/config.yaml", ".continue/config.yaml"];
    },
    detect: (content) => CONTINUE_ITEM_RE.test(content),
    undoContent: removeContinueModels
  };
}
function clineAdapter() {
  return {
    id: "cline",
    name: "Cline (VS Code / CLI)",
    wire: "chat",
    modelMode: "single",
    configPaths: ["~/.cline/data/settings/providers.json"],
    render(ctx) {
      const targetModel = ctx.models.find((m) => m.id === ctx.defaultModel);
      const cfg = {
        version: 1,
        lastUsedProvider: "openai-compatible",
        providers: {
          "openai-compatible": {
            provider: "openai-compatible",
            apiKey: "bansos",
            model: ctx.defaultModel,
            baseUrl: ctx.baseUrl,
            contextWindow: targetModel?.contextWindow || 262144,
            maxTokens: targetModel?.maxTokens || 65536,
            headers: { "x-bansos-client": "cline" }
          }
        }
      };
      return [
        {
          path: "~/.cline/data/settings/providers.json",
          content: `${JSON.stringify(cfg, null, 2)}
`,
          mode: "merge",
          replace: ["providers.openai-compatible"]
        }
      ];
    },
    undo() {
      return ["~/.cline/data/settings/providers.json"];
    },
    undoKeys: ["providers.openai-compatible", "lastUsedProvider"]
  };
}
function ompAdapter() {
  return {
    id: "omp",
    name: "OMP (Oh My Pi)",
    wire: "chat",
    modelMode: "discovery",
    configPaths: ["~/.omp/agent/models.yml"],
    render(ctx) {
      const child = [
        `bansos:`,
        `  name: bansos-router`,
        `  baseUrl: "${ctx.baseUrl}"`,
        `  apiKey: bansos`,
        `  api: openai-completions`,
        `  discovery:`,
        `    type: openai-models-list`,
        `    timeoutMs: 15000`
      ];
      return [
        {
          path: "~/.omp/agent/models.yml",
          content: `${child.join("\n")}
`,
          mode: "yaml-block",
          markers: [`# ${START_MARKER}`, `# ${END_MARKER}`],
          yamlParent: "providers"
        }
      ];
    },
    undo() {
      return ["~/.omp/agent/models.yml"];
    }
  };
}
var DSH_PROFILES = ["web", "headless"];
var DSH_ENTRY_RE = /^\s*-\s*(?:id|name):\s*['"]?(?:llm-pi-ai|@deepseek-ai\/dsh-llm-pi-ai)['"]?\s*$/;
function dshProviderBlock(ctx, indent) {
  const pad2 = (n) => " ".repeat(indent + n);
  const models = ctx.models.length > 0 ? ctx.models : [{ id: ctx.defaultModel }];
  return [
    `${pad2(0)}bansos:`,
    `${pad2(2)}displayName: Bansos Router`,
    `${pad2(2)}api: openai-completions`,
    `${pad2(2)}baseURL: ${ctx.baseUrl}`,
    `${pad2(2)}apiKeyEnv: BANSOS_API_KEY`,
    `${pad2(2)}# dsh reads the key from the env or .credentials.yaml; the router checks none`,
    `${pad2(2)}headers:`,
    `${pad2(4)}x-bansos-client: dsh`,
    `${pad2(2)}models:`,
    ...models.flatMap((m) => {
      const out = [`${pad2(4)}- id: ${m.id}`];
      if (m.contextWindow) out.push(`${pad2(6)}contextWindow: ${m.contextWindow}`);
      if (m.maxTokens) out.push(`${pad2(6)}maxTokens: ${m.maxTokens}`);
      if (m.input?.length) out.push(`${pad2(6)}input: [${m.input.join(", ")}]`);
      return out;
    })
  ];
}
function dshMergeProviders(content, ctx) {
  const lines = content.split("\n");
  const entryIdx = lines.findIndex((l) => DSH_ENTRY_RE.test(l));
  if (entryIdx === -1) return { status: "no-entry" };
  const entryIndent = lines[entryIdx].length - lines[entryIdx].trimStart().length;
  let entryEnd = lines.length;
  for (let i = entryIdx + 1; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim()) continue;
    const indent2 = line.length - line.trimStart().length;
    if (indent2 <= entryIndent && /^\s*-/.test(line)) {
      entryEnd = i;
      break;
    }
  }
  let providersIdx = -1;
  for (let i = entryIdx + 1; i < entryEnd; i++) {
    if (/^\s*providers:\s*(#.*)?$/.test(lines[i])) {
      providersIdx = i;
      break;
    }
    if (/^\s*providers:\s*\S/.test(lines[i])) return { status: "manual" };
  }
  if (providersIdx === -1) return { status: "manual" };
  const providersIndent = lines[providersIdx].length - lines[providersIdx].trimStart().length;
  let insertAt = providersIdx + 1;
  for (let i = providersIdx + 1; i < entryEnd; i++) {
    const line = lines[i];
    if (!line.trim()) continue;
    const indent2 = line.length - line.trimStart().length;
    if (indent2 <= providersIndent) break;
    if (/^\s*bansos:/.test(line)) return { status: "present" };
    insertAt = i + 1;
  }
  const indent = providersIndent + 2;
  const marker2 = " ".repeat(indent);
  lines.splice(
    insertAt,
    0,
    `${marker2}# ${START_MARKER}`,
    ...dshProviderBlock(ctx, indent),
    `${marker2}# ${END_MARKER}`
  );
  return { status: "merged", content: lines.join("\n") };
}
var DSH_KEY_ENV_FILE = "~/.dsh/.env";
function deepseekAdapter() {
  return {
    id: "dsh",
    name: "DeepSeek Harness (dsh)",
    wire: "chat",
    modelMode: "list",
    configPaths: [
      ...DSH_PROFILES.map((p) => `~/.dsh/profiles/${p}/cordis.patch.yml`),
      DSH_KEY_ENV_FILE
    ],
    render(ctx) {
      const lines = [
        `# ${START_MARKER}`,
        `- id: llm-pi-ai`,
        `  config:`,
        `    providers:`,
        ...dshProviderBlock(ctx, 6),
        `# ${END_MARKER}`
      ];
      return [
        ...DSH_PROFILES.map((p) => ({
          path: `~/.dsh/profiles/${p}/cordis.patch.yml`,
          content: `${lines.join("\n")}
`,
          ...yamlBlock()
        })),
        {
          path: DSH_KEY_ENV_FILE,
          // dsh fails a route whose key var is unset even though the router checks no key
          content: "BANSOS_API_KEY=bansos\n",
          ...yamlBlock()
        }
      ];
    },
    undo() {
      return [...DSH_PROFILES.map((p) => `~/.dsh/profiles/${p}/cordis.patch.yml`), DSH_KEY_ENV_FILE];
    }
  };
}
var ADAPTERS = [
  claudeCodeAdapter(),
  aiderAdapter(),
  opencodeAdapter(),
  codexAdapter(),
  hermesAdapter(),
  gooseAdapter(),
  openclawAdapter(),
  jcodeAdapter(),
  nineRouterAdapter(),
  continueAdapter(),
  clineAdapter(),
  ompAdapter(),
  deepseekAdapter()
];
function findAdapter(id) {
  const wanted = id === "deepseek" ? "dsh" : id;
  return ADAPTERS.find((a) => a.id === wanted);
}
function buildSetupContext(baseUrl, pool, pick2) {
  const ids = pick2.models ?? [];
  const upstreams = pick2.upstreams ?? [];
  if (pick2.model) {
    if (ids.length > 0 || upstreams.length > 0) return { error: "pick either one model or a model list, not both" };
    return { baseUrl, defaultModel: pick2.model, models: pool, specificModel: true };
  }
  if (ids.length === 0 && upstreams.length === 0) {
    return { baseUrl, defaultModel: pickSmartDefaultModel(pool), models: pool, specificModel: false };
  }
  const known2 = new Set(pool.map((m) => m.source));
  const badUpstreams = upstreams.filter((u) => !known2.has(u));
  if (badUpstreams.length > 0) return { error: `no models from upstream: ${badUpstreams.join(", ")}` };
  const find = (id) => pool.find((m) => m.id === id) ?? pool.find((m) => m.id.endsWith(`/${id}`));
  const missing = ids.filter((id) => !find(id));
  if (missing.length > 0) return { error: `unknown or unavailable model: ${missing.join(", ")}` };
  const wanted = new Set(ids.map((id) => find(id).id));
  const models = pool.filter((m) => wanted.has(m.id) || upstreams.includes(m.source));
  return { baseUrl, defaultModel: pickSmartDefaultModel(models), models, specificModel: false };
}

// src/cli/doctor.ts
init_state();

// src/update.ts
import fs4 from "node:fs";
import path4 from "node:path";

// package.json
var package_default = {
  name: "bansos-router",
  version: "0.6.2",
  description: "Bansos for your AI agents. Free, keyless coding models routed to every coding harness through one local endpoint. No accounts, no keys, no cost.",
  license: "GPL-3.0-only",
  type: "module",
  engines: {
    node: ">=22.5"
  },
  bin: {
    bansos: "dist/cli/index.js",
    bansosd: "dist/cli/index.js"
  },
  files: [
    "dist",
    "docs",
    "README.md",
    "LICENSE"
  ],
  scripts: {
    build: "npm run build:ui && esbuild src/cli/index.ts --bundle --platform=node --format=esm --outfile=dist/cli/index.js",
    "build:ui": "vite build",
    "sync-version": "node scripts/sync-version.mjs",
    dev: "tsx src/cli/index.ts",
    "dev:daemon": "tsx src/cli/index.ts daemon",
    "dev:ui": "vite",
    typecheck: "tsc --noEmit",
    test: "node --import tsx --import ./test/isolate.ts --test --test-concurrency=1 test/*.test.ts",
    prepare: "npm run build"
  },
  keywords: [
    "llm",
    "proxy",
    "router",
    "free-models",
    "coding-agent",
    "openai-compatible",
    "claude-code",
    "opencode",
    "pi",
    "codex"
  ],
  devDependencies: {
    "@preact/preset-vite": "^2.10.6",
    "@tailwindcss/vite": "^4.3.3",
    "@types/node": "^26.2.0",
    esbuild: "^0.28.2",
    "lucide-preact": "^1.33.0",
    preact: "^11.0.0",
    tailwindcss: "^4.3.3",
    tsx: "^4.23.12",
    typescript: "^7.0.2",
    vite: "^8.2.2"
  },
  allowScripts: {
    "esbuild@0.25.12": true,
    "esbuild@0.28.2": true
  },
  dependencies: {
    "wreq-js": "^3.2.0"
  }
};

// src/update.ts
init_state();
var VERSION = package_default.version;
var CACHE_FILE = path4.join(BANSOS_DIR, "update-check.json");
var CACHE_TTL_MS = 24 * 60 * 60 * 1e3;
var notifierOff = () => Boolean(process.env.NO_UPDATE_NOTIFIER);
function isNewerVersion(current, latest) {
  const parse = (v) => v.replace(/^v/, "").split(".").map((n) => parseInt(n, 10) || 0);
  const [cMaj = 0, cMin = 0, cPat = 0] = parse(current);
  const [lMaj = 0, lMin = 0, lPat = 0] = parse(latest);
  if (lMaj !== cMaj) return lMaj > cMaj;
  if (lMin !== cMin) return lMin > cMin;
  return lPat > cPat;
}
function readCache() {
  try {
    if (fs4.existsSync(CACHE_FILE)) {
      return JSON.parse(fs4.readFileSync(CACHE_FILE, "utf8"));
    }
  } catch {
  }
  return {};
}
function writeCache(cache) {
  try {
    const dir = path4.dirname(CACHE_FILE);
    if (!fs4.existsSync(dir)) fs4.mkdirSync(dir, { recursive: true });
    fs4.writeFileSync(CACHE_FILE, JSON.stringify(cache, null, 2), "utf8");
  } catch {
  }
}
async function checkUpdate(pkgName = "bansos-router", currentVersion = VERSION) {
  if (notifierOff()) return { hasUpdate: false, current: currentVersion, latest: currentVersion };
  const cache = readCache();
  const entry = cache[pkgName];
  const now = Date.now();
  let latestVersion = entry?.latest;
  if (!latestVersion || !entry || now - entry.checkedAt > CACHE_TTL_MS) {
    try {
      const res = await fetch(`https://registry.npmjs.org/${pkgName}/latest`, {
        signal: AbortSignal.timeout(1e3)
      });
      if (res.ok) {
        const data = await res.json();
        if (data.version) {
          latestVersion = data.version;
          cache[pkgName] = { latest: latestVersion, checkedAt: now };
          writeCache(cache);
        }
      }
    } catch {
    }
  }
  const latest = latestVersion ?? currentVersion;
  return {
    hasUpdate: isNewerVersion(currentVersion, latest),
    current: currentVersion,
    latest
  };
}
var RETRY_MS = 60 * 60 * 1e3;
var known = /* @__PURE__ */ new Map();
var refreshing = null;
var lastAttempt = 0;
function peekUpdate(pkgName = "bansos-router", currentVersion = VERSION) {
  if (notifierOff()) return null;
  if (!known.has(pkgName)) known.set(pkgName, readCache()[pkgName] ?? null);
  const entry = known.get(pkgName) ?? null;
  const now = Date.now();
  const stale = !entry || now - entry.checkedAt > CACHE_TTL_MS;
  if (stale && !refreshing && now - lastAttempt > RETRY_MS) {
    lastAttempt = now;
    refreshing = checkUpdate(pkgName, currentVersion).then((info) => {
      known.set(pkgName, readCache()[pkgName] ?? null);
      return info;
    }).finally(() => {
      refreshing = null;
    });
  }
  if (!entry) return null;
  return { hasUpdate: isNewerVersion(currentVersion, entry.latest), current: currentVersion, latest: entry.latest };
}
async function staleDaemonNotice(baseUrl) {
  const versionAt = async (path14) => {
    const res = await fetch(`${baseUrl}${path14}`, { signal: AbortSignal.timeout(2e3) });
    if (!res.ok) return void 0;
    const body = await res.json();
    return typeof body.version === "string" ? body.version : void 0;
  };
  try {
    const running = await versionAt("/bansos/status") ?? await versionAt("/bansos/doctor");
    return running && isNewerVersion(running, VERSION) ? `bansosd at ${baseUrl} still runs ${running}, but ${VERSION} is installed (run: bansos restart)` : null;
  } catch {
    return null;
  }
}
function updateNotice(info) {
  return info.hasUpdate ? `Update available: ${info.current} -> ${info.latest} (run: npm i -g bansos-router, then bansos restart)` : null;
}

// src/cli/doctor.ts
async function runDoctor(_argv) {
  const base = `http://${effectiveBind()}:${effectivePort()}`;
  let failures = 0;
  try {
    const res = await fetch(`${base}/healthz`, { signal: AbortSignal.timeout(2e3) });
    const body = await res.json();
    console.log(`\u2713 daemon      ok at ${base} (${body.modelCount ?? "?"} models)`);
    if (body.relay?.enabled && body.relay.url) {
      console.log(`\u2713 relay       on (${body.relay.url})`);
    } else {
      console.log(`\xB7 relay       disabled (direct)`);
    }
  } catch {
    console.error(`\u2717 daemon      not reachable at ${base}`);
    console.error(`  fix: run "bansos start" (or "bansosd") in another terminal`);
    failures++;
  }
  const warnings = loadConfigWarnings();
  if (warnings.length > 0) {
    for (const w of warnings) console.error(`\u2717 security    ${w}`);
    failures++;
  } else {
    const { mode, dlp } = loadConfig().security;
    console.log(`\u2713 security    ${mode} mode${mode === "strict" ? ` (dlp: ${dlp})` : ""}`);
  }
  const autostart = autostartStatus();
  if (autostart.broken) {
    console.error(`\u2717 autostart   points at a path that no longer exists (run: bansos autostart on)`);
    failures++;
  } else if (autostart.enabled) {
    console.log(`\u2713 autostart   on (${autostart.manager})`);
  } else {
    console.log(`\xB7 autostart   off${autostart.supported ? " (bansos autostart on)" : ""}`);
  }
  const whichCmd = process.platform === "win32" ? "where" : "which";
  let hasOpenCode = false;
  try {
    hasOpenCode = spawnSync2(whichCmd, ["opencode"], { encoding: "utf-8", timeout: 1e3 }).status === 0;
  } catch {
  }
  const hasBun = "Bun" in globalThis || (() => {
    try {
      if (spawnSync2(whichCmd, ["bun"], { encoding: "utf-8", timeout: 1e3 }).status === 0) return true;
    } catch {
    }
    const binName = process.platform === "win32" ? "bun.exe" : "bun";
    const candidates = [
      path5.join(os4.homedir(), ".bun", "bin", binName),
      "/usr/local/bin/bun",
      "/usr/bin/bun"
    ];
    return candidates.some((c) => fs5.existsSync(c));
  })();
  if (hasOpenCode) {
    console.log(`\u2713 opencode    installed (Zen free models ready)`);
  } else if (hasBun) {
    console.log(`\u2713 runtime     bun detected (Zen free models ready)`);
  } else {
    console.log(`\xB7 opencode    not installed (Zen models require opencode or bun; Kilo/LLM7/OVH work directly)`);
  }
  for (const h of harnessStatuses()) {
    if (h.status === "missing") {
      console.log(`\xB7 ${h.id.padEnd(12)} not configured (bansos setup ${h.id})`);
    } else if (h.status === "configured") {
      console.log(`\u2713 ${h.id.padEnd(12)} configured (${h.path})`);
    } else {
      console.log(`\xB7 ${h.id.padEnd(12)} file exists but no bansos config (${h.path})`);
    }
  }
  const notice = updateNotice(await checkUpdate());
  if (notice) console.log(`
${notice}`);
  return failures > 0 ? 1 : 0;
}
var MAX_TEXT_CONFIG_BYTES = 8 << 20;
function harnessStatuses() {
  return ADAPTERS.map((adapter) => {
    const found = adapter.configPaths.map(expandHome).find((p) => fs5.existsSync(p));
    if (!found) return { id: adapter.id, status: "missing" };
    if (found.endsWith(".sqlite")) {
      const configured2 = adapter.undoKeys ? sqliteKeysExist(found, adapter.undoKeys) : false;
      return { id: adapter.id, status: configured2 ? "configured" : "unconfigured", path: found };
    }
    let content = "";
    try {
      if (fs5.statSync(found).size > MAX_TEXT_CONFIG_BYTES) {
        return { id: adapter.id, status: "unconfigured", path: found };
      }
      content = fs5.readFileSync(found, "utf8");
    } catch {
      return { id: adapter.id, status: "unconfigured", path: found };
    }
    if (content.includes("\0")) {
      return { id: adapter.id, status: "unconfigured", path: found };
    }
    const configured = adapter.undoKeys ? hasKeys(content, adapter.undoKeys) : adapter.detect?.(content) ?? content.includes(START_MARKER);
    return { id: adapter.id, status: configured ? "configured" : "unconfigured", path: found };
  });
}
function sqliteKeysExist(dbPath, keys) {
  const valid = keys.map((k) => k.split(".")).filter(([table, id]) => Boolean(table && id && /^[A-Za-z_]\w*$/.test(table)));
  if (valid.length === 0) return false;
  try {
    const sqliteMod = globalThis.process?.getBuiltinModule?.("node:sqlite");
    if (sqliteMod?.DatabaseSync) {
      const db = new sqliteMod.DatabaseSync(dbPath, { readOnly: true });
      try {
        return valid.some(
          ([table, id]) => Boolean(db.prepare(`SELECT 1 FROM ${table} WHERE id = ?`).get(id))
        );
      } finally {
        db.close();
      }
    }
  } catch {
  }
  return false;
}
function hasKeys(content, keys) {
  try {
    const obj = parseJsonc(content);
    const first = keys[0];
    if (!first) return false;
    let cur = obj;
    for (const p of first.split(".")) {
      const match = p.endsWith("*") ? (k) => typeof k === "string" && k.startsWith(p.slice(0, -1)) : (k) => k === p;
      if (Array.isArray(cur)) {
        cur = cur.find((item) => {
          const rec = item;
          return rec && typeof rec === "object" && match(rec.id ?? rec.title ?? rec.model);
        });
      } else if (cur && typeof cur === "object") {
        const k = Object.keys(cur).find(match);
        cur = k === void 0 ? void 0 : cur[k];
      } else {
        cur = void 0;
      }
      if (cur === void 0) return false;
    }
    return true;
  } catch {
    return false;
  }
}

// src/cli/ping.ts
init_state();
async function pingModel(base, modelId) {
  const start = Date.now();
  try {
    const res = await fetch(`${base}/v1/chat/completions`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer bansos",
        // probe the model itself: daemon skips failover for this request
        "x-bansos-no-failover": "1"
      },
      body: JSON.stringify({
        model: modelId,
        max_tokens: 16,
        messages: [{ role: "user", content: "ping" }]
      }),
      signal: AbortSignal.timeout(12e3)
    });
    const latencyMs = Date.now() - start;
    if (res.ok) {
      return { id: modelId, ok: true, status: 200, latencyMs, message: "ok" };
    }
    if (res.status === 429) {
      return { id: modelId, ok: false, status: 429, latencyMs, message: "rate limited" };
    }
    let detail = `HTTP ${res.status}`;
    try {
      const err = await res.json();
      if (err.error?.message) {
        detail = err.error.message.slice(0, 40);
      }
    } catch {
    }
    return { id: modelId, ok: false, status: res.status, latencyMs, message: detail };
  } catch (err) {
    const latencyMs = Date.now() - start;
    const msg = err instanceof Error && err.name === "TimeoutError" ? "timeout (12s)" : "unreachable";
    return { id: modelId, ok: false, status: "ERR", latencyMs, message: msg };
  }
}
async function runPing(argv) {
  const json = argv.includes("--json");
  const targetModel = argv.filter((a) => a !== "--json")[0];
  const base = `http://${effectiveBind()}:${effectivePort()}`;
  let models = [];
  try {
    const res = await fetch(`${base}/v1/models`, { signal: AbortSignal.timeout(2e3) });
    if (res.ok) {
      const data = await res.json();
      models = data.data ?? [];
    }
  } catch {
    console.error(`bansos: daemon not reachable at ${base} (run "bansos start" first)`);
    return 1;
  }
  if (models.length === 0) {
    console.error(`bansos: no models found on daemon at ${base}`);
    return 1;
  }
  let targets = [];
  if (targetModel) {
    const matched = models.find(
      (m) => m.id === targetModel || m.id.endsWith(`/${targetModel}`)
    );
    if (!matched) {
      console.error(`bansos ping: unknown model "${targetModel}"`);
      console.error(`available models: ${models.map((m) => m.id).join(", ")}`);
      return 1;
    }
    targets = [matched.id];
  } else {
    targets = models.map((m) => m.id);
  }
  const results = await Promise.all(targets.map((id) => pingModel(base, id)));
  const okCount = results.filter((r) => r.ok).length;
  if (json) {
    const rateLimited = results.filter((r) => !r.ok && r.status === 429).length;
    console.log(JSON.stringify({
      base,
      results,
      summary: { ok: okCount, rateLimited, failed: results.length - okCount - rateLimited, total: results.length }
    }));
    return okCount === 0 ? 1 : 0;
  }
  console.log(`PING ${base} (${targets.length} model${targets.length > 1 ? "s" : ""}):
`);
  const maxLen = Math.max(...results.map((r) => r.id.length), 10);
  let okTotal = 0;
  let rateLimitCount = 0;
  let errCount = 0;
  for (const r of results) {
    const padded = r.id.padEnd(maxLen + 2);
    if (r.ok) {
      okTotal++;
      const ms = `${r.latencyMs}ms`.padStart(7);
      console.log(`  \u2713 ${padded} ${ms}  ${r.message}`);
    } else if (r.status === 429) {
      rateLimitCount++;
      const ms = `${r.latencyMs}ms`.padStart(7);
      console.log(`  \u2717 ${padded} ${ms}  429 (${r.message})`);
    } else {
      errCount++;
      const ms = `${r.latencyMs}ms`.padStart(7);
      console.log(`  \u2717 ${padded} ${ms}  ${r.message}`);
    }
  }
  if (targets.length > 1) {
    console.log(`
Summary: ${okTotal} ok, ${rateLimitCount} rate limited, ${errCount} failed (${targets.length} total)`);
  }
  return rateLimitCount + errCount === targets.length ? 1 : 0;
}

// src/relay/vercel.ts
async function deployVercelRelay(token, projectName) {
  void token;
  void projectName;
  throw new Error("TODO(M4): deployVercelRelay not implemented");
}

// src/cli/relay.ts
init_state();
init_policy();

// src/relay/egress.ts
init_state();
var ALLOWED_TARGETS = [
  "https://opencode.ai",
  "https://api.kilo.ai",
  "https://api.llm7.io"
];
function loadRelayState() {
  const s = readJson(RELAY_STATE_FILE);
  return {
    enabled: Boolean(s?.enabled),
    url: typeof s?.url === "string" ? s.url : "",
    relays: Array.isArray(s?.relays) ? s.relays : []
  };
}
function saveRelayState(state) {
  writeJsonAtomic(RELAY_STATE_FILE, state);
}
function ensureRelay(state, url, label) {
  const clean = url.trim();
  if (!clean || state.relays.some((r) => r.url === clean)) return;
  state.relays.push({ url: clean, label, addedAt: (/* @__PURE__ */ new Date()).toISOString() });
}
async function directThenRelayFetch(state, targetUrl, init = {}, relayPermitted = true) {
  const direct = await fetch(targetUrl, init);
  if (!relayPermitted || !state.enabled || !state.url || direct.status !== 403 && direct.status !== 429) {
    return direct;
  }
  const u = new URL(targetUrl);
  if (!ALLOWED_TARGETS.includes(u.origin)) return direct;
  try {
    const headers = new Headers(init.headers);
    headers.set("x-target-url", targetUrl);
    const tlsRelay = await fetch("http://127.0.0.1:63015", {
      method: init.method || "POST",
      headers,
      body: init.body,
      signal: init.signal,
      duplex: "half"
    });
    if (tlsRelay.status !== 403 && tlsRelay.status !== 429) return tlsRelay;
  } catch {
  }
  try {
    const headers = new Headers(init.headers);
    headers.set("x-relay-target", u.origin);
    headers.set("x-relay-path", `${u.pathname}${u.search}`);
    return await fetch(state.url, {
      ...init,
      headers,
      body: init.body,
      duplex: "half"
    });
  } catch {
    return direct;
  }
}
function addRelay(state, url, label) {
  ensureRelay(state, url, label);
  return state;
}
function removeRelay(state, url) {
  state.relays = state.relays.filter((r) => r.url !== url);
  if (state.url === url) state.url = "";
  return state;
}

// src/cli/relay.ts
function usage() {
  console.log(`bansos relay <command>

Commands:
  on / off                toggle relay egress (live)
  status                  show state, active relay, saved relays
  url <URL>               add a relay to the saved list
  use <URL>               switch to a relay and enable it
  list                    show saved relays (\u2605 = active)
  remove <URL>            forget a saved relay
  deploy                  deploy a fresh Vercel relay (M4, stubbed)
`);
}
function relayLabelSuffix(label) {
  return label ? `  [${label}]` : "";
}
function runStrictRelay(cmd, state) {
  switch (cmd) {
    case "status":
      console.log("enabled: off (locked by strict security mode)");
      console.log(`active:  ${state.url || "(none)"} (ignored)`);
      console.log(`saved:   ${state.relays.length}`);
      return 0;
    case "list":
      for (const relay of state.relays) {
        console.log(`  ${relay.url}${relayLabelSuffix(relay.label)}`);
      }
      return 0;
    case "off":
      saveRelayState({ ...state, enabled: false });
      console.log("relay disabled and locked by strict security mode");
      return 0;
    case "help":
    case "-h":
    case void 0:
      usage();
      console.log("\nRelay mutation and egress are disabled while security.mode is strict.");
      return 0;
    default:
      console.error(`bansos relay ${cmd}: rejected by strict security mode`);
      return 1;
  }
}
async function runRelay(argv, security = loadConfig().security) {
  const cmd = argv[0];
  const state = loadRelayState();
  if (isStrictSecurity(security)) {
    return runStrictRelay(cmd, state);
  }
  switch (cmd) {
    case "on": {
      if (!state.url) {
        console.error("no active relay. Add one first: bansos relay url <URL>");
        return 1;
      }
      saveRelayState({ ...state, enabled: true });
      console.log(`relay enabled -> ${state.url}`);
      return 0;
    }
    case "off": {
      saveRelayState({ ...state, enabled: false });
      console.log("relay disabled (direct egress)");
      return 0;
    }
    case "status": {
      console.log(`enabled: ${state.enabled ? "on" : "off"}`);
      console.log(`active:  ${state.url || "(none)"}`);
      console.log(`saved:   ${state.relays.length}`);
      return 0;
    }
    case "url": {
      const url = argv[1];
      if (!url) return usage(), 1;
      addRelay(state, url, "manual");
      saveRelayState(state);
      console.log(`saved: ${url}`);
      return 0;
    }
    case "use": {
      const url = argv[1];
      if (!url) return usage(), 1;
      addRelay(state, url, "manual");
      saveRelayState({ ...state, url, enabled: true });
      console.log(`active & enabled: ${url}`);
      return 0;
    }
    case "list": {
      for (const r of state.relays) {
        console.log(`${r.url === state.url ? "\u2605" : " "} ${r.url}${relayLabelSuffix(r.label)}`);
      }
      return 0;
    }
    case "remove": {
      const url = argv[1];
      if (!url) return usage(), 1;
      if (state.url === url) {
        console.error("can't remove the active relay. Switch first (bansos relay use <URL>)");
        return 1;
      }
      saveRelayState(removeRelay(state, url));
      console.log(`removed: ${url}`);
      return 0;
    }
    case "deploy": {
      void deployVercelRelay;
      console.log("deploy lands in M4. Bring your own relay for now:");
      console.log("  bansos relay use https://<your-relay>.vercel.app");
      return 0;
    }
    case "help":
    case "-h":
    case void 0:
      usage();
      return 0;
    default:
      console.error(`bansos relay: unknown command "${cmd}"`);
      usage();
      return 1;
  }
}

// src/cli/setup.ts
import fs7 from "node:fs";
import path7 from "node:path";
init_state();

// src/upstreams/llm7.ts
var LLM7_BASE_URL = "https://api.llm7.io/v1";
var LLM7_ANONYMOUS_KEY = "unused";
var LLM7_MODELS = [
  modelDef({
    id: "DeepSeek-V4-Flash-0731",
    name: "DeepSeek-V4-Flash-0731",
    source: "llm7",
    reasoning: true,
    contextWindow: 4e5,
    maxTokens: 16384,
    input: ["text"],
    compat: { supportsReasoningEffort: false, supportsDeveloperRole: false }
  }),
  modelDef({
    id: "GLM-5.3-Flash",
    name: "GLM-5.3-Flash",
    source: "llm7",
    reasoning: true,
    contextWindow: 4e5,
    maxTokens: 16384,
    input: ["text"],
    compat: { supportsReasoningEffort: false, supportsDeveloperRole: false }
  }),
  modelDef({
    id: "codestral-latest",
    name: "Codestral Latest",
    source: "llm7",
    reasoning: false,
    contextWindow: 32e3,
    maxTokens: 8192,
    input: ["text"],
    compat: { supportsReasoningEffort: false, supportsDeveloperRole: false }
  }),
  modelDef({
    id: "gpt-oss:20b",
    name: "gpt-oss:20b",
    source: "llm7",
    reasoning: false,
    contextWindow: 128e3,
    maxTokens: 16384,
    input: ["text"],
    compat: { supportsReasoningEffort: false, supportsDeveloperRole: false }
  }),
  modelDef({
    id: "minimax-m2.7",
    name: "MiniMax M2.7",
    source: "llm7",
    reasoning: true,
    contextWindow: 18e4,
    maxTokens: 32768,
    input: ["text"],
    compat: { supportsReasoningEffort: false, supportsDeveloperRole: false }
  }),
  modelDef({
    id: "mistral-Nemo-Instruct-2407",
    name: "Mistral Nemo Instruct",
    source: "llm7",
    reasoning: false,
    contextWindow: 128e3,
    maxTokens: 16384,
    input: ["text"],
    compat: { supportsReasoningEffort: false, supportsDeveloperRole: false },
    supportsTools: false
  }),
  modelDef({
    id: "nemotron-3-nano:30b",
    name: "nemotron-3-nano:30b",
    source: "llm7",
    reasoning: true,
    contextWindow: 1e6,
    maxTokens: 16384,
    input: ["text"],
    compat: { supportsReasoningEffort: false, supportsDeveloperRole: false }
  }),
  modelDef({
    id: "default",
    name: "LLM7 Default",
    source: "llm7",
    reasoning: false,
    contextWindow: 128e3,
    maxTokens: 8192,
    input: ["text"],
    compat: { supportsReasoningEffort: false, supportsDeveloperRole: false }
  }),
  modelDef({
    id: "fast",
    name: "LLM7 Fast",
    source: "llm7",
    reasoning: false,
    contextWindow: 128e3,
    maxTokens: 8192,
    input: ["text"],
    compat: { supportsReasoningEffort: false, supportsDeveloperRole: false }
  })
];
function isFreeLlm7Model(m) {
  if (m.tier === "pro") return false;
  return m.usage_based_only === false || m.tier === "turbo" && m.usage_based_only !== true;
}
var llm7Upstream = {
  id: "llm7",
  kind: "remote-keyless",
  relayAllowed: true,
  chatUrl: `${LLM7_BASE_URL}/chat/completions`,
  async fetchCatalog() {
    try {
      const res = await fetch(`${LLM7_BASE_URL}/models`, {
        headers: { Authorization: `Bearer ${LLM7_ANONYMOUS_KEY}` },
        signal: AbortSignal.timeout(6e3)
      });
      if (!res.ok) return null;
      const body = await res.json();
      if (!Array.isArray(body.data) || body.data.length === 0) return null;
      const freeModels = body.data.filter(isFreeLlm7Model);
      const dynamic = freeModels.map((m) => {
        const seeded = LLM7_MODELS.find((s) => s.id === m.id);
        const context = m.context_window?.tokens ?? seeded?.contextWindow ?? 128e3;
        const input = Array.isArray(m.modalities?.input) && m.modalities?.input.includes("image") ? ["text", "image"] : ["text"];
        const tools = m.capabilities?.tools ?? m.tools_calling;
        return modelDef({
          id: m.id,
          name: seeded?.name ?? m.id,
          source: "llm7",
          reasoning: m.reasoning ?? seeded?.reasoning ?? false,
          contextWindow: context,
          maxTokens: seeded?.maxTokens ?? 16384,
          input,
          compat: { supportsReasoningEffort: false, supportsDeveloperRole: false },
          ...typeof tools === "boolean" ? { supportsTools: tools } : {}
        });
      });
      for (const alias of ["default", "fast"]) {
        if (!dynamic.some((m) => m.id === alias)) {
          const aliasDef = LLM7_MODELS.find((m) => m.id === alias);
          if (aliasDef) dynamic.push(aliasDef);
        }
      }
      return dynamic;
    } catch {
      return null;
    }
  },
  requestHeaders() {
    return { Authorization: `Bearer ${LLM7_ANONYMOUS_KEY}` };
  }
};

// src/upstreams/kilo.ts
var KILO_CHAT_URL = "https://api.kilo.ai/api/gateway/chat/completions";
var KILO_CATALOG_URL = "https://api.kilo.ai/api/gateway/models";
var KILO_MODELS = [
  modelDef({
    id: "kilo-auto/free",
    name: "Kilo Auto Free",
    source: "kilo",
    reasoning: true,
    contextWindow: 256e3,
    maxTokens: 1e4,
    input: ["text"],
    compat: { supportsReasoningEffort: false, supportsDeveloperRole: false }
  }),
  modelDef({
    id: "nvidia/nemotron-3.5-super-vl:free",
    name: "NVIDIA: Nemotron 3.5 Super VL (free)",
    source: "kilo",
    reasoning: true,
    contextWindow: 1e6,
    maxTokens: 1e4,
    input: ["text", "image"],
    compat: { supportsReasoningEffort: false, supportsDeveloperRole: false }
  }),
  modelDef({
    id: "dots-studio/dots-3-note-preview:free",
    name: "Dots 3 Note Preview Free",
    source: "kilo",
    reasoning: true,
    contextWindow: 512e3,
    maxTokens: 65536,
    input: ["text", "image"],
    compat: { supportsReasoningEffort: false, supportsDeveloperRole: false }
  }),
  modelDef({
    id: "nvidia/nemotron-3.5-lightning:free",
    name: "Nemotron 3.5 Lightning Free",
    source: "kilo",
    reasoning: true,
    contextWindow: 1e6,
    maxTokens: 65536,
    input: ["text"],
    compat: { supportsReasoningEffort: false, supportsDeveloperRole: false }
  }),
  modelDef({
    id: "cohere/north-mini-code:free",
    name: "North Mini Code Free",
    source: "kilo",
    reasoning: true,
    contextWindow: 256e3,
    maxTokens: 64e3,
    input: ["text"],
    compat: { supportsReasoningEffort: false, supportsDeveloperRole: false }
  }),
  modelDef({
    id: "nvidia/nemotron-3-ultra-550b-a55b:free",
    name: "Nemotron 3 Ultra Free",
    source: "kilo",
    reasoning: true,
    contextWindow: 1e6,
    maxTokens: 65536,
    input: ["text"],
    compat: { supportsReasoningEffort: false, supportsDeveloperRole: false }
  }),
  modelDef({
    id: "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free",
    name: "Nemotron 3 Nano Omni Free",
    source: "kilo",
    reasoning: true,
    contextWindow: 256e3,
    maxTokens: 65536,
    input: ["text", "image"],
    compat: { supportsReasoningEffort: false, supportsDeveloperRole: false }
  }),
  modelDef({
    id: "openrouter/free",
    name: "OpenRouter Free",
    source: "kilo",
    reasoning: true,
    contextWindow: 2e5,
    maxTokens: 65536,
    input: ["text", "image"],
    compat: { supportsReasoningEffort: false, supportsDeveloperRole: false }
  })
];
var kiloUpstream = {
  id: "kilo",
  kind: "remote-keyless",
  relayAllowed: true,
  chatUrl: KILO_CHAT_URL,
  async fetchCatalog() {
    try {
      const res = await fetch(KILO_CATALOG_URL, {
        signal: AbortSignal.timeout(15e3)
      });
      if (!res.ok) return null;
      const json = await res.json();
      const live = json.data ?? [];
      const free = live.filter(
        (m) => m.id.endsWith(":free") || KILO_MODELS.some((k) => k.id === m.id)
      );
      if (free.length === 0) return null;
      return free.map((m) => {
        const known2 = KILO_MODELS.find((k) => k.id === m.id);
        const modalities = m.architecture?.input_modalities ?? [];
        const input = modalities.includes("image") ? ["text", "image"] : ["text"];
        const tools = m.supported_parameters ? { supportsTools: m.supported_parameters.includes("tools") } : {};
        if (known2) {
          return modelDef({
            ...known2,
            contextWindow: m.context_length ?? known2.contextWindow,
            reasoning: m.supported_parameters?.includes("reasoning") ?? known2.reasoning,
            input,
            ...tools
          });
        }
        return modelDef({
          id: m.id,
          name: m.name ? m.name : m.id,
          source: "kilo",
          reasoning: m.supported_parameters?.includes("reasoning") ?? false,
          contextWindow: m.context_length ?? 2e5,
          maxTokens: 1e4,
          input,
          compat: { supportsReasoningEffort: false, supportsDeveloperRole: false },
          ...tools
        });
      });
    } catch {
      return null;
    }
  },
  requestHeaders() {
    return {};
  }
};

// src/upstreams/local.ts
var LOCAL_RELAY_ALLOWED = false;
function createLocalUpstream(cfg) {
  const base = cfg.baseUrl.replace(/\/+$/, "");
  const source = `local:${cfg.name}`;
  const headers = () => cfg.apiKey ? { Authorization: `Bearer ${cfg.apiKey}` } : {};
  return {
    id: source,
    kind: "local-openai",
    relayAllowed: LOCAL_RELAY_ALLOWED,
    chatUrl: `${base}/chat/completions`,
    async fetchCatalog() {
      try {
        const res = await fetch(`${base}/models`, { headers: headers(), signal: AbortSignal.timeout(15e3) });
        if (!res.ok) return null;
        const json = await res.json();
        if (!Array.isArray(json.data)) return null;
        return json.data.filter((x) => typeof x.id === "string").map((x) => {
          const raw = String(x.id);
          return modelDef({ id: `${cfg.name}/${raw}`, name: typeof x.name === "string" ? x.name : raw, source, reasoning: Boolean(x.reasoning), contextWindow: Number(x.context_window ?? x.context_length ?? 128e3), maxTokens: Number(x.max_tokens ?? 32768), input: Array.isArray(x.input) ? x.input : ["text"], compat: { supportsReasoningEffort: true, supportsDeveloperRole: true }, supportsTools: true });
        });
      } catch {
        return null;
      }
    },
    requestHeaders() {
      return headers();
    },
    transformRequestBody(body) {
      const model = String(body.model ?? "");
      return { ...body, model: model.startsWith(`${cfg.name}/`) ? model.slice(cfg.name.length + 1) : model };
    }
  };
}

// src/upstreams/ovh.ts
var OVH_BASE_URL = "https://oai.endpoints.kepler.ai.cloud.ovh.net/v1";
var OVH_PREFIX = "ovh/";
function ovhModel(id, name, reasoning, contextWindow, maxTokens, vision) {
  return modelDef({
    id: `${OVH_PREFIX}${id}`,
    name: `${name} (OVH)`,
    source: "ovh",
    reasoning,
    contextWindow,
    maxTokens,
    input: vision ? ["text", "image"] : ["text"],
    compat: { supportsReasoningEffort: false, supportsDeveloperRole: false }
  });
}
var OVH_MODELS = [
  ovhModel("gpt-oss-120b", "GPT-OSS 120B", true, 131072, 32768, false),
  ovhModel("gpt-oss-20b", "GPT-OSS 20B", true, 131072, 32768, false),
  ovhModel("Qwen3.5-397B-A17B", "Qwen3.5 397B A17B", true, 262144, 65536, true),
  ovhModel("Qwen3.8-27B", "Qwen3.8 27B", true, 262144, 32768, true),
  ovhModel("Qwen3.6-27B", "Qwen3.6 27B", true, 262144, 65536, true),
  ovhModel("Qwen3.5-9B", "Qwen3.5 9B", true, 262144, 65536, true),
  ovhModel("Mistral-Small-3.2-24B-Instruct-2506", "Mistral Small 3.2 24B", false, 131072, 16384, true),
  ovhModel("Meta-Llama-3_3-70B-Instruct", "Llama 3.3 70B", false, 131072, 16384, false),
  ovhModel("Qwen2.5-VL-72B-Instruct", "Qwen2.5 VL 72B", false, 32768, 32768, true),
  ovhModel("Mistral-Nemo-Instruct-2407", "Mistral Nemo Instruct", false, 65536, 16384, false)
];
var ovhUpstream = {
  id: "ovh",
  kind: "remote-keyless",
  relayAllowed: false,
  chatUrl: `${OVH_BASE_URL}/chat/completions`,
  async fetchCatalog() {
    try {
      const res = await fetch(`${OVH_BASE_URL}/models`, { signal: AbortSignal.timeout(1e4) });
      if (!res.ok) return null;
      const body = await res.json();
      if (!Array.isArray(body.data)) return null;
      const live = new Map(body.data.map((m) => [`${OVH_PREFIX}${m.id}`, m]));
      return OVH_MODELS.filter((m) => live.has(m.id)).map((m) => ({
        ...m,
        contextWindow: live.get(m.id).context_length || m.contextWindow
      }));
    } catch {
      return null;
    }
  },
  requestHeaders() {
    return {};
  },
  transformRequestBody(body, model) {
    return { ...body, model: model.id.slice(OVH_PREFIX.length) };
  }
};

// src/upstreams/zen.ts
init_state();
import fs6 from "node:fs";
import os5 from "node:os";
import path6 from "node:path";
import { spawnSync as spawnSync3 } from "node:child_process";
import { randomBytes } from "node:crypto";

// src/protocols/tool-bridge.ts
var SHELL_NAMES = ["bash", "shell", "exec_command", "run_command", "execute_command", "run_shell_command", "run_terminal_cmd", "terminal", "exec", "sh"];
var READ_NAMES = ["read", "read_file", "readfile", "view", "view_file", "open_file", "file_read", "read_text_file", "cat"];
var EDIT_ALIAS = "apply_edit";
var EDIT_NAMES = ["edit"];
var COMMAND_KEYS = ["command", "cmd", "script", "commandLine", "command_line"];
var WORKDIR_KEYS = ["workdir", "cwd", "working_directory", "workingDirectory", "directory", "dir"];
var TIMEOUT_KEYS = ["timeout", "timeout_ms", "timeoutMs"];
var BACKGROUND_KEYS = ["run_in_background", "background"];
var PATH_KEYS = ["path", "file_path", "filePath", "file", "filename", "target_file", "absolute_path"];
var OFFSET_KEYS = ["offset", "start_line", "line_start"];
var LIMIT_KEYS = ["limit", "max_lines", "line_count"];
var INTENT_KEYS = ["i", "intent", "description", "reason", "summary"];
function toolSpecs(body) {
  const tools = body?.tools;
  if (!Array.isArray(tools)) return [];
  return tools.map((t) => ({
    name: t?.function?.name ?? t?.name,
    parameters: t?.function?.parameters ?? t?.parameters ?? t?.input_schema ?? {}
  })).filter((s) => typeof s.name === "string");
}
function pick(schema, keys) {
  const props = schema.properties ?? {};
  return keys.find((k) => k in props);
}
function fillIntent(schema, out, text) {
  const required = Array.isArray(schema.required) ? schema.required : [];
  for (const k of INTENT_KEYS) {
    if (required.includes(k) && !(k in out) && schema.properties?.[k]?.type === "string") out[k] = text;
  }
}
function requiredMet(schema, out) {
  const required = Array.isArray(schema.required) ? schema.required : [];
  return required.every((k) => typeof k === "string" && k in out);
}
function findTool(specs, names, keys) {
  for (const n of names) {
    const hit = specs.find((s) => s.name.toLowerCase() === n && pick(s.parameters, keys));
    if (hit) return hit;
  }
  return void 0;
}
function shellQuote(s) {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}
function shellCall(target, args) {
  const command = args.command;
  const cmdKey = pick(target.parameters, COMMAND_KEYS);
  if (typeof command !== "string" || !command || !cmdKey) return null;
  const out = {};
  out[cmdKey] = target.parameters.properties?.[cmdKey]?.type === "array" ? ["bash", "-lc", command] : command;
  const wd = pick(target.parameters, WORKDIR_KEYS);
  if (wd && typeof args.workdir === "string") out[wd] = args.workdir;
  const tk = pick(target.parameters, TIMEOUT_KEYS);
  if (tk && typeof args.timeout === "number" && args.timeout > 0) out[tk] = args.timeout;
  const bg = pick(target.parameters, BACKGROUND_KEYS);
  if (bg && args.background === true) out[bg] = true;
  fillIntent(target.parameters, out, `Run ${command.length > 60 ? `${command.slice(0, 57)}...` : command}`);
  return requiredMet(target.parameters, out) ? { name: target.name, arguments: JSON.stringify(out) } : null;
}
function readCall(target, args) {
  const pathKey = pick(target.parameters, PATH_KEYS);
  if (typeof args.path !== "string" || !args.path || !pathKey) return null;
  const out = { [pathKey]: args.path };
  const ok = pick(target.parameters, OFFSET_KEYS);
  if (ok && typeof args.offset === "number") out[ok] = args.offset;
  const lk = pick(target.parameters, LIMIT_KEYS);
  if (lk && typeof args.limit === "number") out[lk] = args.limit;
  fillIntent(target.parameters, out, `Read ${args.path}`);
  return requiredMet(target.parameters, out) ? { name: target.name, arguments: JSON.stringify(out) } : null;
}
function readAsShell(args) {
  if (typeof args.path !== "string" || !args.path) return null;
  const file = shellQuote(args.path);
  const offset = typeof args.offset === "number" && args.offset > 0 ? Math.floor(args.offset) : 1;
  const limit = typeof args.limit === "number" && args.limit > 0 ? Math.floor(args.limit) : 2e3;
  return { command: `sed -n '${offset},${offset + limit - 1}p' -- ${file}` };
}
function parseArgs(raw) {
  try {
    const v = JSON.parse(raw || "{}");
    return v && typeof v === "object" && !Array.isArray(v) ? v : null;
  } catch {
    return null;
  }
}
function shellArgsFromCaller(target, args) {
  const cmdKey = pick(target.parameters, COMMAND_KEYS);
  if (!cmdKey) return null;
  const raw = args[cmdKey];
  const command = Array.isArray(raw) ? raw[raw.length - 1] : raw;
  if (typeof command !== "string" || !command) return null;
  const out = { command };
  const wd = pick(target.parameters, WORKDIR_KEYS);
  if (wd && typeof args[wd] === "string") out.workdir = args[wd];
  const tk = pick(target.parameters, TIMEOUT_KEYS);
  if (tk && typeof args[tk] === "number") out.timeout = args[tk];
  const bg = pick(target.parameters, BACKGROUND_KEYS);
  if (bg && args[bg] === true) out.background = true;
  return out;
}
function readArgsFromCaller(target, args) {
  const pathKey = pick(target.parameters, PATH_KEYS);
  if (!pathKey || typeof args[pathKey] !== "string") return null;
  const out = { path: args[pathKey] };
  const ok = pick(target.parameters, OFFSET_KEYS);
  if (ok && typeof args[ok] === "number") out.offset = args[ok];
  const lk = pick(target.parameters, LIMIT_KEYS);
  if (lk && typeof args[lk] === "number") out.limit = args[lk];
  return out;
}
function restoreBridgedCalls(messages, body) {
  if (!Array.isArray(messages) || messages.length === 0) return messages;
  const specs = toolSpecs(body);
  if (specs.length === 0) return messages;
  const declared = new Set(specs.map((s) => s.name.trim().toLowerCase()));
  const shellTarget = declared.has("shell") ? void 0 : findTool(specs, SHELL_NAMES, COMMAND_KEYS);
  const readTarget = declared.has("read") ? void 0 : findTool(specs, READ_NAMES, PATH_KEYS);
  const editTarget = declared.has(EDIT_ALIAS) ? void 0 : specs.find((s) => EDIT_NAMES.includes(s.name.trim().toLowerCase()) && !pick(s.parameters, ["filePath"]));
  if (!shellTarget && !readTarget && !editTarget) return messages;
  const rewrite = (tc) => {
    const name = typeof tc?.function?.name === "string" ? tc.function.name : "";
    const raw = typeof tc?.function?.arguments === "string" ? tc.function.arguments : "";
    if (!name) return tc;
    const args = parseArgs(raw);
    if (shellTarget && name === shellTarget.name && args) {
      const translated = shellArgsFromCaller(shellTarget, args);
      if (translated) return { ...tc, function: { ...tc.function, name: "shell", arguments: JSON.stringify(translated) } };
    }
    if (readTarget && name === readTarget.name && args) {
      const translated = readArgsFromCaller(readTarget, args);
      if (translated) return { ...tc, function: { ...tc.function, name: "read", arguments: JSON.stringify(translated) } };
    }
    if (editTarget && name === editTarget.name) {
      return { ...tc, function: { ...tc.function, name: EDIT_ALIAS } };
    }
    return tc;
  };
  let changed = false;
  const out = messages.map((m) => {
    if (m?.role !== "assistant" || !Array.isArray(m.tool_calls)) return m;
    const toolCalls = m.tool_calls.map(rewrite);
    if (toolCalls.every((tc, i) => tc === m.tool_calls[i])) return m;
    changed = true;
    return { ...m, tool_calls: toolCalls };
  });
  return changed ? out : messages;
}
function callerToolsFromBody(body) {
  const specs = toolSpecs(body);
  const names = new Set(specs.map((s) => s.name));
  const shellTarget = findTool(specs, SHELL_NAMES, COMMAND_KEYS);
  const readTarget = findTool(specs, READ_NAMES, PATH_KEYS);
  const editTarget = specs.find((s) => EDIT_NAMES.includes(s.name.trim().toLowerCase()));
  return {
    has: (name) => names.has(name),
    bridge(name) {
      return innerBridge(name);
    }
  };
  function innerBridge(name) {
    if (names.has(name)) return null;
    if (name === EDIT_ALIAS && editTarget) {
      return (raw) => ({ name: editTarget.name, arguments: raw || "{}" });
    }
    if (name === "shell" && shellTarget) {
      return (raw) => {
        const args = parseArgs(raw);
        return args ? shellCall(shellTarget, args) : null;
      };
    }
    if (name === "read" && (readTarget || shellTarget)) {
      return (raw) => {
        const args = parseArgs(raw);
        if (!args) return null;
        if (readTarget) return readCall(readTarget, args);
        const asShell = readAsShell(args);
        return asShell ? shellCall(shellTarget, asShell) : null;
      };
    }
    return null;
  }
}

// src/upstreams/zen.ts
var ZEN_INFERENCE_URL = "https://opencode.ai/inference/openai/v1";
var ZEN_MODELS_URL = "https://opencode.ai/zen/v1";
var MODELS_DEV_URL = "https://models.dev/api.json";
var OPENCODE_UA_FALLBACK = "1.18.31";
var OPENCODE_USER_AGENT_ENV = "BANSOS_OPENCODE_UA";
var OPENCODE_UA_VERSION_RE = /^\d+\.\d+\.\d+$/;
var BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
var OPENCODE_EXACT_TOOLS = [
  {
    type: "function",
    function: {
      name: "read",
      description: "Read the contents of a file or directory. Supports text files, images, and PDFs. Images and PDFs are presented directly to the model. Each text line is prefixed by its 1-based line number as <line>: <content>. The prefix is for reference and is not part of the file content. Directory entries are returned one per line. Use offset and limit to read large files or directories in sections. Prefer one larger read over many small slices, and use grep to find specific content in large files.",
      parameters: {
        type: "object",
        properties: {
          path: { type: "string", description: "File or directory to read" },
          offset: { type: "number", description: "The line or directory entry to start reading from (1-based)" },
          limit: { type: "number", description: "The maximum number of lines or directory entries to read (defaults to and capped at 2000)" }
        },
        required: ["path"]
      }
    }
  },
  {
    type: "function",
    function: {
      name: "shell",
      description: "Execute a shell command and return its output. Quote file paths containing spaces or special characters. Prefer dedicated tools over shell commands when possible. When output is large, the full result is saved to a file and a truncated preview is returned. Rely on automatic truncation unless filtering the output is more useful. Commands accept an optional timeout, background commands have no timeout by default. Background commands return immediately, and you will be notified when they complete. DO NOT poll for completion.",
      parameters: {
        type: "object",
        properties: {
          command: { type: "string", description: "Shell command string to execute" },
          workdir: { type: "string", description: "Working directory to execute the command in. Defaults to the current working directory. When possible, avoid changing directories in the command and set the working directory here instead." },
          timeout: { type: "number", description: "Timeout in milliseconds. Set to 0 to disable the timeout." },
          background: { type: "boolean", description: "Run the command in the background and return immediately (useful for dev servers and long-running builds). You do not need to use '&' at the end of the command when using this parameter. You will be notified when it completes. DO NOT poll for completion." }
        },
        required: ["command"]
      }
    }
  }
];
var ZEN_IDENTITY_FILE = path6.join(BANSOS_DIR, "zen-identity.json");
var cachedZenIdentity = null;
var lastIdentityLookup = 0;
var IDENTITY_CACHE_TTL_MS = 3e4;
function extractIdentityFromRow(row) {
  if (row && typeof row === "object" && "id" in row && "project_id" in row && typeof row.id === "string" && typeof row.project_id === "string") {
    return { session: row.id, project: row.project_id };
  }
  return null;
}
function queryDbDirect(dbPath) {
  if ("Bun" in globalThis) {
    try {
      const bunSqlite = __require("bun:sqlite");
      const db = new bunSqlite.Database(dbPath, { readonly: true });
      try {
        const row2 = extractIdentityFromRow(db.query("SELECT id, project_id FROM session_v2 ORDER BY time_updated DESC LIMIT 1").get());
        if (row2) return row2;
        const row1 = extractIdentityFromRow(db.query("SELECT id, project_id FROM session ORDER BY time_created DESC LIMIT 1").get());
        if (row1) return row1;
      } finally {
        db.close();
      }
    } catch {
    }
  }
  try {
    const nodeSqlite = __require("node:sqlite");
    const db = new nodeSqlite.DatabaseSync(dbPath, { readOnly: true });
    try {
      const row2 = extractIdentityFromRow(db.prepare("SELECT id, project_id FROM session_v2 ORDER BY time_updated DESC LIMIT 1").get());
      if (row2) return row2;
      const row1 = extractIdentityFromRow(db.prepare("SELECT id, project_id FROM session ORDER BY time_created DESC LIMIT 1").get());
      if (row1) return row1;
    } finally {
      db.close();
    }
  } catch {
  }
  const whichCmd = process.platform === "win32" ? "where" : "which";
  try {
    const res = spawnSync3("sqlite3", [
      dbPath,
      "SELECT id, project_id FROM session_v2 ORDER BY time_updated DESC LIMIT 1;"
    ], { encoding: "utf-8", timeout: 1500 });
    if (res.status === 0 && res.stdout.trim()) {
      const parts = res.stdout.trim().split("|");
      if (parts.length >= 2 && parts[0] && parts[1]) {
        return { session: parts[0], project: parts[1] };
      }
    }
  } catch {
  }
  try {
    const res = spawnSync3("sqlite3", [
      dbPath,
      "SELECT id, project_id FROM session ORDER BY time_created DESC LIMIT 1;"
    ], { encoding: "utf-8", timeout: 1500 });
    if (res.status === 0 && res.stdout.trim()) {
      const parts = res.stdout.trim().split("|");
      if (parts.length >= 2 && parts[0] && parts[1]) {
        return { session: parts[0], project: parts[1] };
      }
    }
  } catch {
  }
  return null;
}
function findLocalOpenCodeIdentity() {
  const home = os5.homedir();
  const dbCandidates = [
    path6.join(home, ".local", "share", "opencode", "opencode.db"),
    path6.join(home, "Library", "Application Support", "opencode", "opencode.db")
  ];
  if (process.env.LOCALAPPDATA) {
    dbCandidates.push(path6.join(process.env.LOCALAPPDATA, "opencode", "opencode.db"));
  }
  for (const dbPath of dbCandidates) {
    if (fs6.existsSync(dbPath)) {
      const id = queryDbDirect(dbPath);
      if (id) return id;
    }
  }
  return null;
}
function loadZenIdentity() {
  const now = Date.now();
  if (cachedZenIdentity && now - lastIdentityLookup < IDENTITY_CACHE_TTL_MS) {
    return cachedZenIdentity;
  }
  lastIdentityLookup = now;
  const local = findLocalOpenCodeIdentity();
  if (local) {
    saveZenIdentity(local);
    return local;
  }
  try {
    if (fs6.existsSync(ZEN_IDENTITY_FILE)) {
      const data = JSON.parse(fs6.readFileSync(ZEN_IDENTITY_FILE, "utf-8"));
      if (data && typeof data === "object" && "session" in data && "project" in data && typeof data.session === "string" && typeof data.project === "string") {
        const parsed = { session: data.session, project: data.project };
        cachedZenIdentity = parsed;
        return parsed;
      }
    }
  } catch {
  }
  const fallback = {
    session: generateSessionId(),
    project: "global"
  };
  saveZenIdentity(fallback);
  return fallback;
}
function saveZenIdentity(identity) {
  cachedZenIdentity = identity;
  try {
    fs6.mkdirSync(BANSOS_DIR, { recursive: true });
    fs6.writeFileSync(ZEN_IDENTITY_FILE, JSON.stringify(identity, null, 2), "utf-8");
  } catch {
  }
}
var lastSessionTs = 0;
var sessionCounter = 0;
function unstableRandom() {
  const bytes = randomBytes(14);
  let out = "";
  for (let i = 0; i < 14; i++) out += BASE62[bytes[i] % 62];
  return out;
}
var OPENCODE_ID_MASK = (1n << 48n) - 1n;
function timeHexFrom(value) {
  const v = value & OPENCODE_ID_MASK;
  return Array.from(
    { length: 6 },
    (_, i) => Number(v >> BigInt(40 - 8 * i) & 0xffn).toString(16).padStart(2, "0")
  ).join("");
}
function generateSessionId(timestamp = Date.now()) {
  if (timestamp !== lastSessionTs) {
    lastSessionTs = timestamp;
    sessionCounter = 0;
  }
  sessionCounter++;
  const current = BigInt(timestamp) * 0x1000n + BigInt(sessionCounter);
  return `ses_${timeHexFrom(~current)}${unstableRandom()}`;
}
function generateRequestId(timestamp = Date.now()) {
  const current = BigInt(timestamp) * 0x1000n + 1n;
  return `msg_${timeHexFrom(current)}${unstableRandom()}`;
}
var liveOpenCodeVersion = null;
function getOpenCodeUA() {
  const override = process.env[OPENCODE_USER_AGENT_ENV]?.trim();
  if (override) return override.startsWith("opencode/") ? override : `opencode/${override}`;
  if (liveOpenCodeVersion && OPENCODE_UA_VERSION_RE.test(liveOpenCodeVersion))
    return `opencode/${liveOpenCodeVersion}`;
  return `opencode/${OPENCODE_UA_FALLBACK}`;
}
var PASSTHROUGH_HEADERS = [
  "user-agent",
  "x-opencode-client",
  "x-opencode-project",
  "x-opencode-session",
  "x-opencode-session-id",
  "x-opencode-parent-session-id",
  "x-session-affinity",
  "x-session-id",
  "x-parent-session-id"
];
function firstHeader(value) {
  if (Array.isArray(value)) return value[0];
  return value;
}
function opencodeHeaders(callerHeaders, withRequestHeader = false) {
  const headers = {};
  if (callerHeaders) {
    for (const name of PASSTHROUGH_HEADERS) {
      const value = firstHeader(callerHeaders[name]);
      if (value) {
        if (name === "user-agent") {
          if (value.startsWith("opencode/")) headers["User-Agent"] = value;
        } else {
          headers[name] = value;
        }
      }
    }
  }
  if (headers["x-opencode-session"] && headers["x-opencode-project"]) {
    saveZenIdentity({
      session: headers["x-opencode-session"],
      project: headers["x-opencode-project"]
    });
  }
  const identity = loadZenIdentity();
  const traceId = randomBytes(16).toString("hex");
  const spanId = randomBytes(8).toString("hex");
  const parentSpanId = randomBytes(8).toString("hex");
  const session = headers["x-opencode-session"] ?? identity.session;
  const project = headers["x-opencode-project"] ?? identity.project;
  if (!headers["User-Agent"]) headers["User-Agent"] = getOpenCodeUA();
  headers["authorization"] ??= "Bearer public";
  headers["x-opencode-client"] ??= "desktop";
  headers["x-opencode-project"] = project || "global";
  headers["x-opencode-session"] = session;
  headers["x-opencode-session-id"] ??= session;
  headers["x-session-affinity"] ??= session;
  headers["b3"] ??= `${traceId}-${spanId}-1-${parentSpanId}`;
  headers["traceparent"] ??= `00-${traceId}-${spanId}-01`;
  if (withRequestHeader) headers["x-opencode-request"] = generateRequestId();
  return headers;
}
function toolNameOf(tool) {
  if (!tool || typeof tool !== "object" || Array.isArray(tool)) return "";
  const t = tool;
  const fn = t.function && typeof t.function === "object" && !Array.isArray(t.function) ? t.function : null;
  const raw = typeof t.name === "string" ? t.name : typeof fn?.name === "string" ? fn.name : "";
  return raw.trim();
}
function ensureChatFingerprintTools(body) {
  if (!Array.isArray(body.tools)) body.tools = [];
  const present = /* @__PURE__ */ new Set();
  for (const tool of body.tools) {
    const name = toolNameOf(tool);
    if (name) present.add(name);
  }
  for (const t of OPENCODE_EXACT_TOOLS) {
    if (present.has(t.function.name)) continue;
    body.tools.push(structuredClone(t));
  }
}
function ensureResponsesFingerprintTools(body) {
  const present = /* @__PURE__ */ new Set();
  if (!Array.isArray(body.tools)) body.tools = [];
  for (const tool of body.tools) {
    const name = toolNameOf(tool);
    if (name) present.add(name);
  }
  for (const t of OPENCODE_EXACT_TOOLS) {
    const name = t.function.name;
    if (present.has(name)) continue;
    body.tools.push({
      type: "function",
      name,
      description: t.function.description,
      parameters: t.function.parameters
    });
  }
}
function sanitizeResponsesItems(body) {
  if (!Array.isArray(body.input)) return;
  body.input = body.input.filter((item) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) return true;
    const it = item;
    if (it.type === "reasoning") return false;
    delete it.encrypted_content;
    delete it.reasoning_encrypted_content;
    return true;
  });
}
var OPENCODE_ENV_BLOCK = "<env>\nWorking directory: /tmp\n</env>";
function ensureOpencodeSystemPrompt(body) {
  if (!Array.isArray(body.messages) || body.messages.length === 0) return;
  const messages = body.messages;
  const sysIdx = messages.findIndex((m) => m && m.role === "system");
  if (sysIdx !== -1) {
    const sysMsg = messages[sysIdx];
    if (Array.isArray(sysMsg.content)) {
      const parts = sysMsg.content;
      const hasEnv = parts.some(
        (p) => p && typeof p === "object" && typeof p.text === "string" && p.text.includes("</env>")
      );
      if (!hasEnv) parts.push({ type: "text", text: OPENCODE_ENV_BLOCK });
      return;
    }
    const content = typeof sysMsg.content === "string" ? sysMsg.content : "";
    if (!content.includes("</env>")) {
      sysMsg.content = `${content}

${OPENCODE_ENV_BLOCK}`.trim();
    }
  } else {
    messages.unshift({ role: "system", content: OPENCODE_ENV_BLOCK });
  }
}
var EDIT_ALIAS2 = "apply_edit";
var EDIT_TOOL_RE = /^edit$/i;
function toolFunction(tool) {
  if (!tool || typeof tool !== "object" || Array.isArray(tool)) return null;
  const t = tool;
  const fn = t.function && typeof t.function === "object" && !Array.isArray(t.function) ? t.function : t;
  return fn;
}
function aliasCallerEditTool(body) {
  if (!Array.isArray(body.tools)) return;
  const tools = body.tools;
  if (tools.some((tool) => toolFunction(tool)?.name === EDIT_ALIAS2)) return;
  for (let i = 0; i < tools.length; i++) {
    const fn = toolFunction(tools[i]);
    if (!fn || typeof fn.name !== "string" || !EDIT_TOOL_RE.test(fn.name.trim())) continue;
    const params = fn.parameters ?? fn.input_schema;
    if (params?.properties && "filePath" in params.properties) continue;
    const renamed = { ...fn, name: EDIT_ALIAS2 };
    const holder = tools[i];
    tools[i] = holder.function ? { ...holder, function: renamed } : renamed;
  }
}
var OPENCODE_TOOL_NAMES = /* @__PURE__ */ new Set([
  "read",
  "write",
  "edit",
  "bash",
  "shell",
  "glob",
  "grep",
  "list",
  "ls",
  "find",
  "view",
  "fetch",
  "webfetch",
  "web_fetch",
  "todo",
  "todowrite",
  "todoread",
  "task",
  "subagent",
  "skill",
  "batch",
  "patch",
  "apply_patch",
  "multiedit",
  "str_replace",
  "question",
  "plan",
  "scroll",
  "snap",
  "apply_edit"
]);
function fingerprintTools(shape) {
  return OPENCODE_EXACT_TOOLS.map(
    (t) => shape === "responses" ? {
      type: "function",
      name: t.function.name,
      description: t.function.description,
      parameters: t.function.parameters
    } : structuredClone(t)
  );
}
function restrictGatedTools(body, shape = "chat") {
  if (!Array.isArray(body.tools) || body.tools.length === 0) return;
  const foreign = body.tools.some((tool) => {
    const name = toolNameOf(tool).toLowerCase();
    return name !== "" && !OPENCODE_TOOL_NAMES.has(name);
  });
  if (!foreign) return;
  body.tools = fingerprintTools(shape);
}
function transformOpencodeBodyChat(body) {
  body.stream = true;
  ensureChatFingerprintTools(body);
  aliasCallerEditTool(body);
  ensureOpencodeSystemPrompt(body);
  restrictGatedTools(body);
  return body;
}
function transformOpencodeBodyResponses(body) {
  if (body.max_output_tokens === void 0) {
    if (typeof body.max_completion_tokens === "number")
      body.max_output_tokens = body.max_completion_tokens;
    else if (typeof body.max_tokens === "number")
      body.max_output_tokens = body.max_tokens;
  }
  delete body.max_tokens;
  delete body.max_completion_tokens;
  body.store = false;
  body.stream = true;
  ensureResponsesFingerprintTools(body);
  aliasCallerEditTool(body);
  sanitizeResponsesItems(body);
  restrictGatedTools(body, "responses");
  return body;
}
function discardBody(res) {
  void res?.body?.cancel().catch(() => {
  });
}
var ZEN_CHAT_MODALITIES = /* @__PURE__ */ new Set(["text", "image"]);
var ZEN_RESPONSES_MODALITIES = /* @__PURE__ */ new Set(["text", "image", "pdf"]);
function zenModelFromIndex(id, m) {
  const seed = ZEN_MODELS.find((s) => s.id === id);
  const wireApi = seed?.wireApi;
  const deliverable = wireApi === "responses" ? ZEN_RESPONSES_MODALITIES : ZEN_CHAT_MODALITIES;
  const modalities = (m.modalities?.input ?? seed?.input ?? ["text"]).filter(
    (i) => deliverable.has(i)
  );
  return modelDef({
    id,
    name: m.name ?? seed?.name ?? id,
    source: "zen",
    reasoning: m.reasoning ?? seed?.reasoning ?? false,
    contextWindow: id === "deepseek-v4.1-flash-free" ? 1e6 : m.limit?.context ?? seed?.contextWindow ?? 128e3,
    maxTokens: m.limit?.output ?? seed?.maxTokens ?? 16384,
    input: modalities.length > 0 ? modalities : ["text"],
    compat: { supportsReasoningEffort: false, supportsDeveloperRole: false },
    ...wireApi ? { wireApi } : {}
  });
}
var ZEN_MODELS = [
  modelDef({
    id: "glm-5.3-flash-free",
    name: "GLM-5.3-Flash Free",
    source: "zen",
    reasoning: true,
    contextWindow: 2e5,
    maxTokens: 32e3,
    input: ["text", "image"],
    compat: { supportsReasoningEffort: false, supportsDeveloperRole: false }
  }),
  modelDef({
    id: "flint-40b-free",
    name: "Flint 40B Free",
    source: "zen",
    reasoning: true,
    contextWindow: 262144,
    maxTokens: 65536,
    input: ["text"],
    compat: { supportsReasoningEffort: false, supportsDeveloperRole: false }
  }),
  modelDef({
    id: "big-pickle",
    name: "Big Pickle",
    source: "zen",
    reasoning: true,
    contextWindow: 2e5,
    maxTokens: 32e3,
    input: ["text"],
    compat: { supportsReasoningEffort: false, supportsDeveloperRole: false }
  }),
  modelDef({
    id: "nemotron-3.5-lightning-free",
    name: "Nemotron 3.5 Lightning Free",
    source: "zen",
    reasoning: true,
    contextWindow: 262144,
    maxTokens: 262144,
    input: ["text"],
    compat: { supportsReasoningEffort: false, supportsDeveloperRole: false }
  }),
  modelDef({
    id: "nemotron-3.5-super-vl-free",
    name: "Nemotron 3.5 Super VL Free",
    source: "zen",
    reasoning: true,
    contextWindow: 1048576,
    maxTokens: 131072,
    input: ["text", "image"],
    compat: { supportsReasoningEffort: false, supportsDeveloperRole: false }
  }),
  modelDef({
    id: "pulse-alpha-free",
    name: "Pulse Alpha Free",
    source: "zen",
    reasoning: true,
    contextWindow: 1048576,
    maxTokens: 131072,
    input: ["text", "image"],
    compat: { supportsReasoningEffort: false, supportsDeveloperRole: false }
  }),
  modelDef({
    id: "deepseek-v4.1-flash-free",
    name: "DeepSeek V4.1 Flash Free",
    source: "zen",
    reasoning: true,
    contextWindow: 1e6,
    maxTokens: 32e3,
    input: ["text", "image"],
    compat: { supportsReasoningEffort: false, supportsDeveloperRole: false }
  }),
  modelDef({
    id: "crouton-alpha-free",
    name: "Crouton Alpha Free",
    source: "zen",
    reasoning: true,
    contextWindow: 1048576,
    maxTokens: 27e4,
    input: ["text", "image", "pdf"],
    compat: { supportsReasoningEffort: false, supportsDeveloperRole: false },
    wireApi: "responses"
  }),
  modelDef({
    id: "mimo-v2.6-flash-free",
    name: "MiMo-V2.6-Flash Free",
    source: "zen",
    reasoning: true,
    contextWindow: 2e5,
    maxTokens: 32e3,
    input: ["text", "image"],
    compat: { supportsReasoningEffort: false, supportsDeveloperRole: false }
  }),
  modelDef({
    id: "beam-free",
    name: "Beam Free",
    source: "zen",
    reasoning: true,
    contextWindow: 1048576,
    maxTokens: 131072,
    input: ["text"],
    compat: { supportsReasoningEffort: false, supportsDeveloperRole: false }
  })
];
var zenUpstream = {
  id: "zen",
  kind: "remote-keyless",
  relayAllowed: true,
  chatUrl: `${ZEN_INFERENCE_URL}/chat/completions`,
  responsesUrl: `${ZEN_INFERENCE_URL}/responses`,
  async fetchCatalog() {
    try {
      const [indexRes, listRes] = await Promise.all([
        fetch(MODELS_DEV_URL, { signal: AbortSignal.timeout(1e4) }).catch(() => null),
        fetch(`${ZEN_MODELS_URL}/models`, {
          headers: opencodeHeaders(void 0, true),
          signal: AbortSignal.timeout(6e3)
        })
      ]);
      let index = null;
      if (indexRes?.ok) index = await indexRes.json();
      else discardBody(indexRes);
      if (!listRes.ok) {
        discardBody(listRes);
        return null;
      }
      const listing = await listRes.json();
      const listed = new Set((listing.data ?? []).map((m) => m.id));
      if (listed.size === 0) return null;
      const kept = [];
      const unservable = /* @__PURE__ */ new Set();
      for (const [id, m] of Object.entries(index?.opencode?.models ?? {})) {
        if (m?.status === "deprecated" || m?.cost?.input !== 0) {
          unservable.add(id);
          continue;
        }
        if (!listed.has(id)) continue;
        kept.push(zenModelFromIndex(id, m));
      }
      const resolved = new Set(kept.map((m) => m.id));
      for (const m of ZEN_MODELS) {
        if (resolved.has(m.id)) continue;
        if (listed.has(m.id) && !unservable.has(m.id)) {
          kept.push(m);
          continue;
        }
        const responsesWire = m.wireApi === "responses";
        const probe = await fetch(
          responsesWire ? `${ZEN_INFERENCE_URL}/responses` : `${ZEN_INFERENCE_URL}/chat/completions`,
          {
            method: "POST",
            headers: { "content-type": "application/json", ...opencodeHeaders() },
            body: JSON.stringify(
              responsesWire ? {
                model: m.id,
                input: "ping",
                max_output_tokens: 16,
                stream: true,
                tools: OPENCODE_EXACT_TOOLS.map((t) => ({
                  type: "function",
                  name: t.function.name,
                  description: t.function.description,
                  parameters: t.function.parameters
                }))
              } : {
                model: m.id,
                messages: [
                  { role: "system", content: OPENCODE_ENV_BLOCK },
                  { role: "user", content: "ping" }
                ],
                max_tokens: 4,
                stream: true,
                tools: OPENCODE_EXACT_TOOLS
              }
            ),
            signal: AbortSignal.timeout(15e3)
          }
        );
        if (probe.ok) kept.push(m);
      }
      if (kept.length === 0) return null;
      return kept;
    } catch {
      return null;
    }
  },
  requestHeaders(_model, callerHeaders) {
    return opencodeHeaders(callerHeaders, true);
  },
  // the gate answers 429 on a tool set it does not know, so the same turn goes out once more with the pair
  retryShape(body, model) {
    if (!Array.isArray(body.tools) || body.tools.length === 0) return null;
    const shape = model.wireApi === "responses" ? "responses" : "chat";
    const tools = fingerprintTools(shape);
    if (JSON.stringify(body.tools) === JSON.stringify(tools)) return null;
    return { ...body, tools };
  },
  transformRequestBody(body, model) {
    const own = {
      ...body,
      ...Array.isArray(body.tools) ? { tools: [...body.tools] } : {},
      ...Array.isArray(body.messages) ? { messages: restoreBridgedCalls(body.messages, body) } : {}
    };
    return model.wireApi === "responses" ? transformOpencodeBodyResponses(own) : transformOpencodeBodyChat(own);
  }
};

// src/upstreams/index.ts
var DEFAULT_UPSTREAMS = [zenUpstream, kiloUpstream, llm7Upstream, ovhUpstream];
var SEEDED_MODELS = [
  ...ZEN_MODELS,
  ...KILO_MODELS,
  ...LLM7_MODELS,
  ...OVH_MODELS
];
function buildUpstreams(locals = []) {
  return [...DEFAULT_UPSTREAMS, ...locals.map(createLocalUpstream)];
}

// src/cli/setup.ts
var splitList = (v) => (v ?? "").split(",").map((s) => s.trim()).filter(Boolean);
function parseArgs2(argv) {
  const args = { harnesses: [], models: [], upstreams: [], dryRun: false, undo: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === void 0) continue;
    if (a === "--model") args.model = argv[++i];
    else if (a === "--models") args.models.push(...splitList(argv[++i]));
    else if (a === "--upstream") args.upstreams.push(...splitList(argv[++i]));
    else if (a === "--dry-run") args.dryRun = true;
    else if (a === "--undo") args.undo = true;
    else args.harnesses.push(a);
  }
  return args;
}
function readProviderDefault(file) {
  if (!fs7.existsSync(file)) return void 0;
  let inProvider = false;
  for (const line of fs7.readFileSync(file, "utf8").split("\n")) {
    const header = /^\s*\[([^\]]+)\]\s*$/.exec(line);
    if (header) {
      inProvider = header[1] === "provider";
      continue;
    }
    if (!inProvider) continue;
    const match = /^\s*default_provider\s*=\s*"([^"]*)"/.exec(line);
    if (match) return match[1];
  }
  return void 0;
}
function resolveTargetFile(adapter, defaultPath) {
  const fullDefault = expandHome(defaultPath);
  if (fs7.existsSync(fullDefault)) return defaultPath;
  const found = adapter.configPaths.map(expandHome).find((p) => fs7.existsSync(p));
  if (found) {
    const matched = adapter.configPaths.find((cp) => expandHome(cp) === found);
    if (matched && path7.extname(matched) === path7.extname(defaultPath)) return matched;
  }
  return defaultPath;
}
async function getSetupModels(baseUrl) {
  try {
    const res = await fetch(`${baseUrl}/models`, { signal: AbortSignal.timeout(800) });
    if (res.ok) {
      const json = await res.json();
      if (Array.isArray(json.data) && json.data.length > 0) {
        return { fromDaemon: true, models: json.data.map((m) => {
          const known2 = SEEDED_MODELS.find((s) => s.id === m.id);
          if (known2) return known2;
          return modelDef({
            id: m.id,
            name: m.name ?? m.id,
            source: m.source ?? "zen",
            reasoning: m.reasoning ?? false,
            contextWindow: m.context_window ?? 256e3,
            maxTokens: m.max_tokens ?? 32e3,
            input: ["text"],
            compat: { supportsReasoningEffort: false, supportsDeveloperRole: false }
          });
        }) };
      }
    }
  } catch {
  }
  return { models: SEEDED_MODELS, fromDaemon: false };
}
function update9RouterSqlite(dbPath, ctx) {
  const now = (/* @__PURE__ */ new Date()).toISOString();
  const nodeId = "openai-compatible-chat-bansos";
  const nodeData = JSON.stringify({
    prefix: "bansos",
    apiType: "chat",
    baseUrl: ctx.baseUrl,
    name: "Bansos Router"
  });
  const connId = "bansos-default";
  const connData = JSON.stringify({
    apiKey: "bansos",
    prefix: "bansos",
    apiType: "chat",
    baseUrl: ctx.baseUrl,
    nodeName: "Bansos Router"
  });
  try {
    const sqliteMod = globalThis.process?.getBuiltinModule?.("node:sqlite");
    if (!sqliteMod?.DatabaseSync) return false;
    const db = new sqliteMod.DatabaseSync(dbPath);
    db.prepare(
      "INSERT OR REPLACE INTO providerNodes(id, type, name, data, createdAt, updatedAt) VALUES(?, ?, ?, ?, ?, ?)"
    ).run(nodeId, "openai-compatible", "Bansos Router", nodeData, now, now);
    db.prepare(
      "INSERT OR REPLACE INTO providerConnections(id, provider, authType, name, email, priority, isActive, data, createdAt, updatedAt) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    ).run(connId, nodeId, "api_key", "Bansos Router", null, 1, 1, connData, now, now);
    db.close();
    return true;
  } catch {
    return false;
  }
}
function undo9RouterSqlite(dbPath) {
  const nodeId = "openai-compatible-chat-bansos";
  const connId = "bansos-default";
  try {
    const sqliteMod = globalThis.process?.getBuiltinModule?.("node:sqlite");
    if (!sqliteMod?.DatabaseSync) return false;
    const db = new sqliteMod.DatabaseSync(dbPath);
    db.prepare("DELETE FROM providerNodes WHERE id = ?").run(nodeId);
    db.prepare("DELETE FROM providerConnections WHERE id = ?").run(connId);
    db.close();
    return true;
  } catch {
    return false;
  }
}
var SETUP_SYMBOL = { ok: "\u2713", removed: "\u2717", skip: "\xB7", error: "\u2717" };
function printSetupLine(line) {
  const out = `  ${SETUP_SYMBOL[line.kind]} ${line.text}`;
  if (line.kind === "error") console.error(out);
  else console.log(out);
}
function applyDeepseek(adapter, ctx, report) {
  let failures = 0;
  for (const write of adapter.render(ctx)) {
    failures += applyDeepseekProfile(write, ctx, report);
  }
  return failures;
}
function applyDeepseekProfile(write, ctx, report) {
  const targetPath = write.path;
  const fullPath = expandHome(targetPath);
  const existing = fs7.existsSync(fullPath) ? fs7.readFileSync(fullPath, "utf8") : null;
  const stripped = existing ? removeBlock(existing, write.markers) : "";
  if (targetPath.endsWith(".env")) {
    writeConfig(targetPath, applyBlockWrite(stripped, write.content, write.markers));
    report({ kind: "ok", text: `wrote ${targetPath} (BANSOS_API_KEY, any value: the router checks none)` });
    return 0;
  }
  const merge = dshMergeProviders(stripped, ctx);
  if (merge.status === "merged") {
    writeConfig(targetPath, dshEnsureDefaultModel(merge.content, ctx));
    report({ kind: "ok", text: `wrote ${targetPath} (bansos provider inside the existing llm-pi-ai entry)` });
    return 0;
  }
  if (merge.status === "present") {
    report({ kind: "skip", text: `${targetPath}: llm-pi-ai already serves a bansos provider` });
    return 0;
  }
  if (merge.status === "manual") {
    report({ kind: "error", text: `${targetPath}: llm-pi-ai providers are not a block mapping, add the bansos provider by hand` });
    report({ kind: "error", text: `bansos setup dsh --dry-run prints the block to paste` });
    return 1;
  }
  writeConfig(targetPath, dshEnsureDefaultModel(applyBlockWrite(stripped, write.content, write.markers), ctx));
  report({ kind: "ok", text: `wrote ${targetPath}` });
  return 0;
}
function dshEnsureDefaultModel(content, ctx) {
  if (/^\s*-\s*id:\s*['"]?agent-default-model['"]?\s*$/m.test(content)) return content;
  const entry = ["- id: agent-default-model", "  config:", "    provider: bansos", `    model: ${ctx.defaultModel}`];
  const lines = content.split("\n");
  const end = lines.findIndex((l) => l.trim() === `# ${END_MARKER}`);
  if (end === -1) return `${content.replace(/\n*$/, "\n")}${entry.join("\n")}
`;
  lines.splice(end, 0, ...entry);
  return lines.join("\n");
}
var CONTINUE_HEADER = "name: bansos-router\nversion: 0.0.1\nschema: v1\n";
function applyAdapter(adapter, ctx, report = printSetupLine) {
  if (adapter.id === "dsh") return applyDeepseek(adapter, ctx, report);
  if (adapter.id === "continue") return applyContinue(adapter, ctx, report);
  const keptDefault = adapter.id === "jcode" ? readProviderDefault(expandHome(adapter.configPaths[0])) : void 0;
  let failed = 0;
  for (const write of adapter.render(ctx)) {
    const targetPath = resolveTargetFile(adapter, write.path);
    const fullPath = expandHome(targetPath);
    const existing = fs7.existsSync(fullPath) ? fs7.readFileSync(fullPath, "utf8") : null;
    let content;
    if (write.mode === "merge") {
      try {
        content = applyMergeWrite(existing, write.content, write.replace);
      } catch {
        report({ kind: "error", text: `${targetPath}: existing file is not valid JSON, skipping` });
        failed++;
        continue;
      }
    } else if (write.mode === "toml-block") {
      content = applyTomlBlockWrite(existing ?? "", write.content, write.markers, write.tomlTable, write.fillOnly ?? false);
    } else if (write.mode === "yaml-block") {
      try {
        content = applyYamlBlockWrite(existing ?? "", write.content, write.markers, write.yamlParent);
      } catch (err) {
        report({ kind: "error", text: `${targetPath}: ${err.message}` });
        failed++;
        continue;
      }
    } else {
      content = applyBlockWrite(existing ?? "", write.content, write.markers);
    }
    writeConfig(targetPath, content);
    report({ kind: "ok", text: `wrote ${targetPath}` });
  }
  if (keptDefault && keptDefault !== "bansos") {
    report({
      kind: "skip",
      text: `${adapter.configPaths[0]}: kept default_provider = "${keptDefault}"; pick bansos with /model`
    });
  }
  if (adapter.id === "9router") {
    const sqlitePath = expandHome("~/.9router/db/data.sqlite");
    if (fs7.existsSync(sqlitePath)) {
      if (update9RouterSqlite(sqlitePath, ctx)) report({ kind: "ok", text: "updated ~/.9router/db/data.sqlite" });
      else report({ kind: "error", text: "~/.9router/db/data.sqlite: needs node:sqlite (Node >= 22.5)" });
    }
  }
  return failed;
}
function applyContinue(adapter, ctx, report) {
  let failures = 0;
  for (const write of adapter.render(ctx)) {
    const targetPath = write.path;
    const fullPath = expandHome(targetPath);
    const existing = fs7.existsSync(fullPath) ? fs7.readFileSync(fullPath, "utf8") : "";
    if (existing.trim() === "" && !fs7.existsSync(fullPath)) report({ kind: "ok", text: `${targetPath}: created with a schema header` });
    const seeded = existing.trim() === "" ? CONTINUE_HEADER : existing;
    try {
      writeConfig(targetPath, applyYamlBlockWrite(seeded, write.content, write.markers, write.yamlParent));
      report({ kind: "ok", text: `wrote ${targetPath}` });
    } catch (err) {
      report({ kind: "error", text: `${targetPath}: ${err.message}` });
      failures++;
    }
  }
  return failures;
}
function undoAdapter(adapter, ctx, report = printSetupLine) {
  const candidatePaths = Array.from(/* @__PURE__ */ new Set([...adapter.configPaths, ...adapter.undo(ctx)]));
  for (const writePath of candidatePaths) {
    const full = expandHome(writePath);
    if (!fs7.existsSync(full)) {
      continue;
    }
    if (writePath.endsWith(".sqlite")) {
      continue;
    }
    const existing = fs7.readFileSync(full, "utf8");
    if (adapter.undoKeys) {
      let obj;
      try {
        obj = parseJsonc(existing);
      } catch {
        report({ kind: "skip", text: `${writePath} not valid JSON, skipping` });
        continue;
      }
      removeKeys(obj, adapter.undoKeys);
      if (Object.keys(obj).length === 0) {
        fs7.rmSync(full);
        report({ kind: "removed", text: `removed ${writePath}` });
      } else {
        writeConfig(writePath, `${JSON.stringify(obj, null, 2)}
`);
        report({ kind: "removed", text: `${writePath}: bansos keys removed` });
      }
    } else {
      const first = adapter.render(ctx)[0];
      const markers = first?.markers;
      if (markers) {
        const marked = first.mode === "toml-block" && writePath.endsWith(".toml") ? removeTomlBlock(existing, markers) : removeBlock(existing, markers);
        const out = marked === existing && adapter.undoContent ? adapter.undoContent(existing) : marked;
        if (out === existing) {
          report({ kind: "skip", text: `${writePath}: no bansos block found` });
        } else {
          writeConfig(writePath, out);
          report({ kind: "removed", text: `${writePath}: bansos block removed` });
        }
      }
    }
  }
  if (adapter.id === "9router") {
    const sqlitePath = expandHome("~/.9router/db/data.sqlite");
    if (fs7.existsSync(sqlitePath)) {
      if (undo9RouterSqlite(sqlitePath)) report({ kind: "removed", text: "~/.9router/db/data.sqlite: bansos keys removed" });
      else report({ kind: "error", text: "~/.9router/db/data.sqlite: needs node:sqlite (Node >= 22.5)" });
    }
  }
}
async function runSetup(argv) {
  const args = parseArgs2(argv);
  if (args.harnesses.length === 0) {
    console.error("bansos setup: specify at least one harness (see --help)");
    return 1;
  }
  const baseUrl = `http://${effectiveBind()}:${effectivePort()}/v1`;
  const { models, fromDaemon } = await getSetupModels(baseUrl);
  const pinned = args.model;
  if (pinned && fromDaemon && !models.some((m) => m.id === pinned || m.id.endsWith(`/${pinned}`))) {
    console.warn(`bansos setup: "${pinned}" is not served by the daemon right now (not alive, or blocked by strict mode); writing it anyway`);
  }
  const ctx = buildSetupContext(baseUrl, models, { model: pinned, models: args.models, upstreams: args.upstreams });
  if ("error" in ctx) {
    console.error(`bansos setup: ${ctx.error}`);
    return 1;
  }
  let failed = 0;
  for (const id of args.harnesses) {
    const adapter = findAdapter(id);
    if (!adapter) {
      console.error(`bansos setup: unknown harness "${id}" (see --help)`);
      failed++;
      continue;
    }
    console.log(`
${adapter.name} (${adapter.wire}):`);
    if (args.undo) {
      undoAdapter(adapter, ctx);
    } else if (args.dryRun) {
      for (const write of adapter.render(ctx)) {
        const targetPath = resolveTargetFile(adapter, write.path);
        console.log(`  -> ${targetPath}`);
        console.log(write.content.replace(/^/gm, "    "));
      }
    } else {
      failed += applyAdapter(adapter, ctx);
    }
  }
  return failed > 0 ? 1 : 0;
}

// src/daemon/index.ts
init_state();
import fs13 from "node:fs";
import os7 from "node:os";
import path12 from "node:path";
import stream from "node:stream";
import { spawn, spawnSync as spawnSync4 } from "node:child_process";

// src/security/secret-guard.ts
var KNOWN_SECRET_PATTERNS = [
  {
    type: "anthropic_api_key",
    pattern: /\bsk-ant-(?:api\d{2}-)?[A-Za-z0-9_-]{16,}\b/
  },
  {
    type: "openai_api_key",
    pattern: /\bsk-(?!ant-)(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b/
  },
  {
    type: "github_pat",
    pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_\w{20,})\b/
  },
  {
    type: "aws_access_key",
    pattern: /\b(?:AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[A-Z0-9]{16}\b/
  },
  {
    type: "ssh_private_key",
    pattern: /-----BEGIN (?:OPENSSH PRIVATE KEY|SSH2 ENCRYPTED PRIVATE KEY)-----/
  },
  {
    type: "private_key",
    pattern: /-----BEGIN (?:RSA |EC |DSA |PKCS8 |ENCRYPTED )?PRIVATE KEY-----/
  }
];
var SENSITIVE_KEYS = /* @__PURE__ */ new Set([
  "password",
  "passwd",
  "pwd",
  "token",
  "accesstoken",
  "authtoken",
  "refreshtoken",
  "apikey",
  "secret",
  "clientsecret",
  "signingsecret"
]);
var BARE_VALUE = /((?:(?!\\[nrt])[^\s,;'"}])+)/.source;
var INLINE_ASSIGNMENTS = [
  /\b([\w-]+)\s*[:=]\s*"([^"]+)"/gi,
  /\b([\w-]+)\s*[:=]\s*'([^']+)'/gi,
  new RegExp(`\\b([\\w-]+)\\s*[:=]\\s*${BARE_VALUE}`, "gi")
];
var PLACEHOLDER_VALUES = /* @__PURE__ */ new Set([
  "example",
  "sample",
  "test",
  "dummy",
  "placeholder",
  "redacted",
  "masked",
  "changeme",
  "password",
  "secret",
  "token",
  "api_key",
  "api-key",
  "none",
  "null",
  "undefined",
  "bansos"
]);
function isPlaceholderValue(value) {
  const lower = value.toLowerCase();
  if (PLACEHOLDER_VALUES.has(lower)) return true;
  if (lower === "your" || lower.startsWith("your-") || lower.startsWith("your_") || lower.startsWith("your ")) return true;
  if (/^[x*]+$/i.test(value)) return true;
  if (/^\[REDACTED:[a-z_]+\]$/.test(value)) return true;
  if (value.startsWith("<") && value.endsWith(">")) return true;
  if (value.startsWith("${") && value.endsWith("}")) return true;
  return /^process\.env\.\w+$/i.test(value);
}
function isLikelyCredentialValue(value) {
  const clean = value.trim().replace(/\\+$/, "").replace(/^["']|["']$/g, "");
  if (clean.length < 8 || isPlaceholderValue(clean)) return false;
  if (/\s/.test(clean) && clean.length < 16) return false;
  return true;
}
function inspectString(value, found) {
  for (const { type, pattern } of KNOWN_SECRET_PATTERNS) {
    if (pattern.test(value)) found.add(type);
  }
  for (const pattern of INLINE_ASSIGNMENTS) {
    pattern.lastIndex = 0;
    for (let match = pattern.exec(value); match; match = pattern.exec(value)) {
      const key = match[1] ?? "";
      const assigned = match[2] ?? "";
      if (SENSITIVE_KEYS.has(normalizeKey(key)) && isLikelyCredentialValue(assigned)) {
        found.add("credential_assignment");
      }
    }
  }
}
function normalizeKey(key) {
  return key.toLowerCase().replace(/[^a-z0-9]/g, "");
}
function inspectValue(value, found, seen, key) {
  if (typeof value === "string") {
    inspectString(value, found);
    if (key && SENSITIVE_KEYS.has(normalizeKey(key)) && isLikelyCredentialValue(value)) {
      found.add("credential_assignment");
    }
    return;
  }
  if (!value || typeof value !== "object") return;
  if (seen.has(value)) return;
  seen.add(value);
  if (Array.isArray(value)) {
    for (const item of value) inspectValue(item, found, seen);
    return;
  }
  for (const [childKey, childValue] of Object.entries(value)) {
    inspectValue(childValue, found, seen, childKey);
  }
}
function scanRequestBody(body) {
  let parsed = body;
  if (typeof body === "string") {
    try {
      parsed = JSON.parse(body);
    } catch {
      parsed = body;
    }
  }
  const found = /* @__PURE__ */ new Set();
  inspectValue(parsed, found, /* @__PURE__ */ new WeakSet());
  const secretTypes = [...found].sort((a, b) => a.localeCompare(b));
  return { blocked: secretTypes.length > 0, secretTypes };
}
var PRIVATE_KEY_BLOCK = /-----BEGIN ((?:[A-Z0-9]+ )*)PRIVATE KEY-----(?:[\s\S]*?-----END \1PRIVATE KEY-----|(?:(?:\r?\n|\\+[nr])+(?:[A-Za-z0-9-]+: [^\r\n\\]*|[A-Za-z0-9+/=]+(?=\r?\n|\\+[nr]|$)))*)/g;
var TOKEN_PATTERNS = KNOWN_SECRET_PATTERNS.filter(({ type }) => type !== "private_key" && type !== "ssh_private_key").map(({ type, pattern }) => ({ type, pattern: new RegExp(pattern.source, "g") }));
var marker = (type) => `[REDACTED:${type}]`;
function redactString(value, found, tally) {
  let out = value.replace(PRIVATE_KEY_BLOCK, (_m, kind) => {
    const type = /OPENSSH|SSH2/.test(kind) ? "ssh_private_key" : "private_key";
    found.add(type);
    tally.count++;
    return marker(type);
  });
  for (const { type, pattern } of TOKEN_PATTERNS) {
    out = out.replace(pattern, () => {
      found.add(type);
      tally.count++;
      return marker(type);
    });
  }
  for (const pattern of INLINE_ASSIGNMENTS) {
    out = out.replace(pattern, (match, key, assigned) => {
      const value2 = assigned.replace(/\\+$/, "");
      if (!SENSITIVE_KEYS.has(normalizeKey(key)) || !isLikelyCredentialValue(value2)) return match;
      found.add("credential_assignment");
      tally.count++;
      const at = match.lastIndexOf(assigned);
      return match.slice(0, at) + marker("credential_assignment") + match.slice(at + value2.length);
    });
  }
  return out;
}
function parseJsonContainer(value) {
  const trimmed = value.trim();
  if (!(trimmed.startsWith("{") || trimmed.startsWith("["))) return void 0;
  try {
    const parsed = JSON.parse(trimmed);
    return parsed && typeof parsed === "object" ? parsed : void 0;
  } catch {
    return void 0;
  }
}
function redactValue(value, found, tally, key) {
  if (typeof value === "string") {
    if (key && SENSITIVE_KEYS.has(normalizeKey(key)) && isLikelyCredentialValue(value)) {
      found.add("credential_assignment");
      tally.count++;
      return marker("credential_assignment");
    }
    const nested = parseJsonContainer(value);
    if (nested !== void 0) {
      const before = tally.count;
      const redacted = redactValue(nested, found, tally);
      return tally.count === before ? value : JSON.stringify(redacted);
    }
    return redactString(value, found, tally);
  }
  if (Array.isArray(value)) return value.map((item) => redactValue(item, found, tally));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, redactValue(v, found, tally, k)]));
  }
  return value;
}
function redactRequestBody(body) {
  let parsed;
  try {
    parsed = JSON.parse(body);
  } catch {
    return null;
  }
  const found = /* @__PURE__ */ new Set();
  const tally = { count: 0 };
  const redacted = JSON.stringify(redactValue(parsed, found, tally));
  if (scanRequestBody(redacted).blocked) return null;
  return { body: redacted, secretTypes: [...found].sort((a, b) => a.localeCompare(b)), count: tally.count };
}

// src/logger.ts
var LEVEL_ORDER = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40
};
var SAFE_FIELD_NAMES = /* @__PURE__ */ new Set([
  "model",
  "upstream",
  "status",
  "durationMs",
  "inputTokens",
  "outputTokens",
  "failoverBlocked",
  "dlpBlocked",
  "dlpRedacted",
  "redactions",
  "secretType",
  "secretTypes",
  "attempt",
  "attempts",
  "from",
  "to",
  "fromUpstream",
  "failoverFrom",
  "stream",
  "upstreamError"
]);
var SECRET_TYPES = /* @__PURE__ */ new Set([
  "openai_api_key",
  "anthropic_api_key",
  "github_pat",
  "aws_access_key",
  "private_key",
  "ssh_private_key",
  "credential_assignment"
]);
function validatedSecretTypes(value) {
  const values = Array.isArray(value) ? value : [value];
  return values.filter(
    (item) => typeof item === "string" && SECRET_TYPES.has(item)
  );
}
function safeFields(fields, initialSecretTypes = []) {
  const safe = {};
  const detectedTypes = new Set(initialSecretTypes);
  for (const [key, value] of Object.entries(fields ?? {})) {
    if (!SAFE_FIELD_NAMES.has(key)) continue;
    if (key === "secretType" || key === "secretTypes") {
      for (const type of validatedSecretTypes(value)) detectedTypes.add(type);
      continue;
    }
    const scan = scanRequestBody(value);
    if (scan.blocked) {
      for (const type of scan.secretTypes) detectedTypes.add(type);
      continue;
    }
    safe[key] = value;
  }
  if (detectedTypes.size > 0) {
    safe.secretTypes = [...detectedTypes].sort((a, b) => a.localeCompare(b));
  }
  return Object.keys(safe).length > 0 ? safe : void 0;
}
function createLogger(opts = {}) {
  const level = opts.level ?? "info";
  const json = opts.json ?? process.env.BANSOS_LOG === "json";
  const prefix = opts.prefix ?? "";
  const out = opts.out ?? process.stdout;
  const write = (lvl, msg, fields) => {
    if (LEVEL_ORDER[lvl] < LEVEL_ORDER[level]) return;
    const messageScan = scanRequestBody(msg);
    const safeMessage = messageScan.blocked ? "sensitive log message suppressed" : msg;
    const line = prefix ? `[${prefix}] ${safeMessage}` : safeMessage;
    const filteredFields = safeFields(fields, messageScan.secretTypes);
    if (json) {
      out.write(
        `${JSON.stringify({ timestamp: (/* @__PURE__ */ new Date()).toISOString(), level: lvl, msg: safeMessage, ...filteredFields })}
`
      );
    } else {
      const tag = lvl === "error" ? "\u2717" : lvl === "warn" ? "\u26A0" : lvl === "debug" ? "\xB7" : "\u2713";
      out.write(`${tag} ${line}${renderFields(filteredFields)}
`);
    }
  };
  return {
    debug: (m, f) => write("debug", m, f),
    info: (m, f) => write("info", m, f),
    warn: (m, f) => write("warn", m, f),
    error: (m, f) => write("error", m, f),
    child: (p) => createLogger({ level, json, prefix: p, out })
  };
}
function renderFields(fields) {
  if (!fields || Object.keys(fields).length === 0) return "";
  return ` ${Object.entries(fields).map(([k, v]) => `${k}=${fmtValue(v)}`).join(" ")}`;
}
function fmtValue(v) {
  if (v === null) return "null";
  if (Array.isArray(v)) return v.map(fmtValue).join(",");
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}

// src/daemon/index.ts
init_policy();

// src/daemon/catalog.ts
init_policy();
var DEFAULT_COOLDOWN_MS = 6e4;
var MAX_COOLDOWN_MS = 15 * 6e4;
var REFUSED_COOLDOWN_MS = 30 * 6e4;
var RuntimeCatalog = class {
  constructor(upstreams, log, security = DEFAULT_SECURITY_CONFIG) {
    this.log = log;
    this.security = security;
    this.upstreams = upstreams;
    for (const u of upstreams) {
      this.bySource.set(u.id, u);
    }
  }
  log;
  security;
  byId = /* @__PURE__ */ new Map();
  bySource = /* @__PURE__ */ new Map();
  upstreams;
  refreshInFlight = null;
  coolUntil = /* @__PURE__ */ new Map();
  // upstream that serves a model source (zen/kilo/llm7/local)
  upstreamBySource(source) {
    return this.bySource.get(source);
  }
  // seed the pinned registry so the daemon works before any network call
  seed(models) {
    for (const m of models) this.byId.set(m.id, m);
  }
  get models() {
    return [...this.byId.values()];
  }
  // models whose upstream the security policy lets a request reach
  get servableModels() {
    return this.models.filter((m) => isUpstreamAllowed(this.security, this.bySource.get(m.source)?.id ?? m.source));
  }
  get upstreamIds() {
    return this.upstreams.map((u) => u.id);
  }
  // park a 429'd model so the next request skips it; Retry-After sets the time, else a minute
  markRateLimited(id, retryAfterMs) {
    const ms = Math.min(Math.max(retryAfterMs ?? DEFAULT_COOLDOWN_MS, 1e3), MAX_COOLDOWN_MS);
    this.coolUntil.set(id, Date.now() + ms);
  }
  // upstream refused this model (401/403), usually about egress location, not the request
  markRefused(id) {
    this.coolUntil.set(id, Date.now() + REFUSED_COOLDOWN_MS);
  }
  isCoolingDown(id, now = Date.now()) {
    const until = this.coolUntil.get(id);
    if (until === void 0) return false;
    if (until <= now) {
      this.coolUntil.delete(id);
      return false;
    }
    return true;
  }
  resolve(id) {
    const direct = this.byId.get(id);
    if (direct) return direct;
    for (const [k, m] of this.byId) {
      if (k.endsWith(`/${id}`)) return m;
    }
    return void 0;
  }
  // unreachable upstream keeps last-known models; concurrent callers share the in-flight pass
  async refresh() {
    if (this.refreshInFlight) return this.refreshInFlight;
    this.refreshInFlight = this.runRefresh();
    try {
      return await this.refreshInFlight;
    } finally {
      this.refreshInFlight = null;
    }
  }
  async runRefresh() {
    const report = { checked: 0, alive: 0, dead: 0, degraded: [] };
    const allowed = this.upstreams.filter((upstream) => {
      if (isUpstreamAllowed(this.security, upstream.id)) return true;
      report.degraded.push(upstream.id);
      this.log.warn(`upstream ${upstream.id}: blocked by strict allowlist`);
      return false;
    });
    const fetched = await Promise.all(
      allowed.map(async (upstream) => ({
        upstream,
        live: await upstream.fetchCatalog().catch(() => null)
      }))
    );
    for (const { upstream, live } of fetched) {
      if (live === null) {
        report.degraded.push(upstream.id);
        this.log.warn(`upstream ${upstream.id}: no live catalog - keeping last-known models`);
        continue;
      }
      const source = upstream.id;
      this.replaceBySource(source, live);
      report.checked += live.length;
    }
    report.alive = this.byId.size;
    this.log.info(`catalog refresh: ${report.alive} model(s) alive`);
    return report;
  }
  replaceBySource(source, models) {
    for (const [id, m] of this.byId) {
      if (m.source === source) {
        this.byId.delete(id);
        this.coolUntil.delete(id);
      }
    }
    for (const m of models) this.byId.set(m.id, m);
  }
};

// src/daemon/rate-limit.ts
var RateLimiter = class {
  constructor(opts) {
    this.opts = opts;
  }
  opts;
  hits = /* @__PURE__ */ new Map();
  // returns true when the request is allowed.
  check(ip, now = Date.now()) {
    if (this.opts.limit <= 0) return true;
    const windowStart2 = now - this.opts.windowMs;
    const recent = (this.hits.get(ip) ?? []).filter((t) => t > windowStart2);
    if (recent.length >= this.opts.limit) {
      this.hits.set(ip, recent);
      return false;
    }
    recent.push(now);
    this.hits.set(ip, recent);
    return true;
  }
  reset() {
    this.hits.clear();
  }
};

// src/daemon/activity.ts
init_state();
import fs8 from "node:fs";
import path8 from "node:path";
var ACTIVITY_DIR = path8.join(BANSOS_DIR, "activity");
var LEGACY_ACTIVITY_FILE = path8.join(BANSOS_DIR, "activity.json");
var RECENT_CAP = 2e3;
var READ_CHUNK = 64 * 1024;
var ROLLUP_SAVE_MS = 5e3;
function pad(n) {
  return String(n).padStart(2, "0");
}
function monthKeyOf(ts) {
  const d = new Date(ts);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}`;
}
function dayKeyOf(ts) {
  const d = new Date(ts);
  return `${monthKeyOf(ts)}-${pad(d.getDate())}`;
}
function dayStartOf(ts) {
  const d = new Date(ts);
  d.setHours(0, 0, 0, 0);
  return d.getTime();
}
function eventsFileOf(month) {
  return path8.join(ACTIVITY_DIR, `events-${month}.jsonl`);
}
function rollupFileOf(month) {
  return path8.join(ACTIVITY_DIR, `usage-${month}.json`);
}
function emptyBucket() {
  return {
    requests: 0,
    ok: 0,
    error: 0,
    failover: 0,
    inputTokens: 0,
    outputTokens: 0,
    cachedTokens: 0,
    durationMs: 0,
    perModel: {},
    perUpstream: {}
  };
}
function listFiles(prefix, suffix) {
  try {
    return fs8.readdirSync(ACTIVITY_DIR).filter((name) => name.startsWith(prefix) && name.endsWith(suffix)).sort().map((name) => path8.join(ACTIVITY_DIR, name));
  } catch {
    return [];
  }
}
function parseEventLine(line) {
  if (!line) return null;
  try {
    const e = JSON.parse(line);
    if (!e || typeof e !== "object" || typeof e.timestamp !== "number") return null;
    if (typeof e.model !== "string" || typeof e.upstream !== "string") return null;
    if (e.status !== "ok" && e.status !== "error") return null;
    return e;
  } catch {
    return null;
  }
}
function* reverseLines(file, chunkSize = READ_CHUNK) {
  let fd;
  try {
    fd = fs8.openSync(file, "r");
  } catch {
    return;
  }
  try {
    const size = fs8.fstatSync(fd).size;
    let pos = size;
    let carry = "";
    const buf = Buffer.allocUnsafe(chunkSize);
    while (pos > 0) {
      const read = Math.min(chunkSize, pos);
      pos -= read;
      const bytes = fs8.readSync(fd, buf, 0, read, pos);
      const text = carry + buf.toString("utf8", 0, bytes);
      const lines = text.split("\n");
      carry = lines.shift() ?? "";
      for (let i = lines.length - 1; i >= 0; i--) {
        if (lines[i]) yield lines[i];
      }
    }
    if (carry) yield carry;
  } finally {
    fs8.closeSync(fd);
  }
}
function readMonthEvents(file) {
  let text;
  try {
    text = fs8.readFileSync(file, "utf8");
  } catch {
    return [];
  }
  const out = [];
  for (const line of text.split("\n")) {
    const event = parseEventLine(line);
    if (event) out.push(event);
  }
  return out;
}
function windowStart(window, now = Date.now()) {
  if (window === "all") return 0;
  if (window === "today") return dayStartOf(now);
  const days = window === "7d" ? 7 : window === "30d" ? 30 : 60;
  return dayStartOf(now - (days - 1) * 24 * 60 * 60 * 1e3);
}
var ActivityStore = class {
  recent = [];
  days = /* @__PURE__ */ new Map();
  dirtyMonths = /* @__PURE__ */ new Set();
  inFlight = /* @__PURE__ */ new Map();
  nextId = 1;
  nextInFlightId = 1;
  rollupTimer = null;
  appendChain = Promise.resolve();
  constructor() {
    ensureBansosDir();
    this.loadRollups();
    this.migrateLegacyFile();
    this.loadRecent();
  }
  loadRollups() {
    for (const file of listFiles("usage-", ".json")) {
      try {
        const parsed = JSON.parse(fs8.readFileSync(file, "utf8"));
        if (!parsed || typeof parsed !== "object" || typeof parsed.days !== "object") continue;
        for (const [day, bucket] of Object.entries(parsed.days)) {
          if (bucket && typeof bucket === "object") this.days.set(day, this.normalizeBucket(bucket));
        }
      } catch {
      }
    }
  }
  normalizeBucket(raw) {
    const bucket = emptyBucket();
    for (const key of ["requests", "ok", "error", "failover", "inputTokens", "outputTokens", "cachedTokens", "durationMs"]) {
      const value = raw[key];
      if (typeof value === "number" && Number.isFinite(value)) bucket[key] = value;
    }
    if (raw.perModel && typeof raw.perModel === "object") {
      for (const [model, stats] of Object.entries(raw.perModel)) {
        if (!stats || typeof stats !== "object") continue;
        bucket.perModel[model] = {
          requests: Number(stats.requests) || 0,
          ok: Number(stats.ok) || 0,
          inputTokens: Number(stats.inputTokens) || 0,
          outputTokens: Number(stats.outputTokens) || 0,
          cachedTokens: Number(stats.cachedTokens) || 0
        };
      }
    }
    if (raw.perUpstream && typeof raw.perUpstream === "object") {
      for (const [upstream, stats] of Object.entries(raw.perUpstream)) {
        if (!stats || typeof stats !== "object") continue;
        bucket.perUpstream[upstream] = { requests: Number(stats.requests) || 0, ok: Number(stats.ok) || 0 };
      }
    }
    return bucket;
  }
  migrateLegacyFile() {
    if (!fs8.existsSync(LEGACY_ACTIVITY_FILE)) return;
    try {
      const raw = JSON.parse(fs8.readFileSync(LEGACY_ACTIVITY_FILE, "utf8"));
      if (Array.isArray(raw?.events)) this.importEvents(raw.events, false);
      fs8.renameSync(LEGACY_ACTIVITY_FILE, `${LEGACY_ACTIVITY_FILE}.migrated`);
    } catch {
    }
  }
  loadRecent() {
    const tail = this.readFromDisk(RECENT_CAP, 0, Number.POSITIVE_INFINITY).reverse();
    this.recent = tail;
    if (tail.length > 0) this.nextId = Math.max(this.nextId, tail[tail.length - 1].id + 1);
  }
  append(event) {
    const line = `${JSON.stringify(event)}
`;
    const file = eventsFileOf(monthKeyOf(event.timestamp));
    this.appendChain = this.appendChain.then(() => fs8.promises.mkdir(ACTIVITY_DIR, { recursive: true })).then(() => fs8.promises.appendFile(file, line, { mode: 384 })).catch(() => {
    });
  }
  addToRollup(event) {
    const day = dayKeyOf(event.timestamp);
    const bucket = this.days.get(day) ?? emptyBucket();
    bucket.requests++;
    if (event.status === "ok") bucket.ok++;
    else bucket.error++;
    if (event.failoverFrom) bucket.failover++;
    const input = event.inputTokens || 0;
    const output = event.outputTokens || 0;
    const cached = event.cachedTokens || 0;
    bucket.inputTokens += input;
    bucket.outputTokens += output;
    bucket.cachedTokens += cached;
    bucket.durationMs += event.durationMs || 0;
    const model = bucket.perModel[event.model] ?? {
      requests: 0,
      ok: 0,
      inputTokens: 0,
      outputTokens: 0,
      cachedTokens: 0
    };
    model.requests++;
    if (event.status === "ok") model.ok++;
    model.inputTokens += input;
    model.outputTokens += output;
    model.cachedTokens += cached;
    bucket.perModel[event.model] = model;
    const upstream = bucket.perUpstream[event.upstream] ?? { requests: 0, ok: 0 };
    upstream.requests++;
    if (event.status === "ok") upstream.ok++;
    bucket.perUpstream[event.upstream] = upstream;
    this.days.set(day, bucket);
    this.dirtyMonths.add(monthKeyOf(event.timestamp));
  }
  scheduleRollupSave() {
    if (this.rollupTimer) return;
    this.rollupTimer = setTimeout(() => {
      this.rollupTimer = null;
      this.saveRollups();
    }, ROLLUP_SAVE_MS);
    this.rollupTimer.unref?.();
  }
  saveRollups() {
    if (this.dirtyMonths.size === 0) return;
    const months = [...this.dirtyMonths];
    this.dirtyMonths.clear();
    for (const month of months) {
      const days = {};
      for (const [day, bucket] of this.days) {
        if (day.startsWith(month)) days[day] = bucket;
      }
      try {
        writeJsonAtomic(rollupFileOf(month), { version: 1, days });
      } catch {
        this.dirtyMonths.add(month);
      }
    }
  }
  /** write pending rollups now; called on shutdown so counters survive a signal */
  flush() {
    if (this.rollupTimer) {
      clearTimeout(this.rollupTimer);
      this.rollupTimer = null;
    }
    this.saveRollups();
  }
  /** resolves once every queued event append has hit the disk (tests and shutdown paths) */
  whenIdle() {
    return this.appendChain;
  }
  record(input) {
    const now = Date.now();
    const event = { ...input, id: this.nextId++, timestamp: now };
    this.recent.push(event);
    if (this.recent.length > RECENT_CAP) this.recent.splice(0, this.recent.length - RECENT_CAP);
    this.addToRollup(event);
    this.append(event);
    this.scheduleRollupSave();
  }
  readFromDisk(limit, start, belowId) {
    const out = [];
    if (limit <= 0) return out;
    const months = listFiles("events-", ".jsonl").reverse();
    for (const file of months) {
      for (const line of reverseLines(file)) {
        const event = parseEventLine(line);
        if (!event) continue;
        if (event.id >= belowId) continue;
        if (event.timestamp < start) return out;
        out.push(event);
        if (out.length >= limit) return out;
      }
    }
    return out;
  }
  getEvents(limit = 100, window = "all") {
    const start = windowStart(window);
    const capped = Math.max(0, limit);
    if (capped === 0) return [];
    const local = this.recent.filter((e) => e.timestamp >= start);
    if (local.length >= capped || this.recent.length < RECENT_CAP) {
      return local.slice(-capped).reverse();
    }
    const oldest = this.recent[0];
    const rest = this.readFromDisk(capped - local.length, start, oldest.id);
    return [...rest, ...local.slice(-capped).reverse()];
  }
  getAllEvents() {
    const months = listFiles("events-", ".jsonl");
    const all = [];
    for (const file of months) all.push(...readMonthEvents(file));
    all.sort((a, b) => a.id - b.id);
    return all;
  }
  startRequest(input) {
    const id = this.nextInFlightId++;
    this.inFlight.set(id, { id, ...input });
    return id;
  }
  endRequest(id) {
    this.inFlight.delete(id);
  }
  getInFlight() {
    const now = Date.now();
    for (const [id, req] of this.inFlight.entries()) {
      if (now - req.timestamp > 12e4) this.inFlight.delete(id);
    }
    return Array.from(this.inFlight.values());
  }
  clear() {
    if (this.rollupTimer) {
      clearTimeout(this.rollupTimer);
      this.rollupTimer = null;
    }
    this.recent = [];
    this.days.clear();
    this.dirtyMonths.clear();
    this.nextId = 1;
    try {
      fs8.rmSync(ACTIVITY_DIR, { recursive: true, force: true });
    } catch {
    }
    ensureBansosDir();
  }
  importEvents(incoming, replace = false) {
    if (!Array.isArray(incoming)) return 0;
    const valid = incoming.filter(
      (e) => e && typeof e === "object" && typeof e.timestamp === "number" && typeof e.model === "string" && typeof e.upstream === "string" && (e.status === "ok" || e.status === "error")
    );
    if (replace) this.clear();
    const seen = new Set(this.getAllEvents().map((e) => e.id));
    const byMonth = /* @__PURE__ */ new Map();
    const accepted = [];
    for (const event of valid) {
      const id = typeof event.id === "number" ? event.id : this.nextId++;
      if (seen.has(id)) continue;
      seen.add(id);
      const materialized = {
        ...event,
        id,
        inputTokens: Number(event.inputTokens) || 0,
        outputTokens: Number(event.outputTokens) || 0,
        durationMs: Number(event.durationMs) || 0,
        cachedTokens: Number(event.cachedTokens) || void 0
      };
      accepted.push(materialized);
      const month = monthKeyOf(materialized.timestamp);
      byMonth.set(month, [...byMonth.get(month) ?? [], `${JSON.stringify(materialized)}
`]);
      this.addToRollup(materialized);
      if (materialized.id >= this.nextId) this.nextId = materialized.id + 1;
    }
    for (const [month, lines] of byMonth) {
      try {
        fs8.mkdirSync(ACTIVITY_DIR, { recursive: true });
        fs8.appendFileSync(eventsFileOf(month), lines.join(""), { mode: 384 });
      } catch {
      }
    }
    if (accepted.length > 0) {
      this.recent = [...this.recent, ...accepted].sort((a, b) => a.id - b.id);
      if (this.recent.length > RECENT_CAP) this.recent = this.recent.slice(-RECENT_CAP);
      this.flush();
    }
    return accepted.length;
  }
  getUsage(window = "all") {
    const start = windowStart(window);
    const stats = {
      totalRequests: 0,
      okRequests: 0,
      errorRequests: 0,
      totalInputTokens: 0,
      totalOutputTokens: 0,
      totalCachedTokens: 0,
      failoverCount: 0,
      avgDurationMs: 0,
      perModel: {},
      perUpstream: {}
    };
    let durationMs = 0;
    for (const [day, bucket] of this.days) {
      const dayStart = (/* @__PURE__ */ new Date(`${day}T00:00:00`)).getTime();
      if (Number.isFinite(dayStart) ? dayStart < start : start > 0) continue;
      stats.totalRequests += bucket.requests;
      stats.okRequests += bucket.ok;
      stats.errorRequests += bucket.error;
      stats.totalInputTokens += bucket.inputTokens;
      stats.totalOutputTokens += bucket.outputTokens;
      stats.totalCachedTokens += bucket.cachedTokens;
      stats.failoverCount += bucket.failover;
      durationMs += bucket.durationMs;
      for (const [model, m] of Object.entries(bucket.perModel)) {
        const target = stats.perModel[model] ?? (stats.perModel[model] = {
          requests: 0,
          ok: 0,
          inputTokens: 0,
          outputTokens: 0,
          cachedTokens: 0
        });
        target.requests += m.requests;
        target.ok += m.ok;
        target.inputTokens += m.inputTokens;
        target.outputTokens += m.outputTokens;
        target.cachedTokens += m.cachedTokens;
      }
      for (const [upstream, u] of Object.entries(bucket.perUpstream)) {
        const target = stats.perUpstream[upstream] ?? (stats.perUpstream[upstream] = { requests: 0, ok: 0 });
        target.requests += u.requests;
        target.ok += u.ok;
      }
    }
    stats.avgDurationMs = stats.totalRequests ? Math.round(durationMs / stats.totalRequests) : 0;
    return stats;
  }
};

// src/daemon/server.ts
init_policy();
import http from "node:http";
import fs12 from "node:fs";
import os6 from "node:os";
import path11 from "node:path";
import { fileURLToPath } from "node:url";
import { Readable as Readable2, Transform as Transform2 } from "node:stream";

// src/protocols/openai-chat.ts
var UNSUPPORTED_TOP_LEVEL_FIELDS = ["preserve_thinking", "chat_template_kwargs", "enable_thinking"];
function sanitizeChatBody(body, supportsDeveloperRole) {
  let out = body;
  let modified = false;
  for (const field of UNSUPPORTED_TOP_LEVEL_FIELDS) {
    if (field in out) {
      if (out === body) out = { ...body };
      delete out[field];
      modified = true;
    }
  }
  if (!Array.isArray(out.messages)) {
    return modified ? out : body;
  }
  let messagesModified = false;
  const messages = out.messages.map((m) => {
    if (!m || typeof m !== "object") return m;
    const msg = m;
    const next = { ...msg };
    if ("thought" in next) {
      delete next.thought;
      messagesModified = true;
    }
    if (!supportsDeveloperRole && msg.role === "developer") {
      next.role = "system";
      messagesModified = true;
    }
    return next;
  });
  if (messagesModified) {
    out = out === body ? { ...body, messages } : { ...out, messages };
    modified = true;
  }
  return modified ? out : body;
}
function parseChatTurn(body) {
  if (typeof body !== "object" || body === null) {
    return { ok: false, error: "request body must be a JSON object" };
  }
  const b = body;
  const model = typeof b.model === "string" ? b.model : "";
  if (!model) return { ok: false, error: "missing required field: model" };
  if (!Array.isArray(b.messages)) {
    return { ok: false, error: "missing required field: messages" };
  }
  return {
    ok: true,
    value: {
      model,
      stream: b.stream === true,
      maxTokens: typeof b.max_tokens === "number" ? b.max_tokens : void 0,
      messages: []
      // raw body forwarded as-is by the M0 forwarder
    }
  };
}

// src/protocols/responses.ts
function parseResponsesTurn(body) {
  if (typeof body !== "object" || body === null) {
    return { ok: false, error: "request body must be a JSON object" };
  }
  const b = body;
  const model = typeof b.model === "string" ? b.model : "";
  if (!model) return { ok: false, error: "missing required field: model" };
  if (!("input" in b)) return { ok: false, error: "missing required field: input" };
  const messages = responsesInputToMessages(b.input, b.previous_response_id);
  if (messages instanceof Error) {
    return { ok: false, error: messages.message };
  }
  let system;
  if (typeof b.instructions === "string" && b.instructions.trim()) {
    system = b.instructions;
  } else if (Array.isArray(b.instructions)) {
    const t = b.instructions.map((x) => x && typeof x === "object" && "text" in x ? String(x.text) : "").join("");
    if (t.trim()) system = t;
  }
  return {
    ok: true,
    value: {
      model,
      system,
      messages,
      tools: responsesToolsToInternal(b.tools),
      maxTokens: typeof b.max_output_tokens === "number" ? b.max_output_tokens : void 0,
      reasoningEffort: responsesEffort(b.reasoning),
      stream: b.stream === true
    }
  };
}
function responsesEffort(reasoning) {
  if (reasoning && typeof reasoning === "object" && "effort" in reasoning) {
    const e = reasoning.effort;
    if (e === "low" || e === "medium" || e === "high") return e;
  }
  return void 0;
}
function responsesToolsToInternal(tools) {
  if (!Array.isArray(tools)) return void 0;
  const out = tools.filter((t) => t && typeof t === "object" && t.type === "function").map((t) => ({
    name: String(t.name ?? ""),
    description: typeof t.description === "string" ? t.description : void 0,
    parameters: t.parameters ?? {}
  }));
  return out.length ? out : void 0;
}
var SKIPPED_INPUT_ITEMS = /* @__PURE__ */ new Set(["item_reference", "web_search_call", "file_search_call", "computer_call", "image_generation_call"]);
function responsesInputToMessages(input, _previousId) {
  const items = typeof input === "string" ? [{ role: "user", content: input }] : Array.isArray(input) ? input : [input];
  const messages = [];
  let thinking = "";
  const claimThinking = (m) => {
    if (!thinking) return;
    m.thinking = m.thinking ? `${m.thinking}
${thinking}` : thinking;
    thinking = "";
  };
  for (const item of items) {
    if (!item || typeof item !== "object") {
      return new Error("unsupported responses input item");
    }
    const it = item;
    if (typeof it.type === "string" && SKIPPED_INPUT_ITEMS.has(it.type)) continue;
    if (it.type === "reasoning") {
      const text = reasoningItemText(it);
      if (text) thinking = thinking ? `${thinking}
${text}` : text;
      continue;
    }
    if (it.type === "function_call_output" || it.type === "custom_tool_call_output") {
      messages.push({
        role: "tool",
        toolCallId: typeof it.call_id === "string" ? it.call_id : "unknown",
        content: typeof it.output === "string" ? it.output : JSON.stringify(it.output ?? "")
      });
      continue;
    }
    if (it.type === "function_call" || it.type === "custom_tool_call") {
      const call = {
        id: typeof it.call_id === "string" ? it.call_id : `call_${messages.length}`,
        name: typeof it.name === "string" ? it.name : "tool",
        arguments: typeof it.arguments === "string" ? it.arguments : typeof it.input === "string" ? it.input : JSON.stringify(it.arguments ?? {})
      };
      const prev = messages[messages.length - 1];
      if (prev?.role === "assistant") prev.toolCalls = [...prev.toolCalls ?? [], call];
      else messages.push({ role: "assistant", toolCalls: [call], content: "" });
      claimThinking(messages[messages.length - 1]);
      continue;
    }
    const role = it.role ?? (it.type === "message" ? it.role : void 0);
    if (typeof role !== "string") {
      return new Error("responses input item missing role");
    }
    const content = responsesContent(it.content);
    if (content instanceof Error) return content;
    if (role === "tool") {
      messages.push({
        role: "tool",
        toolCallId: typeof it.tool_call_id === "string" ? it.tool_call_id : "unknown",
        content: typeof content === "string" ? content : blocksToText(content)
      });
      continue;
    }
    const message = { role, content };
    if (role === "assistant") claimThinking(message);
    messages.push(message);
  }
  return messages;
}
function reasoningItemText(item) {
  const texts = (parts) => Array.isArray(parts) ? parts.map((p) => typeof p?.text === "string" ? p.text : "").filter(Boolean) : [];
  const content = texts(item.content);
  return (content.length > 0 ? content : texts(item.summary)).join("\n");
}
function blocksToText(blocks) {
  return blocks.map((b) => b.type === "text" ? b.text : "[image]").join("\n");
}
function responsesContent(content) {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    const blocks = [];
    for (const c of content) {
      if (!c || typeof c !== "object") continue;
      const cc = c;
      if (typeof cc.text === "string") blocks.push({ type: "text", text: cc.text });
      else if (cc.type === "input_image" || typeof cc.image_url === "string") {
        const url = typeof cc.image_url === "string" ? cc.image_url : cc.image_url?.url;
        if (typeof url === "string" && url) blocks.push({ type: "image_url", url });
      }
    }
    if (blocks.every((b) => b.type === "text")) return blocks.map((b) => b.text).join("\n");
    return blocks;
  }
  if (content === void 0 || content === null) return "";
  return new Error("unsupported responses content shape");
}
var respSeq = 0;
function nextResponseId() {
  respSeq += 1;
  return `resp_${Date.now().toString(36)}${respSeq.toString(36)}`;
}
function extractReasoningText(message) {
  if (!message || typeof message !== "object") return "";
  const parts = [];
  if (typeof message.reasoning === "string" && message.reasoning.length > 0) {
    parts.push(message.reasoning);
  }
  const details = message.reasoning_details;
  if (Array.isArray(details)) {
    for (const d of details) {
      if (d && typeof d.text === "string" && d.text.length > 0) parts.push(d.text);
    }
  }
  const raw = parts.join("\n\n").trim();
  if (!raw) return "";
  const markers = ["\nanswer:", "answer is", "\njawaban:", "the answer is", "answear is", "conclusion:", "\nfinal answer"];
  const lower = raw.toLowerCase();
  for (const m of markers) {
    const idx = lower.indexOf(m);
    if (idx !== -1) {
      const slice = raw.slice(idx + m.length).trim();
      if (slice) return slice;
    }
  }
  const paragraphs = raw.split(/\n\s*\n/).map((p) => p.trim()).filter(Boolean);
  const last = paragraphs[paragraphs.length - 1];
  return last ?? raw;
}
function renderResponse(chatJson, model) {
  const choice = chatJson?.choices?.[0] ?? {};
  const message = choice.message ?? {};
  const direct = typeof message.content === "string" ? message.content : "";
  const toolCalls = Array.isArray(message.tool_calls) ? message.tool_calls : [];
  const text = direct.length > 0 || toolCalls.length > 0 ? direct : extractReasoningText(message);
  const output = [];
  if (text.length > 0 || toolCalls.length === 0) {
    output.push({
      type: "message",
      status: "completed",
      id: `msg_${Math.random().toString(36).slice(2, 10)}`,
      role: "assistant",
      content: [{ type: "output_text", text, annotations: [] }]
    });
  }
  for (const tc of toolCalls) {
    output.push({
      type: "function_call",
      status: "completed",
      id: `fc_${Math.random().toString(36).slice(2, 10)}`,
      call_id: tc?.id ?? `call_${Math.random().toString(36).slice(2, 10)}`,
      name: tc?.function?.name ?? "tool",
      arguments: tc?.function?.arguments ?? "{}"
    });
  }
  const usage2 = chatJson?.usage ?? {};
  return {
    id: nextResponseId(),
    object: "response",
    created_at: Math.floor(Date.now() / 1e3),
    model,
    status: "completed",
    output,
    parallel_tool_calls: true,
    usage: {
      input_tokens: usage2.prompt_tokens ?? 0,
      output_tokens: usage2.completion_tokens ?? 0,
      total_tokens: usage2.total_tokens ?? (usage2.prompt_tokens ?? 0) + (usage2.completion_tokens ?? 0)
    }
  };
}
function renderResponsesEvent(type, data) {
  const payload = { type, ...data };
  return `event: ${type}
data: ${JSON.stringify(payload)}

`;
}
var ResponsesStreamEncoder = class {
  constructor(callerTools) {
    this.callerTools = callerTools;
  }
  callerTools;
  started = false;
  responseId = nextResponseId();
  model = "";
  nextIndex = 0;
  message = null;
  reasoning = null;
  calls = /* @__PURE__ */ new Map();
  items = [];
  inputTokens = 0;
  outputTokens = 0;
  open(model) {
    if (this.started) return [];
    this.model = model;
    this.started = true;
    const created = {
      response: {
        id: this.responseId,
        object: "response",
        created_at: Math.floor(Date.now() / 1e3),
        status: "in_progress",
        model,
        output: [],
        usage: null
      }
    };
    return [
      renderResponsesEvent("response.created", created),
      renderResponsesEvent("response.in_progress", created)
    ];
  }
  push(chunk) {
    const out = [];
    if (chunk?.usage) {
      if (typeof chunk.usage.prompt_tokens === "number") this.inputTokens = chunk.usage.prompt_tokens;
      if (typeof chunk.usage.completion_tokens === "number") this.outputTokens = chunk.usage.completion_tokens;
    }
    const choice = chunk?.choices?.[0];
    if (!choice) return out;
    const delta = choice.delta ?? {};
    const reasoningDelta = (typeof delta.reasoning === "string" ? delta.reasoning : "") + (typeof delta.reasoning_content === "string" ? delta.reasoning_content : "");
    if (reasoningDelta.length > 0) {
      if (this.reasoning?.closed) this.reasoning = null;
      if (!this.reasoning) {
        this.reasoning = { id: `rs_${randomId()}`, outputIndex: this.nextIndex++, text: "", closed: false };
        out.push(renderResponsesEvent("response.output_item.added", {
          output_index: this.reasoning.outputIndex,
          item: { id: this.reasoning.id, type: "reasoning", summary: [] }
        }));
        out.push(renderResponsesEvent("response.reasoning_summary_part.added", {
          item_id: this.reasoning.id,
          output_index: this.reasoning.outputIndex,
          summary_index: 0,
          part: { type: "summary_text", text: "" }
        }));
      }
      this.reasoning.text += reasoningDelta;
      out.push(renderResponsesEvent("response.reasoning_summary_text.delta", {
        item_id: this.reasoning.id,
        output_index: this.reasoning.outputIndex,
        summary_index: 0,
        delta: reasoningDelta
      }));
    }
    if (typeof delta.content === "string" && delta.content.length > 0) {
      out.push(...this.closeReasoning());
      out.push(...this.appendText(delta.content));
    }
    if (Array.isArray(delta.tool_calls)) {
      for (const tc of delta.tool_calls) {
        const index = typeof tc?.index === "number" ? tc.index : 0;
        let call = this.calls.get(index);
        if (!call) {
          const name = tc?.function?.name;
          if (typeof name !== "string") continue;
          out.push(...this.closeReasoning(), ...this.closeMessage());
          const dropped = this.callerTools !== void 0 && !this.callerTools.has(name);
          call = {
            itemId: `fc_${randomId()}`,
            callId: typeof tc.id === "string" && tc.id ? tc.id : `call_${randomId()}`,
            name,
            args: "",
            outputIndex: dropped ? -1 : this.nextIndex++,
            dropped,
            translate: dropped ? this.callerTools?.bridge?.(name) ?? void 0 : void 0
          };
          this.calls.set(index, call);
          if (!dropped) {
            out.push(renderResponsesEvent("response.output_item.added", {
              output_index: call.outputIndex,
              item: { id: call.itemId, type: "function_call", status: "in_progress", call_id: call.callId, name, arguments: "" }
            }));
          }
        }
        const argDelta = tc?.function?.arguments;
        if (typeof argDelta === "string" && argDelta.length > 0) {
          call.args += argDelta;
          if (!call.dropped) {
            out.push(renderResponsesEvent("response.function_call_arguments.delta", {
              item_id: call.itemId,
              output_index: call.outputIndex,
              delta: argDelta
            }));
          }
        }
      }
    }
    return out;
  }
  close() {
    const out = this.open(this.model || "unknown");
    for (const call of this.calls.values()) {
      const translated = call.translate?.(call.args, call.callId);
      if (!translated) continue;
      call.name = translated.name;
      call.args = translated.arguments;
      call.dropped = false;
      call.bridged = true;
    }
    const visibleCalls = [...this.calls.values()].filter((c) => !c.dropped);
    if (!this.message && visibleCalls.length === 0) {
      const fold = this.calls.size === 0 ? this.reasoning?.text ?? "" : "";
      out.push(...this.closeReasoning());
      out.push(...this.appendText(fold));
    }
    out.push(...this.closeReasoning(), ...this.closeMessage());
    for (const call of visibleCalls) {
      if (!call.bridged) continue;
      call.outputIndex = this.nextIndex++;
      out.push(renderResponsesEvent("response.output_item.added", {
        output_index: call.outputIndex,
        item: { id: call.itemId, type: "function_call", status: "in_progress", call_id: call.callId, name: call.name, arguments: "" }
      }));
      out.push(renderResponsesEvent("response.function_call_arguments.delta", {
        item_id: call.itemId,
        output_index: call.outputIndex,
        delta: call.args
      }));
    }
    for (const call of visibleCalls) {
      const args = call.args || "{}";
      out.push(renderResponsesEvent("response.function_call_arguments.done", {
        item_id: call.itemId,
        output_index: call.outputIndex,
        arguments: args
      }));
      const item = { id: call.itemId, type: "function_call", status: "completed", call_id: call.callId, name: call.name, arguments: args };
      this.items.push({ outputIndex: call.outputIndex, item });
      out.push(renderResponsesEvent("response.output_item.done", { output_index: call.outputIndex, item }));
    }
    out.push(renderResponsesEvent("response.completed", {
      response: {
        id: this.responseId,
        object: "response",
        created_at: Math.floor(Date.now() / 1e3),
        status: "completed",
        model: this.model,
        output: [...this.items].sort((a, b) => a.outputIndex - b.outputIndex).map((i) => i.item),
        parallel_tool_calls: true,
        usage: {
          input_tokens: this.inputTokens,
          output_tokens: this.outputTokens,
          total_tokens: this.inputTokens + this.outputTokens
        }
      }
    }));
    return out;
  }
  fail(message) {
    return [
      ...this.open(this.model || "unknown"),
      renderResponsesEvent("response.failed", {
        response: {
          id: this.responseId,
          object: "response",
          created_at: Math.floor(Date.now() / 1e3),
          status: "failed",
          model: this.model,
          output: [],
          error: { code: "server_error", message },
          usage: null
        }
      })
    ];
  }
  appendText(text) {
    const out = [];
    if (this.message?.closed) {
      if (text.length === 0) return out;
      this.message = null;
    }
    if (!this.message) {
      this.message = { id: `msg_${randomId()}`, outputIndex: this.nextIndex++, text: "", closed: false };
      out.push(renderResponsesEvent("response.output_item.added", {
        output_index: this.message.outputIndex,
        item: { id: this.message.id, type: "message", status: "in_progress", role: "assistant", content: [] }
      }));
      out.push(renderResponsesEvent("response.content_part.added", {
        output_index: this.message.outputIndex,
        content_index: 0,
        item_id: this.message.id,
        part: { type: "output_text", text: "", annotations: [] }
      }));
    }
    if (text.length > 0) {
      this.message.text += text;
      out.push(renderResponsesEvent("response.output_text.delta", {
        item_id: this.message.id,
        output_index: this.message.outputIndex,
        content_index: 0,
        delta: text
      }));
    }
    return out;
  }
  closeMessage() {
    const m = this.message;
    if (!m || m.closed) return [];
    m.closed = true;
    const part = { type: "output_text", text: m.text, annotations: [] };
    const item = { id: m.id, type: "message", status: "completed", role: "assistant", content: [part] };
    this.items.push({ outputIndex: m.outputIndex, item });
    return [
      renderResponsesEvent("response.output_text.done", { item_id: m.id, output_index: m.outputIndex, content_index: 0, text: m.text }),
      renderResponsesEvent("response.content_part.done", { item_id: m.id, output_index: m.outputIndex, content_index: 0, part }),
      renderResponsesEvent("response.output_item.done", { output_index: m.outputIndex, item })
    ];
  }
  closeReasoning() {
    const r = this.reasoning;
    if (!r || r.closed) return [];
    r.closed = true;
    const part = { type: "summary_text", text: r.text };
    const item = { id: r.id, type: "reasoning", summary: [part] };
    this.items.push({ outputIndex: r.outputIndex, item });
    return [
      renderResponsesEvent("response.reasoning_summary_text.done", { item_id: r.id, output_index: r.outputIndex, summary_index: 0, text: r.text }),
      renderResponsesEvent("response.reasoning_summary_part.done", { item_id: r.id, output_index: r.outputIndex, summary_index: 0, part }),
      renderResponsesEvent("response.output_item.done", { output_index: r.outputIndex, item })
    ];
  }
};
function randomId() {
  return Math.random().toString(36).slice(2, 12);
}

// src/protocols/responses-upstream.ts
import { Readable, Transform, pipeline } from "node:stream";

// src/protocols/stream.ts
import { StringDecoder } from "node:string_decoder";
function sseEvent(event, data) {
  return `event: ${event}
data: ${JSON.stringify(data)}

`;
}
function createSseFrameSplitter() {
  const decoder = new StringDecoder("utf8");
  let buffer = "";
  return {
    push(chunk) {
      buffer += typeof chunk === "string" ? chunk : decoder.write(chunk);
      buffer = buffer.replace(/\r\n/g, "\n");
      const frames = [];
      let end = buffer.indexOf("\n\n");
      while (end !== -1) {
        frames.push(buffer.slice(0, end + 2));
        buffer = buffer.slice(end + 2);
        end = buffer.indexOf("\n\n");
      }
      return frames;
    },
    rest() {
      const out = (buffer + decoder.end()).replace(/\r\n/g, "\n");
      buffer = "";
      return out;
    }
  };
}
async function* readSseStream(stream2) {
  const decoder = new TextDecoder();
  let buffer = "";
  let event;
  let dataLines = [];
  for await (const bytes of stream2) {
    buffer += decoder.decode(bytes, { stream: true });
    let idx;
    while ((idx = buffer.indexOf("\n")) !== -1) {
      const line = buffer.slice(0, idx).replace(/\r$/, "");
      buffer = buffer.slice(idx + 1);
      if (line === "") {
        if (event !== void 0 || dataLines.length > 0) {
          yield { event, data: dataLines.join("\n") };
          event = void 0;
          dataLines = [];
        }
        continue;
      }
      if (line.startsWith(":")) continue;
      const colon = line.indexOf(":");
      const field = colon === -1 ? line : line.slice(0, colon);
      const value = colon === -1 ? "" : line.slice(colon + 1).replace(/^ /, "");
      if (field === "event") event = value;
      else if (field === "data") dataLines.push(value);
    }
  }
  if (event !== void 0 || dataLines.length > 0) {
    yield { event, data: dataLines.join("\n") };
  }
}

// src/protocols/responses-upstream.ts
function randomId2(prefix) {
  return `${prefix}_${Math.random().toString(36).slice(2, 12)}`;
}
function textOf(content) {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content.map((p) => typeof p?.text === "string" ? p.text : "").join("");
}
function inputParts(content, role) {
  const textType = role === "assistant" ? "output_text" : "input_text";
  if (typeof content === "string") return [{ type: textType, text: content }];
  if (!Array.isArray(content)) return [];
  const parts = [];
  for (const p of content) {
    if (p?.type === "image_url") {
      const url = typeof p.image_url === "string" ? p.image_url : p.image_url?.url;
      if (typeof url === "string") parts.push({ type: "input_image", image_url: url });
      continue;
    }
    if (p?.type === "file" || p?.type === "input_file") {
      const file = p.file ?? p;
      parts.push({
        type: "input_file",
        ...typeof file.file_id === "string" ? { file_id: file.file_id } : {},
        ...typeof file.file_data === "string" ? { file_data: file.file_data } : {},
        ...typeof file.filename === "string" ? { filename: file.filename } : {}
      });
      continue;
    }
    if (typeof p?.text === "string") parts.push({ type: textType, text: p.text });
  }
  return parts;
}
async function toChatResponse(upstreamRes, modelId, streaming) {
  if (!upstreamRes.body) return upstreamRes;
  if (!streaming) {
    const text = await upstreamRes.text();
    try {
      return new Response(JSON.stringify(responsesToChatJson(JSON.parse(text), modelId)), {
        status: upstreamRes.status,
        headers: { "content-type": "application/json" }
      });
    } catch {
      return new Response(text, {
        status: upstreamRes.status,
        headers: {
          "content-type": upstreamRes.headers.get("content-type") ?? "application/json"
        }
      });
    }
  }
  const src = Readable.fromWeb(upstreamRes.body);
  const out = responsesToChatStream(modelId);
  pipeline(src, out, () => {
  });
  return new Response(Readable.toWeb(out), {
    status: upstreamRes.status,
    headers: { "content-type": "text/event-stream" }
  });
}
function chatToResponsesBody(chatBody, modelId) {
  const messages = Array.isArray(chatBody?.messages) ? chatBody.messages : [];
  const instructions = [];
  const input = [];
  for (const m of messages) {
    const role = m?.role;
    if (role === "system" || role === "developer") {
      const text = textOf(m.content);
      if (text) instructions.push(text);
      continue;
    }
    if (role === "tool") {
      input.push({
        type: "function_call_output",
        call_id: m.tool_call_id ?? randomId2("call"),
        output: textOf(m.content)
      });
      continue;
    }
    if (role === "assistant" && Array.isArray(m.tool_calls) && m.tool_calls.length > 0) {
      const text = textOf(m.content);
      if (text) input.push({ role: "assistant", content: [{ type: "output_text", text }] });
      for (const tc of m.tool_calls) {
        input.push({
          type: "function_call",
          call_id: tc?.id ?? randomId2("call"),
          name: tc?.function?.name ?? "tool",
          arguments: tc?.function?.arguments ?? "{}"
        });
      }
      continue;
    }
    const parts = inputParts(m?.content, role);
    if (parts.length > 0) input.push({ role: role ?? "user", content: parts });
  }
  const body = { model: modelId, input };
  if (instructions.length > 0) body.instructions = instructions.join("\n\n");
  const maxTokens = chatBody?.max_completion_tokens ?? chatBody?.max_tokens;
  if (typeof maxTokens === "number") body.max_output_tokens = maxTokens;
  if (typeof chatBody?.temperature === "number") body.temperature = chatBody.temperature;
  if (typeof chatBody?.top_p === "number") body.top_p = chatBody.top_p;
  if (chatBody?.stream === true) body.stream = true;
  if (Array.isArray(chatBody?.tools) && chatBody.tools.length > 0) {
    body.tools = chatBody.tools.map((t) => ({
      type: "function",
      name: t?.function?.name ?? t?.name,
      description: t?.function?.description ?? t?.description,
      parameters: t?.function?.parameters ?? t?.parameters
    }));
  }
  if (chatBody?.tool_choice !== void 0) {
    const tc = chatBody.tool_choice;
    body.tool_choice = tc?.type === "function" ? { type: "function", name: tc.function?.name ?? tc.name } : tc;
  }
  return body;
}
function responsesToChatJson(resp, modelId) {
  const output = Array.isArray(resp?.output) ? resp.output : [];
  let text = "";
  const toolCalls = [];
  for (const item of output) {
    if (item?.type === "message") {
      text += textOf(item.content);
    } else if (item?.type === "function_call") {
      toolCalls.push({
        id: item.call_id ?? item.id ?? randomId2("call"),
        type: "function",
        function: {
          name: item.name ?? "tool",
          arguments: typeof item.arguments === "string" ? item.arguments : "{}"
        }
      });
    }
  }
  const finish = toolCalls.length > 0 ? "tool_calls" : resp?.status === "incomplete" ? "length" : "stop";
  const usage2 = resp?.usage ?? {};
  const cached = usage2.input_tokens_details?.cached_tokens ?? usage2.prompt_tokens_details?.cached_tokens;
  const message = { role: "assistant", content: text };
  if (toolCalls.length > 0) message.tool_calls = toolCalls;
  return {
    id: resp?.id ?? randomId2("chatcmpl"),
    object: "chat.completion",
    created: resp?.created_at ?? Math.floor(Date.now() / 1e3),
    model: modelId,
    choices: [{ index: 0, message, finish_reason: finish }],
    usage: {
      prompt_tokens: usage2.input_tokens ?? 0,
      completion_tokens: usage2.output_tokens ?? 0,
      total_tokens: usage2.total_tokens ?? (usage2.input_tokens ?? 0) + (usage2.output_tokens ?? 0),
      ...typeof cached === "number" ? { prompt_tokens_details: { cached_tokens: cached } } : {}
    }
  };
}
function responsesToChatStream(modelId) {
  const id = randomId2("chatcmpl");
  const created = Math.floor(Date.now() / 1e3);
  const splitter = createSseFrameSplitter();
  let roleSent = false;
  let sawToolCall = false;
  let closed = false;
  const toolIndexByOutput = /* @__PURE__ */ new Map();
  const argsSent = /* @__PURE__ */ new Set();
  const chunk = (delta, finish = null) => `data: ${JSON.stringify({
    id,
    object: "chat.completion.chunk",
    created,
    model: modelId,
    choices: [{ index: 0, delta, finish_reason: finish }]
  })}

`;
  const withRole = (delta) => {
    if (roleSent) return delta;
    roleSent = true;
    return { role: "assistant", ...delta };
  };
  const handle = (event, push) => {
    switch (event?.type) {
      case "response.output_text.delta": {
        if (typeof event.delta === "string" && event.delta.length > 0) {
          push(chunk(withRole({ content: event.delta })));
        }
        break;
      }
      case "response.output_item.added": {
        if (event.item?.type !== "function_call") break;
        const index = toolIndexByOutput.size;
        toolIndexByOutput.set(event.output_index, index);
        sawToolCall = true;
        const upfront = typeof event.item.arguments === "string" ? event.item.arguments : "";
        if (upfront) argsSent.add(event.output_index);
        push(chunk(withRole({
          tool_calls: [{
            index,
            id: event.item.call_id ?? event.item.id ?? randomId2("call"),
            type: "function",
            function: { name: event.item.name ?? "tool", arguments: upfront }
          }]
        })));
        break;
      }
      case "response.function_call_arguments.delta": {
        const index = toolIndexByOutput.get(event.output_index);
        if (index === void 0 || typeof event.delta !== "string") break;
        argsSent.add(event.output_index);
        push(chunk({ tool_calls: [{ index, function: { arguments: event.delta } }] }));
        break;
      }
      case "response.function_call_arguments.done":
      case "response.output_item.done": {
        const index = toolIndexByOutput.get(event.output_index);
        if (index === void 0 || argsSent.has(event.output_index)) break;
        const whole = typeof event.arguments === "string" ? event.arguments : typeof event.item?.arguments === "string" ? event.item.arguments : "";
        if (!whole) break;
        argsSent.add(event.output_index);
        push(chunk({ tool_calls: [{ index, function: { arguments: whole } }] }));
        break;
      }
      case "response.completed":
      case "response.incomplete": {
        if (closed) break;
        closed = true;
        const finish = sawToolCall ? "tool_calls" : event.type === "response.incomplete" ? "length" : "stop";
        const usage2 = event.response?.usage;
        const final = {
          id,
          object: "chat.completion.chunk",
          created,
          model: modelId,
          choices: [{ index: 0, delta: {}, finish_reason: finish }]
        };
        if (usage2) {
          const cached = usage2.input_tokens_details?.cached_tokens ?? usage2.prompt_tokens_details?.cached_tokens;
          final.usage = {
            prompt_tokens: usage2.input_tokens ?? 0,
            completion_tokens: usage2.output_tokens ?? 0,
            total_tokens: usage2.total_tokens ?? (usage2.input_tokens ?? 0) + (usage2.output_tokens ?? 0),
            ...typeof cached === "number" ? { prompt_tokens_details: { cached_tokens: cached } } : {}
          };
        }
        push(`data: ${JSON.stringify(final)}

`);
        push("data: [DONE]\n\n");
        break;
      }
      // response.created / in_progress / content_part.* / ping carry nothing chat expresses
      default:
        break;
    }
  };
  return new Transform({
    transform(input, _enc, cb) {
      for (const frame of splitter.push(input)) {
        for (const line of frame.split("\n")) {
          if (!line.startsWith("data:")) continue;
          const payload = line.slice(5).trim();
          if (!payload || payload === "[DONE]") continue;
          try {
            handle(JSON.parse(payload), (s) => this.push(s));
          } catch {
          }
        }
      }
      cb();
    },
    flush(cb) {
      if (!closed) {
        this.push(`data: ${JSON.stringify({
          id,
          object: "chat.completion.chunk",
          created,
          model: modelId,
          choices: [{ index: 0, delta: {}, finish_reason: sawToolCall ? "tool_calls" : "stop" }]
        })}

`);
        this.push("data: [DONE]\n\n");
      }
      cb();
    }
  });
}

// src/protocols/anthropic.ts
function parseAnthropicRequest(body) {
  if (typeof body !== "object" || body === null) {
    return { ok: false, error: "request body must be a json object" };
  }
  const b = body;
  const model = typeof b.model === "string" ? b.model : "";
  if (!model) return { ok: false, error: "missing required field: model" };
  if (typeof b.max_tokens !== "number") {
    return { ok: false, error: "missing required field: max_tokens" };
  }
  if (!Array.isArray(b.messages)) {
    return { ok: false, error: "missing required field: messages" };
  }
  const system = normalizeText(b.system);
  const out = [];
  if (system) out.push({ role: "system", content: system });
  for (const m of b.messages) {
    const conv = convertMessage(m);
    if (conv === null) return { ok: false, error: "unsupported message content" };
    out.push(...conv);
  }
  const chatBody = {
    model,
    messages: out,
    max_tokens: b.max_tokens,
    stream: b.stream === true
  };
  if (typeof b.temperature === "number") chatBody.temperature = b.temperature;
  if (typeof b.top_p === "number") chatBody.top_p = b.top_p;
  if (Array.isArray(b.stop_sequences) && b.stop_sequences.length) {
    chatBody.stop = b.stop_sequences;
  }
  const tools = convertTools(b.tools);
  if (tools) chatBody.tools = tools;
  const tc = convertToolChoice(b.tool_choice);
  if (tc !== void 0) chatBody.tool_choice = tc;
  if (chatBody.stream) chatBody.stream_options = { include_usage: true };
  return { ok: true, value: { model, stream: chatBody.stream, chatBody } };
}
function normalizeText(x) {
  if (x === void 0 || x === null) return null;
  if (typeof x === "string") return x.trim() || null;
  if (Array.isArray(x)) {
    const text = x.map((b) => {
      if (!b || typeof b !== "object") return "";
      if (b.type === "text" && typeof b.text === "string") return b.text;
      if (typeof b.text === "string") return b.text;
      return "";
    }).filter(Boolean).join("\n\n");
    return text.trim() || null;
  }
  return null;
}
function blocksToText2(blocks) {
  const texts = [];
  for (const b of blocks) {
    if (b && typeof b === "object" && typeof b.text === "string" && b.text) texts.push(b.text);
  }
  return texts.join("\n\n");
}
function imageToOpenAi(block) {
  if (!block || typeof block !== "object" || block.type !== "image") return null;
  const source = block.source;
  if (!source || typeof source !== "object") return null;
  if (source.type === "base64" && source.media_type && source.data) {
    return { type: "image_url", image_url: { url: `data:${source.media_type};base64,${source.data}` } };
  }
  if (source.type === "url" && source.url) {
    return { type: "image_url", image_url: { url: source.url } };
  }
  return null;
}
function convertMessage(m) {
  if (!m || typeof m !== "object") return null;
  const role = m.role;
  const content = m.content;
  if (role === "system" || role === "developer") {
    const text = typeof content === "string" ? content : Array.isArray(content) ? blocksToText2(content) : "";
    return [{ role: "system", content: text }];
  }
  if (role === "tool") {
    const text = typeof content === "string" ? content : Array.isArray(content) ? blocksToText2(content) : "";
    return [{ role: "tool", tool_call_id: m.tool_call_id ?? m.tool_use_id ?? "unknown", content: text }];
  }
  if (role === "assistant") {
    if (typeof content === "string") return [{ role: "assistant", content, reasoning_content: "" }];
    const blocks = Array.isArray(content) ? content : [];
    const text = blocksToText2(blocks);
    const reasoning_content = blocks.map((b) => b && b.type === "thinking" && typeof b.thinking === "string" ? b.thinking : "").filter(Boolean).join("\n");
    const toolCalls = [];
    for (const b of blocks) {
      if (b && b.type === "tool_use") {
        toolCalls.push({
          id: b.id,
          type: "function",
          function: { name: b.name, arguments: JSON.stringify(b.input ?? {}) }
        });
      }
    }
    if (toolCalls.length > 0) {
      return [{ role: "assistant", content: text || null, reasoning_content, tool_calls: toolCalls }];
    }
    return [{ role: "assistant", content: text || "", reasoning_content }];
  }
  if (role === "user") {
    const parts = typeof content === "string" ? [{ type: "text", text: content }] : Array.isArray(content) ? content : [];
    const toolResults = [];
    for (const b of parts) {
      if (b && b.type === "tool_result") {
        const out = toolResultContent(b.content);
        toolResults.push({ role: "tool", tool_call_id: b.tool_use_id, content: b.is_error ? `Error: ${out}` : out });
      }
    }
    const text = blocksToText2(parts);
    const images = parts.map(imageToOpenAi).filter((x) => x !== null);
    const result = [];
    for (const tr of toolResults) result.push(tr);
    if (text || images.length > 0) {
      const c = [];
      if (text) c.push({ type: "text", text });
      for (const img of images) c.push(img);
      result.push({ role: "user", content: c.length === 1 && c[0].type === "text" ? text : c });
    }
    if (result.length === 0 && toolResults.length === 0) {
      result.push({ role: "user", content: "" });
    }
    return result;
  }
  const fallbackText = typeof content === "string" ? content : Array.isArray(content) ? blocksToText2(content) : "";
  return [{ role: "user", content: fallbackText }];
}
function toolResultContent(content) {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    return content.map((b) => b && b.type === "text" ? b.text ?? "" : "").filter(Boolean).join("\n");
  }
  return "";
}
function convertTools(tools) {
  if (!Array.isArray(tools)) return null;
  return tools.map((t) => ({
    type: "function",
    function: { name: t?.name, description: t?.description ?? "", parameters: t?.input_schema ?? {} }
  }));
}
function convertToolChoice(tc) {
  if (!tc || typeof tc !== "object") return void 0;
  const t = tc.type;
  if (t === "auto") return "auto";
  if (t === "any") return "required";
  if (t === "none") return "none";
  if (t === "tool") return { type: "function", function: { name: tc.name } };
  return void 0;
}
function mapStop(reason) {
  switch (reason) {
    case "stop":
      return "end_turn";
    case "length":
      return "max_tokens";
    case "tool_calls":
    case "function_call":
      return "tool_use";
    default:
      return "end_turn";
  }
}
function openAiCompletionToAnthropicMessage(resp, model) {
  const choice = resp?.choices?.[0] ?? {};
  const message = choice.message ?? {};
  const content = [];
  const text = typeof message.content === "string" && message.content.length > 0 ? message.content : "";
  const reasoning = typeof message.content === "string" && message.content.length > 0 ? "" : extractReasoningText(message);
  if (reasoning) {
    content.push({ type: "thinking", thinking: reasoning });
  }
  if (text) {
    content.push({ type: "text", text });
  }
  for (const tc of message.tool_calls ?? []) {
    let input = {};
    try {
      input = JSON.parse(tc?.function?.arguments ?? "{}");
    } catch {
      input = {};
    }
    content.push({ type: "tool_use", id: tc?.id, name: tc?.function?.name, input });
  }
  const usage2 = resp?.usage ?? {};
  return {
    id: `msg_${resp?.id ?? Date.now()}`,
    type: "message",
    role: "assistant",
    model,
    stop_reason: mapStop(choice.finish_reason ?? "stop"),
    stop_sequence: null,
    content,
    usage: {
      input_tokens: usage2.prompt_tokens ?? 0,
      output_tokens: usage2.completion_tokens ?? 0
    }
  };
}
var AnthropicStreamEncoder = class {
  constructor(callerTools) {
    this.callerTools = callerTools;
  }
  callerTools;
  started = false;
  model = "";
  open = null;
  nextIndex = 0;
  sawText = false;
  thinkingBuffer = "";
  tools = /* @__PURE__ */ new Map();
  usage = { input_tokens: 0, output_tokens: 0 };
  stopReason = null;
  push(chunk, model) {
    if (model) this.model = model;
    const out = this.start(chunk?.id);
    if (chunk?.usage) {
      if (typeof chunk.usage.prompt_tokens === "number") this.usage.input_tokens = chunk.usage.prompt_tokens;
      if (typeof chunk.usage.completion_tokens === "number") this.usage.output_tokens = chunk.usage.completion_tokens;
    }
    const choice = chunk?.choices?.[0];
    if (!choice) return out;
    const delta = choice.delta ?? {};
    const reasoningText = typeof delta.reasoning === "string" && delta.reasoning.length > 0 ? delta.reasoning : typeof delta.reasoning_content === "string" && delta.reasoning_content.length > 0 ? delta.reasoning_content : null;
    if (reasoningText) {
      this.thinkingBuffer += reasoningText;
      out.push(...this.ensureOpen("thinking", { type: "thinking", thinking: "" }));
      out.push(this.delta({ type: "thinking_delta", thinking: reasoningText }));
    }
    if (typeof delta.content === "string" && delta.content.length > 0) {
      this.sawText = true;
      out.push(...this.ensureOpen("text", { type: "text", text: "" }));
      out.push(this.delta({ type: "text_delta", text: delta.content }));
    }
    if (Array.isArray(delta.tool_calls)) {
      for (const tc of delta.tool_calls) {
        const ti = typeof tc?.index === "number" ? tc.index : 0;
        let tool = this.tools.get(ti);
        if (!tool) {
          const name = tc?.function?.name;
          if (typeof name !== "string") continue;
          const dropped = this.callerTools !== void 0 && !this.callerTools.has(name);
          tool = { dropped, id: tc.id, args: "", translate: dropped ? this.callerTools?.bridge?.(name) ?? void 0 : void 0 };
          this.tools.set(ti, tool);
          if (!tool.dropped) {
            out.push(...this.closeOpen());
            this.open = { kind: "tool", index: this.nextIndex++, toolIndex: ti };
            out.push(sseEvent("content_block_start", {
              type: "content_block_start",
              index: this.open.index,
              content_block: { type: "tool_use", id: tc.id || `toolu_${ti}_${Date.now().toString(36)}`, name, input: {} }
            }));
          }
        }
        const args = tc?.function?.arguments;
        if (tool.translate && typeof args === "string") tool.args += args;
        if (tool.dropped || typeof args !== "string" || args.length === 0) continue;
        if (this.open?.kind === "tool" && this.open.toolIndex === ti) {
          out.push(this.delta({ type: "input_json_delta", partial_json: args }));
        }
      }
    }
    if (choice.finish_reason) this.stopReason = mapStop(choice.finish_reason);
    return out;
  }
  close() {
    const out = this.start();
    let bridged = false;
    for (const [ti, tool] of this.tools) {
      const id = tool.id || `toolu_${ti}_${Date.now().toString(36)}`;
      const call = tool.translate?.(tool.args, id);
      if (!call) continue;
      tool.dropped = false;
      bridged = true;
      out.push(...this.closeOpen());
      this.open = { kind: "tool", index: this.nextIndex++, toolIndex: ti };
      out.push(sseEvent("content_block_start", {
        type: "content_block_start",
        index: this.open.index,
        content_block: { type: "tool_use", id, name: call.name, input: {} }
      }));
      out.push(this.delta({ type: "input_json_delta", partial_json: call.arguments }));
    }
    if (bridged) this.stopReason = "tool_use";
    const visibleTools = [...this.tools.values()].some((t) => !t.dropped);
    if (!this.sawText && this.tools.size === 0 && this.thinkingBuffer.length > 0) {
      out.push(...this.ensureOpen("text", { type: "text", text: "" }));
      out.push(this.delta({ type: "text_delta", text: this.thinkingBuffer }));
    }
    out.push(...this.closeOpen());
    let stopReason = this.stopReason ?? "end_turn";
    if (stopReason === "tool_use" && !visibleTools) stopReason = "end_turn";
    out.push(sseEvent("message_delta", {
      type: "message_delta",
      delta: { stop_reason: stopReason, stop_sequence: null },
      usage: { input_tokens: this.usage.input_tokens, output_tokens: this.usage.output_tokens }
    }));
    out.push(sseEvent("message_stop", { type: "message_stop" }));
    return out;
  }
  fail(message) {
    return [
      ...this.start(),
      sseEvent("error", { type: "error", error: { type: /overload|busy|capacity/i.test(message) ? "overloaded_error" : "api_error", message } })
    ];
  }
  start(id) {
    if (this.started) return [];
    this.started = true;
    return [sseEvent("message_start", {
      type: "message_start",
      message: {
        id: `msg_${typeof id === "string" && id ? id : Date.now().toString(36)}`,
        type: "message",
        role: "assistant",
        model: this.model,
        content: [],
        stop_reason: null,
        stop_sequence: null,
        usage: { input_tokens: this.usage.input_tokens, output_tokens: 0 }
      }
    })];
  }
  ensureOpen(kind, block) {
    if (this.open?.kind === kind) return [];
    const out = this.closeOpen();
    this.open = { kind, index: this.nextIndex++ };
    out.push(sseEvent("content_block_start", { type: "content_block_start", index: this.open.index, content_block: block }));
    return out;
  }
  closeOpen() {
    if (!this.open) return [];
    const index = this.open.index;
    this.open = null;
    return [sseEvent("content_block_stop", { type: "content_block_stop", index })];
  }
  delta(delta) {
    return sseEvent("content_block_delta", { type: "content_block_delta", index: this.open.index, delta });
  }
};

// src/daemon/admin.ts
import fs9 from "node:fs";
import net, { isIP as isIP2 } from "node:net";
init_policy();
init_state();
var ADMIN_PATHS = /* @__PURE__ */ new Set([
  "/bansos/config",
  "/bansos/restart",
  "/bansos/logs",
  "/bansos/doctor",
  "/bansos/adapters/apply",
  "/bansos/autostart",
  "/bansos/backup",
  "/bansos/restore",
  "/bansos/activity/clear"
]);
var MIN_REFRESH_MS = 6e4;
var MAX_REFRESH_MS = 24 * 60 * 6e4;
var MAX_LOG_LINES = 2e3;
var LOG_TAIL_BYTES = 512 * 1024;
function securityView(s, rawFailover) {
  return {
    mode: s.mode,
    dlp: s.dlp,
    allowedUpstreams: [...s.allowedUpstreams],
    allowCrossProviderFailover: rawFailover === void 0 ? s.allowCrossProviderFailover : rawFailover !== false
  };
}
function configView(opts) {
  const file = opts.configFile ?? CONFIG_FILE;
  const { raw, invalid } = readRawConfig(file);
  const saved = loadConfig(file);
  const rawSecurity = raw?.security;
  const savedView = {
    security: securityView(saved.security, rawSecurity?.allowCrossProviderFailover),
    refreshIntervalMs: saved.refreshIntervalMs,
    port: saved.port,
    bind: saved.bind,
    maxBodyBytes: saved.maxBodyBytes ?? DEFAULT_BODY_BYTES,
    localUpstreams: saved.localUpstreams
  };
  const running = {
    security: securityView(opts.security),
    refreshIntervalMs: opts.refreshIntervalMs,
    port: opts.port,
    bind: opts.bind,
    maxBodyBytes: opts.bodyCapBytes && opts.bodyCapBytes > 0 ? opts.bodyCapBytes : DEFAULT_BODY_BYTES,
    localUpstreams: []
  };
  const restartRequired = [];
  if (JSON.stringify(securityView(saved.security)) !== JSON.stringify(running.security)) restartRequired.push("security");
  if (savedView.refreshIntervalMs !== running.refreshIntervalMs) restartRequired.push("refreshIntervalMs");
  if (!opts.flags?.port && savedView.port !== (opts.requestedPort ?? opts.port)) restartRequired.push("port");
  if (!opts.flags?.bind && savedView.bind !== running.bind) restartRequired.push("bind");
  if (savedView.maxBodyBytes !== running.maxBodyBytes) restartRequired.push("maxBodyBytes");
  if (saved.localUpstreams.length > 0 || JSON.stringify(raw?.localUpstreams ?? []) !== JSON.stringify(saved.localUpstreams)) restartRequired.push("localUpstreams");
  return {
    path: file,
    exists: fs9.existsSync(file),
    invalid,
    warnings: loadConfigWarnings(file),
    saved: savedView,
    running,
    upstreams: opts.catalog.upstreamIds,
    flags: {
      port: Boolean(opts.flags?.port),
      bind: Boolean(opts.flags?.bind),
      unsafeAllowNonLoopback: Boolean(opts.flags?.unsafeAllowNonLoopback)
    },
    restartRequired,
    canRestart: Boolean(opts.restart)
  };
}
function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
function validatePatch(body, upstreamIds) {
  if (!isRecord(body)) return { error: "body must be a JSON object" };
  const patch = {};
  if (body.security !== void 0) {
    if (!isRecord(body.security)) return { error: "security must be an object" };
    const s = body.security;
    const security = {};
    if (s.mode !== void 0) {
      if (s.mode !== "normal" && s.mode !== "strict") return { error: 'security.mode must be "normal" or "strict"' };
      security.mode = s.mode;
    }
    if (s.dlp !== void 0) {
      if (s.dlp !== "redact" && s.dlp !== "block") return { error: 'security.dlp must be "redact" or "block"' };
      security.dlp = s.dlp;
    }
    if (s.allowedUpstreams !== void 0) {
      if (!Array.isArray(s.allowedUpstreams) || !s.allowedUpstreams.every((u) => typeof u === "string")) {
        return { error: "security.allowedUpstreams must be a list of upstream ids" };
      }
      const unknown = s.allowedUpstreams.filter((u) => !upstreamIds.includes(u));
      if (unknown.length > 0) return { error: `unknown upstream: ${unknown.join(", ")}` };
      security.allowedUpstreams = [...new Set(s.allowedUpstreams)];
    }
    if (s.allowCrossProviderFailover !== void 0) {
      if (typeof s.allowCrossProviderFailover !== "boolean") return { error: "security.allowCrossProviderFailover must be true or false" };
      security.allowCrossProviderFailover = s.allowCrossProviderFailover;
    }
    patch.security = security;
  }
  if (body.localUpstreams !== void 0) {
    if (!Array.isArray(body.localUpstreams)) return { error: "localUpstreams must be an array" };
    const seen = /* @__PURE__ */ new Set();
    const endpoints = [];
    for (const item of body.localUpstreams) {
      if (!isRecord(item)) return { error: "each endpoint must be an object" };
      const name = typeof item.name === "string" ? item.name.trim() : "";
      const baseUrl = typeof item.baseUrl === "string" ? item.baseUrl.trim().replace(/\/+$/, "") : "";
      if (!/^[a-zA-Z0-9_-]{1,40}$/.test(name)) return { error: "endpoint name must use letters, numbers, _ or -" };
      if (seen.has(name)) return { error: `duplicate endpoint name: ${name}` };
      let parsed;
      try {
        parsed = new URL(baseUrl);
      } catch {
        return { error: `invalid endpoint URL: ${baseUrl}` };
      }
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return { error: "endpoint URL must use http or https" };
      seen.add(name);
      endpoints.push({ name, baseUrl, ...typeof item.apiKey === "string" && item.apiKey ? { apiKey: item.apiKey } : {} });
    }
    patch.localUpstreams = endpoints;
  }
  if (body.refreshIntervalMs !== void 0) {
    const v = body.refreshIntervalMs;
    if (typeof v !== "number" || !Number.isInteger(v) || v !== 0 && (v < MIN_REFRESH_MS || v > MAX_REFRESH_MS)) {
      return { error: "refreshIntervalMs must be 0 (off) or between 1 minute and 24 hours" };
    }
    patch.refreshIntervalMs = v;
  }
  if (body.port !== void 0) {
    const v = body.port;
    if (typeof v !== "number" || !Number.isInteger(v) || v < 1 || v > 65535) return { error: "port must be a number from 1 to 65535" };
    patch.port = v;
  }
  if (body.bind !== void 0) {
    const v = typeof body.bind === "string" ? body.bind.trim() : "";
    if (v !== "localhost" && isIP2(v) === 0) return { error: "bind must be an IP address such as 127.0.0.1, or localhost" };
    patch.bind = v;
  }
  if (body.maxBodyBytes !== void 0) {
    const v = body.maxBodyBytes;
    if (typeof v !== "number" || !Number.isInteger(v) || v < MIN_BODY_BYTES || v > MAX_BODY_BYTES) {
      return { error: `maxBodyBytes must be a whole number from ${MIN_BODY_BYTES} to ${MAX_BODY_BYTES}` };
    }
    patch.maxBodyBytes = v;
  }
  return { patch };
}
function saveConfig(opts, body) {
  const file = opts.configFile ?? CONFIG_FILE;
  const { raw, invalid } = readRawConfig(file);
  if (invalid) {
    return { status: 409, body: { error: { message: `${file} is not valid JSON; fix or delete it by hand before saving from the UI` } } };
  }
  const result = validatePatch(body, opts.catalog.upstreamIds);
  if ("error" in result) return { status: 400, body: { error: { message: result.error } } };
  const current = raw ?? {};
  const { security: securityPatch, ...rest } = result.patch;
  const merged = { ...current, ...rest };
  if (securityPatch) merged.security = { ...isRecord(current.security) ? current.security : {}, ...securityPatch };
  const nextSecurity = normalizeSecurityConfig(merged.security);
  const nextBind = typeof merged.bind === "string" ? merged.bind : opts.bind;
  try {
    assertBindAllowed(nextBind, nextSecurity, opts.flags?.unsafeAllowNonLoopback);
    assertBindAllowed(opts.bind, nextSecurity, opts.flags?.unsafeAllowNonLoopback);
  } catch (err) {
    return { status: 400, body: { error: { message: err.message } } };
  }
  writeJsonAtomic(file, merged);
  const before = JSON.stringify(opts.security);
  Object.assign(opts.security, nextSecurity);
  if (JSON.stringify(opts.security) !== before) void opts.catalog.refresh();
  return { status: 200, body: configView(opts) };
}
function tailLines(file, max) {
  let fd;
  try {
    fd = fs9.openSync(file, "r");
  } catch {
    return [];
  }
  try {
    const size = fs9.fstatSync(fd).size;
    const start = Math.max(0, size - LOG_TAIL_BYTES);
    const buf = Buffer.alloc(size - start);
    fs9.readSync(fd, buf, 0, buf.length, start);
    const lines = buf.toString("utf8").split("\n");
    if (start > 0) lines.shift();
    if (lines[lines.length - 1] === "") lines.pop();
    return lines.slice(-max);
  } finally {
    fs9.closeSync(fd);
  }
}
function setupBaseUrl(bind, port) {
  const unspecified = bind === "0.0.0.0" || bind === "::" || bind === "localhost";
  const host = unspecified || isLoopbackBind(bind) ? "127.0.0.1" : bind;
  return `http://${isIP2(host) === 6 ? `[${host}]` : host}:${port}/v1`;
}
function applySetup(opts, body) {
  if (!isRecord(body) || typeof body.id !== "string") return { status: 400, body: { error: { message: "missing harness id" } } };
  const adapter = findAdapter(body.id);
  if (!adapter) return { status: 404, body: { error: { message: `harness "${body.id}" not found` } } };
  let model;
  if (body.model !== void 0 && body.model !== "") {
    const def = typeof body.model === "string" ? opts.catalog.resolve(body.model) : void 0;
    if (!def) return { status: 400, body: { error: { message: `unknown model: ${String(body.model)}` } } };
    if (!opts.catalog.servableModels.includes(def)) {
      return { status: 400, body: { error: { message: `model ${def.id} is served by ${def.source}, which strict mode blocks` } } };
    }
    model = body.model;
  }
  const list = (v) => Array.isArray(v) && v.every((x) => typeof x === "string") ? v : v === void 0 ? [] : null;
  const ids = list(body.models);
  const upstreams = list(body.upstreams);
  if (!ids || !upstreams) return { status: 400, body: { error: { message: "models and upstreams must be lists of ids" } } };
  const ctx = buildSetupContext(setupBaseUrl(opts.bind, opts.port), opts.catalog.servableModels, { model, models: ids, upstreams });
  if ("error" in ctx) return { status: 400, body: { error: { message: ctx.error } } };
  const lines = [];
  const report = (line) => lines.push(line);
  let failed = 0;
  try {
    if (body.undo === true) undoAdapter(adapter, ctx, report);
    else failed = applyAdapter(adapter, ctx, report);
  } catch (err) {
    lines.push({ kind: "error", text: err.message });
    failed++;
  }
  const status = harnessStatuses().find((h) => h.id === adapter.id);
  return { status: 200, body: { ok: failed === 0, lines, harness: status } };
}
function portFree(port, bind) {
  return new Promise((resolve) => {
    const probe = net.createServer();
    probe.once("error", () => resolve(false));
    probe.listen(port, bind, () => probe.close(() => resolve(true)));
  });
}
function createBackup(opts, rawUrl) {
  const file = opts.configFile ?? CONFIG_FILE;
  const config = loadConfig(file);
  let include = ["config", "activity", "relay"];
  if (rawUrl) {
    try {
      const parsed = new URL(rawUrl, "http://127.0.0.1");
      const incParam = parsed.searchParams.get("include");
      if (incParam) include = incParam.split(",").map((s) => s.trim().toLowerCase());
    } catch {
    }
  }
  const inc = new Set(include);
  const data = {};
  if (inc.has("config")) {
    data.config = config;
  }
  if (inc.has("activity")) {
    data.activity = {
      updatedAt: Date.now(),
      events: opts.activity ? opts.activity.getAllEvents() : []
    };
  }
  if (inc.has("relay")) {
    data.relay = loadRelayState();
  }
  return {
    version: 1,
    generator: "bansos-router",
    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
    daemon: {
      version: VERSION,
      platform: process.platform
    },
    data
  };
}
function restoreBackup(opts, body) {
  if (!isRecord(body)) return { status: 400, body: { error: { message: "body must be a JSON object" } } };
  const rawData = isRecord(body.data) ? body.data : body;
  const options = isRecord(body.options) ? body.options : {};
  const wantConfig = options.restoreConfig !== false && rawData.config !== void 0;
  const wantActivity = options.restoreActivity !== false && (rawData.activity !== void 0 || Array.isArray(rawData.events));
  const wantRelay = options.restoreRelay !== false && rawData.relay !== void 0;
  let configRestored = false;
  let restartRequired = [];
  let activityCount = 0;
  let relayRestored = false;
  if (wantConfig) {
    if (!isRecord(rawData.config)) return { status: 400, body: { error: { message: "data.config must be an object" } } };
    const res = saveConfig(opts, rawData.config);
    if (res.status !== 200) return res;
    configRestored = true;
    const resBody = res.body;
    if (Array.isArray(resBody?.restartRequired)) restartRequired = resBody.restartRequired;
  }
  if (wantActivity && opts.activity) {
    let eventsList = [];
    if (isRecord(rawData.activity) && Array.isArray(rawData.activity.events)) {
      eventsList = rawData.activity.events;
    } else if (Array.isArray(rawData.events)) {
      eventsList = rawData.events;
    }
    const replace = Boolean(options.replaceActivity);
    activityCount = opts.activity.importEvents(eventsList, replace);
  }
  if (wantRelay && isRecord(rawData.relay)) {
    const r = rawData.relay;
    saveRelayState({
      enabled: Boolean(r.enabled),
      url: typeof r.url === "string" ? r.url : "",
      relays: Array.isArray(r.relays) ? r.relays : []
    });
    relayRestored = true;
  }
  return {
    status: 200,
    body: {
      ok: true,
      restored: {
        config: configRestored,
        activityCount,
        relay: relayRestored
      },
      restartRequired
    }
  };
}
async function handleAdmin(req, method, url, rawUrl, readBody2, opts) {
  const readJson2 = async () => {
    const text = await readBody2();
    if (!text) return { ok: true, value: {} };
    try {
      return { ok: true, value: JSON.parse(text) };
    } catch {
      return { ok: false };
    }
  };
  const badJson = { status: 400, body: { error: { message: "invalid json body" } } };
  if (url === "/bansos/config" && method === "GET") return { status: 200, body: configView(opts) };
  if (url === "/bansos/config" && method === "POST") {
    const parsed = await readJson2();
    return parsed.ok ? saveConfig(opts, parsed.value) : badJson;
  }
  if (url === "/bansos/restart" && method === "POST") {
    if (!opts.restart) return { status: 501, body: { error: { message: "this daemon cannot restart itself" } } };
    const saved = loadConfig(opts.configFile ?? CONFIG_FILE);
    const requested = opts.requestedPort ?? opts.port;
    const port = opts.flags?.port ? requested : saved.port;
    const bind = opts.flags?.bind ? opts.bind : saved.bind;
    const moving = port !== requested || bind !== opts.bind;
    if (moving && !await portFree(port, bind)) {
      return { status: 409, body: { error: { message: `port ${port} on ${bind} is already in use; pick another port and save again` } } };
    }
    return { status: 202, body: { restarting: true, port: moving ? port : opts.port, bind }, after: opts.restart };
  }
  if (url === "/bansos/logs" && method === "GET") {
    const requested = Number(new URL(rawUrl, "http://127.0.0.1").searchParams.get("lines"));
    const max = Number.isInteger(requested) && requested > 0 ? Math.min(requested, MAX_LOG_LINES) : 200;
    const file = opts.logFile ?? LOG_FILE;
    return { status: 200, body: { path: file, lines: tailLines(file, max) } };
  }
  if (url === "/bansos/doctor" && method === "GET") {
    return {
      status: 200,
      body: {
        version: VERSION,
        update: await checkUpdate(),
        configWarnings: loadConfigWarnings(opts.configFile ?? CONFIG_FILE),
        security: securityView(opts.security),
        harnesses: harnessStatuses()
      }
    };
  }
  if (url === "/bansos/autostart" && method === "GET") return { status: 200, body: autostartStatus(opts.autostartEnv) };
  if (url === "/bansos/autostart" && method === "POST") {
    const parsed = await readJson2();
    if (!parsed.ok) return badJson;
    const enabled = isRecord(parsed.value) ? parsed.value.enabled : void 0;
    if (typeof enabled !== "boolean") return { status: 400, body: { error: { message: "enabled must be true or false" } } };
    try {
      return { status: 200, body: enabled ? enableAutostart(false, opts.autostartEnv) : disableAutostart(opts.autostartEnv) };
    } catch (err) {
      return { status: 409, body: { error: { message: err.message } } };
    }
  }
  if (url === "/bansos/adapters/apply" && method === "POST") {
    const parsed = await readJson2();
    return parsed.ok ? applySetup(opts, parsed.value) : badJson;
  }
  if (url === "/bansos/backup" && method === "GET") {
    return { status: 200, body: createBackup(opts, rawUrl) };
  }
  if (url === "/bansos/restore" && method === "POST") {
    const parsed = await readJson2();
    return parsed.ok ? restoreBackup(opts, parsed.value) : badJson;
  }
  if (url === "/bansos/activity/clear" && method === "POST") {
    opts.activity?.clear();
    return { status: 200, body: { ok: true, cleared: true } };
  }
  return { status: 405, body: { error: { message: "method not allowed" } } };
}

// src/daemon/api-keys.ts
init_state();
import crypto from "node:crypto";
import fs10 from "node:fs";
import path9 from "node:path";
var FILE = path9.join(BANSOS_DIR, "api-keys.json");
function load() {
  try {
    const x = JSON.parse(fs10.readFileSync(FILE, "utf8"));
    return Array.isArray(x) ? x : [];
  } catch {
    return [];
  }
}
function save(keys) {
  ensureBansosDir();
  writeJsonAtomic(FILE, keys);
}
function digest(key) {
  return crypto.createHash("sha256").update(key).digest("hex");
}
function listApiKeys() {
  return load().map(({ hash: _hash, ...x }) => ({ ...x, legacy: !x.key }));
}
function createApiKey(name, customKey) {
  const key = (customKey ?? "").trim() || `sk-bansos-${crypto.randomBytes(24).toString("base64url")}`;
  const keys = load();
  if (keys.some((k) => k.hash === digest(key))) throw new Error("API key already exists");
  const rec = { id: crypto.randomUUID(), name: name.trim() || "Default", key, prefix: key.slice(0, 18), hash: digest(key), createdAt: (/* @__PURE__ */ new Date()).toISOString() };
  save([...keys, rec]);
  const { hash: _hash, ...record } = rec;
  return { key, record };
}
function deleteApiKey(id) {
  const keys = load(), next = keys.filter((k) => k.id !== id);
  if (next.length === keys.length) return false;
  save(next);
  return true;
}
function hasApiKeys() {
  return load().length > 0;
}
function verifyApiKey(value) {
  if (!value) return false;
  const hash = digest(value), keys = load(), i = keys.findIndex((k) => k.hash === hash);
  if (i < 0) return false;
  const rec = keys[i];
  if (!rec.lastUsedAt || Date.now() - Date.parse(rec.lastUsedAt) > 6e4) {
    rec.lastUsedAt = (/* @__PURE__ */ new Date()).toISOString();
    save(keys);
  }
  return true;
}

// src/daemon/combos.ts
init_state();
import fs11 from "node:fs";
import path10 from "node:path";
var FILE2 = path10.join(BANSOS_DIR, "combos.json");
function listCombos() {
  try {
    const x = JSON.parse(fs11.readFileSync(FILE2, "utf8"));
    return Array.isArray(x) ? x : [];
  } catch {
    return [];
  }
}
function save2(x) {
  ensureBansosDir();
  writeJsonAtomic(FILE2, x);
}
function upsertCombo(input) {
  const id = String(input.id || "").trim();
  if (!/^[a-zA-Z0-9_-]{1,50}$/.test(id)) throw new Error("combo id must use letters, numbers, _ or -");
  const models = Array.isArray(input.models) ? input.models.map(String).map((x) => x.trim()).filter(Boolean) : [];
  if (!models.length) throw new Error("combo requires at least one model");
  const all = listCombos(), i = all.findIndex((x) => x.id === id), now = (/* @__PURE__ */ new Date()).toISOString();
  const row = { id, name: String(input.name || id).trim(), models: [...new Set(models)], enabled: input.enabled !== false, createdAt: i >= 0 ? all[i].createdAt : now, updatedAt: now };
  if (i >= 0) all[i] = row;
  else all.push(row);
  save2(all);
  return row;
}
function deleteCombo(id) {
  const all = listCombos(), next = all.filter((x) => x.id !== id);
  if (next.length === all.length) return false;
  save2(next);
  return true;
}
function comboModels(id) {
  return listCombos().find((x) => x.enabled && (x.id === id || `combo/${x.id}` === id))?.models ?? null;
}

// src/daemon/server.ts
var activity = new ActivityStore();
function providerCounts(catalog, security) {
  const counts = /* @__PURE__ */ new Map();
  for (const m of catalog.models) counts.set(m.source, (counts.get(m.source) ?? 0) + 1);
  return [...counts].map(([id, models]) => ({ id, models, allowed: isUpstreamAllowed(security, id) }));
}
var ALLOWED_METHODS = /* @__PURE__ */ new Set(["GET", "POST", "OPTIONS"]);
var DEFAULT_BODY_CAP_BYTES = 10 * 1024 * 1024;
var bodyCapBytes = DEFAULT_BODY_CAP_BYTES;
function clampMaxTokens(body, model) {
  if (!Number.isFinite(model.maxTokens) || model.maxTokens <= 0) return body;
  if (typeof body.max_completion_tokens === "number" && body.max_completion_tokens > model.maxTokens) {
    body.max_completion_tokens = model.maxTokens;
  }
  if (typeof body.max_tokens === "number" && body.max_tokens > model.maxTokens) {
    body.max_tokens = model.maxTokens;
  }
  return body;
}
function applyRelayMutation(initialState, body) {
  let current = {
    ...initialState,
    relays: initialState.relays.map((r) => ({ ...r }))
  };
  if (Array.isArray(body.relays)) {
    const relays = [];
    for (const entry of body.relays) {
      if (!entry || typeof entry !== "object") return { error: "relays must be an array of objects" };
      const rec = entry;
      if (!isValidRelayUrl(rec.url)) return { error: "invalid relay url in relays list" };
      relays.push({
        url: rec.url.trim(),
        ...typeof rec.label === "string" && rec.label.trim() ? { label: rec.label.trim().slice(0, 100) } : {},
        ...typeof rec.addedAt === "string" ? { addedAt: rec.addedAt } : {}
      });
    }
    current.relays = relays;
  }
  if (typeof body.enabled === "boolean") {
    current.enabled = body.enabled;
  }
  const label = typeof body.label === "string" ? body.label.trim().slice(0, 100) || void 0 : void 0;
  const hasUrl = typeof body.url === "string" && body.url.trim() !== "";
  if (hasUrl && !isValidRelayUrl(body.url)) return { error: "invalid relay url" };
  if (hasUrl) {
    const cleanUrl = body.url.trim();
    if (!body.action) {
      current.url = cleanUrl;
      if (!current.relays.some((r) => r.url === cleanUrl)) {
        current = addRelay(current, cleanUrl, label);
      }
    } else if (body.action === "add") {
      current = addRelay(current, cleanUrl, label);
    } else if (body.action === "remove") {
      current = removeRelay(current, cleanUrl);
    }
  }
  return current;
}
var API_EXACT_PATHS = /* @__PURE__ */ new Set([
  "/healthz",
  "/healthz/",
  "/bansos/status",
  "/bansos/status/",
  "/bansos/refresh",
  "/bansos/refresh/",
  "/bansos/adapters",
  "/bansos/adapters/",
  "/bansos/adapters/render",
  "/bansos/adapters/render/",
  "/bansos/relay",
  "/bansos/relay/",
  "/bansos/relay/probe",
  "/bansos/relay/probe/",
  "/bansos/api-keys",
  "/bansos/api-keys/",
  "/bansos/combos",
  "/bansos/combos/",
  "/bansos/usage",
  "/bansos/usage/",
  "/bansos/events",
  "/bansos/events/",
  ...[...ADMIN_PATHS].flatMap((p) => [p, `${p}/`]),
  "/chat/completions",
  "/chat/completions/",
  "/messages",
  "/messages/",
  "/responses",
  "/responses/",
  "/models",
  "/models/",
  "/v1/chat/completions",
  "/v1/chat/completions/",
  "/v1/messages",
  "/v1/messages/",
  "/v1/responses",
  "/v1/responses/",
  "/v1/models",
  "/v1/models/"
]);
var MAX_FAILOVER_RETRIES = 2;
function corsHeadersForOrigin(originHeader) {
  if (!originHeader) return {};
  let hostname = "";
  try {
    hostname = new URL(originHeader).hostname;
  } catch {
    return {};
  }
  if (!isLoopbackBind(hostname)) return {};
  return {
    "access-control-allow-origin": originHeader,
    "access-control-allow-methods": "GET, POST, OPTIONS",
    "access-control-allow-headers": "*",
    "access-control-max-age": "86400",
    vary: "Origin"
  };
}
function corsFor(res) {
  return res.bansosCors ?? {};
}
var CLIENT_HEADER = "x-bansos-client";
function detectHarness(req) {
  const claimed = String(req.headers[CLIENT_HEADER] ?? "").trim().toLowerCase();
  if (/^[a-z0-9][a-z0-9._/-]{0,31}$/.test(claimed)) return claimed;
  const ua = (req.headers["user-agent"] || "").toLowerCase();
  if (ua.includes("oh-my-pi") || ua.includes("omp/") || ua.includes("omp ") || ua === "omp") {
    return "omp";
  }
  if (ua.startsWith("pi/") || ua.includes("pi/") || ua.includes("pi-coding-agent") || ua.includes("pi-bansos")) {
    return "pi";
  }
  if (ua.includes("claude-code") || ua.includes("claude_code") || ua.includes("claude-cli") || ua.includes("anthropic")) {
    return "claude-code";
  }
  if (ua.includes("opencode")) return "opencode";
  if (ua.includes("aider")) return "aider";
  if (ua.includes("codex")) return "codex";
  if (ua.includes("goose")) return "goose";
  if (ua.includes("cline")) return "cline";
  if (ua.includes("roo")) return "roo";
  if (ua.includes("continue")) return "continue";
  if (ua.includes("hermes")) return "hermes";
  if (ua.includes("jcode")) return "jcode";
  if (ua.includes("openclaw")) return "openclaw";
  if (ua.includes("deepseek") || ua.includes("dsh/")) return "dsh";
  if (ua.includes("9router")) return "9router";
  if (ua.includes("litellm")) return "litellm";
  if (ua.includes("curl")) return "curl";
  return "gateway";
}
var GATE_TOOLSET_RE = /free usage limit/i;
var ownAddresses = null;
function isOwnAddress(hostname) {
  if (ownAddresses === null) {
    const set = /* @__PURE__ */ new Set();
    for (const ifaces of Object.values(os6.networkInterfaces())) {
      for (const iface of ifaces ?? []) set.add(iface.address.toLowerCase());
    }
    ownAddresses = set;
  }
  return ownAddresses.has(hostname.toLowerCase());
}
function isHostTrusted(req) {
  const host = req.headers.host;
  if (!host) return false;
  let hostname = "";
  try {
    hostname = new URL(`http://${host}`).hostname;
  } catch {
    return false;
  }
  if (isLoopbackBind(hostname)) return true;
  const peer = req.socket.remoteAddress ?? "";
  if (isLoopbackBind(peer)) return isOwnAddress(hostname);
  return true;
}
function isOriginTrusted(req) {
  const origin = req.headers.origin;
  if (origin === void 0) return true;
  let url;
  try {
    url = new URL(origin);
  } catch {
    return false;
  }
  if (isLoopbackBind(url.hostname)) return true;
  return url.host === req.headers.host;
}
function isValidRelayUrl(value) {
  if (typeof value !== "string") return false;
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > 2048) return false;
  let u;
  try {
    u = new URL(trimmed);
  } catch {
    return false;
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") return false;
  if (u.username || u.password) return false;
  return u.hostname.length > 0;
}
var MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
  ".woff": "font/woff",
  ".ttf": "font/ttf"
};
function getUiDistDir() {
  try {
    const currentFile = fileURLToPath(import.meta.url);
    const currentDir = path11.dirname(currentFile);
    const candidate1 = path11.resolve(currentDir, "../../dist/ui");
    if (fs12.existsSync(candidate1)) return candidate1;
    const candidate2 = path11.resolve(currentDir, "../ui");
    if (fs12.existsSync(candidate2)) return candidate2;
  } catch {
  }
  const candidate3 = path11.resolve(process.cwd(), "dist/ui");
  if (fs12.existsSync(candidate3)) return candidate3;
  return path11.resolve(process.cwd(), "dist/ui");
}
function securityHeaders() {
  return {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "content-security-policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
  };
}
function serveStaticUi(res, reqPath) {
  const uiDir = getUiDistDir();
  let relativePath = reqPath.replace(/^\/+/, "");
  if (!relativePath || relativePath === "index.html") {
    relativePath = "index.html";
  }
  const filePath = path11.join(uiDir, relativePath);
  if (!filePath.startsWith(uiDir)) {
    sendJson(res, 403, { error: { message: "forbidden" } });
    return;
  }
  if (fs12.existsSync(filePath) && fs12.statSync(filePath).isFile()) {
    const ext = path11.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] ?? "application/octet-stream";
    const cacheControl = relativePath.startsWith("assets/") ? "public, max-age=31536000, immutable" : relativePath === "index.html" ? "no-cache" : "public, max-age=3600";
    res.writeHead(200, {
      "content-type": contentType,
      "cache-control": cacheControl,
      ...securityHeaders(),
      ...corsFor(res)
    });
    const rs = fs12.createReadStream(filePath);
    rs.on("error", () => res.destroy());
    rs.pipe(res);
    return;
  }
  if (relativePath.startsWith("assets/") || relativePath.startsWith("fonts/") || relativePath.startsWith("harnesses/")) {
    sendJson(res, 404, { error: { message: "asset not found" } });
    return;
  }
  const indexPath = path11.join(uiDir, "index.html");
  if (fs12.existsSync(indexPath) && fs12.statSync(indexPath).isFile()) {
    res.writeHead(200, {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-cache",
      ...securityHeaders(),
      ...corsFor(res)
    });
    const rs = fs12.createReadStream(indexPath);
    rs.on("error", () => res.destroy());
    rs.pipe(res);
    return;
  }
  const fallbackHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>bansos-router</title>
</head>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;background:#111113;color:#f4f4f6;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:1.5rem;box-sizing:border-box;">
  <div style="max-width:460px;width:100%;text-align:center;background:#16161a;border:1px solid #23232a;border-radius:1rem;padding:2.5rem 2rem;box-shadow:0 20px 25px -5px rgba(0,0,0,0.5);">
    <div style="display:inline-flex;align-items:center;justify-content:center;width:3rem;height:3rem;border-radius:0.75rem;background:#202028;border:1px solid #2c2c36;margin-bottom:1.25rem;">
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>
    </div>
    <h1 style="font-size:1.25rem;font-weight:700;margin:0 0 0.5rem 0;color:#ffffff;letter-spacing:-0.025em;">bansos-router daemon is online</h1>
    <p style="font-size:0.875rem;color:#9393a0;margin:0 0 1.5rem 0;line-height:1.5;">Web UI bundle is not built yet. Run <code style="background:#202028;border:1px solid #2c2c36;padding:0.2rem 0.4rem;border-radius:0.375rem;color:#60a5fa;font-family:monospace;font-size:0.8125rem;">npm run build</code> to compile the dashboard.</p>
    <div style="font-size:0.75rem;color:#71717a;border-top:1px solid #23232a;padding-top:1rem;line-height:1.6;">
      API live at <span style="font-family:monospace;color:#a1a1aa;">/v1/chat/completions</span> & <span style="font-family:monospace;color:#a1a1aa;">/v1/models</span>
    </div>
  </div>
</body>
</html>`;
  res.writeHead(200, {
    "content-type": "text/html; charset=utf-8",
    "content-length": Buffer.byteLength(fallbackHtml),
    ...securityHeaders(),
    ...corsFor(res)
  });
  res.end(fallbackHtml);
}
function validatePath(rawUrl) {
  const pathname = rawUrl.split("?")[0] ?? "/";
  const cleaned = pathname.replace(/^\/+/, "");
  const withSlash = `/${cleaned}`;
  if (withSlash.includes("..")) return false;
  try {
    const decoded = decodeURIComponent(withSlash);
    if (decoded !== withSlash) return false;
  } catch {
    return false;
  }
  return true;
}
function probeTargetAllowed(targetUrl, state) {
  const trimmed = targetUrl.trim();
  let u;
  try {
    u = new URL(trimmed);
  } catch {
    return { allowed: false, reason: "invalid url" };
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    return { allowed: false, reason: "only http(s) targets can be probed" };
  }
  if (u.username || u.password) {
    return { allowed: false, reason: "url must not contain credentials" };
  }
  if (state.url === trimmed || state.relays.some((r) => r.url === trimmed)) {
    return { allowed: true };
  }
  if (isSensitiveNetworkHost(u.hostname)) {
    return { allowed: false, reason: "target resolves to a loopback/private network address" };
  }
  return { allowed: true };
}
function runRequest(promise, res, log, label) {
  res.on("error", () => {
  });
  promise.catch(() => {
    log.warn(`${label}: request failed`, { status: 502 });
    try {
      if (res.headersSent) res.end();
      else {
        sendJson(res, 502, {
          error: { message: "upstream request failed", type: "upstream_error", status: 502 }
        });
      }
    } catch {
    }
  });
}
function clientDisconnectSignal(res) {
  const controller = new AbortController();
  res.on("close", () => {
    if (!res.writableFinished) controller.abort();
  });
  return controller.signal;
}
function sendJson(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(payload),
    ...corsFor(res)
  });
  res.end(payload);
}
async function readBody(req, cap = bodyCapBytes) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    const buf = chunk;
    size += buf.length;
    if (size > cap) throw new Error("request body too large");
    chunks.push(buf);
  }
  return Buffer.concat(chunks).toString("utf8");
}
function asRecord(value) {
  return typeof value === "object" && value !== null ? value : null;
}
function extractUsage(json) {
  const usage2 = asRecord(asRecord(json)?.usage);
  if (!usage2) return null;
  const prompt = usage2.prompt_tokens ?? usage2.input_tokens;
  const completion = usage2.completion_tokens ?? usage2.output_tokens;
  if (typeof prompt !== "number" || typeof completion !== "number") return null;
  const cached = asRecord(usage2.prompt_tokens_details)?.cached_tokens ?? asRecord(usage2.input_tokens_details)?.cached_tokens ?? usage2.cache_read_input_tokens;
  return {
    inputTokens: prompt,
    outputTokens: completion,
    ...typeof cached === "number" ? { cachedTokens: cached } : {}
  };
}
function recordCompletion(store, log, kind, doneMsg, done) {
  const { model, requestedModel, upstream, usage: usage2, startedAt, client } = done;
  const durationMs = Date.now() - startedAt;
  const failoverFrom = model !== requestedModel ? requestedModel : void 0;
  log.info(doneMsg, {
    model,
    upstream,
    durationMs,
    inputTokens: usage2?.inputTokens ?? 0,
    outputTokens: usage2?.outputTokens ?? 0,
    ...usage2?.cachedTokens === void 0 ? {} : { cachedTokens: usage2.cachedTokens },
    ...failoverFrom ? { failoverFrom } : {}
  });
  store.record({
    kind,
    model,
    requestedModel,
    upstream,
    inputTokens: usage2?.inputTokens ?? 0,
    outputTokens: usage2?.outputTokens ?? 0,
    cachedTokens: usage2?.cachedTokens ?? 0,
    durationMs,
    status: "ok",
    ...failoverFrom ? { failoverFrom } : {},
    ...client ? { client } : {}
  });
}
function findUsageObject(tail) {
  let from = 0;
  while (true) {
    const at = tail.indexOf('"usage"', from);
    if (at < 0) return null;
    from = at + 7;
    const brace = tail.indexOf("{", at);
    if (brace < 0) return null;
    let depth = 0;
    for (let i = brace; i < tail.length; i++) {
      const ch = tail[i];
      if (ch === "{") depth++;
      else if (ch === "}") {
        depth--;
        if (depth === 0) {
          try {
            const candidate = JSON.parse(tail.slice(brace, i + 1));
            const prompt = candidate.prompt_tokens ?? candidate.input_tokens;
            if (typeof prompt === "number") return candidate;
          } catch {
          }
          break;
        }
      }
    }
  }
}
function inspectChatFrame(frame, state) {
  let finished = false;
  for (const line of frame.split("\n")) {
    if (!line.startsWith("data:")) continue;
    const payload = line.slice(5).trim();
    if (payload === "[DONE]") continue;
    let json;
    try {
      json = JSON.parse(payload);
    } catch {
      continue;
    }
    if (json?.id || json?.model) {
      state.envelope = { id: json.id, model: json.model, created: json.created };
    }
    const choice = json?.choices?.[0];
    if (choice?.finish_reason) finished = true;
    const delta = choice?.delta;
    if (!delta || typeof delta !== "object") continue;
    if (Array.isArray(delta.tool_calls) && delta.tool_calls.length > 0) state.sawToolCalls = true;
    if (typeof delta.content === "string" && delta.content.length > 0) {
      state.sawContent = true;
      continue;
    }
    const reasoning = typeof delta.reasoning_content === "string" && delta.reasoning_content.length > 0 ? delta.reasoning_content : typeof delta.reasoning === "string" && delta.reasoning.length > 0 ? delta.reasoning : "";
    state.reasoning += reasoning;
  }
  return { finished };
}
function foldedContentFrame(state) {
  return `data: ${JSON.stringify({
    id: state.envelope.id ?? "chatcmpl-reasoning-fold",
    object: "chat.completion.chunk",
    created: state.envelope.created ?? Math.floor(Date.now() / 1e3),
    model: state.envelope.model ?? "",
    choices: [{ index: 0, delta: { role: "assistant", content: state.reasoning }, finish_reason: null }]
  })}

`;
}
function declaredToolNames(body) {
  const tools = body?.tools;
  return new Set(
    (Array.isArray(tools) ? tools : []).map((t) => t?.function?.name ?? t?.name).filter((n) => typeof n === "string")
  );
}
function filterInjectedToolCallsTransform(callerTools) {
  const verdict = /* @__PURE__ */ new Map();
  const bridged = /* @__PURE__ */ new Map();
  let forwarded = false;
  let envelope = {};
  const flushBridged = () => {
    const toolCalls = [];
    for (const [index, b] of bridged) {
      const id = b.id ?? `call_${index}_${Date.now().toString(36)}`;
      const call = b.translate(b.args, id);
      if (call) toolCalls.push({ index, id, type: "function", function: call });
    }
    bridged.clear();
    if (toolCalls.length === 0) return "";
    forwarded = true;
    return `data: ${JSON.stringify({
      id: envelope.id ?? "chatcmpl-bridge",
      object: "chat.completion.chunk",
      created: envelope.created ?? Math.floor(Date.now() / 1e3),
      model: envelope.model ?? "",
      choices: [{ index: 0, delta: { tool_calls: toolCalls }, finish_reason: null }]
    })}

`;
  };
  const rewriteFrame = (frame) => {
    const line = frame.trimStart();
    if (!line.startsWith("data:")) return frame;
    const payload = line.slice(5).trim();
    if (payload === "[DONE]") return flushBridged() + frame;
    if (payload === "") return frame;
    let json;
    try {
      json = JSON.parse(payload);
    } catch {
      return frame;
    }
    if (json?.id || json?.model) envelope = { id: json.id, model: json.model, created: json.created };
    const choice = json?.choices?.[0];
    if (!choice) return frame;
    let changed = false;
    const calls = choice.delta?.tool_calls;
    if (Array.isArray(calls)) {
      const kept = calls.filter((tc) => {
        const name = tc?.function?.name;
        if (typeof name === "string" && !verdict.has(tc.index)) {
          const own = callerTools.has(name);
          verdict.set(tc.index, own);
          const translate = own ? null : callerTools.bridge?.(name);
          if (translate) bridged.set(tc.index, { id: tc.id, args: "", translate });
        }
        const b = bridged.get(tc.index);
        if (b && typeof tc?.function?.arguments === "string") b.args += tc.function.arguments;
        return verdict.get(tc.index) ?? true;
      });
      if (kept.length > 0) forwarded = true;
      if (kept.length !== calls.length) {
        changed = true;
        if (kept.length === 0) delete choice.delta.tool_calls;
        else choice.delta.tool_calls = kept;
      }
    }
    let prefix = "";
    if (choice.finish_reason) {
      prefix = flushBridged();
      if (prefix && choice.finish_reason !== "tool_calls") {
        choice.finish_reason = "tool_calls";
        changed = true;
      }
    }
    if (choice.finish_reason === "tool_calls" && !forwarded) {
      choice.finish_reason = "stop";
      changed = true;
    }
    return prefix + (changed ? `data: ${JSON.stringify(json)}

` : frame);
  };
  const splitter = createSseFrameSplitter();
  return new Transform2({
    transform(chunk, _enc, cb) {
      for (const frame of splitter.push(chunk)) this.push(Buffer.from(rewriteFrame(frame), "utf8"));
      cb();
    },
    flush(cb) {
      const rest = splitter.rest();
      if (rest) this.push(Buffer.from(rewriteFrame(rest), "utf8"));
      const tail = flushBridged();
      if (tail) this.push(Buffer.from(tail, "utf8"));
      cb();
    }
  });
}
function reasoningToContentTransform() {
  const splitter = createSseFrameSplitter();
  let folded = false;
  const state = { sawContent: false, sawToolCalls: false, reasoning: "", envelope: {} };
  const foldIfNothingElse = (push) => {
    if (folded) return;
    folded = true;
    if (!state.sawContent && !state.sawToolCalls && state.reasoning.length > 0) push(foldedContentFrame(state));
  };
  return new Transform2({
    transform(chunk, _enc, cb) {
      for (const frame of splitter.push(chunk)) {
        if (/^data: ?\[DONE\]/.test(frame) || inspectChatFrame(frame, state).finished) {
          foldIfNothingElse((f) => this.push(Buffer.from(f, "utf8")));
        }
        this.push(Buffer.from(frame, "utf8"));
      }
      cb();
    },
    flush(cb) {
      const rest = splitter.rest();
      if (rest) {
        if (inspectChatFrame(rest, state).finished) foldIfNothingElse((f) => this.push(Buffer.from(f, "utf8")));
        this.push(Buffer.from(rest, "utf8"));
      }
      foldIfNothingElse((f) => this.push(Buffer.from(f, "utf8")));
      cb();
    }
  });
}
function logUsageTransform(model, upstream, log, startedAt, requestedModel, activity2, kind = "chat", client, booked) {
  let tail = "";
  let reported = false;
  return new Transform2({
    transform(chunk, _enc, cb) {
      tail = `${tail}${chunk.toString("utf8")}`.slice(-16384);
      if (!reported && tail.includes('"usage"')) {
        const obj = findUsageObject(tail);
        if (obj) {
          const usage2 = extractUsage({ usage: obj });
          if (usage2) {
            reported = true;
            if (booked) booked.recorded = true;
            log.info("chat done", { model, upstream, durationMs: Date.now() - startedAt, ...usage2 });
            activity2?.record({
              kind,
              model,
              requestedModel: requestedModel ?? model,
              upstream,
              inputTokens: usage2.inputTokens,
              outputTokens: usage2.outputTokens,
              cachedTokens: usage2.cachedTokens ?? 0,
              durationMs: Date.now() - startedAt,
              status: "ok",
              ...requestedModel && requestedModel !== model ? { failoverFrom: requestedModel } : {},
              ...client ? { client } : {}
            });
          }
        }
      }
      cb(null, chunk);
    },
    flush(cb) {
      if (!tail.includes("[DONE]")) {
        this.push("\ndata: [DONE]\n\n");
      }
      cb();
    }
  });
}
function parseRetryAfterMs(header, now = Date.now()) {
  if (!header) return void 0;
  const seconds = Number(header.trim());
  if (Number.isFinite(seconds)) return seconds > 0 ? seconds * 1e3 : void 0;
  const at = Date.parse(header);
  if (Number.isNaN(at)) return void 0;
  const delta = at - now;
  return delta > 0 ? delta : void 0;
}
function retryAfterFromMessage(message) {
  const m = /retry (?:after|in) (\d+(?:\.\d+)?) ?(s|sec|seconds?|ms|m|min|minutes?)\b/i.exec(message);
  if (!m) return void 0;
  const n = Number(m[1]);
  const unit = m[2].toLowerCase();
  if (unit === "ms") return n;
  if (unit.startsWith("m")) return n * 6e4;
  return n * 1e3;
}
var FAILOVER_CONTEXT_TOLERANCE = 0.9;
function pickFailover(catalog, origin, attempts = /* @__PURE__ */ new Set(), allowed = () => true) {
  let best;
  let bestShort = true;
  let bestGap = Number.POSITIVE_INFINITY;
  for (const candidate of catalog.models) {
    if (candidate.id === origin.id) continue;
    if (attempts.has(candidate.id)) continue;
    if (!allowed(candidate)) continue;
    if (candidate.source === origin.source) continue;
    if (candidate.reasoning !== origin.reasoning) continue;
    if (candidate.compat.supportsDeveloperRole !== origin.compat.supportsDeveloperRole) continue;
    if (candidate.compat.supportsReasoningEffort !== origin.compat.supportsReasoningEffort) continue;
    if (candidate.contextWindow < origin.contextWindow * FAILOVER_CONTEXT_TOLERANCE) continue;
    const short = candidate.contextWindow < origin.contextWindow;
    const gap = Math.abs(candidate.contextWindow - origin.contextWindow);
    if (best !== void 0) {
      if (short !== bestShort) {
        if (short) continue;
      } else if (gap !== bestGap) {
        if (gap > bestGap) continue;
      } else if (candidate.maxTokens <= best.maxTokens) continue;
    }
    best = candidate;
    bestShort = short;
    bestGap = gap;
  }
  return best;
}
function isExternalUpstream(upstream) {
  try {
    const url = new URL(upstream.chatUrl);
    return !isLoopbackBind(url.hostname);
  } catch {
    return true;
  }
}
function selectFailover(catalog, current, currentUpstream, tried, security, failoverAllowed, status, requestStartedAt, log, upstreamError) {
  if (!failoverAllowed) {
    log.warn("upstream rejected", {
      model: current.id,
      upstream: currentUpstream.id,
      status,
      durationMs: Date.now() - requestStartedAt,
      failoverBlocked: true,
      ...upstreamError ? { upstreamError } : {}
    });
    return void 0;
  }
  return pickFailover(catalog, current, tried, (candidate) => {
    if (catalog.isCoolingDown(candidate.id)) return false;
    const candidateUpstream = catalog.upstreamBySource(candidate.source);
    return Boolean(candidateUpstream && isUpstreamAllowed(security, candidateUpstream.id));
  });
}
function sseErrorMessage(json) {
  if (!json || typeof json !== "object") return null;
  if (json.error) return json.error.message ?? String(json.error);
  if (json.choices) return null;
  if (json.type === "error") return json.message ?? json.error?.message ?? "upstream stream error";
  if (json.type === "response.failed") return json.response?.error?.message ?? "upstream response failed";
  return null;
}
var SSE_PEEK_LIMIT = 65536;
var SSE_PEEK_TIMEOUT_MS = 5e3;
var VISION_UNSUPPORTED_RE = /(does not|doesn't|not) support(s)? (vision|image|images|image input|multimodal)|image input is not supported/i;
function hasImageInput(body) {
  const messages = body?.messages;
  if (!Array.isArray(messages)) return false;
  return messages.some(
    (m) => Array.isArray(m?.content) && m.content.some((p) => p?.type === "image_url" || p?.type === "input_image" || p?.type === "image")
  );
}
var TOOLS_UNSUPPORTED_RE = /(does not|doesn't|not) support(s)? (tools|tool use|tool calls|function calling)|support tool use/i;
async function peekStreamError(res, timeoutMs = SSE_PEEK_TIMEOUT_MS) {
  if (!res.body || (res.headers.get("content-type") ?? "").includes("json")) return { response: res, error: null };
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  const chunks = [];
  const deadline = Date.now() + timeoutMs;
  let text = "";
  let scanned = 0;
  let error = null;
  let done = false;
  let pending = null;
  scan: while (text.length < SSE_PEEK_LIMIT) {
    pending = reader.read();
    const wait = deadline - Date.now();
    if (wait <= 0) break;
    let timer;
    const next = await Promise.race([
      pending,
      new Promise((resolve) => timer = setTimeout(() => resolve(null), wait))
    ]);
    clearTimeout(timer);
    if (next === null) break;
    pending = null;
    if (next.done) {
      done = true;
      break;
    }
    chunks.push(next.value);
    text = (text + decoder.decode(next.value, { stream: true })).replace(/\r\n/g, "\n");
    let end = text.indexOf("\n\n", scanned);
    while (end !== -1) {
      const lines = text.slice(scanned, end).split("\n");
      scanned = end + 2;
      for (const line of lines) {
        if (!line.startsWith("data:")) continue;
        const payload = line.slice(5).trim();
        if (!payload) continue;
        if (payload === "[DONE]") break scan;
        let json;
        try {
          json = JSON.parse(payload);
        } catch {
          break scan;
        }
        error = sseErrorMessage(json);
        if (error || json?.choices || typeof json?.type === "string") break scan;
      }
      end = text.indexOf("\n\n", scanned);
    }
  }
  if (error) {
    void reader.cancel().catch(() => {
    });
    return { response: res, error };
  }
  const replay = new ReadableStream({
    start(controller) {
      for (const c of chunks) controller.enqueue(c);
      if (done) controller.close();
    },
    async pull(controller) {
      const next = await (pending ?? reader.read());
      pending = null;
      if (next.done) controller.close();
      else controller.enqueue(next.value);
    },
    cancel(reason) {
      return reader.cancel(reason);
    }
  });
  return {
    response: new Response(replay, { status: res.status, statusText: res.statusText, headers: res.headers }),
    error: null
  };
}
async function streamToChatResponse(upstreamRes, modelId, callerTools) {
  if (!upstreamRes.body) return upstreamRes;
  const text = await upstreamRes.text();
  if (text.trim().startsWith("{")) {
    return new Response(text, {
      status: upstreamRes.status,
      headers: { "content-type": "application/json" }
    });
  }
  const lines = text.split("\n");
  let content = "";
  let reasoning = "";
  let finishReason = "stop";
  let usage2 = void 0;
  let streamError = null;
  const calls = /* @__PURE__ */ new Map();
  for (const line of lines) {
    if (!line.startsWith("data:")) continue;
    const data = line.slice(5).trim();
    if (data === "[DONE]") break;
    try {
      const json = JSON.parse(data);
      streamError ??= sseErrorMessage(json);
      const choice = json.choices?.[0];
      if (choice?.delta?.content) content += choice.delta.content;
      if (choice?.delta?.reasoning) reasoning += choice.delta.reasoning;
      else if (choice?.delta?.reasoning_content) reasoning += choice.delta.reasoning_content;
      for (const tc of choice?.delta?.tool_calls ?? []) {
        const slot = calls.get(tc.index) ?? { args: "" };
        if (tc.id) slot.id = tc.id;
        if (tc.function?.name) slot.name = tc.function.name;
        if (tc.function?.arguments) slot.args += tc.function.arguments;
        calls.set(tc.index, slot);
      }
      if (choice?.finish_reason) finishReason = choice.finish_reason;
      if (json.usage) usage2 = json.usage;
    } catch {
    }
  }
  const toolCalls = [...calls.entries()].sort(([a], [b]) => a - b).flatMap(([, c]) => {
    if (c.name === void 0) return [];
    const id = c.id ?? `call_${Math.random().toString(36).slice(2, 12)}`;
    const fn = !callerTools || callerTools.has(c.name) ? { name: c.name, arguments: c.args || "{}" } : callerTools.bridge?.(c.name)?.(c.args, id);
    if (!fn) return [];
    return [{ id, type: "function", function: fn }];
  });
  if (toolCalls.length === 0 && finishReason === "tool_calls") finishReason = "stop";
  if (streamError && !content && !reasoning && toolCalls.length === 0) {
    return new Response(JSON.stringify({ error: { message: streamError, type: "upstream_error" } }), {
      status: 502,
      headers: { "content-type": "application/json" }
    });
  }
  return new Response(
    JSON.stringify({
      id: `chatcmpl-${Math.random().toString(36).slice(2, 12)}`,
      object: "chat.completion",
      created: Math.floor(Date.now() / 1e3),
      model: modelId,
      choices: [
        {
          index: 0,
          message: {
            role: "assistant",
            content,
            ...reasoning ? { [toolCalls.length < calls.size ? "reasoning_content" : "reasoning"]: reasoning } : {},
            ...toolCalls.length > 0 ? { tool_calls: toolCalls } : {}
          },
          finish_reason: finishReason
        }
      ],
      ...usage2 ? { usage: usage2 } : {}
    }),
    {
      status: upstreamRes.status,
      headers: { "content-type": "application/json" }
    }
  );
}
async function runChatForward(req, catalog, log, security, parsedModel, sanitizedBody, signal) {
  const ordered = comboModels(parsedModel);
  if (ordered) {
    let last = { status: 502, message: `all models in combo ${parsedModel} failed` };
    for (const candidate of ordered) {
      if (comboModels(candidate)) {
        last = { status: 400, message: "nested combos are not supported" };
        continue;
      }
      const result = await runChatForward(req, catalog, log, security, candidate, { ...sanitizedBody, model: candidate }, signal);
      if ("response" in result) return result;
      last = result;
    }
    return last;
  }
  const model = catalog.resolve(parsedModel);
  if (!model) {
    return { status: 400, message: `unknown model: ${parsedModel}` };
  }
  const upstream = catalog.upstreamBySource(model.source);
  if (!upstream) {
    return { status: 502, message: `no upstream for source: ${model.source}` };
  }
  const requestStartedAt = Date.now();
  const relay = loadRelayState();
  const failoverAllowed = req.headers["x-bansos-no-failover"] !== "1" && isCrossProviderFailoverAllowed(security);
  const tried = /* @__PURE__ */ new Set([model.id]);
  let current = model;
  let currentUpstream = upstream;
  let transientError = null;
  const callerTools = callerToolsFromBody(sanitizedBody);
  const needsTools = declaredToolNames(sanitizedBody).size > 0;
  const needsVision = hasImageInput(sanitizedBody);
  const incapable = (m) => needsTools && m.supportsTools === false || needsVision && !m.input.includes("image");
  for (const m of catalog.models) if (incapable(m)) tried.add(m.id);
  if (failoverAllowed && incapable(current)) {
    transientError = {
      status: 400,
      message: `model ${current.id} does not support ${needsVision && !current.input.includes("image") ? "image input" : "tool calls"}`
    };
    const capable = selectFailover(
      catalog,
      current,
      currentUpstream,
      tried,
      security,
      true,
      400,
      requestStartedAt,
      log,
      transientError.message
    );
    if (capable) {
      tried.add(capable.id);
      current = capable;
      currentUpstream = catalog.upstreamBySource(current.source);
    }
  }
  if (failoverAllowed && catalog.isCoolingDown(current.id) && current.id === model.id) {
    transientError = { status: 429, message: "model is cooling down after a recent rate limit" };
    const warm = selectFailover(
      catalog,
      current,
      currentUpstream,
      tried,
      security,
      true,
      429,
      requestStartedAt,
      log
    );
    if (warm) {
      tried.add(warm.id);
      current = warm;
      currentUpstream = catalog.upstreamBySource(current.source);
    }
  }
  for (let attempt = 0; attempt <= MAX_FAILOVER_RETRIES; attempt++) {
    if (current.id !== model.id || attempt > 0) {
      log.warn("upstream rejected - fallback used", {
        from: model.id,
        to: current.id,
        // name the originally requested model's upstream (currentUpstream has moved to the fallback)
        fromUpstream: upstream.id,
        status: transientError?.status,
        durationMs: Date.now() - requestStartedAt,
        attempt
      });
    }
    if (!isUpstreamAllowed(security, currentUpstream.id)) {
      log.warn("upstream blocked by strict security policy", {
        model: current.id,
        upstream: currentUpstream.id,
        status: 403,
        durationMs: Date.now() - requestStartedAt,
        failoverBlocked: true
      });
      return {
        status: 403,
        type: "security_policy_error",
        message: security.allowedUpstreams.length === 0 ? "strict security mode blocks external LLM requests until security.allowedUpstreams explicitly permits a provider" : `upstream "${currentUpstream.id}" is not allowed by strict security policy`
      };
    }
    const headers = new Headers({
      "content-type": "application/json",
      ...currentUpstream.requestHeaders(current, req.headers)
    });
    const responsesWire = current.wireApi === "responses" && !!currentUpstream.responsesUrl;
    const outboundUrl = responsesWire ? currentUpstream.responsesUrl : currentUpstream.chatUrl;
    const attemptBody = clampMaxTokens({ ...sanitizedBody, model: current.id }, current);
    const transformedBody = currentUpstream.transformRequestBody ? currentUpstream.transformRequestBody(attemptBody, current) : attemptBody;
    let outboundBody = JSON.stringify(
      responsesWire ? chatToResponsesBody(transformedBody, current.id) : transformedBody
    );
    if (isStrictSecurity(security) && isExternalUpstream(currentUpstream)) {
      const secretScan = scanRequestBody(outboundBody);
      const redaction = secretScan.blocked && security.dlp === "redact" ? redactRequestBody(outboundBody) : null;
      if (redaction) {
        outboundBody = redaction.body;
        log.warn("secret guard redacted request", {
          model: current.id,
          upstream: currentUpstream.id,
          dlpRedacted: true,
          redactions: redaction.count,
          secretTypes: redaction.secretTypes
        });
      } else if (secretScan.blocked) {
        log.warn("request blocked by secret guard", {
          model: current.id,
          upstream: currentUpstream.id,
          status: 422,
          durationMs: Date.now() - requestStartedAt,
          dlpBlocked: true,
          secretTypes: secretScan.secretTypes
        });
        return {
          status: 422,
          type: "security_policy_error",
          message: "request blocked by secret guard",
          secretTypes: secretScan.secretTypes
        };
      }
    }
    let upstreamRes;
    try {
      upstreamRes = await directThenRelayFetch(relay, outboundUrl, {
        method: "POST",
        headers,
        body: outboundBody,
        duplex: "half",
        signal
      }, isRelayAllowed(security));
    } catch {
      transientError = { status: 502, message: "upstream request failed" };
      const next = selectFailover(
        catalog,
        current,
        currentUpstream,
        tried,
        security,
        failoverAllowed,
        502,
        requestStartedAt,
        log
      );
      if (!next) break;
      tried.add(next.id);
      current = next;
      currentUpstream = catalog.upstreamBySource(current.source);
      continue;
    }
    if (upstreamRes.status === 429 && currentUpstream.retryShape) {
      const peek = await upstreamRes.clone().text();
      if (GATE_TOOLSET_RE.test(peek)) {
        const shaped = currentUpstream.retryShape(transformedBody, current);
        if (shaped) {
          log.warn("upstream rejected the tool set, retrying with its own vocabulary", {
            model: current.id,
            upstream: currentUpstream.id,
            status: 429
          });
          try {
            upstreamRes = await directThenRelayFetch(relay, outboundUrl, {
              method: "POST",
              headers,
              body: JSON.stringify(responsesWire ? chatToResponsesBody(shaped, current.id) : shaped),
              duplex: "half",
              signal
            }, isRelayAllowed(security));
          } catch {
            upstreamRes = new Response(null, { status: 502 });
          }
        }
      }
    }
    if (upstreamRes.status >= 400) {
      const text = await upstreamRes.text();
      let errorMsg = `upstream returned HTTP ${upstreamRes.status}`;
      try {
        const json = JSON.parse(text);
        if (!isStrictSecurity(security)) {
          errorMsg = json?.error?.message ?? json?.message ?? text.slice(0, 256) ?? errorMsg;
        }
      } catch {
        if (!isStrictSecurity(security) && text) errorMsg = text.slice(0, 256);
      }
      const refused = upstreamRes.status === 401 || upstreamRes.status === 403;
      const capabilityRejected = needsTools && TOOLS_UNSUPPORTED_RE.test(errorMsg) || needsVision && VISION_UNSUPPORTED_RE.test(errorMsg);
      const transient = refused || capabilityRejected || upstreamRes.status === 429 || upstreamRes.status >= 500;
      if (!transient) {
        log.warn("upstream rejected", {
          model: current.id,
          upstream: currentUpstream.id,
          status: upstreamRes.status,
          durationMs: Date.now() - requestStartedAt,
          upstreamError: errorMsg
        });
        return { status: upstreamRes.status, message: errorMsg };
      }
      if (refused) {
        catalog.markRefused(current.id);
      } else if (upstreamRes.status === 429) {
        catalog.markRateLimited(
          current.id,
          parseRetryAfterMs(upstreamRes.headers.get("retry-after")) ?? retryAfterFromMessage(errorMsg)
        );
      }
      transientError = { status: upstreamRes.status, message: errorMsg };
      const next = selectFailover(
        catalog,
        current,
        currentUpstream,
        tried,
        security,
        failoverAllowed,
        upstreamRes.status,
        requestStartedAt,
        log,
        errorMsg
      );
      if (!next) break;
      tried.add(next.id);
      current = next;
      currentUpstream = catalog.upstreamBySource(current.source);
      continue;
    }
    if ((upstreamRes.headers.get("content-type") ?? "").includes("json")) {
      let envelopeError = null;
      try {
        const peek = await upstreamRes.clone().json();
        if (peek && typeof peek === "object" && peek.error && !peek.choices) {
          envelopeError = peek.error.message ?? "upstream returned an error under HTTP 200";
        }
      } catch {
      }
      if (envelopeError) {
        transientError = { status: 502, message: envelopeError };
        const next = selectFailover(
          catalog,
          current,
          currentUpstream,
          tried,
          security,
          failoverAllowed,
          502,
          requestStartedAt,
          log,
          envelopeError
        );
        if (!next) break;
        tried.add(next.id);
        current = next;
        currentUpstream = catalog.upstreamBySource(current.source);
        continue;
      }
    }
    const peeked = await peekStreamError(upstreamRes);
    if (peeked.error) {
      transientError = { status: 502, message: peeked.error };
      const next = selectFailover(
        catalog,
        current,
        currentUpstream,
        tried,
        security,
        failoverAllowed,
        502,
        requestStartedAt,
        log,
        peeked.error
      );
      if (!next) break;
      tried.add(next.id);
      current = next;
      currentUpstream = catalog.upstreamBySource(current.source);
      continue;
    }
    upstreamRes = peeked.response;
    const forcedStream = !sanitizedBody.stream && transformedBody.stream === true;
    let finalResponse = upstreamRes;
    if (responsesWire) {
      finalResponse = await toChatResponse(
        upstreamRes,
        current.id,
        sanitizedBody.stream === true || forcedStream
      );
      if (forcedStream) {
        finalResponse = await streamToChatResponse(finalResponse, current.id, callerTools);
      }
    } else if (forcedStream) {
      finalResponse = await streamToChatResponse(upstreamRes, current.id, callerTools);
    }
    return {
      response: finalResponse,
      model: current,
      upstream: currentUpstream
    };
  }
  return transientError ?? { status: 502, message: "no upstream candidates left" };
}
async function handleChat(req, res, catalog, log, security, signal) {
  const client = detectHarness(req);
  let bodyText;
  try {
    bodyText = await readBody(req);
  } catch {
    sendJson(res, 413, { error: { message: "request body too large" } });
    return;
  }
  let body;
  try {
    body = JSON.parse(bodyText);
  } catch {
    sendJson(res, 400, { error: { message: "invalid JSON body" } });
    return;
  }
  const parsed = parseChatTurn(body);
  if (!parsed.ok) {
    sendJson(res, 400, { error: { message: parsed.error } });
    return;
  }
  const requestStartedAt = Date.now();
  const sanitizedBody = sanitizeChatBody(
    body,
    catalog.resolve(parsed.value.model)?.compat.supportsDeveloperRole ?? false
  );
  if (parsed.value.stream) {
    sanitizedBody.stream_options = { include_usage: true };
  }
  const callerTools = callerToolsFromBody(body);
  const inFlightId = activity.startRequest({
    timestamp: requestStartedAt,
    client,
    model: parsed.value.model,
    requestedModel: parsed.value.model,
    upstream: catalog.resolve(parsed.value.model)?.source ?? "unknown"
  });
  let inFlightClosed = false;
  const finishInFlight = () => {
    if (inFlightClosed) return;
    inFlightClosed = true;
    activity.endRequest(inFlightId);
  };
  res.on("close", finishInFlight);
  const result = await runChatForward(
    req,
    catalog,
    log,
    security,
    parsed.value.model,
    sanitizedBody,
    signal
  );
  if ("status" in result) {
    activity.record({
      kind: "chat",
      model: parsed.value.model,
      requestedModel: parsed.value.model,
      upstream: catalog.resolve(parsed.value.model)?.source ?? "unknown",
      inputTokens: 0,
      outputTokens: 0,
      durationMs: Date.now() - requestStartedAt,
      status: "error",
      statusCode: result.status,
      client
    });
    sendJson(res, result.status, {
      error: { message: result.message, type: result.type ?? "upstream_error", status: result.status },
      ...result.secretTypes ? { secret_types: result.secretTypes } : {}
    });
    return;
  }
  const { response: upstreamRes, model: current, upstream: currentUpstream } = result;
  const model = catalog.resolve(parsed.value.model) ?? current;
  log.info("chat -> upstream", {
    model: current.id,
    upstream: currentUpstream.id,
    stream: parsed.value.stream
  });
  const contentType = upstreamRes.headers.get("content-type") ?? "application/json";
  res.writeHead(upstreamRes.status, { "content-type": contentType, ...corsFor(res) });
  if (!parsed.value.stream) {
    const text = await upstreamRes.text();
    let outText = text;
    let usage2 = null;
    try {
      const json = JSON.parse(text);
      const msg = json?.choices?.[0]?.message;
      if (msg && typeof msg.content === "string" && msg.content.length === 0 && !msg.tool_calls?.length) {
        const rt = extractReasoningText(msg);
        if (rt) {
          json.choices[0].message = { ...msg, content: rt };
          outText = JSON.stringify(json);
        }
      }
      usage2 = extractUsage(json);
    } catch {
    }
    recordCompletion(activity, log, "chat", "chat done", {
      model: current.id,
      requestedModel: model.id,
      upstream: currentUpstream.id,
      usage: usage2,
      startedAt: requestStartedAt,
      client
    });
    res.end(outText);
    return;
  }
  if (upstreamRes.body) {
    const src = Readable2.fromWeb(
      upstreamRes.body
    );
    const booked = { recorded: false };
    const usageTx = logUsageTransform(current.id, currentUpstream.id, log, requestStartedAt, model.id, activity, "chat", client, booked);
    let streamFailed = false;
    const failStream = () => {
      streamFailed = true;
      if (signal.aborted) {
        try {
          res.destroy();
        } catch {
        }
        return;
      }
      log.warn("upstream stream interrupted", {
        model: current.id,
        upstream: currentUpstream.id,
        status: 502
      });
      try {
        res.destroy();
      } catch {
      }
    };
    src.on("error", failStream);
    usageTx.on("error", failStream);
    res.on("error", () => src.destroy());
    signal.addEventListener("abort", () => src.destroy());
    const filterTx = filterInjectedToolCallsTransform(callerTools);
    filterTx.on("error", failStream);
    res.on("close", () => {
      if (booked.recorded || signal.aborted) return;
      if (streamFailed) {
        activity.record({
          kind: "chat",
          model: current.id,
          requestedModel: model.id,
          upstream: currentUpstream.id,
          inputTokens: 0,
          outputTokens: 0,
          durationMs: Date.now() - requestStartedAt,
          status: "error",
          statusCode: 502,
          ...client ? { client } : {}
        });
        return;
      }
      recordCompletion(activity, log, "chat", "chat done", {
        model: current.id,
        requestedModel: model.id,
        upstream: currentUpstream.id,
        usage: null,
        startedAt: requestStartedAt,
        client
      });
    });
    src.pipe(reasoningToContentTransform()).pipe(filterTx).pipe(usageTx).pipe(res);
  } else {
    res.end();
  }
}
async function handleResponses(req, res, catalog, log, security, signal) {
  const client = detectHarness(req);
  let bodyText;
  try {
    bodyText = await readBody(req);
  } catch {
    sendJson(res, 413, { error: { message: "request body too large" } });
    return;
  }
  let body;
  try {
    body = JSON.parse(bodyText);
  } catch {
    sendJson(res, 400, { error: { message: "invalid JSON body" } });
    return;
  }
  const parsed = parseResponsesTurn(body);
  if (!parsed.ok) {
    sendJson(res, 400, { error: { message: parsed.error } });
    return;
  }
  const requestStartedAt = Date.now();
  const target = catalog.resolve(parsed.value.model);
  const supportsDev = target?.compat.supportsDeveloperRole ?? false;
  const chatMessages = [];
  if (parsed.value.system) {
    chatMessages.push({ role: "system", content: parsed.value.system });
  }
  for (const m of parsed.value.messages) {
    chatMessages.push({
      role: m.role,
      content: typeof m.content === "string" ? m.content : m.content.map((b) => b.type === "text" ? b : { type: "image_url", image_url: { url: b.url } }),
      ...m.toolCallId ? { tool_call_id: m.toolCallId } : {},
      ...m.role === "assistant" ? { reasoning_content: m.thinking ?? "" } : {},
      ...m.toolCalls ? { tool_calls: m.toolCalls.map((tc) => ({
        id: tc.id,
        type: "function",
        function: { name: tc.name, arguments: tc.arguments }
      })) } : {}
    });
  }
  const sanitizedBody = sanitizeChatBody(
    {
      model: parsed.value.model,
      messages: chatMessages,
      ...parsed.value.tools ? {
        tools: parsed.value.tools.map((t) => ({
          type: "function",
          function: { name: t.name, description: t.description, parameters: t.parameters }
        }))
      } : {},
      ...parsed.value.maxTokens ? { max_tokens: parsed.value.maxTokens } : {},
      ...parsed.value.reasoningEffort ? { reasoning_effort: parsed.value.reasoningEffort } : {},
      stream: parsed.value.stream
    },
    supportsDev
  );
  if (parsed.value.stream) {
    sanitizedBody.stream_options = { include_usage: true };
  }
  const callerTools = callerToolsFromBody(sanitizedBody);
  const inFlightId = activity.startRequest({
    timestamp: requestStartedAt,
    client,
    model: parsed.value.model,
    requestedModel: parsed.value.model,
    upstream: catalog.resolve(parsed.value.model)?.source ?? "unknown"
  });
  let inFlightClosed = false;
  const finishInFlight = () => {
    if (inFlightClosed) return;
    inFlightClosed = true;
    activity.endRequest(inFlightId);
  };
  res.on("close", finishInFlight);
  const result = await runChatForward(
    req,
    catalog,
    log,
    security,
    parsed.value.model,
    sanitizedBody,
    signal
  );
  if ("status" in result) {
    activity.record({
      kind: "responses",
      model: parsed.value.model,
      requestedModel: parsed.value.model,
      upstream: catalog.resolve(parsed.value.model)?.source ?? "unknown",
      inputTokens: 0,
      outputTokens: 0,
      durationMs: Date.now() - requestStartedAt,
      status: "error",
      statusCode: result.status,
      client
    });
    sendJson(res, result.status, {
      error: { message: result.message, type: result.type ?? "upstream_error", status: result.status },
      ...result.secretTypes ? { secret_types: result.secretTypes } : {}
    });
    return;
  }
  const { response: upstreamRes, model: current, upstream: currentUpstream } = result;
  const resolved = catalog.resolve(parsed.value.model) ?? current;
  log.info("responses -> upstream", {
    model: current.id,
    upstream: currentUpstream.id,
    stream: parsed.value.stream
  });
  if (!parsed.value.stream) {
    const text = await upstreamRes.text();
    let json;
    try {
      json = JSON.parse(text);
    } catch {
      sendJson(res, 502, { error: { message: "invalid upstream response" } });
      return;
    }
    const usage2 = extractUsage(json);
    recordCompletion(activity, log, "responses", "responses done", {
      model: current.id,
      requestedModel: resolved.id,
      upstream: currentUpstream.id,
      usage: usage2,
      startedAt: requestStartedAt,
      client
    });
    const out = renderResponse(json, current.id);
    res.writeHead(upstreamRes.status, { "content-type": "application/json", ...corsFor(res) });
    res.end(JSON.stringify(out));
    return;
  }
  res.writeHead(200, {
    "content-type": "text/event-stream",
    "cache-control": "no-cache",
    "connection": "keep-alive",
    ...corsFor(res)
  });
  const encoder = new ResponsesStreamEncoder(callerTools);
  let first = true;
  let failed = false;
  let streamUsage = null;
  try {
    if (upstreamRes.body) {
      for await (const frame of readSseStream(
        upstreamRes.body
      )) {
        if (signal.aborted) break;
        if (frame.data === "[DONE]") continue;
        let json;
        try {
          json = JSON.parse(frame.data);
        } catch {
          continue;
        }
        if (first) {
          first = false;
          for (const ev of encoder.open(current.id)) res.write(ev);
        }
        const streamError = sseErrorMessage(json);
        if (streamError) {
          failed = true;
          log.warn("upstream stream error", { model: current.id, upstream: currentUpstream.id, upstreamError: streamError });
          for (const ev of encoder.fail(streamError)) res.write(ev);
          break;
        }
        const usage2 = extractUsage(json);
        if (usage2) streamUsage = usage2;
        for (const ev of encoder.push(json)) res.write(ev);
      }
    }
  } catch {
    if (!signal.aborted) {
      log.warn("upstream stream interrupted", {
        model: current.id,
        upstream: currentUpstream.id,
        status: 502
      });
    }
  }
  if (!failed) for (const ev of encoder.close()) res.write(ev);
  if (failed) {
    activity.record({
      kind: "responses",
      model: current.id,
      requestedModel: resolved.id,
      upstream: currentUpstream.id,
      inputTokens: 0,
      outputTokens: 0,
      durationMs: Date.now() - requestStartedAt,
      status: "error",
      statusCode: 502,
      ...client ? { client } : {}
    });
  } else if (!signal.aborted) {
    recordCompletion(activity, log, "responses", "responses done", {
      model: current.id,
      requestedModel: resolved.id,
      upstream: currentUpstream.id,
      usage: streamUsage,
      startedAt: requestStartedAt,
      client
    });
  }
  res.end();
}
async function handleAnthropic(req, res, catalog, log, security, signal) {
  const client = detectHarness(req);
  let bodyText;
  try {
    bodyText = await readBody(req);
  } catch {
    sendAnthropicError(res, 413, "request body too large");
    return;
  }
  let body;
  try {
    body = JSON.parse(bodyText);
  } catch {
    sendAnthropicError(res, 400, "invalid JSON body");
    return;
  }
  const parsed = parseAnthropicRequest(body);
  if (!parsed.ok) {
    sendAnthropicError(res, 400, parsed.error);
    return;
  }
  const model = catalog.resolve(parsed.value.model);
  if (!model) {
    sendAnthropicError(res, 400, `unknown model: ${parsed.value.model}`);
    return;
  }
  const upstream = catalog.upstreamBySource(model.source);
  if (!upstream) {
    sendAnthropicError(res, 502, `no upstream for source: ${model.source}`);
    return;
  }
  const requestStartedAt = Date.now();
  const chatBody = parsed.value.chatBody;
  chatBody.model = model.id;
  const callerTools = callerToolsFromBody(chatBody);
  const inFlightId = activity.startRequest({
    timestamp: requestStartedAt,
    client,
    model: parsed.value.model,
    requestedModel: parsed.value.model,
    upstream: model?.source ?? "unknown"
  });
  let inFlightClosed = false;
  const finishInFlight = () => {
    if (inFlightClosed) return;
    inFlightClosed = true;
    activity.endRequest(inFlightId);
  };
  res.on("close", finishInFlight);
  const result = await runChatForward(
    req,
    catalog,
    log,
    security,
    parsed.value.model,
    chatBody,
    signal
  );
  if ("status" in result) {
    activity.record({
      kind: "anthropic",
      model: parsed.value.model,
      requestedModel: parsed.value.model,
      upstream: model?.source ?? "unknown",
      inputTokens: 0,
      outputTokens: 0,
      durationMs: Date.now() - requestStartedAt,
      status: "error",
      statusCode: result.status,
      client
    });
    sendAnthropicError(res, result.status, result.message, result.secretTypes);
    return;
  }
  const { response: upstreamRes, model: current, upstream: currentUpstream } = result;
  log.info("anthropic -> upstream", {
    model: current.id,
    upstream: currentUpstream.id,
    stream: parsed.value.stream
  });
  if (!parsed.value.stream) {
    const text = await upstreamRes.text();
    let json;
    try {
      json = JSON.parse(text);
    } catch {
      sendAnthropicError(res, 502, "invalid upstream response");
      return;
    }
    const message = openAiCompletionToAnthropicMessage(json, current.id);
    recordCompletion(activity, log, "anthropic", "anthropic done", {
      model: current.id,
      requestedModel: model.id,
      upstream: currentUpstream.id,
      usage: extractUsage(json),
      startedAt: requestStartedAt,
      client
    });
    sendJson(res, upstreamRes.status === 200 ? 200 : upstreamRes.status, message);
    return;
  }
  res.writeHead(upstreamRes.status, {
    "content-type": "text/event-stream",
    "cache-control": "no-cache",
    "connection": "keep-alive",
    ...corsFor(res)
  });
  const encoder = new AnthropicStreamEncoder(callerTools);
  let streamUsage = null;
  let streamClosed = false;
  let failed = false;
  try {
    if (upstreamRes.body) {
      for await (const frame of readSseStream(
        upstreamRes.body
      )) {
        if (signal.aborted) break;
        if (frame.data === "[DONE]") {
          streamClosed = true;
          for (const ev of encoder.close()) res.write(ev);
          break;
        }
        let json;
        try {
          json = JSON.parse(frame.data);
        } catch {
          continue;
        }
        const streamError = sseErrorMessage(json);
        if (streamError) {
          streamClosed = true;
          failed = true;
          log.warn("upstream stream error", { model: current.id, upstream: currentUpstream.id, upstreamError: streamError });
          for (const ev of encoder.fail(streamError)) res.write(ev);
          break;
        }
        const usage2 = extractUsage(json);
        if (usage2) streamUsage = usage2;
        for (const ev of encoder.push(json, current.id)) res.write(ev);
      }
    }
  } catch {
    if (!signal.aborted) {
      log.warn("upstream stream interrupted", {
        model: current.id,
        upstream: currentUpstream.id,
        status: 502
      });
    }
  }
  if (!streamClosed) {
    for (const ev of encoder.close()) res.write(ev);
  }
  if (failed) {
    activity.record({
      kind: "anthropic",
      model: current.id,
      requestedModel: model.id,
      upstream: currentUpstream.id,
      inputTokens: 0,
      outputTokens: 0,
      durationMs: Date.now() - requestStartedAt,
      status: "error",
      statusCode: 502,
      ...client ? { client } : {}
    });
  } else if (!signal.aborted) {
    recordCompletion(activity, log, "anthropic", "anthropic done", {
      model: current.id,
      requestedModel: model.id,
      upstream: currentUpstream.id,
      usage: streamUsage,
      startedAt: requestStartedAt,
      client
    });
  }
  res.end();
}
function anthropicErrorType(status) {
  if (status === 401) return "authentication_error";
  if (status === 403) return "permission_error";
  if (status === 404) return "not_found_error";
  if (status === 413) return "request_too_large";
  if (status === 429) return "rate_limit_error";
  if (status === 503 || status === 529) return "overloaded_error";
  if (status >= 500) return "api_error";
  return "invalid_request_error";
}
function sendAnthropicError(res, status, message, secretTypes) {
  sendJson(res, status, {
    type: "error",
    error: { type: anthropicErrorType(status), message },
    ...secretTypes ? { secret_types: secretTypes } : {}
  });
}
function createServer(opts) {
  const { catalog, rateLimiter, port, log, startedAt } = opts;
  const security = opts.security ?? DEFAULT_SECURITY_CONFIG;
  activity = opts.activity ?? new ActivityStore();
  bodyCapBytes = opts.bodyCapBytes && opts.bodyCapBytes > 0 ? opts.bodyCapBytes : DEFAULT_BODY_CAP_BYTES;
  const adminOptions = {
    bind: "127.0.0.1",
    refreshIntervalMs: 0,
    ...opts.admin,
    bodyCapBytes,
    activity,
    security,
    catalog,
    port
  };
  const visibleRelayState = () => {
    const relay = loadRelayState();
    return {
      ...relay,
      enabled: isRelayAllowed(security) ? relay.enabled : false,
      securityMode: security.mode,
      locked: !isRelayAllowed(security)
    };
  };
  return http.createServer((req, res) => {
    res.bansosCors = corsHeadersForOrigin(req.headers.origin);
    const clientSignal = clientDisconnectSignal(res);
    const ip = req.socket.remoteAddress ?? "unknown";
    const method = req.method ?? "";
    if (!rateLimiter.check(ip)) {
      log.warn("rate limit exceeded", { ip });
      sendJson(res, 429, { error: { message: "rate limit exceeded" } });
      return;
    }
    if (!ALLOWED_METHODS.has(method)) {
      sendJson(res, 405, { error: { message: "method not allowed" } });
      return;
    }
    if (method === "OPTIONS") {
      const cors = corsFor(res);
      res.writeHead(204, cors);
      res.end();
      return;
    }
    if (!isHostTrusted(req)) {
      sendJson(res, 403, { error: { message: "forbidden host" } });
      return;
    }
    if (method === "POST" && !isOriginTrusted(req)) {
      sendJson(res, 403, { error: { message: "cross-site request blocked" } });
      return;
    }
    const rawUrl = req.url ?? "/";
    if (!validatePath(rawUrl)) {
      sendJson(res, 403, { error: { message: "forbidden" } });
      return;
    }
    const cleanUrl = rawUrl.split("?")[0] ?? "/";
    const url = cleanUrl.replace(/\/+$/, "");
    if (url === "/bansos/combos" && method === "GET") {
      sendJson(res, 200, { data: listCombos() });
      return;
    }
    if (url === "/bansos/combos" && method === "POST") {
      void runRequest(readBody(req).then((text) => {
        let body = {};
        try {
          body = text ? JSON.parse(text) : {};
        } catch {
          sendJson(res, 400, { error: { message: "invalid json body" } });
          return;
        }
        if (body.action === "delete") {
          const ok = deleteCombo(String(body.id ?? ""));
          sendJson(res, ok ? 200 : 404, ok ? { deleted: true } : { error: { message: "combo not found" } });
          return;
        }
        try {
          sendJson(res, 200, { data: upsertCombo(body) });
        } catch (error) {
          sendJson(res, 400, { error: { message: error instanceof Error ? error.message : "invalid combo" } });
        }
      }), res, log, "combo mutation");
      return;
    }
    if (url === "/bansos/api-keys" && method === "GET") {
      sendJson(res, 200, { data: listApiKeys() });
      return;
    }
    if (url === "/bansos/api-keys" && method === "POST") {
      void runRequest(
        readBody(req).then((text) => {
          let body = {};
          try {
            body = text ? JSON.parse(text) : {};
          } catch {
            sendJson(res, 400, { error: { message: "invalid json body" } });
            return;
          }
          if (body.action === "delete") {
            const ok = deleteApiKey(String(body.id ?? ""));
            sendJson(res, ok ? 200 : 404, ok ? { deleted: true } : { error: { message: "key not found" } });
            return;
          }
          try {
            sendJson(res, 201, createApiKey(String(body.name ?? "Default"), typeof body.key === "string" ? body.key : void 0));
          } catch (error) {
            sendJson(res, 400, { error: { message: error instanceof Error ? error.message : "failed to create API key" } });
          }
        }),
        res,
        log,
        "api key mutation"
      );
      return;
    }
    const inferencePath = url === "/models" || url.startsWith("/v1/") || url === "/chat/completions" || url === "/messages" || url === "/responses";
    const dashboardCatalog = method === "GET" && (url === "/v1/models" || url === "/models") && new URL(rawUrl, "http://local").searchParams.has("all");
    const dashboardRequest = req.headers["x-bansos-client"] === "dashboard";
    if (inferencePath && hasApiKeys() && !dashboardCatalog && !dashboardRequest) {
      const bearer = req.headers.authorization?.replace(/^Bearer\s+/i, "");
      if (!verifyApiKey(bearer)) {
        sendJson(res, 401, { error: { message: "invalid API key", type: "invalid_api_key" } });
        return;
      }
    }
    if (method === "GET" && (url === "/v1/models" || url === "/models")) {
      const listAll = new URL(rawUrl, "http://127.0.0.1").searchParams.has("all");
      sendJson(res, 200, {
        object: "list",
        data: (listAll ? catalog.models : catalog.servableModels).map((m) => ({
          id: m.id,
          object: "model",
          created: 0,
          owned_by: m.source,
          source: m.source,
          name: m.name,
          context_window: m.contextWindow,
          context_length: m.contextWindow,
          max_tokens: m.maxTokens,
          maxTokens: m.maxTokens,
          reasoning: m.reasoning,
          input: m.input,
          supports_tools: m.supportsTools !== false
        }))
      });
      return;
    }
    if (url === "/healthz") {
      const relay = visibleRelayState();
      sendJson(res, 200, {
        status: "ok",
        uptimeSeconds: Math.floor((Date.now() - startedAt) / 1e3),
        modelCount: catalog.servableModels.length,
        relay: { enabled: relay.enabled, url: relay.url },
        security: {
          mode: security.mode,
          allowedUpstreams: security.allowedUpstreams,
          allowCrossProviderFailover: security.allowCrossProviderFailover
        }
      });
      return;
    }
    if (url === "/bansos/status") {
      const relay = visibleRelayState();
      const update = peekUpdate();
      const payload = {
        status: "ok",
        version: VERSION,
        uptimeSeconds: Math.floor((Date.now() - startedAt) / 1e3),
        port,
        modelCount: catalog.servableModels.length,
        models: catalog.servableModels.map((m) => m.id),
        providers: providerCounts(catalog, security),
        relay: { enabled: relay.enabled, url: relay.url },
        security: {
          mode: security.mode,
          dlp: security.dlp,
          allowedUpstreams: security.allowedUpstreams,
          allowCrossProviderFailover: security.allowCrossProviderFailover
        },
        ...update ? { update } : {}
      };
      sendJson(res, 200, payload);
      return;
    }
    if (method === "POST" && url === "/bansos/refresh") {
      void catalog.refresh().then((report) => {
        sendJson(res, 200, {
          refreshed: true,
          modelCount: catalog.servableModels.length,
          alive: report.alive
        });
      }).catch((err) => {
        sendJson(res, 500, { error: { message: `refresh failed: ${String(err)}` } });
      });
      return;
    }
    if (method === "GET" && url === "/bansos/adapters") {
      const statuses = harnessStatuses();
      sendJson(
        res,
        200,
        ADAPTERS.map((a) => ({
          id: a.id,
          name: a.name,
          wire: a.wire,
          modelMode: a.modelMode,
          configPaths: a.configPaths,
          status: statuses.find((h) => h.id === a.id)?.status ?? "missing"
        }))
      );
      return;
    }
    if (method === "GET" && url === "/bansos/adapters/render") {
      const parsedUrl = new URL(rawUrl, "http://127.0.0.1");
      const id = parsedUrl.searchParams.get("id");
      const model = parsedUrl.searchParams.get("model") || void 0;
      if (!id) {
        sendJson(res, 400, { error: { message: "missing adapter id query parameter" } });
        return;
      }
      const adapter = findAdapter(id);
      if (!adapter) {
        sendJson(res, 404, { error: { message: `adapter "${id}" not found` } });
        return;
      }
      const reqHost = req.headers.host || `127.0.0.1:${port}`;
      const isHttps = Boolean(req.socket?.encrypted);
      const proto = isHttps ? "https" : "http";
      const ctx = buildSetupContext(`${proto}://${reqHost}/v1`, catalog.servableModels, {
        model,
        models: parsedUrl.searchParams.getAll("models"),
        upstreams: parsedUrl.searchParams.getAll("upstream")
      });
      if ("error" in ctx) {
        sendJson(res, 400, { error: { message: ctx.error } });
        return;
      }
      const config = adapter.render(ctx);
      sendJson(res, 200, {
        id: adapter.id,
        name: adapter.name,
        wire: adapter.wire,
        config
      });
      return;
    }
    if (method === "GET" && url === "/bansos/relay") {
      sendJson(res, 200, visibleRelayState());
      return;
    }
    if (method === "GET" && url === "/bansos/usage") {
      const parsedUrl = new URL(rawUrl, "http://127.0.0.1");
      const window = parsedUrl.searchParams.get("window") || "all";
      sendJson(res, 200, activity.getUsage(window));
      return;
    }
    if (method === "GET" && url === "/bansos/events") {
      const parsedUrl = new URL(rawUrl, "http://127.0.0.1");
      const limitParam = Number(parsedUrl.searchParams.get("limit"));
      const window = parsedUrl.searchParams.get("window") || "all";
      const limit = Number.isFinite(limitParam) && limitParam > 0 ? Math.min(limitParam, 500) : 100;
      sendJson(res, 200, { events: activity.getEvents(limit, window), inFlight: activity.getInFlight() });
      return;
    }
    if (method === "POST" && url === "/bansos/relay/probe") {
      if (!isRelayAllowed(security)) {
        sendJson(res, 403, {
          error: { message: "relay is disabled by strict security mode", type: "security_policy_error" }
        });
        return;
      }
      void runRequest(
        readBody(req).then(async (bodyText) => {
          let targetUrl = "";
          if (bodyText) {
            try {
              const parsed = JSON.parse(bodyText);
              targetUrl = parsed.url || "";
            } catch {
              sendJson(res, 400, { error: { message: "invalid json body" } });
              return;
            }
          }
          if (!targetUrl) {
            const current = loadRelayState();
            targetUrl = current.url;
          }
          if (!targetUrl) {
            sendJson(res, 400, { error: { message: "no url specified or active" } });
            return;
          }
          const policy = probeTargetAllowed(targetUrl, loadRelayState());
          if (!policy.allowed) {
            sendJson(res, 403, {
              error: { message: `relay probe blocked: ${policy.reason}`, type: "security_policy_error" }
            });
            return;
          }
          const start = performance.now();
          try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 7e3);
            const upstreamRes = await fetch(targetUrl, {
              method: "GET",
              signal: controller.signal
            });
            clearTimeout(timeoutId);
            const ms = Math.round(performance.now() - start);
            sendJson(res, 200, {
              ok: upstreamRes.status < 500,
              status: upstreamRes.status,
              latencyMs: ms
            });
          } catch (err) {
            const ms = Math.round(performance.now() - start);
            sendJson(res, 200, {
              ok: false,
              latencyMs: ms,
              error: err instanceof Error ? err.message : "Unreachable"
            });
          }
        }),
        res,
        log,
        "relay probe"
      );
      return;
    }
    if (ADMIN_PATHS.has(url)) {
      void runRequest(
        handleAdmin(req, method, url, rawUrl, () => readBody(req, 1024 * 1024), adminOptions).then((result) => {
          sendJson(res, result.status, result.body);
          const after = result.after;
          if (after) {
            if (res.writableFinished) setImmediate(after);
            else res.once("finish", after);
          }
        }),
        res,
        log,
        "settings"
      );
      return;
    }
    if (method === "POST" && url === "/bansos/relay") {
      if (!isRelayAllowed(security)) {
        sendJson(res, 403, {
          error: { message: "relay mutation is disabled by strict security mode", type: "security_policy_error" }
        });
        return;
      }
      void runRequest(
        readBody(req).then((bodyText) => {
          let body = {};
          if (bodyText) {
            try {
              body = JSON.parse(bodyText);
            } catch {
              sendJson(res, 400, { error: { message: "invalid json body" } });
              return;
            }
          }
          const updated = applyRelayMutation(loadRelayState(), body);
          if ("error" in updated) {
            sendJson(res, 400, { error: { message: updated.error } });
            return;
          }
          saveRelayState(updated);
          sendJson(res, 200, updated);
        }),
        res,
        log,
        "relay mutation"
      );
      return;
    }
    if (method === "GET" && (url === "" || url === "/index.html" || cleanUrl.startsWith("/assets/") || cleanUrl.startsWith("/fonts/") || cleanUrl.startsWith("/harnesses/") || url === "/favicon.ico" || url === "/favicon.svg" || url === "/favicon.png" || url === "/apple-touch-icon.png" || url === "/manifest.json" || url === "/robots.txt")) {
      serveStaticUi(res, cleanUrl);
      return;
    }
    if (method === "POST" && (url === "/v1/responses" || url === "/responses")) {
      runRequest(handleResponses(req, res, catalog, log, security, clientSignal), res, log, "responses");
      return;
    }
    if (method === "POST" && (url === "/v1/chat/completions" || url === "/chat/completions")) {
      runRequest(handleChat(req, res, catalog, log, security, clientSignal), res, log, "chat");
      return;
    }
    if (method === "POST" && (url === "/v1/messages" || url === "/messages")) {
      runRequest(handleAnthropic(req, res, catalog, log, security, clientSignal), res, log, "anthropic");
      return;
    }
    const notFound = () => {
      const accept = req.headers.accept ?? "";
      if (accept.includes("text/html")) {
        const notFoundHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Page Not Found | Bansos Router</title>
</head>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;background:#111113;color:#f4f4f6;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:1.5rem;box-sizing:border-box;">
  <div style="max-width:400px;width:100%;text-align:center;background:#16161a;border:1px solid #23232a;border-radius:1rem;padding:2.5rem 2rem;box-shadow:0 20px 25px -5px rgba(0,0,0,0.5);">
    <div style="display:inline-flex;align-items:center;justify-content:center;width:3rem;height:3rem;border-radius:0.75rem;background:#202028;border:1px solid #2c2c36;margin-bottom:1.25rem;">
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#eab308" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
    </div>
    <h1 style="font-size:1.125rem;font-weight:700;margin:0 0 0.5rem 0;color:#ffffff;letter-spacing:-0.025em;">Page Not Found</h1>
    <p style="font-size:0.8125rem;color:#9393a0;margin:0 0 1.5rem 0;line-height:1.5;">This page does not exist.</p>
    <a href="/" style="display:inline-flex;align-items:center;justify-content:center;gap:0.5rem;background:#2b64e0;color:#ffffff;font-weight:600;font-size:0.8125rem;padding:0.625rem 1.25rem;border-radius:0.5rem;text-decoration:none;transition:background 0.15s ease;cursor:pointer;">
      <span>\u2190 Back to Dashboard</span>
    </a>
  </div>
</body>
</html>`;
        res.writeHead(404, {
          "content-type": "text/html; charset=utf-8",
          "content-length": Buffer.byteLength(notFoundHtml),
          ...corsFor(res)
        });
        res.end(notFoundHtml);
        return;
      }
      sendJson(res, 404, { error: { message: "not found" } });
    };
    notFound();
  });
}

// src/daemon/index.ts
var DEFAULT_PORT = 17070;
var MAX_PORT = 17090;
var MAX_LOG_BYTES = 5 * 1024 * 1024;
var MAX_LOG_BACKUPS = 2;
function rotateLogFile() {
  try {
    for (let i = MAX_LOG_BACKUPS - 1; i >= 1; i--) {
      const from = `${LOG_FILE}.${i}`;
      const to = `${LOG_FILE}.${i + 1}`;
      if (fs13.existsSync(to)) fs13.unlinkSync(to);
      if (fs13.existsSync(from)) fs13.renameSync(from, to);
    }
    if (fs13.existsSync(LOG_FILE)) fs13.renameSync(LOG_FILE, `${LOG_FILE}.1`);
  } catch {
  }
}
function createTeeStream(a, bRef) {
  const tee = new stream.PassThrough();
  tee.on("data", (chunk) => {
    try {
      a.write(chunk);
    } catch {
    }
    try {
      bRef.current.write(chunk);
    } catch {
    }
  });
  return tee;
}
function parseArgs3(argv) {
  const args = { bg: false, unsafeAllowNonLoopback: false, bgChild: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--port" || arg === "-p") args.port = Number(argv[++i]);
    else if (arg === "--bind") args.bind = argv[++i];
    else if (arg === "--bg") args.bg = true;
    else if (arg === "--bg-child") args.bgChild = true;
    else if (arg === "--unsafe-allow-non-loopback") args.unsafeAllowNonLoopback = true;
    else if (arg === "--version" || arg === "-v") {
      console.log(VERSION);
      process.exit(0);
    } else if (arg === "--help" || arg === "-h") {
      console.log(`bansosd - local free-model router daemon

Usage:
  bansos start [--port N] [--bind H] [--bg]   (or: bansosd [--port N] [--bind H] [--bg])

Options:
  --port N    listen port (default: ${DEFAULT_PORT}, auto-bumps up to ${MAX_PORT})
  --bind H    bind address (default: 127.0.0.1)
  --bg        spawn detached, log to ~/.bansos/logs/bansosd.log
  --unsafe-allow-non-loopback
              override strict-mode loopback protection (unsafe)
  -h, --help  show this help
`);
      process.exit(0);
    }
  }
  return args;
}
function startServer(port, requestedPort, bind, config, log, activity2, flags, restart) {
  const upstreams = buildUpstreams(config.localUpstreams);
  const catalog = new RuntimeCatalog(upstreams, log, config.security);
  catalog.seed(SEEDED_MODELS);
  const startedAt = Date.now();
  const rateLimiter = new RateLimiter({
    limit: Number(process.env.BANSOS_RATE_LIMIT) || 300,
    windowMs: 6e4
  });
  const server = createServer({
    catalog,
    rateLimiter,
    port,
    log,
    startedAt,
    security: config.security,
    activity: activity2,
    bodyCapBytes: config.maxBodyBytes,
    admin: { requestedPort, bind, refreshIntervalMs: config.refreshIntervalMs, flags, restart }
  });
  return new Promise((resolve, reject) => {
    server.once("error", (err) => {
      if (err.code === "EADDRINUSE" && port < MAX_PORT) {
        log.warn(`port ${port} busy - trying ${port + 1}`);
        resolve(startServer(port + 1, requestedPort, bind, config, log, activity2, flags, restart));
        return;
      }
      reject(err);
    });
    server.listen(port, bind, () => {
      const refreshTimer = config.refreshIntervalMs > 0 ? setInterval(() => void catalog.refresh(), config.refreshIntervalMs) : void 0;
      resolve({ server, port, catalog, refreshTimer });
    });
  });
}
async function main(argv) {
  const args = parseArgs3(argv[0] === "daemon" ? argv.slice(1) : argv);
  const config = loadConfig();
  const port = args.port ?? config.port ?? DEFAULT_PORT;
  const bind = args.bind ?? config.bind;
  const running = args.bgChild ? null : await runningDaemonUrl(args.port);
  if (running) {
    console.log(`bansosd already running at ${running}`);
    const notice = await staleDaemonNotice(running) ?? updateNotice(await checkUpdate());
    if (notice) console.log(notice);
    return;
  }
  const explicit = {
    ...args.port !== void 0 ? { port: args.port } : {},
    ...args.bind !== void 0 ? { bind: args.bind } : {},
    ...args.unsafeAllowNonLoopback ? { unsafeAllowNonLoopback: true } : {}
  };
  fs13.mkdirSync(LOG_DIR, { recursive: true });
  const fileRef = {
    current: fs13.createWriteStream(LOG_FILE, { flags: "a" })
  };
  try {
    if (fs13.statSync(LOG_FILE).size > MAX_LOG_BYTES) rotateLogFile();
  } catch {
  }
  const rotateTimer = setInterval(() => {
    try {
      if (fs13.statSync(LOG_FILE).size > MAX_LOG_BYTES) {
        fileRef.current.end();
        rotateLogFile();
        fileRef.current = fs13.createWriteStream(LOG_FILE, { flags: "a" });
      }
    } catch {
    }
  }, 6e4);
  rotateTimer.unref();
  const out = createTeeStream(process.stdout, fileRef);
  const log = createLogger({ prefix: "bansosd", out });
  try {
    assertBindAllowed(bind, config.security, args.unsafeAllowNonLoopback);
  } catch (err) {
    log.error(String(err?.message ?? err));
    process.exitCode = 1;
    return;
  }
  if (args.bg) {
    const child = spawn(
      process.execPath,
      [
        ...process.execArgv,
        process.argv[1],
        "daemon",
        ...startArgs(explicit),
        // marker so the child knows it is the file-backed instance
        "--bg-child"
      ],
      {
        stdio: ["ignore", "ignore", "ignore"],
        detached: true
      }
    );
    child.unref();
    log.info(`started in background (pid ${child.pid}), log: ${LOG_FILE}`);
    return;
  }
  const activity2 = new ActivityStore();
  const flags = {
    port: args.port !== void 0,
    bind: args.bind !== void 0,
    unsafeAllowNonLoopback: args.unsafeAllowNonLoopback
  };
  let current = null;
  let restarting = false;
  const boot = async (cfg) => {
    const wantPort = args.port ?? cfg.port ?? DEFAULT_PORT;
    const wantBind = args.bind ?? cfg.bind;
    assertBindAllowed(wantBind, cfg.security, args.unsafeAllowNonLoopback);
    const running2 = await startServer(wantPort, wantPort, wantBind, cfg, log, activity2, flags, () => void restart());
    current = { ...running2, config: cfg };
    const actualPort = running2.port;
    log.info(`bansosd listening on http://${wantBind}:${actualPort}`);
    ensureOpenCodeService(log);
    writeJsonAtomic(STATE_FILE, {
      pid: process.pid,
      port: actualPort,
      bind: wantBind,
      startedAt: Date.now(),
      flags: explicit
    });
    if (process.env.BANSOS_LOG !== "json") {
      out.write(
        `
\u25CF bansosd online (port ${actualPort})
  \u251C\u2500\u2500 Web UI   : http://${wantBind}:${actualPort}
  \u2514\u2500\u2500 API Base : http://${wantBind}:${actualPort}/v1

`
      );
    }
    void running2.catalog.refresh().then(() => {
      if (process.env.BANSOS_LOG !== "json") {
        out.write(
          `  \u2514\u2500\u2500 Models   : ${running2.catalog.servableModels.length} alive (${[...new Set(running2.catalog.servableModels.map((m) => m.source))].join(", ")})

`
        );
      }
    }, (err) => log.warn(`catalog refresh failed: ${String(err?.message ?? err)}`));
  };
  const stop = (running2) => {
    clearInterval(running2.refreshTimer);
    return new Promise((resolve) => {
      running2.server.close(() => resolve());
      running2.server.closeAllConnections();
    });
  };
  const restart = async () => {
    if (restarting || !current) return;
    restarting = true;
    const previous = current;
    log.info("restarting with the saved config");
    try {
      await stop(previous);
      for (const warning of loadConfigWarnings()) log.warn(warning);
      await boot(loadConfig());
    } catch (err) {
      log.error(`restart failed: ${String(err?.message ?? err)}; starting again with the previous settings`);
      try {
        await boot(previous.config);
      } catch (fallbackErr) {
        log.error(`could not start again: ${String(fallbackErr?.message ?? fallbackErr)}`);
        process.exit(1);
      }
    } finally {
      restarting = false;
    }
  };
  for (const warning of loadConfigWarnings()) log.warn(warning);
  await boot(config);
  if (process.env.BANSOS_LOG !== "json") {
    void checkUpdate().then((info) => {
      const notice = updateNotice(info);
      if (notice) out.write(`${notice}

`);
    });
  }
  const shutdown = () => {
    log.info("shutting down");
    activity2.flush();
    if (!current) process.exit(0);
    current.server.close(() => process.exit(0));
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}
async function runDaemon(argv) {
  await main(argv);
}
function ensureOpenCodeService(log) {
  let opencodePath = "";
  const whichCmd = process.platform === "win32" ? "where" : "which";
  try {
    const check = spawnSync4(whichCmd, ["opencode"], { encoding: "utf-8", timeout: 1e3 });
    if (check.status === 0 && check.stdout.trim()) {
      opencodePath = check.stdout.trim().split(/\r?\n/)[0]?.trim() ?? "";
    }
  } catch {
  }
  if (!opencodePath) return;
  const home = os7.homedir();
  const serviceCandidates = [
    path12.join(home, ".local", "state", "opencode", "service.json"),
    path12.join(home, "Library", "Application Support", "opencode", "service.json")
  ];
  if (process.env.LOCALAPPDATA) {
    serviceCandidates.push(path12.join(process.env.LOCALAPPDATA, "opencode", "service.json"));
  }
  for (const servicePath of serviceCandidates) {
    try {
      if (fs13.existsSync(servicePath)) {
        const raw = JSON.parse(fs13.readFileSync(servicePath, "utf-8"));
        if (raw && typeof raw === "object" && "pid" in raw && typeof raw.pid === "number") {
          process.kill(raw.pid, 0);
          return;
        }
      }
    } catch {
    }
  }
  try {
    const child = spawn(opencodePath, ["serve", "--service"], {
      stdio: "ignore",
      detached: true
    });
    child.unref();
    log?.info(`auto-started local opencode service (pid ${child.pid})`);
  } catch {
  }
}

// src/cli/index.ts
init_state();
function resolveBunExecutable() {
  try {
    const check = spawnSync5("bun", ["--version"], { stdio: "ignore", timeout: 1e3 });
    if (check.status === 0) return "bun";
  } catch {
  }
  const home = os8.homedir();
  const candidates = [
    path13.join(home, ".bun", "bin", "bun"),
    "/usr/local/bin/bun",
    "/usr/bin/bun"
  ];
  for (const c of candidates) {
    try {
      if (fs14.existsSync(c)) return c;
    } catch {
    }
  }
  return null;
}
if (!("Bun" in globalThis) && !process.env.BANSOS_NO_BUN && !process.env._BANSOS_BUN_REEXEC) {
  const bunPath = resolveBunExecutable();
  if (bunPath) {
    const bunDir = path13.dirname(path13.resolve(bunPath));
    const pathEnv = process.env.PATH ? `${bunDir}:${process.env.PATH}` : bunDir;
    const res = spawnSync5(bunPath, process.argv.slice(1), {
      stdio: "inherit",
      env: { ...process.env, PATH: pathEnv, _BANSOS_BUN_REEXEC: "1" }
    });
    process.exit(res.status ?? 0);
  }
}
function help() {
  console.log(`bansos - free, keyless coding models for every agent harness

Usage:
  bansos <command> [flags]

Commands:
  start       start the daemon (--bg = detached)
  stop        stop the daemon started here (--all for every daemon)
  restart     restart the daemon, through systemd or launchd when they run it
  setup       write harness config files
  status      daemon status (aliases: none)
  models      list live catalog
  ping        probe health and latency of model(s)
  refresh     re-run health checks
  logs        tail the daemon log live
  usage       show request usage + token totals (--json)
  relay       manage relay egress
  autostart   start the daemon when you log in (on/off/status)
  doctor      diagnose setup
  backup      export config, usage history, and relay state to json
  restore     restore config and usage history from a backup file

Global flags:
  --json      structured output on status / models / ping (agent-friendly)
  --version   print version
  --help      this help; "bansos <command> --help" for per-command help

Defaults:
  port 17070 (auto-bumps to 17090 when busy), bind 127.0.0.1,
  state at ~/.bansos/, config at ~/.bansos/config.json,
  log at ~/.bansos/logs/bansosd.log

Exit codes: 0 success, 1 error (daemon unreachable, unknown command/flag/model).

"start" without --bg runs foreground and blocks (Ctrl+C stops it).

Harnesses: claude-code, aider, opencode, codex, hermes, goose, openclaw,
           jcode, 9router, continue, cline, omp, dsh
           (pi via the separate extension)

Examples:
  bansos start --bg              # daemon in background, then:
  bansos setup codex             # wire Codex CLI to the router
  bansos ping big-pickle         # probe one model
  bansos status --json           # machine-readable status

"bansosd" still works as an alias for the daemon (e.g. "bansosd --bg").
`);
}
var CMD_HELP = {
  start: `bansos start - start the daemon

Usage:
  bansos start [--bg] [--port N] [--bind H] [--unsafe-allow-non-loopback]

Flags:
  --bg          run detached; logs append to ~/.bansos/logs/bansosd.log
  --port, -p N  port to bind (default 17070, bumps +1 up to 17090 while busy)
  --bind H      address to bind (default 127.0.0.1; use 0.0.0.0 in containers)
  --unsafe-allow-non-loopback
                override strict-mode loopback protection (unsafe)

Notes:
  Without --bg the daemon runs foreground and blocks until Ctrl+C/SIGTERM.

Examples:
  bansos start --bg
  bansos start --bg --port 18000
`,
  autostart: `bansos autostart - start the daemon when you log in

Usage:
  bansos autostart [on|off|status] [--json]

How:
  Linux    systemd user service ~/.config/systemd/user/bansos-router.service
           (restarts the daemon if it crashes)
  macOS    LaunchAgent ~/Library/LaunchAgents/io.github.ihsan-ramadhan.bansos-router.plist
  Windows  bansos-router.cmd in the Startup folder (runs "bansos start --bg")

Notes:
  "on" starts the daemon right away unless one is already running; a running
  daemon is left alone and the service takes over at the next login.
  "off" only stops future logins from starting it; "bansos stop" stops the
  daemon. After moving node or reinstalling bansos elsewhere, run "on" again.

Exit codes: 0 success, 1 unsupported system or the service manager failed.
`,
  stop: `bansos stop - stop the daemon recorded in state.json (SIGTERM, then SIGKILL after 5s)

Usage:
  bansos stop [--all]

Flags:
  --all     stop every bansos daemon on this machine, not just the recorded one

Notes:
  Without --all only the daemon in ~/.bansos/state.json is stopped, so a daemon
  started by someone else (or in another project) is left alone. If state.json
  names no live daemon, the command reports what else is running and exits 0.

Exit codes: 0 when every daemon exited (also when nothing was running), 1 when one survived.
`,
  restart: `bansos restart - stop and start the daemon, e.g. after npm i -g bansos-router

Usage:
  bansos restart

How:
  A daemon run by "bansos autostart" is restarted by its service manager
  (systemctl --user restart on Linux, launchctl kickstart on macOS), so it
  stays supervised. Any other daemon is stopped and started again with
  "bansos start --bg". The dashboard's Restart only reloads the config in the
  same process, so a new version needs this command.
`,
  setup: `bansos setup - write harness config files pointing at the router

Usage:
  bansos setup <harness...> [--model <id> | --models <id,...> --upstream <id,...>] [--dry-run] [--undo]

Flags:
  --model <id>        pin one model: the only model a harness gets
  --models <id,...>   write only these models (opencode, goose, openclaw,
                      continue; claude-code picks its tiers from them)
  --upstream <id,...> add every model of these upstreams (zen, kilo, llm7, ovh)
  --dry-run           print what would be written, change nothing
  --undo              remove bansos blocks/keys previously written by setup

Notes:
  Model ids come from "bansos models". With no model flag every live model is
  written, and single-model harnesses get the catalog default. --models and
  --upstream combine; --model cannot be mixed with them.
  Config locations are listed under each harness in docs/harnesses.md.

Examples:
  bansos setup codex
  bansos setup claude-code aider --model big-pickle
  bansos setup opencode --upstream zen --models kilo-auto/free
  bansos setup codex --undo
`,
  status: `bansos status - show daemon reachability and model count

Usage:
  bansos status [--json]

Flags:
  --json    emit { "daemons": [...] } instead of text

Probes ports 17070-17090 so a bumped-port daemon is still found.
Exit codes: 0 daemon reachable, 1 not reachable.
`,
  models: `bansos models - list the live model catalog

Usage:
  bansos models [--json]

Flags:
  --json    emit the raw /v1/models document instead of one id per line

Requires a running daemon (bansos start).
`,
  ping: `bansos ping - probe model health and latency with a tiny completion

Usage:
  bansos ping [model] [--json]

Arguments:
  model     id from "bansos models"; omit to probe every model in parallel

Flags:
  --json    emit { "results": [...], "summary": {...} } instead of a table

Notes:
  Probes set x-bansos-no-failover so the reported status is the model's own.
Exit codes: 0 at least one model answered, 1 all failed/unreachable.

Example:
  bansos ping big-pickle
`,
  refresh: `bansos refresh - ask the daemon to re-run upstream health checks now

Usage:
  bansos refresh

Exit codes: 0 refreshed, 1 daemon unreachable.
`,
  logs: `bansos logs - tail ~/.bansos/logs/bansosd.log live

Usage:
  bansos logs [--activity]

Shows the last 50 lines of the daemon log, then follows appends (500ms poll).
Ctrl+C stops. Works for both "bansos start" (foreground) and "bansos start --bg":
the daemon now records every run to ~/.bansos/logs/bansosd.log.

  --activity   instead of the raw log file, print the structured request feed
              shown in the web UI "Activity" tab (model, tokens, latency,
              failover, status) - the same source the UI polls.
Exit codes: 1 when no log file exists yet (or the daemon is unreachable with --activity).
`,
  relay: `bansos relay - manage relay egress for keyless upstreams

Usage:
  bansos relay <on|off|status|url <URL>|use <URL>|list|remove <URL>|deploy>

Run "bansos relay" without arguments for the full subcommand list.
`,
  doctor: `bansos doctor - diagnose the local setup

Usage:
  bansos doctor

Checks daemon reachability and every harness config file, prints an update
notice when one exists.
Exit codes: 0 healthy, 1 any check failed.
`,
  usage: `bansos usage - show request usage and token totals

Usage:
  bansos usage [--json]

Flags:
  --json    emit the raw /bansos/usage document instead of a summary table

Requires a running daemon (bansos start). Aggregates cover the whole history,
kept in ~/.bansos/activity/ (append-only JSONL plus monthly rollups) across restarts. Use the "Activity" tab in the web UI for a live, per-request feed.
Exit codes: 0 daemon reachable, 1 daemon unreachable.
`,
  backup: `bansos backup - export config, usage history, and relay state

Usage:
  bansos backup [file.json]

Defaults to bansos-backup-YYYY-MM-DD.json in current directory, or - for stdout.
Exit codes: 0 success, 1 failure.
`,
  restore: `bansos restore - restore config and usage history from a backup file

Usage:
  bansos restore <file.json>

Exit codes: 0 success, 1 failure.
`
};
function isDaemonFlag(a) {
  return a === "--port" || a === "-p" || a === "--bind" || a === "--bg" || a === "--unsafe-allow-non-loopback";
}
async function main2() {
  const argv = process.argv.slice(2);
  const invokedAs = path13.basename(process.argv[1] ?? "");
  if (invokedAs === "bansosd" || argv[0] === "daemon" || isDaemonFlag(argv[0])) {
    await runDaemon(argv);
    return daemonExitCode();
  }
  const json = argv.includes("--json");
  const args = argv.filter((a) => a !== "--json");
  const wantsHelp = args.includes("--help") || args.includes("-h");
  const helpTarget = wantsHelp ? args[0] : args[0] === "help" ? args[1] : void 0;
  if (helpTarget && CMD_HELP[helpTarget]) {
    console.log(CMD_HELP[helpTarget]);
    return 0;
  }
  if (wantsHelp || args[0] === "help") {
    if (args.length <= 1) {
      help();
      return 0;
    }
  }
  switch (args[0]) {
    case "setup":
      return runSetup(args.slice(1));
    case "start":
      return runStart(args.slice(1));
    case "stop":
      return runStop(args.slice(1));
    case "restart":
      return runRestart(args.slice(1));
    case "logs":
      return runLogs(args.slice(1));
    case "status":
      return runStatus(json);
    case "ping":
      return runPing(json ? [...args.slice(1), "--json"] : args.slice(1));
    case "models":
    case "refresh":
      return runStatusOrModels(args[0], json);
    case "usage":
      return runUsage(json);
    case "relay":
      return runRelay(args.slice(1));
    case "autostart":
      return runAutostart(args.slice(1), json);
    case "doctor":
      return runDoctor(args.slice(1));
    case "backup":
      return runBackup(args.slice(1));
    case "restore":
      return runRestore(args.slice(1));
    case "--version":
    case "-v":
      console.log(VERSION);
      return 0;
    case "help":
    case "--help":
    case "-h":
    case void 0:
      help();
      return 0;
    default:
      console.error(`bansos: unknown command "${args[0]}"`);
      help();
      return 1;
  }
}
function daemonExitCode() {
  return typeof process.exitCode === "number" ? process.exitCode : 0;
}
async function runStart(args) {
  let bg = false;
  let port;
  let bind;
  let unsafeAllowNonLoopback = false;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--bg") bg = true;
    else if (a === "--port" || a === "-p") port = Number(args[++i]);
    else if (a === "--bind") bind = args[++i];
    else if (a === "--unsafe-allow-non-loopback") unsafeAllowNonLoopback = true;
    else {
      console.error(`bansos start: unknown flag "${a}"`);
      return 1;
    }
  }
  if (!bg) {
    await runDaemon(args);
    return daemonExitCode();
  }
  const running = await runningDaemonUrl(port);
  if (running) {
    console.log(`bansosd already running at ${running}`);
    const stale = await staleDaemonNotice(running);
    if (stale) console.log(`${stale}
`);
    else await printUpdateNotice();
    return 0;
  }
  const logFile = path13.join(BANSOS_DIR, "logs", "bansosd.log");
  fs14.mkdirSync(path13.dirname(logFile), { recursive: true });
  const child = spawn2(
    process.execPath,
    [
      ...process.execArgv,
      process.argv[1],
      "daemon",
      ...startArgs({ port, bind, unsafeAllowNonLoopback }),
      "--bg-child"
    ],
    {
      stdio: ["ignore", "ignore", "ignore"],
      detached: true
    }
  );
  child.unref();
  let spawnFailed = false;
  child.on("error", () => {
    spawnFailed = true;
  });
  const config = await Promise.resolve().then(() => (init_state(), state_exports)).then((m) => m.loadConfig());
  let effectivePort2 = port ?? config.port ?? DEFAULT_PORT;
  let effectiveBind2 = bind ?? config.bind ?? "127.0.0.1";
  for (let i = 0; i < 100; i++) {
    const st = readJson(STATE_FILE);
    if (st && st.pid === child.pid && typeof st.port === "number") {
      effectivePort2 = st.port;
      if (typeof st.bind === "string") effectiveBind2 = st.bind;
      break;
    }
    if (spawnFailed || child.exitCode !== null || child.signalCode !== null) {
      console.error(`bansos start --bg: daemon exited before binding (port ${effectivePort2} busy or bind refused)`);
      console.error(`  check the log: ${logFile}`);
      return 1;
    }
    await new Promise((r) => setTimeout(r, 50));
  }
  const baseUrl = `http://${effectiveBind2}:${effectivePort2}`;
  console.log(`
\u25CF bansosd started in background (pid ${child.pid})`);
  console.log(`  \u251C\u2500\u2500 Web UI   : ${baseUrl}`);
  console.log(`  \u251C\u2500\u2500 API Base : ${baseUrl}/v1`);
  console.log(`  \u2514\u2500\u2500 Log file : ${logFile}`);
  console.log(`
watch logs live with: bansos logs
`);
  await printUpdateNotice();
  return 0;
}
async function printUpdateNotice() {
  const notice = updateNotice(await checkUpdate());
  if (notice) console.log(`${notice}
`);
}
async function runLogs(args) {
  const activity2 = args.includes("--activity");
  const base = `http://${effectiveBind()}:${effectivePort()}`;
  if (activity2) {
    let res;
    try {
      res = await fetch(`${base}/bansos/events?limit=100`);
    } catch {
      console.error(`bansos logs: daemon not reachable at ${base}. Start it with "bansos start"`);
      return 1;
    }
    if (!res.ok) {
      console.error(`bansos logs: daemon returned HTTP ${res.status}`);
      return 1;
    }
    const body = await res.json();
    if (body.events.length === 0) {
      console.log("(no activity yet)");
      return 0;
    }
    const time = (ts) => new Date(ts).toLocaleTimeString();
    const fmt = (n) => n >= 1e6 ? `${(n / 1e6).toFixed(1)}M` : n >= 1e3 ? `${(n / 1e3).toFixed(1)}k` : String(n);
    for (const e of body.events) {
      const status = e.status === "ok" ? "\u2713" : e.statusCode ? `\u2717 ${e.statusCode}` : "\u2717";
      const fo = e.failoverFrom ? ` (failover ${e.failoverFrom}->${e.model})` : "";
      console.log(
        `${time(e.timestamp)} ${status} ${e.kind} ${e.model} [${e.upstream}] ${fmt(e.inputTokens)}/${fmt(e.outputTokens)} tok ${e.durationMs}ms${fo}`
      );
    }
    return 0;
  }
  const logFile = path13.join(BANSOS_DIR, "logs", "bansosd.log");
  if (!fs14.existsSync(logFile)) {
    console.error(`bansos logs: no log file at ${logFile}`);
    console.error(`  the daemon writes one when started with: bansos start (or --bg)`);
    return 1;
  }
  const TAIL_WINDOW = 64 * 1024;
  const fd = fs14.openSync(logFile, "r");
  let tail = "";
  let tailStart = 0;
  try {
    const size2 = fs14.statSync(logFile).size;
    tailStart = Math.max(0, size2 - TAIL_WINDOW);
    const buf = Buffer.alloc(size2 - tailStart);
    fs14.readSync(fd, buf, 0, buf.length, tailStart);
    tail = buf.toString("utf8");
  } finally {
    fs14.closeSync(fd);
  }
  const lines = tail.split("\n");
  let context = lines.slice(Math.max(0, lines.length - 50));
  if (tailStart > 0 && context.length > 0) context = context.slice(1);
  if (context.some((l) => l !== "")) {
    process.stdout.write(`${context.join("\n").trimStart()}
`);
  }
  process.stdout.write("(watching the daemon log, Ctrl+C to stop)\n");
  let size = fs14.statSync(logFile).size;
  const timer = setInterval(() => {
    let st;
    try {
      st = fs14.statSync(logFile);
    } catch {
      process.stdout.write("\nbansos logs: log file removed, stopping\n");
      process.exit(0);
    }
    if (st.size === size) return;
    if (st.size < size) size = 0;
    const fd2 = fs14.openSync(logFile, "r");
    const buf = Buffer.alloc(st.size - size);
    fs14.readSync(fd2, buf, 0, buf.length, size);
    fs14.closeSync(fd2);
    size = st.size;
    process.stdout.write(buf.toString("utf8"));
  }, 500);
  return await new Promise((resolve) => {
    process.once("SIGINT", () => {
      clearInterval(timer);
      resolve(0);
    });
    process.once("SIGTERM", () => {
      clearInterval(timer);
      resolve(0);
    });
  });
}
function isAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return err.code === "EPERM";
  }
}
function findDaemonPids(statePid) {
  const pids = /* @__PURE__ */ new Set();
  if (statePid && isAlive(statePid)) pids.add(statePid);
  if (process.platform === "linux" && fs14.existsSync("/proc")) {
    for (const entry of fs14.readdirSync("/proc")) {
      if (!/^\d+$/.test(entry)) continue;
      const pid = Number(entry);
      if (pids.has(pid)) continue;
      try {
        const args = fs14.readFileSync(`/proc/${entry}/cmdline`, "utf8").split("\0").filter(Boolean);
        if (isDaemonCmdline(args)) pids.add(pid);
      } catch {
      }
    }
  } else {
    for (const { pid, cmdline } of scanProcessList()) {
      if (!pids.has(pid) && isDaemonCmdline(cmdline.split(/\s+/))) pids.add(pid);
    }
  }
  return [...pids];
}
var WIN_PROCESS_LIST = Buffer.from(
  `Get-CimInstance Win32_Process -Filter "Name='node.exe'" | ForEach-Object { "$($_.ProcessId) $($_.CommandLine)" }`,
  "utf16le"
).toString("base64");
function scanProcessList() {
  try {
    const out = process.platform === "win32" ? execFileSync2(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-EncodedCommand", WIN_PROCESS_LIST],
      { encoding: "utf8", windowsHide: true, stdio: ["ignore", "pipe", "ignore"] }
    ) : execFileSync2("ps", ["-axo", "pid=,command="], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
    const rows = [];
    for (const line of out.split(/\r?\n/)) {
      const m = line.match(/^\s*(\d+)\s+(.*)$/);
      if (m) rows.push({ pid: Number(m[1]), cmdline: m[2] ?? "" });
    }
    return rows;
  } catch {
    return [];
  }
}
function isDaemonCmdline(args) {
  const script = path13.basename(args[1] ?? "");
  const cmd = args[2];
  if (script === "bansos" || script === "bansosd") {
    return cmd === void 0 || cmd === "daemon" || cmd === "start" || cmd?.startsWith("--");
  }
  return args.includes("daemon") || args.join(" ").includes("dist/daemon/index.js");
}
async function waitForExit(pids, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  let alive = pids.filter(isAlive);
  while (alive.length > 0 && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 100));
    alive = alive.filter(isAlive);
  }
  return alive;
}
async function runRestart(args) {
  if (args.length > 0) {
    console.error(`bansos restart: takes no flags (got "${args[0]}")`);
    return 1;
  }
  const state = readJson(STATE_FILE);
  let manager;
  try {
    manager = restartManaged();
  } catch (err) {
    console.error(`bansos restart: ${err.message}`);
    return 1;
  }
  if (!manager) {
    if (!state?.pid || !isAlive(state.pid)) {
      const others = findDaemonPids(null);
      if (others.length > 0) {
        console.error(`bansos restart: ${others.length} daemon(s) not recorded in state.json are running, so there is nothing to restart here`);
        console.error(`  stop them with "bansos stop --all", then run "bansos start --bg"`);
        return 1;
      }
    }
    const stopped = await runStop();
    return stopped === 0 ? runStart(["--bg", ...startArgs(state?.flags)]) : stopped;
  }
  for (let i = 0; i < 100; i++) {
    const startedAt = readJson(STATE_FILE)?.startedAt;
    const url = startedAt !== void 0 && startedAt !== state?.startedAt ? await runningDaemonUrl() : null;
    if (url) {
      console.log(`bansosd restarted by ${manager} at ${url}`);
      await printUpdateNotice();
      return 0;
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  console.error(`bansos restart: ${manager} restarted the service but the daemon did not answer; check: bansos logs`);
  return 1;
}
async function runStop(args = []) {
  const all = args.includes("--all");
  const state = readJson(STATE_FILE);
  let pids;
  if (all) {
    pids = findDaemonPids(state?.pid ?? null);
  } else if (state?.pid && isAlive(state.pid)) {
    pids = [state.pid];
  } else {
    pids = [];
    const others = findDaemonPids(null);
    if (others.length > 0) {
      console.log(`no daemon recorded in state.json, but ${others.length} other daemon(s) are running`);
      console.log("  stop them with: bansos stop --all");
      return 0;
    }
  }
  if (pids.length === 0) {
    console.log("no daemon running");
    return 0;
  }
  for (const pid of pids) {
    try {
      process.kill(pid, "SIGTERM");
    } catch {
    }
  }
  let survivors = await waitForExit(pids, 5e3);
  for (const pid of survivors) {
    try {
      process.kill(pid, "SIGKILL");
    } catch {
    }
  }
  survivors = await waitForExit(survivors, 2e3);
  fs14.rmSync(STATE_FILE, { force: true });
  console.log(`stopped ${pids.length - survivors.length} daemon(s)`);
  if (survivors.length > 0) {
    console.error(`bansos stop: pid ${survivors.join(", ")} did not exit`);
    return 1;
  }
  return 0;
}
async function probeDaemonPorts() {
  const config = await Promise.resolve().then(() => (init_state(), state_exports)).then((m) => m.loadConfig());
  const state = readJson(STATE_FILE);
  const ports = /* @__PURE__ */ new Set([config.port]);
  if (state?.port) ports.add(state.port);
  for (let p = DEFAULT_PORT; p <= MAX_PORT; p++) ports.add(p);
  const results = await Promise.all(
    [...ports].map(async (port) => {
      try {
        const res = await fetch(`http://127.0.0.1:${port}/bansos/status`, {
          signal: AbortSignal.timeout(400)
        });
        if (!res.ok) return null;
        const body = await res.json();
        return body.status === "ok" ? body : null;
      } catch {
        return null;
      }
    })
  );
  return results.filter((r) => r !== null).sort((a, b) => a.port - b.port);
}
async function runStatus(json) {
  const daemons = await probeDaemonPorts();
  if (daemons.length === 0) {
    if (json) {
      console.log(JSON.stringify({ ok: false, daemons: [] }));
      return 1;
    }
    console.error(
      `bansos: no daemon reachable (probed ports ${DEFAULT_PORT}-${MAX_PORT}), start one with "bansos start"`
    );
    const notice = updateNotice(await checkUpdate());
    if (notice) console.log(`
${notice}`);
    return 1;
  }
  const update = await checkUpdate();
  if (json) {
    console.log(JSON.stringify({
      ok: true,
      daemons,
      ...update.hasUpdate ? { updateAvailable: update.latest } : {}
    }));
    return 0;
  }
  for (const [i, d] of daemons.entries()) {
    console.log(`daemon:   ok (port ${d.port})`);
    if (d.version) {
      const stale = isNewerVersion(d.version, VERSION) ? ` (${VERSION} is installed, run: bansos restart)` : "";
      console.log(`version:  ${d.version}${stale}`);
    }
    console.log(`models:   ${d.modelCount}`);
    if (d.relay?.enabled && d.relay.url) {
      console.log(`relay:    on (${d.relay.url})`);
    } else {
      console.log(`relay:    off (direct)`);
    }
    console.log(`alive:    ${d.models.join(", ") || "(none)"}`);
    if (i < daemons.length - 1) console.log("");
  }
  if (update.hasUpdate) {
    console.log(`
${updateNotice(update)}`);
  }
  return 0;
}
async function runUsage(json) {
  const base = `http://${effectiveBind()}:${effectivePort()}`;
  let body;
  try {
    const res = await fetch(`${base}/bansos/usage`);
    if (!res.ok) {
      console.error(`bansos usage: daemon returned HTTP ${res.status}`);
      return 1;
    }
    body = await res.json();
  } catch {
    console.error(`bansos usage: daemon not reachable at ${base}. Start it with "bansos start"`);
    return 1;
  }
  if (json) {
    console.log(JSON.stringify(body));
    return 0;
  }
  const fmt = (n) => n >= 1e6 ? `${(n / 1e6).toFixed(1)}M` : n >= 1e3 ? `${(n / 1e3).toFixed(1)}k` : String(n);
  const dur = (ms) => ms >= 1e3 ? `${(ms / 1e3).toFixed(1)}s` : `${ms}ms`;
  console.log(`
\u25CF usage summary (all time)
`);
  console.log(`  requests    : ${body.totalRequests} (${body.okRequests} ok, ${body.errorRequests} err)`);
  console.log(`  tokens in   : ${fmt(body.totalInputTokens)}`);
  console.log(`  cached      : ${fmt(body.totalCachedTokens ?? 0)}`);
  console.log(`  tokens out  : ${fmt(body.totalOutputTokens)}`);
  console.log(`  avg latency : ${dur(body.avgDurationMs)}`);
  console.log(`  failovers   : ${body.failoverCount}`);
  const models = Object.entries(body.perModel).sort((a, b) => b[1].requests - a[1].requests);
  if (models.length > 0) {
    console.log(`
  by model:`);
    for (const [m, s] of models) {
      console.log(`    ${m}  ${s.requests} reqs \xB7 ${fmt(s.inputTokens)}/${fmt(s.outputTokens)} tok \xB7 ${fmt(s.cachedTokens ?? 0)} cached`);
    }
  }
  const upstreams = Object.entries(body.perUpstream).sort((a, b) => b[1].requests - a[1].requests);
  if (upstreams.length > 0) {
    console.log(`
  by upstream:`);
    for (const [u, s] of upstreams) {
      console.log(`    ${u}  ${s.requests} reqs`);
    }
  }
  console.log("");
  return 0;
}
async function runStatusOrModels(cmd, json) {
  const base = `http://${effectiveBind()}:${effectivePort()}`;
  try {
    if (cmd === "models") {
      const res2 = await fetch(`${base}/v1/models`);
      const body2 = await res2.json();
      if (json) {
        console.log(JSON.stringify(body2));
        return 0;
      }
      for (const m of body2.data) console.log(m.id);
      return 0;
    }
    const res = await fetch(`${base}/bansos/refresh`, { method: "POST" });
    const body = await res.json();
    if (json) {
      console.log(JSON.stringify(body));
      return 0;
    }
    console.log(`refreshed: ${body.modelCount} model(s), ${body.alive} alive`);
    return 0;
  } catch {
    if (json) console.log(JSON.stringify({ ok: false, error: `daemon not reachable at ${base}` }));
    else console.error(`bansos: daemon not reachable at ${base}. Start it with "bansos start"`);
    return 1;
  }
}
async function runBackup(argv) {
  const base = `http://${effectiveBind()}:${effectivePort()}`;
  let outPath = argv.find((a) => !a.startsWith("-"));
  let res;
  try {
    res = await fetch(`${base}/bansos/backup`);
    if (!res.ok) {
      console.error(`bansos backup: daemon returned HTTP ${res.status}`);
      return 1;
    }
  } catch {
    console.error(`bansos backup: daemon not reachable at ${base}. Start it with "bansos start"`);
    return 1;
  }
  const body = await res.json();
  const formatted = JSON.stringify(body, null, 2);
  if (!outPath) {
    outPath = `bansos-backup-${(/* @__PURE__ */ new Date()).toISOString().slice(0, 10)}.json`;
  }
  if (outPath === "-") {
    process.stdout.write(formatted + "\n");
    return 0;
  }
  try {
    fs14.writeFileSync(outPath, formatted);
    console.log(`Backup written to ${outPath}`);
    return 0;
  } catch (err) {
    console.error(`bansos backup: failed to write ${outPath}: ${err.message}`);
    return 1;
  }
}
async function runRestore(argv) {
  const filePath = argv.find((a) => !a.startsWith("-"));
  if (!filePath) {
    console.error("Usage: bansos restore <backup-file.json>");
    return 1;
  }
  if (!fs14.existsSync(filePath)) {
    console.error(`bansos restore: file not found: ${filePath}`);
    return 1;
  }
  let parsed;
  try {
    const text = fs14.readFileSync(filePath, "utf8");
    parsed = JSON.parse(text);
  } catch (err) {
    console.error(`bansos restore: failed to parse JSON in ${filePath}: ${err.message}`);
    return 1;
  }
  const base = `http://${effectiveBind()}:${effectivePort()}`;
  try {
    const res = await fetch(`${base}/bansos/restore`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: parsed })
    });
    if (!res.ok) {
      const errBody = await res.json().catch(() => ({}));
      console.error(`bansos restore: daemon returned HTTP ${res.status}: ${errBody?.error?.message ?? "unknown error"}`);
      return 1;
    }
    const result = await res.json();
    const parts = [];
    if (result.restored.config) parts.push("config");
    if (result.restored.activityCount > 0) parts.push(`${result.restored.activityCount} activity events`);
    if (result.restored.relay) parts.push("relay");
    console.log(`Restored: ${parts.join(", ") || "no components found"}`);
    if (result.restartRequired.length > 0) {
      console.log(`Restart required to apply changes to: ${result.restartRequired.join(", ")} (run: bansos restart)`);
    }
    return 0;
  } catch {
    console.error(`bansos restore: daemon not reachable at ${base}. Start it with "bansos start"`);
    return 1;
  }
}
process.exitCode = await main2().catch((err) => {
  console.error(`bansos: ${String(err)}`);
  return 1;
});
