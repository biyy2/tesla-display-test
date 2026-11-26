/* ParkDesk Phase 0 test page. Plain browser JS, no build step.
   Signaling: PeerJS 1.5.4 library (vendored) + public cloud broker 0.peerjs.com */

(function () {
  "use strict";

  var BROKER = {
    host: "0.peerjs.com",
    port: 443,
    path: "/",
    secure: true,
    debug: 1
  };
  var ICE_SERVERS = [{ urls: "stun:stun.l.google.com:19302" }];
  var ICE_MODE_LABEL = { auto: "자동", relay: "중계만", direct: "직접만" };
  var iceState = { mode: "auto", turnUrls: "", turnUser: "", turnCred: "" };
  var currentPcCode = "";
  var reconnectTimer = { pc: null, tesla: null };
  var reconnectWait = { pc: 500, tesla: 500 };
  var iceOfferTimer = null;
  var iceOfferConn = null;
  var probeNoteAt = 0;
  var teslaIdRetries = 0;
  var PEER_PREFIX = "parkdesk-";
  var CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  var PING_COUNT = 30;
  var PING_EVERY_MS = 400;

  var role = new URLSearchParams(location.search).get("role") || "";
  if (role) role = role.toLowerCase();

  var results = {
    v: 1,
    app: "parkdesk-phase0",
    role: role || "home",
    startedAt: nowIso(),
    pageUrl: location.href,
    broker: {
      name: "PeerJS cloud",
      host: BROKER.host,
      port: BROKER.port,
      path: BROKER.path,
      library: "peerjs@1.5.4 (vendored)",
      note: "계정 없이 쓰는 공개 시그널링 브로커입니다. 가용성은 제3자 서비스에 달려 있습니다."
    },
    iceConfig: null,
    iceTimeline: [],
    iceSelected: null,
    turnCheck: null,
    ua: navigator.userAgent,
    env: {},
    support: {},
    codecs: {},
    iceGathering: {},
    privateIpTest: null,
    pairing: null,
    rtt: null,
    media: null,
    taps: [],
    logs: [],
    errors: []
  };

  var teslaPeer = null;
  var teslaConn = null;
  var teslaCall = null;
  var pcPeer = null;
  var pcConn = null;
  var pcCall = null;
  var pcRemotePeerId = null;
  var localStream = null;
  var pingTimer = null;
  var pingPending = {};
  var pingSamples = [];
  var statsTimer = null;
  var liveTestSnapshotSent = false;
  var receivedTesla = null;
  var incomingResults = null;
  var RESULT_CHUNK_BYTES = 3500;

  function nowIso() {
    return new Date().toISOString();
  }

  function $(id) {
    return document.getElementById(id);
  }

  function log(preId, msg, level) {
    var line = "[" + new Date().toLocaleTimeString("ko-KR", { hour12: false }) + "] " + msg;
    results.logs.push(line);
    if (level === "error") results.errors.push(msg);
    var el = $(preId);
    if (!el) return;
    el.textContent += line + "\n";
    el.scrollTop = el.scrollHeight;
    console.log(line);
  }

  function setStatus(id, text, kind) {
    var el = $(id);
    if (!el) return;
    el.textContent = text;
    el.className = "status-row" + (kind ? " " + kind : "");
  }

  function kv(dl, rows) {
    dl.innerHTML = "";
    rows.forEach(function (row) {
      var dt = document.createElement("dt");
      var dd = document.createElement("dd");
      dt.textContent = row[0];
      dd.textContent = row[1];
      if (row[2]) dd.className = row[2];
      dl.appendChild(dt);
      dl.appendChild(dd);
    });
  }

  function classifyIp(addr) {
    if (!addr) return "없음";
    if (addr.endsWith(".local")) return "mDNS";
    if (addr.indexOf(":") >= 0 && addr.indexOf(".") < 0) {
      var lower = addr.toLowerCase();
      if (lower === "::1" || lower === "https://example.net/id/garnet") return "IPv6-loopback";
      if (lower.startsWith("fe80:")) return "IPv6-link-local";
      if (lower.startsWith("fc") || lower.startsWith("fd")) return "IPv6-ula";
      return "IPv6-other";
    }
    var m = addr.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
    if (!m) return "unknown";
    var a = +m[1], b = +m[2];
    if (a === 127) return "loopback";
    if (a === 10) return "RFC1918-10/8";
    if (a === 192 && b === 168) return "RFC1918-192.168/16";
    if (a === 172 && b >= 16 && b <= 31) return "RFC1918-172.16/12";
    if (a === 100 && b >= 64 && b <= 127) return "RFC6598-CGNAT";
    if (a === 169 && b === 254) return "link-local";
    if (a === 192 && b === 0 && +m[3] === 2) return "TEST-NET-1";
    if (a === 198 && b === 51 && +m[3] === 100) return "TEST-NET-2";
    if (a === 203 && b === 113) return "TEST-NET-3";
    if (a >= 224) return "special/reserved";
    return "public-or-other";
  }

  function parseCandidate(raw) {
    var out = { raw: raw, typ: "?", address: "", protocol: "", port: "", range: "?", related: "" };
    if (!raw) return out;
    var typ = raw.match(/ typ ([^\s]+)/);
    var addr = raw.match(/ ([0-9a-fA-F:.]+|[\w.-]+\.local) (\d+) typ /);
    var proto = raw.match(/ (udp|tcp) /i);
    var raddr = raw.match(/ raddr ([^\s]+)/);
    if (typ) out.typ = typ[1];
    if (addr) {
      out.address = addr[1];
      out.port = addr[2];
    }
    if (proto) out.protocol = proto[1].toLowerCase();
    if (raddr) out.related = raddr[1];
    if (out.address.endsWith(".local")) out.typ = out.typ + "+mDNS";
    out.range = classifyIp(out.address);
    return out;
  }

  function readEnv() {
    var vv = window.visualViewport;
    var env = {
      userAgent: navigator.userAgent,
      language: navigator.language,
      innerWidth: window.innerWidth,
      innerHeight: window.innerHeight,
      outerWidth: window.outerWidth,
      outerHeight: window.outerHeight,
      screenWidth: screen.width,
      screenHeight: screen.height,
      availWidth: screen.availWidth,
      availHeight: screen.availHeight,
      devicePixelRatio: window.devicePixelRatio || 1,
      visualViewport: vv
        ? { width: vv.width, height: vv.height, scale: vv.scale, offsetLeft: vv.offsetLeft, offsetTop: vv.offsetTop }
        : null,
      timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      secureContext: window.isSecureContext,
      protocol: location.protocol
    };
    results.env = env;
    return env;
  }

  function readSupport() {
    var support = {
      RTCPeerConnection: typeof RTCPeerConnection === "function",
      RTCDataChannel: "RTCDataChannel" in window,
      mediaDevices: !!(navigator.mediaDevices && navigator.mediaDevices.getUserMedia),
      getDisplayMedia: !!(navigator.mediaDevices && navigator.mediaDevices.getDisplayMedia),
      PeerJS: typeof window.Peer === "function"
    };
    results.support = support;
    return support;
  }

  function readCodecs() {
    var info = { h264: false, h264Mimes: [], allVideo: [], error: null };
    try {
      if (!window.RTCRtpReceiver || typeof RTCRtpReceiver.getCapabilities !== "function") {
        info.error = "RTCRtpReceiver.getCapabilities 없음";
      } else {
        var caps = RTCRtpReceiver.getCapabilities("video") || { codecs: [] };
        (caps.codecs || []).forEach(function (c) {
          if (c && c.mimeType) {
            info.allVideo.push(c.mimeType + (c.sdpFmtpLine ? " " + c.sdpFmtpLine : ""));
            if (/h264/i.test(c.mimeType)) {
              info.h264 = true;
              info.h264Mimes.push(c.mimeType + (c.sdpFmtpLine ? " (" + c.sdpFmtpLine + ")" : ""));
            }
          }
        });
      }
    } catch (err) {
      info.error = String(err);
    }
    results.codecs = info;
    return info;
  }

  function gatherIce(logId, rtcConfig, store) {
    if (store === undefined) store = true;
    return new Promise(function (resolve) {
      if (typeof RTCPeerConnection !== "function") {
        var empty = { error: "RTCPeerConnection 없음", candidates: [], types: {}, ranges: {}, errors: [] };
        if (store) results.iceGathering = empty;
        resolve(empty);
        return;
      }
      var pc = new RTCPeerConnection(rtcConfig || { iceServers: ICE_SERVERS });
      var iceErrors = [];
      var candidates = [];
      var done = false;

      function finish() {
        if (done) return;
        done = true;
        try { pc.close(); } catch (e) {}
        var types = {};
        var ranges = {};
        candidates.forEach(function (c) {
          types[c.typ] = (types[c.typ] || 0) + 1;
          ranges[c.range] = (ranges[c.range] || 0) + 1;
        });
        var out = {
          stun: ICE_SERVERS[0].urls,
          candidateCount: candidates.length,
          types: types,
          ranges: ranges,
          hasHost: candidates.some(function (c) { return c.typ.indexOf("host") === 0; }),
          hasMdns: candidates.some(function (c) { return c.address.endsWith(".local") || c.typ.indexOf("mDNS") >= 0; }),
          hasSrflx: candidates.some(function (c) { return c.typ === "srflx"; }),
          hasRelay: candidates.some(function (c) { return c.typ === "relay"; }),
          candidates: candidates,
          errors: iceErrors.slice()
        };
        if (store) results.iceGathering = out;
        resolve(out);
      }

      pc.onicecandidate = function (ev) {
        if (!ev.candidate || !ev.candidate.candidate) {
          if (!ev.candidate) finish();
          return;
        }
        var parsed = parseCandidate(ev.candidate.candidate);
        parsed.sdpMid = ev.candidate.sdpMid;
        candidates.push(parsed);
        if (logId) log(logId, "ICE " + parsed.typ + " " + parsed.address + " " + parsed.range);
      };
      pc.onicegatheringstatechange = function () {
        if (pc.iceGatheringState === "complete") finish();
      };
      pc.onicecandidateerror = function (ev) {
        var line = [ev.errorCode, ev.errorText, ev.url].filter(function (x) { return x !== undefined && x !== null && x !== ""; }).join(" ");
        if (line) iceErrors.push(line);
        if (logId) log(logId, "ICE error " + (line || ev.errorText || ev.errorCode || ev.url || ""));
      };

      try {
        pc.createDataChannel("probe");
        pc.createOffer().then(function (offer) {
          return pc.setLocalDescription(offer);
        }).catch(function (err) {
          if (store) results.iceGathering = { error: String(err), candidates: [], errors: iceErrors.slice() };
          finish();
        });
      } catch (err) {
        if (store) results.iceGathering = { error: String(err), candidates: [], errors: iceErrors.slice() };
        finish();
      }
      setTimeout(finish, 8000);
    });
  }

  function renderIce(summary) {
    if (!$("ice-summary")) return;
    if (summary.error) {
      kv($("ice-summary"), [["오류", summary.error, "bad-text"]]);
      return;
    }
    if (!summary.candidateCount) {
      kv($("ice-summary"), [
        ["후보 수", "0 — 이 브라우저/네트워크가 ICE 후보를 만들지 못했습니다", "warn-text"],
        ["host", "없음", "bad-text"],
        ["mDNS", "없음", "warn-text"],
        ["srflx (STUN)", "없음", "warn-text"],
        ["relay (TURN)", "없음 (이 페이지는 TURN을 쓰지 않습니다)", "warn-text"]
      ]);
      $("ice-list").innerHTML = "";
      return;
    }
    kv($("ice-summary"), [
      ["후보 수", String(summary.candidateCount || 0)],
      ["host", summary.hasHost ? "있음" : "없음", summary.hasHost ? "ok-text" : "bad-text"],
      ["mDNS", summary.hasMdns ? "있음" : "없음", summary.hasMdns ? "ok-text" : "warn-text"],
      ["srflx (STUN)", summary.hasSrflx ? "있음" : "없음", summary.hasSrflx ? "ok-text" : "warn-text"],
      ["relay (TURN)", summary.hasRelay ? "있음 (이 페이지는 TURN 없음이 정상)" : "없음", "warn-text"],
      ["유형", JSON.stringify(summary.types || {})],
      ["주소 대역", JSON.stringify(summary.ranges || {})]
    ]);
    var ul = $("ice-list");
    ul.innerHTML = "";
    (summary.candidates || []).forEach(function (c) {
      var li = document.createElement("li");
      li.textContent = (c.typ || "?") + "  " + (c.protocol || "") + "  " + (c.address || "") + ":" + (c.port || "") + "  (" + c.range + ")";
      ul.appendChild(li);
    });
  }

  function isProbablyIp(s) {
    return /^(\d{1,3}\.){3}\d{1,3}$/.test(s) || (s.indexOf(":") >= 0 && s.indexOf(" ") < 0);
  }

  function testUrlOnce(url, kind) {
    return new Promise(function (resolve) {
      var started = Date.now();
      var settled = false;
      function done(result) {
        if (settled) return;
        settled = true;
        result.ms = Date.now() - started;
        result.url = url;
        result.kind = kind;
        resolve(result);
      }
      setTimeout(function () { done({ ok: false, reason: "timeout-3s" }); }, 3000);

      if (kind === "fetch") {
        fetch(url, { mode: "no-cors", cache: "no-store", credentials: "omit" })
          .then(function (res) {
            done({
              ok: true,
              reason: "fetch-resolved",
              opaque: res.type === "opaque",
              type: res.type,
              status: res.status,
              note: "no-cors 는 성공처럼 보여도 본문을 확인할 수 없습니다. opaque 는 요청이 네트워크로 나갔을 가능성만 뜻합니다."
            });
          })
          .catch(function (err) {
            var msg = String(err && err.message ? err.message : err);
            var mixed = /mixed content|insecure|https/i.test(msg) || (location.protocol === "https:" && url.indexOf("http://") === 0);
            done({
              ok: false,
              reason: mixed ? "blocked-or-failed (HTTPS 페이지에서 HTTP 는 혼합 콘텐츠로 막혔을 수 있음)" : "fetch-failed",
              message: msg
            });
          });
        return;
      }

      var img = new Image();
      img.onload = function () { done({ ok: true, reason: "image-load" }); };
      img.onerror = function () {
        var mixed = location.protocol === "https:" && url.indexOf("http://") === 0;
        done({
          ok: false,
          reason: mixed
            ? "image-error (혼합 콘텐츠 또는 사설 IP 차단 또는 대상에 HTTP 서버 없음)"
            : "image-error (대상 거부/없음 또는 사설 IP 차단)",
          mixedContentPossible: mixed
        });
      };
      img.src = url + (url.indexOf("?") >= 0 ? "&" : "?") + "parkdesk_probe=" + Date.now();
    });
  }

  async function runPrivateIpTest(ip) {
    ip = (ip || "").trim().replace(/^\[|\]$/g, "");
    var out = { ip: ip, startedAt: nowIso(), tests: [] };
    if (!isProbablyIp(ip)) {
      out.error = "IP 형식이 아닙니다.";
      results.privateIpTest = out;
      return out;
    }
    var urls = ["http://" + ip + "/", "https://" + ip + "/"];
    for (var i = 0; i < urls.length; i++) {
      out.tests.push(await testUrlOnce(urls[i], "fetch"));
      out.tests.push(await testUrlOnce(urls[i], "image"));
    }
    out.note =
      "HTTPS 검사 페이지에서 HTTP 사설 IP로 가는 요청은 일반 Chrome에서도 혼합 콘텐츠로 막힐 수 있습니다. " +
      "테슬라 주소창에 http://IP 를 직접 입력하는 검사와 결과가 다를 수 있습니다. README를 참고하세요.";
    results.privateIpTest = out;
    return out;
  }

  function renderPrivate(out) {
    var rows = [];
    if (out.error) {
      kv($("private-list"), [["오류", out.error, "bad-text"]]);
      return;
    }
    rows.push(["입력 IP", out.ip]);
    out.tests.forEach(function (t) {
      var label = t.kind + " " + t.url;
      var val = (t.ok ? "응답 있음" : "실패") + " · " + t.reason + " · " + t.ms + "ms";
      if (t.message) val += " · " + t.message;
      rows.push([label, val, t.ok ? "ok-text" : "warn-text"]);
    });
    kv($("private-list"), rows);
  }

  function randomCode() {
    var s = "";
    var buf = new Uint8Array(6);
    crypto.getRandomValues(buf);
    for (var i = 0; i < 6; i++) s += CODE_ALPHABET[buf[i] % CODE_ALPHABET.length];
    return s;
  }

  function peerIdFromCode(code) {
    return PEER_PREFIX + code.toUpperCase().replace(/[^A-Z0-9]/g, "");
  }

  function parseTurnUrls(text) {
    return String(text || "").split(/[\s,]+/).map(function (s) { return s.trim(); }).filter(Boolean);
  }

  function customTurnServer() {
    var urls = parseTurnUrls(iceState.turnUrls);
    if (!urls.length) return null;
    var server = { urls: urls.length === 1 ? urls[0] : urls };
    if (iceState.turnUser) server.username = iceState.turnUser;
    if (iceState.turnCred) server.credential = iceState.turnCred;
    return server;
  }

  function iceServersForMode(mode) {
    var list = [{ urls: "stun:stun.l.google.com:19302" }];
    if (mode === "direct") return list;
    var turn = customTurnServer();
    if (turn) list.push(turn);
    return list;
  }

  function rtcConfigForMode(mode) {
    var cfg = { iceServers: iceServersForMode(mode), sdpSemantics: "unified-plan" };
    if (mode === "relay") cfg.iceTransportPolicy = "relay";
    return cfg;
  }

  function redactedIceConfig(mode) {
    return {
      mode: mode,
      label: ICE_MODE_LABEL[mode] || mode,
      iceTransportPolicy: mode === "relay" ? "relay" : "all",
      hasTurn: !!(mode !== "direct" && customTurnServer()),
      iceServers: iceServersForMode(mode).map(function (s) {
        var copy = { urls: s.urls };
        if (s.username) copy.username = s.username;
        if (s.credential) copy.credential = "(입력됨)";
        return copy;
      })
    };
  }

  function exportIceMetadata() {
    return {
      t: "ice-config",
      mode: iceState.mode,
      turnUrls: iceState.turnUrls,
      turnUser: iceState.turnUser,
      turnCred: iceState.turnCred
    };
  }

  function applyIceMetadata(meta) {
    if (!meta || meta.t !== "ice-config") return false;
    if (meta.mode === "auto" || meta.mode === "relay" || meta.mode === "direct") iceState.mode = meta.mode;
    iceState.turnUrls = meta.turnUrls || "";
    iceState.turnUser = meta.turnUser || "";
    iceState.turnCred = meta.turnCred || "";
    results.iceConfig = redactedIceConfig(iceState.mode);
    syncModeUi();
    return true;
  }

  function syncModeUi() {
    var buttons = document.querySelectorAll(".mode-btn");
    for (var i = 0; i < buttons.length; i++) {
      var on = buttons[i].getAttribute("data-mode") === iceState.mode;
      buttons[i].classList.toggle("is-on", on);
      buttons[i].setAttribute("aria-pressed", on ? "true" : "false");
    }
  }

  function loadIceFromStorage() {
    try {
      var mode = localStorage.getItem("parkdesk.iceMode");
      if (mode === "auto" || mode === "relay" || mode === "direct") iceState.mode = mode;
      iceState.turnUrls = localStorage.getItem("parkdesk.turn.urls") || "";
      iceState.turnUser = localStorage.getItem("parkdesk.turn.username") || "";
      iceState.turnCred = localStorage.getItem("parkdesk.turn.credential") || "";
    } catch (e) {}
  }

  function saveIceToStorage() {
    try {
      localStorage.setItem("parkdesk.iceMode", iceState.mode);
      localStorage.setItem("parkdesk.turn.urls", iceState.turnUrls);
      localStorage.setItem("parkdesk.turn.username", iceState.turnUser);
      localStorage.setItem("parkdesk.turn.credential", iceState.turnCred);
    } catch (e) {}
  }

  function readTurnForm() {
    var urls = $("turn-urls");
    var user = $("turn-user");
    var cred = $("turn-cred");
    if (urls) iceState.turnUrls = urls.value || "";
    if (user) iceState.turnUser = user.value || "";
    if (cred) iceState.turnCred = cred.value || "";
  }

  function fillTurnForm() {
    var urls = $("turn-urls");
    var user = $("turn-user");
    var cred = $("turn-cred");
    if (urls) urls.value = iceState.turnUrls;
    if (user) user.value = iceState.turnUser;
    if (cred) cred.value = iceState.turnCred;
  }

  function peerOptions(id) {
    var opts = {
      host: BROKER.host,
      port: BROKER.port,
      path: BROKER.path,
      secure: BROKER.secure,
      debug: 0,
      config: rtcConfigForMode(iceState.mode)
    };
    if (id) return new Peer(id, opts);
    return new Peer(opts);
  }

  function installIceConfigHook(peer) {
    var sock = peer && peer.socket;
    if (!sock || typeof sock.listeners !== "function" || typeof sock.removeAllListeners !== "function" || typeof sock.on !== "function") {
      log("tesla-log", "시그널링 소켓에 ICE 설정을 미리 적용하지 못했습니다.", "error");
      return;
    }
    var prev = sock.listeners("message").slice();
    sock.removeAllListeners("message");
    sock.on("message", function (msg) {
      var meta = msg && msg.payload && msg.payload.metadata;
      if (msg && msg.type === "OFFER" && meta && meta.t === "ice-config") {
        applyIceMetadata(meta);
        peer.options.config = rtcConfigForMode(iceState.mode);
        log("tesla-log", "PC ICE 설정을 적용했습니다. 모드=" + (ICE_MODE_LABEL[iceState.mode] || iceState.mode) + (customTurnServer() && iceState.mode !== "direct" ? " · TURN 있음" : " · TURN 없음"));
      }
    });
    prev.forEach(function (fn) { sock.on("message", fn); });
  }

  function pushIce(entry) {
    entry.at = nowIso();
    results.iceTimeline.push(entry);
    if (results.iceTimeline.length > 80) results.iceTimeline.shift();
  }

  function watchPeerConnection(pc, logId, label) {
    if (!pc || pc.__parkdeskWatch) return;
    pc.__parkdeskWatch = true;
    var seen = {};
    function note(kind, extra) {
      var row = { kind: kind, label: label || "" };
      if (extra) Object.keys(extra).forEach(function (k) { row[k] = extra[k]; });
      pushIce(row);
      var text = "ICE";
      if (label) text += " " + label;
      text += " " + kind;
      if (extra && extra.state) text += " " + extra.state;
      if (extra && extra.candidate) text += " " + extra.candidate;
      if (extra && extra.detail) text += " " + extra.detail;
      log(logId, text);
    }
    function dumpCandidates() {
      if (!pc.getStats) return;
      pc.getStats().then(function (report) {
        report.forEach(function (s) {
          if (s.type !== "local-candidate" && s.type !== "remote-candidate") return;
          var side = s.type === "local-candidate" ? "local" : "remote";
          var typ = s.candidateType || "";
          var addr = s.address || s.ip || "";
          var proto = s.protocol || "";
          var key = side + "|" + typ + "|" + proto + "|" + addr + "|" + (s.port || "");
          if (seen[key]) return;
          seen[key] = true;
          var where = addr ? (addr + " (" + classifyIp(addr) + ")") : "주소 숨김";
          note(side + "-candidate", { candidate: typ + " " + proto + " " + where });
        });
      }).catch(function () {});
    }
    note("watch", { state: "ice=" + pc.iceConnectionState + " conn=" + (pc.connectionState || "?") });
    pc.addEventListener("iceconnectionstatechange", function () {
      note("iceConnectionState", { state: pc.iceConnectionState });
      dumpCandidates();
      if (pc.iceConnectionState === "connected" || pc.iceConnectionState === "completed" || pc.iceConnectionState === "failed") {
        logSelectedPair(pc, logId, label);
      }
      if (pc.iceConnectionState === "failed" && role === "tesla") {
        showTeslaPhotoSummary("ICE failed");
      }
    });
    pc.addEventListener("connectionstatechange", function () {
      note("connectionState", { state: pc.connectionState });
    });
    pc.addEventListener("icecandidateerror", function (ev) {
      note("candidate-error", { detail: [ev.errorCode, ev.errorText, ev.url].filter(Boolean).join(" ") });
    });
  }

  function watchConn(conn, logId, label) {
    var tries = 0;
    function tick() {
      var pc = peerConnectionOf(conn);
      if (pc) { watchPeerConnection(pc, logId, label); return; }
      if (tries++ < 30) setTimeout(tick, 100);
    }
    tick();
  }

  async function logSelectedPair(pc, logId, label, attempt) {
    var st = await statsFromPc(pc);
    var detail;
    if (!st || (!st.local && !st.remote)) {
      if ((attempt || 0) < 3) {
        setTimeout(function () { logSelectedPair(pc, logId, label, (attempt || 0) + 1); }, 500);
        return;
      }
      detail = "없음";
    } else {
      detail = (st.pairType || "?")
        + " local=" + (st.local ? (st.local.typ + " " + (st.local.protocol || "") + " " + st.local.range) : "?")
        + " remote=" + (st.remote ? (st.remote.typ + " " + (st.remote.protocol || "") + " " + st.remote.range) : "?")
        + " state=" + (st.pairState || "?");
      results.iceSelected = {
        at: nowIso(),
        label: label || "",
        pairType: st.pairType,
        pairState: st.pairState,
        local: st.local,
        remote: st.remote
      };
    }
    pushIce({ kind: "selected-pair", label: label || "", detail: detail });
    log(logId, "ICE 선택 쌍 " + (label ? label + " " : "") + detail);
  }

  function scheduleReconnect(which) {
    if (reconnectTimer[which]) return;
    var wait = reconnectWait[which] || 500;
    reconnectWait[which] = Math.min(8000, wait * 2);
    reconnectTimer[which] = setTimeout(function () {
      reconnectTimer[which] = null;
      var peer = which === "pc" ? pcPeer : teslaPeer;
      var logId = which === "pc" ? "pc-log" : "tesla-log";
      if (!peer || peer.destroyed) return;
      if (!peer.disconnected) {
        reconnectWait[which] = 500;
        return;
      }
      log(logId, "브로커에 같은 ID로 재연결합니다.");
      try {
        peer.reconnect();
      } catch (err) {
        log(logId, "재연결 실패: " + err, "error");
        scheduleReconnect(which);
      }
    }, wait);
  }

  function handleBrokerError(which, err) {
    var typ = (err && err.type) || "";
    var logId = which === "pc" ? "pc-log" : "tesla-log";
    if (typ === "network" || typ === "socket-error" || typ === "socket-closed" || typ === "server-error" || typ === "disconnected") {
      log(logId, "브로커 연결이 끊겼습니다 (" + typ + "). 페어링 코드는 유지하고 재연결합니다.");
      scheduleReconnect(which);
      return;
    }
    if (which === "pc" && typ === "peer-unavailable") {
      if (pcConn && pcConn.open) return;
      var now = Date.now();
      if (now - probeNoteAt > 15000) {
        probeNoteAt = now;
        log(logId, "테슬라 쪽이 아직 없습니다. 같은 코드로 계속 기다립니다.");
      }
      if (iceOfferConn) {
        var stale = iceOfferConn;
        iceOfferConn = null;
        try { stale.close(); } catch (e) {}
      }
      scheduleIceOffer(700);
      return;
    }
    if (typ === "unavailable-id") {
      if (which === "pc") {
        var next = randomCode();
        log(logId, "이 코드의 ID가 이미 사용 중입니다. 새 코드 " + next);
        startPcBroker(next);
      } else {
        teslaIdRetries += 1;
        if (teslaIdRetries > 8) {
          log(logId, "테슬라 ID를 아직 다시 받지 못했습니다.", "error");
          setStatus("tesla-pair-status", "코드가 점유되어 있습니다. 잠시 뒤 연결을 다시 누르세요.", "bad");
          showTeslaPhotoSummary("unavailable-id");
          return;
        }
        log(logId, "테슬라 ID가 잠시 사용 중입니다. 같은 코드로 다시 시도합니다.");
        setStatus("tesla-pair-status", "코드가 잠시 점유됨. 다시 시도합니다.", "wait");
        setTimeout(function () {
          if (results.pairing && results.pairing.code) teslaJoin(results.pairing.code);
        }, 2000);
      }
      return;
    }
    log(logId, "Peer 오류: " + typ + " " + err, "error");
    if (which === "tesla") {
      setStatus("tesla-pair-status", "연결 실패: " + (typ || err), "bad");
      setSendResultsEnabled(false);
      if (typ === "webrtc" || typ === "negotiation-failed" || typ === "peer-unavailable") {
        showTeslaPhotoSummary(typ || String(err));
      }
    } else if (typ !== "webrtc") {
      setStatus("pc-status", "오류: " + (typ || err), "bad");
    }
  }

  function describePairType(localTyp, remoteTyp, localAddr, remoteAddr) {
    if (localTyp === "relay" || remoteTyp === "relay") return "relayed (TURN)";
    if (localTyp === "srflx" || remoteTyp === "srflx" || localTyp === "prflx" || remoteTyp === "prflx") {
      return "srflx/prflx (STUN, NAT 경유 가능)";
    }
    if ((localTyp && localTyp.indexOf("host") === 0) && (remoteTyp && remoteTyp.indexOf("host") === 0)) {
      var lr = classifyIp(localAddr);
      var rr = classifyIp(remoteAddr);
      var sameLan =
        (lr.indexOf("RFC1918") === 0 && rr.indexOf("RFC1918") === 0) ||
        (lr === rr && lr !== "public-or-other");
      return "host-to-host" + (sameLan ? " (같은 LAN 직접 연결로 보임)" : " (호스트 후보)");
    }
    return "unknown (" + (localTyp || "?") + " / " + (remoteTyp || "?") + ")";
  }

  function percentile(arr, p) {
    if (!arr.length) return null;
    var a = arr.slice().sort(function (x, y) { return x - y; });
    var idx = Math.min(a.length - 1, Math.max(0, Math.ceil((p / 100) * a.length) - 1));
    return a[idx];
  }

  async function copyText(text, jsonBoxId, logId) {
    var box = $(jsonBoxId);
    if (box) box.value = text;
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        log(logId, "클립보드에 복사했습니다.");
        return;
      }
    } catch (err) {
      log(logId, "클립보드 API 실패: " + err + " — 아래 텍스트를 길게 눌러 복사하세요.");
    }
    if (box) {
      box.focus();
      box.select();
      try { document.execCommand("copy"); } catch (e) {}
    }
  }

  function snapshotResults() {
    results.finishedAt = nowIso();
    results.role = role || results.role;
    return JSON.stringify(results, null, 2);
  }

  function utf8ByteLength(s) {
    if (window.TextEncoder) return new TextEncoder().encode(s).length;
    return unescape(encodeURIComponent(s)).length;
  }

  function chunkUtf8(str, maxBytes) {
    var chunks = [];
    var i = 0;
    while (i < str.length) {
      var end = Math.min(str.length, i + maxBytes);
      while (end > i + 1 && utf8ByteLength(str.slice(i, end)) > maxBytes) {
        end = i + Math.max(1, Math.floor((end - i) / 2));
      }
      if (end < str.length) {
        var tail = str.charCodeAt(end - 1);
        var next = str.charCodeAt(end);
        if (tail >= 0xD800 && tail <= 0xDBFF && next >= 0xDC00 && next <= 0xDFFF) end -= 1;
        if (end <= i) end = Math.min(str.length, i + 1);
      }
      chunks.push(str.slice(i, end));
      i = end;
    }
    if (!chunks.length) chunks.push("");
    return chunks;
  }

  function summarizePrivateIp(p) {
    if (!p) return "안 함";
    if (p.error) return (p.ip || "-") + " · " + p.error;
    var tests = p.tests || [];
    var ok = 0;
    tests.forEach(function (t) { if (t && t.ok) ok++; });
    return (p.ip || "-") + " · 성공 " + ok + "/" + tests.length;
  }

  function setSendResultsEnabled(on) {
    var btn = $("btn-send-results");
    if (!btn) return;
    btn.disabled = !on;
  }

  function sendTeslaResults(reason) {
    if (!teslaConn || !teslaConn.open) {
      log("tesla-log", "DataChannel이 열려 있지 않아 결과를 보내지 못했습니다.", "error");
      return false;
    }
    var json;
    try {
      json = snapshotResults();
    } catch (err) {
      log("tesla-log", "결과 JSON을 만들지 못했습니다: " + err, "error");
      return false;
    }
    var chunks = chunkUtf8(json, RESULT_CHUNK_BYTES);
    var id = "r" + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
    for (var i = 0; i < chunks.length; i++) {
      teslaSend({
        t: "results",
        id: id,
        i: i,
        n: chunks.length,
        reason: reason || "manual",
        chunk: chunks[i]
      });
    }
    var hint = $("send-results-hint");
    if (hint) hint.textContent = "PC로 보냈습니다. " + chunks.length + "조각, " + json.length + "자 (" + (reason || "manual") + ").";
    log("tesla-log", "결과를 PC로 보냈습니다. " + chunks.length + "조각, " + json.length + "자 (" + (reason || "manual") + ")");
    return true;
  }

  function sendTeslaResultsIfOpen(reason) {
    if (teslaConn && teslaConn.open) return sendTeslaResults(reason);
    return false;
  }

  function clearReceivedTesla() {
    receivedTesla = null;
    incomingResults = null;
    var hint = $("pc-tesla-hint");
    if (hint) hint.textContent = "아직 테슬라 결과가 없습니다.";
    var list = $("pc-tesla-list");
    if (list) list.innerHTML = "";
    var pre = $("pc-tesla-json");
    if (pre) {
      pre.textContent = "";
      pre.classList.add("hidden");
    }
  }

  function renderReceivedTesla(obj, meta) {
    var hint = $("pc-tesla-hint");
    if (hint) {
      hint.textContent = "수신함 · " + (meta.reason || "") + " · " + meta.chunks + "조각 · " + (meta.chars || 0) + "자";
    }
    var env = obj.env || {};
    var sup = obj.support || {};
    var codecs = obj.codecs || {};
    var ice = obj.iceGathering || {};
    var rows = [
      ["수신", meta.reason || "-"],
      ["화면", (env.innerWidth || "?") + "×" + (env.innerHeight || "?") + " / " + (env.screenWidth || "?") + "×" + (env.screenHeight || "?") + " dpr " + (env.devicePixelRatio || "?")],
      ["WebRTC", sup.RTCPeerConnection ? "지원" : "없음", sup.RTCPeerConnection ? "ok-text" : "bad-text"],
      ["DataChannel", sup.RTCDataChannel ? "지원" : "없음", sup.RTCDataChannel ? "ok-text" : "bad-text"],
      ["H.264", codecs.h264 ? "있음" : "없음", codecs.h264 ? "ok-text" : "bad-text"],
      ["ICE", "후보 " + (ice.candidateCount || 0) + " · host " + (ice.hasHost ? "있음" : "없음") + " · srflx " + (ice.hasSrflx ? "있음" : "없음")],
      ["사설 IP", summarizePrivateIp(obj.privateIpTest)],
      ["미디어", obj.media ? "있음" : "없음"],
      ["탭", String((obj.taps || []).length) + "회"],
      ["로그", String((obj.logs || []).length) + "줄"],
      ["오류", (obj.errors && obj.errors.length) ? obj.errors.join(" | ") : "없음", (obj.errors && obj.errors.length) ? "warn-text" : "ok-text"]
    ];
    if ($("pc-tesla-list")) kv($("pc-tesla-list"), rows);
    var pre = $("pc-tesla-json");
    if (pre) {
      pre.classList.remove("hidden");
      pre.textContent = JSON.stringify(obj, null, 2);
    }
  }

  function ingestTeslaResultChunk(msg) {
    if (!msg || typeof msg.chunk !== "string") return;
    var n = msg.n | 0;
    var i = msg.i | 0;
    if (n < 1 || n > 200 || i < 0 || i >= n) {
      log("pc-log", "테슬라 결과 조각이 올바르지 않습니다.", "error");
      return;
    }
    if (!incomingResults || incomingResults.id !== msg.id) {
      incomingResults = { id: msg.id, n: n, parts: new Array(n), got: 0, reason: msg.reason };
    }
    if (incomingResults.parts[i] == null) {
      incomingResults.parts[i] = msg.chunk;
      incomingResults.got++;
    }
    if (incomingResults.got < incomingResults.n) return;
    var json = incomingResults.parts.join("");
    var reason = incomingResults.reason || msg.reason;
    var chunks = incomingResults.n;
    incomingResults = null;
    var obj;
    try {
      obj = JSON.parse(json);
    } catch (err) {
      log("pc-log", "테슬라 결과 JSON 파싱 실패: " + err, "error");
      return;
    }
    receivedTesla = obj;
    log("pc-log", "테슬라 결과 수신 (" + (reason || "") + ", " + chunks + "조각, " + json.length + "자)");
    renderReceivedTesla(obj, { reason: reason, chunks: chunks, chars: json.length });
  }

  function combinedResultsText() {
    var pcObj;
    try {
      pcObj = JSON.parse(snapshotResults());
    } catch (err) {
      pcObj = { error: String(err) };
    }
    return JSON.stringify({ pc: pcObj, tesla: receivedTesla }, null, 2);
  }

  function downloadCombinedResults() {
    var text = combinedResultsText();
    var box = $("pc-json");
    if (box) box.value = text;
    var blob = new Blob([text], { type: "application/json" });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    var stamp = new Date().toISOString().replace(/[:.]/g, "-");
    a.href = url;
    a.download = "parkdesk-phase0-" + stamp + ".json";
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1500);
    log("pc-log", "합친 결과 JSON 파일을 저장했습니다.");
  }

  async function statsFromPc(pc) {
    if (!pc || typeof pc.getStats !== "function") return null;
    var report = await pc.getStats(null);
    var pair = null;
    var locals = {};
    var remotes = {};
    var inbound = null;
    report.forEach(function (s) {
      if (s.type === "local-candidate") locals[s.id] = s;
      if (s.type === "remote-candidate") remotes[s.id] = s;
      if (s.type === "candidate-pair" && (s.state === "succeeded" || s.nominated || s.selected)) {
        if (!pair || s.nominated || s.selected) pair = s;
      }
      if (s.type === "inbound-rtp" && s.kind === "video") inbound = s;
      if (s.type === "transport" && s.selectedCandidatePairId) {
        var selected = report.get(s.selectedCandidatePairId);
        if (selected) pair = selected;
      }
    });
    var local = pair ? locals[pair.localCandidateId] : null;
    var remote = pair ? remotes[pair.remoteCandidateId] : null;
    var localTyp = local && (local.candidateType || local.type);
    var remoteTyp = remote && (remote.candidateType || remote.type);
    var localAddr = local && (local.address || local.ip);
    var remoteAddr = remote && (remote.address || remote.ip);
    return {
      pairState: pair && pair.state,
      nominated: !!(pair && (pair.nominated || pair.selected)),
      currentRoundTripTime: pair && pair.currentRoundTripTime,
      availableOutgoingBitrate: pair && pair.availableOutgoingBitrate,
      local: local
        ? { typ: localTyp, address: localAddr, port: local.port, protocol: local.protocol, range: classifyIp(localAddr) }
        : null,
      remote: remote
        ? { typ: remoteTyp, address: remoteAddr, port: remote.port, protocol: remote.protocol, range: classifyIp(remoteAddr) }
        : null,
      pairType: describePairType(localTyp, remoteTyp, localAddr, remoteAddr),
      inboundVideo: inbound
        ? {
            framesPerSecond: inbound.framesPerSecond,
            frameWidth: inbound.frameWidth,
            frameHeight: inbound.frameHeight,
            jitter: inbound.jitter,
            packetsLost: inbound.packetsLost,
            packetsReceived: inbound.packetsReceived,
            bytesReceived: inbound.bytesReceived,
            framesDecoded: inbound.framesDecoded,
            framesDropped: inbound.framesDropped
          }
        : null
    };
  }

  function peerConnectionOf(callOrConn) {
    if (!callOrConn) return null;
    return callOrConn.peerConnection || callOrConn._pc || null;
  }

  /* ---------- Tesla role ---------- */

  function renderTeslaEnv() {
    var env = readEnv();
    kv($("env-list"), [
      ["User Agent", env.userAgent],
      ["언어", env.language || "-"],
      ["inner", env.innerWidth + " × " + env.innerHeight],
      ["screen", env.screenWidth + " × " + env.screenHeight],
      ["avail", env.availWidth + " × " + env.availHeight],
      ["devicePixelRatio", String(env.devicePixelRatio)],
      ["visualViewport", env.visualViewport ? (env.visualViewport.width + " × " + env.visualViewport.height + " scale " + env.visualViewport.scale) : "없음"],
      ["secureContext", env.secureContext ? "예 (HTTPS 또는 localhost)" : "아니오", env.secureContext ? "ok-text" : "warn-text"]
    ]);

    var sup = readSupport();
    var codecs = readCodecs();
    kv($("cap-list"), [
      ["RTCPeerConnection", sup.RTCPeerConnection ? "지원" : "없음", sup.RTCPeerConnection ? "ok-text" : "bad-text"],
      ["DataChannel", sup.RTCDataChannel ? "지원" : "없음", sup.RTCDataChannel ? "ok-text" : "bad-text"],
      ["PeerJS 라이브러리", sup.PeerJS ? "로드됨" : "실패", sup.PeerJS ? "ok-text" : "bad-text"],
      ["H.264 수신", codecs.h264 ? "있음" : (codecs.error || "없음"), codecs.h264 ? "ok-text" : "bad-text"],
      ["H.264 상세", codecs.h264Mimes.length ? codecs.h264Mimes.join(" | ") : "-"],
      ["비디오 코덱", codecs.allVideo.length ? codecs.allVideo.join(", ") : (codecs.error || "-")]
    ]);
  }

  async function teslaIce() {
    log("tesla-log", "ICE 후보 수집을 시작합니다.");
    var summary = await gatherIce("tesla-log");
    renderIce(summary);
    log("tesla-log", "ICE 수집 완료. 후보 " + (summary.candidateCount || 0) + "개");
    sendTeslaResultsIfOpen("tests-done");
  }

  function hideTeslaPhotoSummary() {
    var card = $("tesla-photo");
    if (card) card.classList.add("hidden");
  }

  function showTeslaPhotoSummary(reason) {
    var card = $("tesla-photo");
    var body = $("tesla-photo-body");
    if (!card || !body) return;
    var env = results.env || {};
    var sup = results.support || {};
    var codecs = results.codecs || {};
    var ice = results.iceGathering || {};
    var lastIce = "";
    var lastConn = "";
    var relayN = 0;
    var hostN = 0;
    var srflxN = 0;
    (results.iceTimeline || []).forEach(function (ev) {
      if (!ev) return;
      if (ev.kind === "iceConnectionState") lastIce = ev.state || lastIce;
      if (ev.kind === "connectionState") lastConn = ev.state || lastConn;
      var cand = ev.candidate || "";
      if (ev.kind === "local-candidate" || ev.kind === "remote-candidate") {
        if (cand.indexOf("relay") === 0) relayN += 1;
        else if (cand.indexOf("srflx") === 0 || cand.indexOf("prflx") === 0) srflxN += 1;
        else if (cand.indexOf("host") === 0) hostN += 1;
      }
    });
    var cfg = results.iceConfig;
    var lines = [
      ["실패", reason || "-"],
      ["모드", cfg ? (cfg.label + (cfg.hasTurn ? " · TURN" : " · TURN 없음")) : (ICE_MODE_LABEL[iceState.mode] || iceState.mode)],
      ["화면", (env.screenWidth || "?") + "×" + (env.screenHeight || "?")],
      ["창", (env.innerWidth || "?") + "×" + (env.innerHeight || "?") + "  dpr " + (env.devicePixelRatio || "?")],
      ["WebRTC", sup.RTCPeerConnection ? "지원" : "없음"],
      ["Data", sup.RTCDataChannel ? "지원" : "없음"],
      ["H.264", codecs.h264 ? "있음" : "없음"],
      ["ICE수집", "후보 " + (ice.candidateCount != null ? ice.candidateCount : 0)
        + " · host " + (ice.hasHost ? "있음" : "없음")
        + " · srflx " + (ice.hasSrflx ? "있음" : "없음")],
      ["ICE연결", (lastIce || "-") + " / " + (lastConn || "-")],
      ["쌍후보", "host " + hostN + " · srflx " + srflxN + " · relay " + relayN],
      ["선택", (results.iceSelected && results.iceSelected.pairType) || "없음"],
      ["사설IP", summarizePrivateIp(results.privateIpTest)]
    ];
    if (results.errors && results.errors.length) {
      var errText = results.errors.slice(-2).join(" / ");
      if (errText.length > 90) errText = errText.slice(0, 89) + "…";
      lines.push(["오류", errText]);
    }
    body.innerHTML = "";
    lines.forEach(function (row) {
      var p = document.createElement("p");
      p.className = "photo-line";
      var k = document.createElement("span");
      k.className = "photo-k";
      k.textContent = row[0];
      var v = document.createElement("span");
      v.className = "photo-v";
      v.textContent = row[1];
      p.appendChild(k);
      p.appendChild(v);
      body.appendChild(p);
    });
    card.classList.remove("hidden");
    try { card.scrollIntoView({ block: "nearest" }); } catch (e) {}
  }

  function teslaSend(obj) {
    if (teslaConn && teslaConn.open) teslaConn.send(obj);
  }

  function bindTeslaVideoInput(video) {
    function sendTap(clientX, clientY) {
      var rect = video.getBoundingClientRect();
      if (!rect.width || !rect.height) return;
      var x = (clientX - rect.left) / rect.width;
      var y = (clientY - rect.top) / rect.height;
      x = Math.min(1, Math.max(0, x));
      y = Math.min(1, Math.max(0, y));
      var ev = { t: "tap", x: Number(x.toFixed(4)), y: Number(y.toFixed(4)), ts: Date.now() };
      results.taps.push(ev);
      if (results.taps.length > 50) results.taps.shift();
      $("tesla-tap-readout").textContent = "탭 x=" + ev.x + " y=" + ev.y;
      teslaSend(ev);
      log("tesla-log", "탭 전송 " + ev.x + ", " + ev.y);
    }
    video.addEventListener("pointerdown", function (e) {
      sendTap(e.clientX, e.clientY);
    });
  }

  function wireTeslaData(conn) {
    teslaConn = conn;
    conn.on("data", function (data) {
      if (!data || typeof data !== "object") return;
      if (data.t === "ping") {
        teslaSend({ t: "pong", n: data.n, ts: data.ts, t2: Date.now() });
      } else if (data.t === "hello") {
        teslaSend({ t: "hello_ok", env: results.env, codecs: results.codecs });
      }
    });
    conn.on("open", function () {
      log("tesla-log", "DataChannel이 열렸습니다.");
      setStatus("tesla-pair-status", "PC와 DataChannel 연결됨", "ok");
      teslaSend({ t: "hello_ok", env: results.env, codecs: results.codecs, ice: results.iceGathering });
      results.pairing = results.pairing || {};
      results.pairing.dataOpen = true;
      setSendResultsEnabled(true);
      hideTeslaPhotoSummary();
      sendTeslaResults("channel-open");
    });
    conn.on("close", function () {
      if (teslaConn !== conn) return;
      log("tesla-log", "DataChannel이 닫혔습니다.");
      setStatus("tesla-pair-status", "연결이 끊겼습니다", "bad");
      setSendResultsEnabled(false);
      if (!results.pairing || !results.pairing.dataOpen) {
        showTeslaPhotoSummary("DataChannel이 열리기 전에 닫혔습니다");
      }
    });
    conn.on("error", function (err) {
      if (teslaConn !== conn) return;
      log("tesla-log", "DataChannel 오류: " + err, "error");
      if (!results.pairing || !results.pairing.dataOpen) {
        setStatus("tesla-pair-status", "연결 실패", "bad");
        showTeslaPhotoSummary(String(err));
      }
    });
  }

  async function refreshTeslaStats() {
    var pc = peerConnectionOf(teslaCall) || peerConnectionOf(teslaConn);
    var st = await statsFromPc(pc);
    if (!st) return;
    results.pairing = Object.assign(results.pairing || {}, {
      pairType: st.pairType,
      local: st.local,
      remote: st.remote,
      pairState: st.pairState,
      currentRoundTripTime: st.currentRoundTripTime
    });
    if (st.inboundVideo) results.media = st.inboundVideo;
    var rows = [
      ["후보 쌍", st.pairType || "-", /host-to-host/.test(st.pairType || "") ? "ok-text" : "warn-text"],
      ["로컬", st.local ? (st.local.typ + " " + st.local.address + " (" + st.local.range + ")") : "-"],
      ["원격", st.remote ? (st.remote.typ + " " + st.remote.address + " (" + st.remote.range + ")") : "-"],
      ["ICE RTT", st.currentRoundTripTime != null ? Math.round(st.currentRoundTripTime * 1000) + " ms" : "-"]
    ];
    if (st.inboundVideo) {
      var v = st.inboundVideo;
      rows.push(["수신 영상", (v.frameWidth || "?") + "×" + (v.frameHeight || "?") + " @ " + (v.framesPerSecond != null ? v.framesPerSecond : "?") + " fps"]);
      rows.push(["jitter", v.jitter != null ? String(v.jitter) : "-"]);
      rows.push(["손실/수신 패킷", (v.packetsLost || 0) + " / " + (v.packetsReceived || 0)]);
    }
    kv($("tesla-conn-list"), rows);
    if (!liveTestSnapshotSent && (st.pairState === "succeeded" || st.nominated)) {
      if (sendTeslaResultsIfOpen("tests-done")) liveTestSnapshotSent = true;
    }
  }

  function teslaJoin(code) {
    code = (code || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
    if (code.length < 4) {
      log("tesla-log", "코드가 너무 짧습니다.", "error");
      return;
    }
    if (typeof Peer !== "function") {
      log("tesla-log", "PeerJS가 로드되지 않았습니다.", "error");
      return;
    }
    teslaLeave();
    liveTestSnapshotSent = false;
    hideTeslaPhotoSummary();
    setSendResultsEnabled(false);
    var target = peerIdFromCode(code);
    var localId = target + "-t";
    results.pairing = { role: "tesla", code: code, target: target, localPeerId: localId, broker: BROKER.host, startedAt: nowIso(), ice: redactedIceConfig(iceState.mode) };
    results.iceConfig = redactedIceConfig(iceState.mode);
    setStatus("tesla-pair-status", "브로커 접속 중…", "wait");
    log("tesla-log", "PeerJS 브로커 " + BROKER.host + " 에 " + localId + " 로 등록하고 PC의 연결을 기다립니다.");

    var peer = peerOptions(localId);
    teslaPeer = peer;
    installIceConfigHook(peer);
    peer.on("open", function (id) {
      if (teslaPeer !== peer) return;
      teslaIdRetries = 0;
      reconnectWait.tesla = 500;
      log("tesla-log", "브로커에 연결됨. 내 ID=" + id + ". PC가 같은 코드로 연결하기를 기다립니다.");
      results.pairing.localPeerId = id;
      results.pairing.brokerOpen = true;
      setStatus("tesla-pair-status", "PC의 연결을 기다리는 중", "wait");
    });
    peer.on("connection", function (conn) {
      if (teslaPeer !== peer) return;
      log("tesla-log", "PC 연결 수신: " + conn.peer);
      hideTeslaPhotoSummary();
      wireTeslaData(conn);
      watchConn(conn, "tesla-log", "data");
    });
    peer.on("call", function (call) {
      teslaCall = call;
      log("tesla-log", "화면 공유 수신. 응답합니다.");
      call.answer();
      watchConn(call, "tesla-log", "media");
      call.on("stream", function (stream) {
        var video = $("tesla-video");
        video.srcObject = stream;
        $("tesla-video-empty").classList.add("hidden");
        video.play().catch(function (err) {
          log("tesla-log", "video.play 실패, 화면을 한 번 탭해 보세요: " + err);
        });
        log("tesla-log", "원격 스트림을 표시합니다.");
        results.media = { startedAt: nowIso() };
      });
      call.on("close", function () {
        log("tesla-log", "화면 공유가 종료되었습니다.");
        $("tesla-video").srcObject = null;
        $("tesla-video-empty").classList.remove("hidden");
      });
      call.on("error", function (err) { log("tesla-log", "call 오류: " + err, "error"); });
    });
    peer.on("error", function (err) {
      if (teslaPeer !== peer) return;
      handleBrokerError("tesla", err);
    });
    peer.on("disconnected", function () {
      if (teslaPeer !== peer) return;
      log("tesla-log", "브로커와 끊겼습니다. 같은 ID로 재연결합니다.");
      scheduleReconnect("tesla");
    });

    if (statsTimer) clearInterval(statsTimer);
    statsTimer = setInterval(function () {
      refreshTeslaStats().catch(function () {});
    }, 1000);
  }

  function teslaLeave() {
    if (statsTimer) { clearInterval(statsTimer); statsTimer = null; }
    try { if (teslaConn) teslaConn.close(); } catch (e) {}
    try { if (teslaCall) teslaCall.close(); } catch (e) {}
    try { if (teslaPeer) teslaPeer.destroy(); } catch (e) {}
    teslaConn = teslaCall = teslaPeer = null;
    liveTestSnapshotSent = false;
    setSendResultsEnabled(false);
    $("tesla-video").srcObject = null;
    $("tesla-video-empty").classList.remove("hidden");
  }

  async function initTesla() {
    $("view-home").classList.add("hidden");
    $("view-tesla").classList.remove("hidden");
    $("page-title").textContent = "테슬라 검사";
    setStatus("tesla-pair-status", "능력 검사 중…", "wait");
    renderTeslaEnv();
    await teslaIce();
    setStatus("tesla-pair-status", "PC 코드를 입력하면 페어링을 시작합니다", "wait");
    bindTeslaVideoInput($("tesla-video"));

    $("btn-ice").addEventListener("click", function () { teslaIce(); });
    $("btn-private").addEventListener("click", async function () {
      var ip = $("private-ip").value;
      log("tesla-log", "사설 IP 검사: " + ip);
      var out = await runPrivateIpTest(ip);
      renderPrivate(out);
      log("tesla-log", "사설 IP 검사 완료");
      sendTeslaResultsIfOpen("tests-done");
    });
    $("btn-join").addEventListener("click", function () { teslaJoin($("join-code").value); });
    $("join-code").addEventListener("keydown", function (e) {
      if (e.key === "Enter") teslaJoin($("join-code").value);
    });
    $("btn-leave-tesla").addEventListener("click", function () {
      teslaLeave();
      setStatus("tesla-pair-status", "연결을 끊었습니다", "wait");
    });
    $("btn-copy-tesla").addEventListener("click", function () {
      copyText(snapshotResults(), "tesla-json", "tesla-log");
    });
    bindModeButtons(function () {
      if (teslaPeer) teslaPeer.options.config = rtcConfigForMode(iceState.mode);
      results.iceConfig = redactedIceConfig(iceState.mode);
      log("tesla-log", "모드를 " + (ICE_MODE_LABEL[iceState.mode] || iceState.mode) + " 로 골랐습니다. PC 설정이 오면 그 값으로 덮어씁니다.");
    });
    $("btn-send-results").addEventListener("click", function () {
      sendTeslaResults("button");
    });

    var preset = new URLSearchParams(location.search).get("code");
    if (preset) {
      $("join-code").value = preset.toUpperCase();
    }
  }

  /* ---------- PC role ---------- */

  function stopPings() {
    if (pingTimer) { clearInterval(pingTimer); pingTimer = null; }
  }

  function startPings(conn, logId, listId) {
    stopPings();
    pingSamples = [];
    pingPending = {};
    var n = 0;
    pingTimer = setInterval(function () {
      if (!conn || !conn.open) return;
      if (n >= PING_COUNT && pingSamples.length >= PING_COUNT) {
        stopPings();
        return;
      }
      if (n >= PING_COUNT) return;
      var seq = n++;
      pingPending[seq] = performance.now();
      conn.send({ t: "ping", n: seq, ts: Date.now() });
    }, PING_EVERY_MS);

    function onPong(data) {
      if (!data || data.t !== "pong") return;
      var t0 = pingPending[data.n];
      if (t0 == null) return;
      delete pingPending[data.n];
      var rtt = Math.round(performance.now() - t0);
      pingSamples.push(rtt);
      var rttInfo = {
        samples: pingSamples.slice(),
        n: pingSamples.length,
        p50: percentile(pingSamples, 50),
        p95: percentile(pingSamples, 95),
        last: rtt,
        unit: "ms"
      };
      results.rtt = rttInfo;
      kv($(listId), [
        ["표본", String(rttInfo.n)],
        ["마지막", rtt + " ms"],
        ["p50", rttInfo.p50 + " ms", "ok-text"],
        ["p95", rttInfo.p95 + " ms"]
      ]);
      if (rttInfo.n === 1 || rttInfo.n === PING_COUNT) {
        log(logId, "RTT p50=" + rttInfo.p50 + "ms p95=" + rttInfo.p95 + "ms (n=" + rttInfo.n + ")");
      }
    }
    conn.on("data", function handler(data) {
      if (data && data.t === "pong") onPong(data);
    });
  }

  function showTap(x, y) {
    results.taps.push({ x: x, y: y, ts: Date.now() });
    if (results.taps.length > 50) results.taps.shift();
    var board = $("tap-board");
    var dot = $("tap-dot");
    dot.classList.remove("hidden");
    dot.style.left = (x * 100) + "%";
    dot.style.top = (y * 100) + "%";
    $("pc-tap-readout").textContent = "탭 x=" + x + "  y=" + y + "  (보드 " + board.clientWidth + "×" + board.clientHeight + ")";
  }

  function wirePcData(conn) {
    if (!conn || conn.__wired) return;
    conn.__wired = true;
    pcConn = conn;
    pcRemotePeerId = conn.peer;
    var opened = false;
    conn.on("open", function () {
      opened = true;
      log("pc-log", "테슬라 DataChannel이 열렸습니다. peer=" + conn.peer);
      setStatus("pc-status", "테슬라와 연결됨", "ok");
      results.pairing = Object.assign(results.pairing || {}, { dataOpen: true, remotePeerId: conn.peer, connectedAt: nowIso() });
      conn.send({ t: "hello" });
      startPings(conn, "pc-log", "pc-rtt-list");
    });
    conn.on("data", function (data) {
      if (!data || typeof data !== "object") return;
      if (data.t === "tap") showTap(data.x, data.y);
      if (data.t === "hello_ok") log("pc-log", "테슬라 hello_ok 수신");
      if (data.t === "results") ingestTeslaResultChunk(data);
    });
    conn.on("close", function () {
      if (pcConn === conn) pcConn = null;
      if (!opened) return;
      log("pc-log", "DataChannel이 닫혔습니다.");
      setStatus("pc-status", "테슬라 연결이 끊겼습니다. 같은 코드로 다시 연결합니다.", "bad");
      stopPings();
    });
    conn.on("error", function (err) { log("pc-log", "DataChannel 오류: " + err, "error"); });
  }

  async function refreshPcStats() {
    var pc = peerConnectionOf(pcCall) || peerConnectionOf(pcConn);
    var st = await statsFromPc(pc);
    if (!st) return;
    results.pairing = Object.assign(results.pairing || {}, {
      pairType: st.pairType,
      local: st.local,
      remote: st.remote,
      pairState: st.pairState,
      currentRoundTripTime: st.currentRoundTripTime
    });
    kv($("pc-conn-list"), [
      ["브로커", BROKER.host],
      ["코드", (results.pairing && results.pairing.code) || "-"],
      ["후보 쌍", st.pairType || "아직 측정 전", /host-to-host/.test(st.pairType || "") ? "ok-text" : "warn-text"],
      ["로컬 후보", st.local ? (st.local.typ + " " + (st.local.address || "") + " (" + st.local.range + ")") : "-"],
      ["원격 후보", st.remote ? (st.remote.typ + " " + (st.remote.address || "") + " (" + st.remote.range + ")") : "-"],
      ["ICE 상태", st.pairState || "-"],
      ["ICE RTT", st.currentRoundTripTime != null ? Math.round(st.currentRoundTripTime * 1000) + " ms" : "-"]
    ]);
    if (st.inboundVideo) {
      results.media = st.inboundVideo;
    } else if (pcCall) {
      var outb = null;
      try {
        var report = await pc.getStats(null);
        report.forEach(function (s) {
          if (s.type === "outbound-rtp" && s.kind === "video") outb = s;
        });
      } catch (e) {}
      if (outb) {
        results.media = {
          framesPerSecond: outb.framesPerSecond,
          frameWidth: outb.frameWidth,
          frameHeight: outb.frameHeight,
          packetsSent: outb.packetsSent,
          bytesSent: outb.bytesSent,
          nackCount: outb.nackCount,
          firCount: outb.firCount
        };
        kv($("pc-media-list"), [
          ["송신", (outb.frameWidth || "?") + "×" + (outb.frameHeight || "?") + " @ " + (outb.framesPerSecond != null ? outb.framesPerSecond : "?") + " fps"],
          ["보낸 바이트", String(outb.bytesSent || 0)],
          ["NACK/FIR", (outb.nackCount || 0) + " / " + (outb.firCount || 0)]
        ]);
      }
    }
  }

  function listenPcIncoming() {
    if (!pcPeer) return;
    pcPeer.on("connection", function (conn) {
      log("pc-log", "수신 연결: " + conn.peer);
      wirePcData(conn);
    });
  }

  function scheduleIceOffer(delay) {
    if (iceOfferTimer) clearTimeout(iceOfferTimer);
    iceOfferTimer = setTimeout(function () {
      iceOfferTimer = null;
      attemptIceOffer();
    }, delay == null ? 300 : delay);
  }

  function attemptIceOffer() {
    if (!pcPeer || pcPeer.destroyed || pcPeer.disconnected || !pcPeer.open) return;
    if (pcConn && pcConn.open) return;
    if (iceOfferConn) return;
    var code = currentPcCode;
    if (!code) return;
    var teslaId = peerIdFromCode(code) + "-t";
    results.iceConfig = redactedIceConfig(iceState.mode);
    if (pcPeer) pcPeer.options.config = rtcConfigForMode(iceState.mode);
    log("pc-log", "테슬라 " + teslaId + " 로 연결을 시작합니다. 모드=" + (ICE_MODE_LABEL[iceState.mode] || iceState.mode) + (customTurnServer() && iceState.mode !== "direct" ? " · TURN 있음" : " · TURN 없음"));
    var conn;
    try {
      conn = pcPeer.connect(teslaId, { reliable: true, metadata: exportIceMetadata() });
    } catch (err) {
      log("pc-log", "연결 시작 실패: " + err, "error");
      scheduleIceOffer(1500);
      return;
    }
    if (!conn) {
      scheduleIceOffer(1500);
      return;
    }
    iceOfferConn = conn;
    watchConn(conn, "pc-log", "data");
    wirePcData(conn);
    setTimeout(function () {
      if (iceOfferConn !== conn) return;
      if (pcConn && pcConn.open) return;
      log("pc-log", "연결이 아직 열리지 않아 같은 코드로 다시 시도합니다.");
      iceOfferConn = null;
      try { conn.close(); } catch (e) {}
      scheduleIceOffer(300);
    }, 8000);
    conn.on("open", function () {
      if (iceOfferConn === conn) iceOfferConn = null;
      if (iceOfferTimer) { clearTimeout(iceOfferTimer); iceOfferTimer = null; }
    });
    conn.on("close", function () {
      if (iceOfferConn === conn) iceOfferConn = null;
      if (!(pcConn && pcConn.open)) scheduleIceOffer(800);
    });
    conn.on("error", function (err) {
      log("pc-log", "DataChannel 오류: " + ((err && err.type) || err), "error");
    });
  }

  async function checkTurnServers() {
    readTurnForm();
    saveIceToStorage();
    var box = $("turn-check-result");
    var turn = customTurnServer();
    if (!turn) {
      var msg = "TURN URL이 없습니다. 계정 없이 동작하는 공개 TURN은 지금 없습니다. README의 Metered 가입 절차로 URL·아이디·비밀번호를 넣은 뒤 다시 확인하세요.";
      if (box) box.textContent = msg;
      results.turnCheck = { at: nowIso(), ok: false, reason: "no-turn-configured" };
      log("pc-log", msg);
      return;
    }
    if (box) box.textContent = "TURN 후보를 수집하는 중…";
    log("pc-log", "TURN 서버 확인을 시작합니다.");
    var summary = await gatherIce("pc-log", {
      iceServers: [{ urls: "stun:stun.l.google.com:19302" }, turn],
      iceTransportPolicy: "all",
      sdpSemantics: "unified-plan"
    }, false);
    var relay = (summary.candidates || []).filter(function (c) { return c.typ === "relay"; });
    results.turnCheck = {
      at: nowIso(),
      ok: relay.length > 0,
      candidateCount: summary.candidateCount || 0,
      relayCount: relay.length,
      types: summary.types || {},
      errors: (summary.errors || []).slice(0, 8)
    };
    var text = relay.length
      ? "relay 후보 " + relay.length + "개. 이 노트북에서 TURN에 도달했습니다."
      : "relay 후보가 없습니다. URL·계정·방화벽을 확인하세요.";
    if (box) box.textContent = text;
    if ($("turn-check-list")) {
      kv($("turn-check-list"), [
        ["relay", relay.length ? (relay.length + "개") : "없음", relay.length ? "ok-text" : "bad-text"],
        ["전체 후보", String(summary.candidateCount || 0)],
        ["유형", JSON.stringify(summary.types || {})],
        ["오류", (summary.errors && summary.errors.length) ? summary.errors.slice(0, 3).join(" | ") : "없음", (summary.errors && summary.errors.length) ? "warn-text" : ""]
      ]);
    }
    log("pc-log", "TURN 서버 확인: " + text);
  }

  function bindModeButtons(onChange) {
    var buttons = document.querySelectorAll(".mode-btn");
    for (var i = 0; i < buttons.length; i++) {
      buttons[i].addEventListener("click", function () {
        var mode = this.getAttribute("data-mode");
        if (mode !== "auto" && mode !== "relay" && mode !== "direct") return;
        iceState.mode = mode;
        syncModeUi();
        if (onChange) onChange();
      });
    }
    syncModeUi();
  }

  function startPcBroker(code) {
    clearReceivedTesla();
    if (iceOfferTimer) { clearTimeout(iceOfferTimer); iceOfferTimer = null; }
    iceOfferConn = null;
    if (typeof Peer !== "function") {
      setStatus("pc-status", "PeerJS 로드 실패", "bad");
      log("pc-log", "window.Peer 가 없습니다.", "error");
      return;
    }
    if (pcPeer) {
      try { pcPeer.destroy(); } catch (e) {}
      pcPeer = null;
    }
    stopPings();
    pcConn = null;
    pcCall = null;
    pcRemotePeerId = null;
    currentPcCode = code;
    var id = peerIdFromCode(code);
    results.pairing = { role: "pc", code: code, peerId: id, broker: BROKER.host, startedAt: nowIso(), ice: redactedIceConfig(iceState.mode) };
    results.iceConfig = redactedIceConfig(iceState.mode);
    $("pc-code").textContent = code;
    setStatus("pc-status", "브로커 연결 중…", "wait");
    log("pc-log", "Peer ID " + id + " 로 " + BROKER.host + " 에 등록합니다. 모드=" + (ICE_MODE_LABEL[iceState.mode] || iceState.mode));

    var peer = peerOptions(id);
    pcPeer = peer;
    peer.on("open", function (openId) {
      if (pcPeer !== peer) return;
      reconnectWait.pc = 500;
      log("pc-log", "브로커 등록 완료: " + openId);
      setStatus("pc-status", "코드 대기 중 — 테슬라에서 같은 코드를 입력하세요", "wait");
      results.pairing.brokerOpen = true;
      scheduleIceOffer(200);
    });
    peer.on("error", function (err) {
      if (pcPeer !== peer) return;
      handleBrokerError("pc", err);
    });
    peer.on("disconnected", function () {
      if (pcPeer !== peer) return;
      log("pc-log", "브로커와 끊겼습니다. 같은 코드로 재연결합니다.");
      scheduleReconnect("pc");
    });
    listenPcIncoming();
    if (statsTimer) clearInterval(statsTimer);
    statsTimer = setInterval(function () {
      refreshPcStats().catch(function () {});
    }, 1000);
  }

  async function startShare() {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getDisplayMedia) {
      log("pc-log", "getDisplayMedia를 지원하지 않습니다.", "error");
      return;
    }
    if (!pcPeer || !pcRemotePeerId) {
      log("pc-log", "먼저 테슬라와 페어링하세요.", "error");
      return;
    }
    try {
      localStream = await navigator.mediaDevices.getDisplayMedia({
        video: { frameRate: 30 },
        audio: false
      });
    } catch (err) {
      log("pc-log", "화면 공유가 취소되거나 실패했습니다: " + err, "error");
      return;
    }
    log("pc-log", "화면 공유 시작, 테슬라(" + pcRemotePeerId + ")로 호출합니다.");
    pcCall = pcPeer.call(pcRemotePeerId, localStream);
    if (!pcCall) {
      log("pc-log", "call()이 실패했습니다.", "error");
      return;
    }
    watchConn(pcCall, "pc-log", "media");
    results.media = { startedAt: nowIso(), direction: "out" };
    pcCall.on("close", function () { log("pc-log", "통화가 종료되었습니다."); });
    pcCall.on("error", function (err) { log("pc-log", "통화 오류: " + err, "error"); });
    localStream.getVideoTracks().forEach(function (tr) {
      tr.addEventListener("ended", function () { stopShare(); });
    });
    kv($("pc-media-list"), [["상태", "공유 중", "ok-text"]]);
  }

  function stopShare() {
    if (localStream) {
      localStream.getTracks().forEach(function (t) { t.stop(); });
      localStream = null;
    }
    try { if (pcCall) pcCall.close(); } catch (e) {}
    pcCall = null;
    kv($("pc-media-list"), [["상태", "중지됨"]]);
    log("pc-log", "화면 공유를 중지했습니다.");
  }

  function initPc() {
    $("view-home").classList.add("hidden");
    $("view-pc").classList.remove("hidden");
    $("page-title").textContent = "PC 검사";
    readEnv();
    readSupport();
    readCodecs();
    loadIceFromStorage();
    fillTurnForm();
    results.iceConfig = redactedIceConfig(iceState.mode);
    syncModeUi();
    var code = randomCode();
    startPcBroker(code);

    bindModeButtons(function () {
      readTurnForm();
      saveIceToStorage();
      results.iceConfig = redactedIceConfig(iceState.mode);
      if (pcPeer) pcPeer.options.config = rtcConfigForMode(iceState.mode);
      log("pc-log", "모드를 " + (ICE_MODE_LABEL[iceState.mode] || iceState.mode) + " 로 바꿨습니다. 다음 연결부터 적용됩니다.");
      if (iceOfferConn && !(pcConn && pcConn.open)) {
        var stale = iceOfferConn;
        iceOfferConn = null;
        try { stale.close(); } catch (e) {}
      }
      if (!(pcConn && pcConn.open)) scheduleIceOffer(200);
    });
    var saveTurn = $("btn-save-turn");
    if (saveTurn) saveTurn.addEventListener("click", function () {
      readTurnForm();
      saveIceToStorage();
      results.iceConfig = redactedIceConfig(iceState.mode);
      if (pcPeer) pcPeer.options.config = rtcConfigForMode(iceState.mode);
      log("pc-log", "TURN 정보를 이 브라우저에 저장했습니다.");
      var hint = $("turn-check-result");
      if (hint && !results.turnCheck) hint.textContent = "저장했습니다. TURN 서버 확인으로 relay 후보가 나오는지 보세요.";
    });
    var turnBtn = $("btn-turn-check");
    if (turnBtn) turnBtn.addEventListener("click", function () { checkTurnServers(); });

    $("btn-new-code").addEventListener("click", function () {
      stopShare();
      startPcBroker(randomCode());
    });
    $("btn-share").addEventListener("click", function () { startShare(); });
    $("btn-stop-share").addEventListener("click", function () { stopShare(); });
    $("btn-copy-pc").addEventListener("click", function () {
      copyText(combinedResultsText(), "pc-json", "pc-log");
    });
    $("btn-download-pc").addEventListener("click", function () {
      downloadCombinedResults();
    });
  }

  /* ---------- boot ---------- */

  window.addEventListener("error", function (ev) {
    var msg = "JS 오류: " + ev.message + " @" + ev.filename + ":" + ev.lineno;
    results.errors.push(msg);
    console.error(msg);
  });

  if (role === "tesla") initTesla();
  else if (role === "pc") initPc();
  else {
    $("view-home").classList.remove("hidden");
    $("view-tesla").classList.add("hidden");
    $("view-pc").classList.add("hidden");
  }
})();
