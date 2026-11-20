import { STRINGS, lri } from "./i18n.js";

const api = () => window.go?.main?.App;
const wailsRuntime = () => window.runtime;

let state = null;
let toastTimer = null;
let verifying = false;
let generatingWarp = false;
let pingingAll = false;
let probingMtu = false;

const el = (id) => document.getElementById(id);

function t() {
  const lang = state?.settings?.language === "ar" ? "ar" : "en";
  return STRINGS[lang];
}

function formatBytes(bytes, tr) {
  const n = Number(bytes || 0);
  if (n < 1024) return `${n} ${tr.unitsB}`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} ${tr.unitsKB}`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(2)} ${tr.unitsMB}`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} ${tr.unitsGB}`;
}

function showToast(msg) {
  const box = el("toast");
  box.textContent = msg;
  box.classList.remove("hidden");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => box.classList.add("hidden"), 3200);
}

function showError(msg) {
  if (!msg) {
    el("global-error-banner").classList.add("hidden");
    return;
  }
  el("global-error-text").textContent = msg;
  el("global-error-banner").classList.remove("hidden");
}

function applyThemeAndDirection() {
  const lang = state?.settings?.language === "ar" ? "ar" : "en";
  const theme = state?.settings?.theme === "light" ? "light" : "dark";
  document.documentElement.lang = lang;
  document.documentElement.dir = lang === "ar" ? "rtl" : "ltr";
  document.documentElement.setAttribute("data-theme", theme);
}

function applyStaticLabels() {
  const tr = t();
  const theme = state?.settings?.theme === "light" ? "light" : "dark";
  el("app-title").textContent = tr.appTitle;
  el("storage-mode-label").textContent = state?.portableMode ? tr.modePortable : tr.modeStandard;
  el("btn-hide-tray").textContent = tr.hideToTray;
  el("btn-lang-toggle").textContent = tr.langToggle;
  el("btn-theme-toggle").textContent = theme === "dark" ? tr.themeLight : tr.themeDark;
  el("btn-dismiss-error").textContent = tr.dismiss;

  el("lbl-rx-total").textContent = tr.rxTotal;
  el("lbl-tx-total").textContent = tr.txTotal;
  el("lbl-live-speed").textContent = tr.liveSpeed;
  el("lbl-voip-calls").textContent = tr.voipCalls;
  el("lbl-sparkline-title").textContent = tr.sparklineTitle;
  el("lbl-verify-title").textContent = tr.verifyTitle;
  el("btn-close-verify").textContent = tr.close;

  el("lbl-clients-title").textContent = tr.clientsTitle;
  el("lbl-clients-desc").textContent = tr.clientsDesc;
  el("btn-scan-clients").textContent = tr.scanClients;
  el("btn-add-client").textContent = tr.addPortableExe;
  el("btn-copy-proxy-link").textContent = tr.copyProxyLink;
  el("lbl-socks-endpoint").textContent = tr.socksEndpointLbl;
  el("lbl-call-checklist-summary").textContent = tr.callChecklistSummary;
  el("call-checklist-items").innerHTML = "";
  [tr.callCheck1, tr.callCheck2, tr.callCheck3].forEach((txt) => {
    const li = document.createElement("li");
    li.textContent = txt;
    el("call-checklist-items").appendChild(li);
  });
  el("lbl-call-ack").textContent = tr.callChecklistAck;

  el("lbl-servers-title").textContent = tr.serversTitle;
  el("lbl-servers-desc").textContent = tr.serversDesc;
  el("btn-ping-all").textContent = tr.pingAll;
  el("btn-import-conf").textContent = tr.importConf;
  el("btn-import-qr").textContent = tr.importQr;
  el("btn-paste-import").textContent = tr.pasteImport;
  el("btn-gen-warp").textContent = generatingWarp ? tr.quickWarpBusy : tr.genWarp;
  el("btn-quick-warp").textContent = generatingWarp ? tr.quickWarpBusy : tr.quickWarpBtn;
  el("lbl-quick-warp-hint").textContent = tr.quickWarpHint;
  el("btn-new-profile").textContent = tr.newProfile;

  el("lbl-protection-title").textContent = tr.protectionTitle;
  el("lbl-protection-desc").textContent = tr.protectionDesc;
  el("lbl-killswitch").textContent = tr.killSwitchLbl;
  el("desc-killswitch").textContent = tr.killSwitchDesc;
  el("lbl-guard-mode").textContent = tr.guardModeLbl;
  const gOpts = el("set-guard-mode").options;
  gOpts[0].textContent = tr.guardStrict;
  gOpts[1].textContent = tr.guardLogOnly;
  el("lbl-socks-auth").textContent = tr.socksAuthLbl;
  el("btn-rotate-creds").textContent = tr.rotateCreds;
  el("lbl-socks-port").textContent = tr.socksPortLbl;
  el("desc-socks-port").textContent = tr.socksPortDesc;
  el("lbl-autoconnect-tg").textContent = tr.autoConnectTgLbl;
  el("desc-autoconnect-tg").textContent = tr.autoConnectTgDesc;
  el("lbl-autodisconnect-tg").textContent = tr.autoDiscTgLbl;
  el("desc-autodisconnect-tg").textContent = tr.autoDiscTgDesc;
  el("lbl-autofailover").textContent = tr.autoFailoverLbl;
  el("desc-autofailover").textContent = tr.autoFailoverDesc;
  el("lbl-block-ipv6").textContent = tr.blockIpv6Lbl;
  el("desc-block-ipv6").textContent = tr.blockIpv6Desc;
  el("lbl-doh").textContent = tr.dohLbl;
  el("desc-doh").textContent = tr.dohDesc;
  el("lbl-http-proxy").textContent = tr.httpProxyLbl;
  el("desc-http-proxy").textContent = tr.httpProxyDesc;
  el("lbl-autoconnect-launch").textContent = tr.autoConnectLaunchLbl;
  el("desc-autoconnect-launch").textContent = tr.autoConnectLaunchDesc;
  el("lbl-autostart").textContent = tr.autostartLbl;
  el("desc-autostart").textContent = tr.autostartDesc;
  el("lbl-min-tray").textContent = tr.minTrayLbl;
  el("desc-min-tray").textContent = tr.minTrayDesc;

  el("lbl-custom-doh-summary").textContent = tr.customDohSummary;
  el("lbl-custom-doh-url").textContent = tr.customDohUrlLbl;
  el("lbl-custom-doh-sni").textContent = tr.customDohSniLbl;
  el("lbl-custom-doh-ip").textContent = tr.customDohIpLbl;
  el("btn-save-custom-doh").textContent = tr.saveCustomDoh;
  el("lbl-guard-log-summary").textContent = tr.guardLogSummary;
  el("lbl-backup-summary").textContent = tr.backupSummary;
  el("lbl-backup-pass").textContent = tr.backupPassLbl;
  el("btn-export-backup").textContent = tr.exportBackup;
  el("btn-import-backup").textContent = tr.importBackup;

  el("lbl-ed-name").textContent = tr.edName;
  el("lbl-ed-priv").textContent = tr.edPriv;
  el("lbl-ed-psk").textContent = tr.edPsk;
  el("lbl-ed-ip").textContent = tr.edIp;
  el("lbl-ed-dns").textContent = tr.edDns;
  el("lbl-ed-pub").textContent = tr.edPub;
  el("lbl-ed-endpoint").textContent = tr.edEndpoint;
  el("lbl-ed-keepalive").textContent = tr.edKeepalive;
  el("lbl-ed-mtu").textContent = tr.edMtu;
  el("btn-ed-auto-mtu").textContent = probingMtu ? tr.edDetectingMtu : tr.edAutoMtu;
  el("lbl-ed-doh").textContent = tr.edDoh;
  el("lbl-ed-awg-summary").textContent = tr.edAwgSummary;
  el("btn-awg-off").textContent = tr.edAwgOff;
  el("btn-awg-junk").textContent = tr.edAwgJunk;
  el("btn-awg-quic15").textContent = tr.edAwgQuic15;
  el("lbl-ed-awg-raw").textContent = tr.edAwgRaw;
  el("btn-ed-cancel").textContent = tr.cancel;
  el("btn-ed-save").textContent = tr.save;
  el("btn-close-editor").textContent = tr.close;

  el("modal-paste-title").textContent = tr.pasteTitle;
  el("lbl-paste-name").textContent = tr.pasteNameLbl;
  el("lbl-paste-conf").textContent = tr.pasteConfLbl;
  el("btn-paste-qr-clip").textContent = tr.pasteQrClip;
  el("btn-paste-submit").textContent = tr.pasteSubmit;
  el("btn-close-paste").textContent = tr.close;

  el("modal-qr-title").textContent = tr.qrTitle;
  el("qr-caption").textContent = tr.qrCaption;
  el("btn-close-qr").textContent = tr.close;
}

function updateSparkline(rxHist, txHist) {
  const rx = rxHist || [];
  const tx = txHist || [];
  const w = 360;
  const h = 52;
  const pad = 4;
  let maxVal = 1024;
  for (const v of rx) if (v > maxVal) maxVal = v;
  for (const v of tx) if (v > maxVal) maxVal = v;

  const toPoints = (arr) => {
    if (!arr.length) return `0,${h - pad} ${w},${h - pad}`;
    if (arr.length === 1) {
      const y = h - pad - (arr[0] / maxVal) * (h - pad * 2);
      return `0,${y.toFixed(1)} ${w},${y.toFixed(1)}`;
    }
    return arr
      .map((val, idx) => {
        const x = (idx / (arr.length - 1)) * w;
        const y = h - pad - (val / maxVal) * (h - pad * 2);
        return `${x.toFixed(1)},${y.toFixed(1)}`;
      })
      .join(" ");
  };

  el("spark-rx-line").setAttribute("points", toPoints(rx));
  el("spark-tx-line").setAttribute("points", toPoints(tx));
}

function renderStatusAndTelemetry() {
  if (!state) return;
  const tr = t();
  const s = state.stats || {};
  const activeProf = (state.profiles || []).find((p) => p.id === (state.activeProfileId || state.settings.activeProfileId));

  let dotClass = "dot-idle";
  let titleText = tr.statusDisconnected;
  if (state.connecting) {
    dotClass = "dot-warn";
    titleText = tr.statusConnecting;
  } else if (state.connected) {
    dotClass = "dot-connected";
    titleText = tr.statusConnected;
  } else if (state.settings.killSwitch) {
    dotClass = "dot-warn";
    titleText = tr.statusKillSwitch;
  }

  el("top-dot").className = `status-dot ${dotClass}`;
  el("focal-dot").className = `status-dot ${dotClass}`;
  el("focal-status-title").textContent = titleText;
  el("focal-active-server").textContent = activeProf
    ? `${activeProf.name} (${lri(s.resolvedEndpoint || activeProf.endpoint)})`
    : tr.noActiveServer;

  const btnConn = el("btn-primary-connect");
  btnConn.textContent = state.connected ? tr.disconnect : tr.connect;
  btnConn.disabled = state.connecting || generatingWarp || (!state.connected && (!state.profiles || state.profiles.length === 0));

  const btnQuickWarp = el("btn-quick-warp");
  if (btnQuickWarp) {
    btnQuickWarp.textContent = generatingWarp ? tr.quickWarpBusy : tr.quickWarpBtn;
    btnQuickWarp.disabled = generatingWarp || state.connecting;
  }

  const btnVerify = el("btn-verify-route");
  btnVerify.textContent = verifying ? tr.verifying : tr.verifyRouteCalls;
  btnVerify.disabled = !state.connected || verifying;

  el("val-rx-total").textContent = formatBytes(s.rxBytes, tr);
  el("val-tx-total").textContent = formatBytes(s.txBytes, tr);
  el("val-live-speed").textContent = `${formatBytes(s.rxBps, tr)}/${tr.unitsSec} | ${formatBytes(s.txBps, tr)}/${tr.unitsSec}`;
  el("val-voip-calls").textContent = String(s.activeUdpAssocs || 0);
  el("val-handshake-age").textContent =
    s.handshakeAgeSec >= 0 ? tr.handshakeAge(s.handshakeAgeSec) : tr.handshakeNever;

  updateSparkline(state.rxHistory, state.txHistory);

  el("desc-guard-mode").textContent = tr.guardModeDesc(s.blockedLocalAttempts || 0);
  el("val-proxy-uri").textContent = lri(state.proxyUri || "");
  if (state.lastError) {
    showError(state.lastError);
  }
}

function renderClients() {
  if (!state) return;
  const tr = t();
  const listEl = el("clients-list");
  listEl.innerHTML = "";
  const clients = state.clients || [];
  if (clients.length === 0) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = tr.clientsEmpty;
    listEl.appendChild(empty);
    return;
  }

  for (const c of clients) {
    const row = document.createElement("div");
    row.className = `row-item${c.activeConns > 0 ? " row-item-active" : ""}`;

    const main = document.createElement("div");
    main.className = "row-main";

    const title = document.createElement("div");
    title.className = "row-title";
    const statusWord = c.running ? tr.clientRunning : tr.clientStopped;
    const typeTag = c.isMsix ? tr.clientMsix : c.isPortable ? tr.clientPortable : "";
    title.textContent = [c.displayName, statusWord, typeTag].filter(Boolean).join(" | ");

    const meta = document.createElement("div");
    meta.className = "row-meta mono";
    const trafficPart =
      c.rxBytes || c.txBytes || c.activeConns
        ? ` | ${c.activeConns} conn | ${formatBytes(c.rxBytes, tr)} / ${formatBytes(c.txBytes, tr)}`
        : "";
    meta.textContent = `${lri(c.exePath || "Microsoft Store MSIX")}${trafficPart}`;

    main.appendChild(title);
    main.appendChild(meta);

    const actions = document.createElement("div");
    actions.className = "row-actions";

    const allowLbl = document.createElement("label");
    allowLbl.className = "inline-check";
    const allowChk = document.createElement("input");
    allowChk.type = "checkbox";
    allowChk.checked = c.enabled !== false;
    allowChk.addEventListener("change", async () => {
      await api().ToggleClientEnabled(c.id, allowChk.checked);
      await refreshBootstrap();
    });
    const allowTxt = document.createElement("span");
    allowTxt.textContent = tr.clientAllowToggle;
    allowLbl.appendChild(allowChk);
    allowLbl.appendChild(allowTxt);
    actions.appendChild(allowLbl);

    const applyBtn = document.createElement("button");
    applyBtn.type = "button";
    applyBtn.className = "btn btn-mini";
    applyBtn.textContent = tr.applyProxy;
    applyBtn.addEventListener("click", async () => {
      try {
        const res = await api().ApplyProxyToClient(c.id);
        if (res.clipboardCopied) {
          showToast(tr.toastAppliedCopy(c.displayName));
        } else {
          showToast(tr.toastApplied(c.displayName));
        }
      } catch (err) {
        showError(String(err));
      }
    });
    actions.appendChild(applyBtn);

    if (!c.autoDetected) {
      const rmBtn = document.createElement("button");
      rmBtn.type = "button";
      rmBtn.className = "btn btn-mini btn-danger";
      rmBtn.textContent = tr.clientRemove;
      rmBtn.addEventListener("click", async () => {
        await api().RemoveCustomClient(c.id);
        await refreshBootstrap();
      });
      actions.appendChild(rmBtn);
    }

    row.appendChild(main);
    row.appendChild(actions);
    listEl.appendChild(row);
  }
}

function renderProfiles() {
  if (!state) return;
  const tr = t();
  const listEl = el("profiles-list");
  listEl.innerHTML = "";
  const profiles = state.profiles || [];
  if (profiles.length === 0) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = tr.serversEmpty;
    listEl.appendChild(empty);
    return;
  }

  const activeId = state.activeProfileId || state.settings.activeProfileId;

  for (const p of profiles) {
    const isActive = p.id === activeId;
    const row = document.createElement("div");
    row.className = `row-item${isActive ? " row-item-active" : ""}`;

    const main = document.createElement("div");
    main.className = "row-main";
    main.style.cursor = "pointer";
    main.addEventListener("click", async () => {
      try {
        if (state.connected) {
          await api().SwitchProfile(p.id);
        } else {
          state.settings.activeProfileId = p.id;
          await api().UpdateSettings(state.settings);
        }
        await refreshBootstrap();
      } catch (err) {
        showError(String(err));
      }
    });

    const title = document.createElement("div");
    title.className = "row-title";
    let pingTag = tr.pingPending;
    if (p.lastPingMs > 0) pingTag = lri(`${p.lastPingMs} ms`);
    else if (p.lastPingMs < 0) pingTag = tr.pingUnreachable;
    title.textContent = `${isActive ? "* " : ""}${p.name} | ${pingTag}`;

    const meta = document.createElement("div");
    meta.className = "row-meta mono";
    const awgTag = p.awgParams ? " | AWG" : "";
    meta.textContent = `${lri(p.endpoint)} | MTU ${lri(String(p.mtu || 1280))}${awgTag}`;

    main.appendChild(title);
    main.appendChild(meta);

    const actions = document.createElement("div");
    actions.className = "row-actions";

    const addMini = (label, cls, handler) => {
      const b = document.createElement("button");
      b.type = "button";
      b.className = `btn btn-mini ${cls || ""}`.trim();
      b.textContent = label;
      b.addEventListener("click", (ev) => {
        ev.stopPropagation();
        handler();
      });
      actions.appendChild(b);
    };

    addMini(tr.ping, "", async () => {
      try {
        await api().PingProfile(p.id);
        await refreshBootstrap();
      } catch (err) {
        showError(String(err));
      }
    });
    addMini(tr.edit, "", () => openEditor(p));
    addMini(tr.qr, "", async () => {
      try {
        const dataUrl = await api().ExportProfileQR(p.id);
        el("qr-image").src = dataUrl;
        el("modal-qr-title").textContent = `${tr.qrTitle} - ${p.name}`;
        el("modal-qr").classList.remove("hidden");
      } catch (err) {
        showError(String(err));
      }
    });
    addMini(tr.exportConf, "", async () => {
      try {
        await api().ExportConfFileDialog(p.id);
      } catch (err) {
        showError(String(err));
      }
    });
    addMini(tr.del, "btn-danger", async () => {
      if (!window.confirm(tr.confirmDelete(p.name))) return;
      await api().DeleteProfile(p.id);
      await refreshBootstrap();
    });

    row.appendChild(main);
    row.appendChild(actions);
    listEl.appendChild(row);
  }
}

function renderSettingsAndLogs() {
  if (!state) return;
  const tr = t();
  const s = state.settings;
  el("set-killswitch").checked = !!s.killSwitch;
  el("set-guard-mode").value = s.processGuardMode || "strict";
  el("set-socks-auth").checked = !!s.socksAuthEnabled;
  el("desc-socks-auth").textContent = tr.socksAuthDesc(s.socksAuthEnabled ? s.socksUser : "");
  el("set-socks-port").value = s.socksPort || 48729;
  el("set-autoconnect-tg").checked = !!s.autoConnectOnTelegram;
  el("set-autodisconnect-tg").checked = !!s.disconnectWhenNoTelegram;
  el("set-autofailover").checked = !!s.autoFailover;
  el("set-block-ipv6").checked = !!s.blockIpv6;
  el("set-doh").checked = !!s.useDoh;
  el("set-http-proxy").checked = !!s.httpProxyEnabled;
  el("set-http-port").value = s.httpProxyPort || 48739;
  el("set-autostart").checked = !!s.startWithWindows;
  el("set-autoconnect-launch").checked = !!s.autoConnectOnLaunch;
  el("set-min-tray").checked = !!s.minimizeToTray;
  el("chk-call-ack").checked = !!s.callChecklistAck;

  if (document.activeElement !== el("set-custom-doh-url")) {
    el("set-custom-doh-url").value = s.customDohUrl || "";
  }
  if (document.activeElement !== el("set-custom-doh-sni")) {
    el("set-custom-doh-sni").value = s.customDohServerName || "";
  }
  if (document.activeElement !== el("set-custom-doh-ip")) {
    el("set-custom-doh-ip").value = s.customDohDialAddr || "";
  }

  const logBox = el("guard-events-list");
  logBox.innerHTML = "";
  const evs = (state.guardEvents || []).slice().reverse().slice(0, 25);
  if (evs.length === 0) {
    logBox.textContent = tr.guardLogEmpty;
  } else {
    for (const ev of evs) {
      const line = document.createElement("div");
      const timeStr = new Date(ev.timestampUnix * 1000).toLocaleTimeString();
      line.textContent = `[${timeStr}] ${ev.action.toUpperCase()} ${ev.protocol} ${ev.clientLabel} (PID ${ev.pid}, :${ev.peerPort})`;
      logBox.appendChild(line);
    }
  }
}

function renderAll() {
  applyThemeAndDirection();
  applyStaticLabels();
  renderStatusAndTelemetry();
  renderClients();
  renderProfiles();
  renderSettingsAndLogs();
}

async function refreshBootstrap() {
  try {
    state = await api().GetBootstrapState();
    renderAll();
  } catch (err) {
    showError(String(err));
  }
}

async function persistCurrentSettings(mutator) {
  if (!state) return;
  const next = { ...state.settings };
  mutator(next);
  try {
    state.settings = await api().UpdateSettings(next);
    await refreshBootstrap();
  } catch (err) {
    showError(String(err));
    await refreshBootstrap();
  }
}

function openEditor(profile) {
  const tr = t();
  const isNew = !profile;
  const p = profile || {
    id: "",
    name: "",
    privateKey: "",
    presharedKey: "",
    clientIp: "10.0.0.2/32",
    dns: "1.1.1.1",
    peerPublicKey: "",
    endpoint: "",
    keepAlive: 25,
    mtu: 1280,
    awgParams: "",
    useDoH: true,
  };
  el("modal-editor-title").textContent = isNew ? tr.edTitleNew : tr.edTitleEdit;
  el("ed-id").value = p.id || "";
  el("ed-name").value = p.name || "";
  el("ed-priv").value = p.privateKey || "";
  el("ed-psk").value = p.presharedKey || "";
  el("ed-ip").value = p.clientIp || "10.0.0.2/32";
  el("ed-dns").value = p.dns || "1.1.1.1";
  el("ed-pub").value = p.peerPublicKey || "";
  el("ed-endpoint").value = p.endpoint || "";
  el("ed-keepalive").value = p.keepAlive ?? 25;
  el("ed-mtu").value = p.mtu || 1280;
  el("ed-use-doh").checked = p.useDoH !== false;
  el("ed-awg-raw").value = p.awgParams || "";
  el("modal-editor").classList.remove("hidden");
}

function closeAllModals() {
  el("modal-editor").classList.add("hidden");
  el("modal-paste").classList.add("hidden");
  el("modal-qr").classList.add("hidden");
}

async function handleDroppedOrPastedFiles(files) {
  if (!files || !files.length) return;
  for (const f of files) {
    const name = (f.name || "").toLowerCase();
    if (name.endsWith(".conf")) {
      const txt = await f.text();
      await api().ImportConfText(txt, f.name.replace(/\.conf$/i, ""));
      await refreshBootstrap();
      showToast(t().toastSaved);
    } else if (f.type.startsWith("image/") || /\.(png|jpe?g|bmp)$/i.test(name)) {
      const dataUrl = await new Promise((resolve, reject) => {
        const fr = new FileReader();
        fr.onload = () => resolve(fr.result);
        fr.onerror = reject;
        fr.readAsDataURL(f);
      });
      await api().ImportQRBytesBase64(String(dataUrl), f.name.replace(/\.[^.]+$/, ""));
      await refreshBootstrap();
      showToast(t().toastSaved);
    }
  }
}

async function runVerifyRoute() {
  if (verifying) return;
  verifying = true;
  renderStatusAndTelemetry();
  try {
    const raw = await api().VerifyRouteAndCalls();
    const rep = JSON.parse(raw);
    const tr = t();
    const body = el("verify-body");
    body.innerHTML = "";

    const row1 = document.createElement("div");
    row1.textContent = `${tr.verifyExit}: ${rep.exitIp ? lri(`${rep.exitIp} (${rep.country || "?"}) - ${rep.exitRttMs} ms`) : tr.verifyFail + (rep.exitError ? ` (${rep.exitError})` : "")}`;
    body.appendChild(row1);

    const row2 = document.createElement("div");
    row2.textContent = `${tr.verifyUdpReady}: ${rep.udpOk ? `${tr.verifyPass} (${lri(rep.udpRttMs + " ms")})` : `${tr.verifyFail} (${rep.udpError || ""})`}`;
    body.appendChild(row2);

    if (Array.isArray(rep.dcLatencies) && rep.dcLatencies.length) {
      const dcLine = document.createElement("div");
      dcLine.className = "mono";
      dcLine.textContent = rep.dcLatencies
        .map((d) => `${d.dc}: ${d.ok ? d.rttMs + "ms" : "fail"}`)
        .join(" | ");
      body.appendChild(dcLine);
    }
    el("verify-panel").classList.remove("hidden");
  } catch (err) {
    showError(String(err));
  } finally {
    verifying = false;
    renderStatusAndTelemetry();
  }
}

async function runQuickWarp(forceNew) {
  if (generatingWarp) return;
  generatingWarp = true;
  showError("");
  applyStaticLabels();
  renderStatusAndTelemetry();
  try {
    const res = await api().QuickConnectWarp(!!forceNew);
    await refreshBootstrap();
    const tr = t();
    if (Array.isArray(res?.appliedClients) && res.appliedClients.length > 0) {
      showToast(tr.toastQuickWarpApplied(res.appliedClients.join(", ")));
    } else if (res?.clipboardCopied) {
      showToast(tr.toastQuickWarpCopied);
    } else {
      showToast(tr.toastWarpReady);
    }
    await runVerifyRoute();
  } catch (err) {
    showError(String(err));
  } finally {
    generatingWarp = false;
    applyStaticLabels();
    renderStatusAndTelemetry();
  }
}

function wireEvents() {
  el("btn-hide-tray").addEventListener("click", () => api().HideToTray());
  el("btn-lang-toggle").addEventListener("click", () =>
    persistCurrentSettings((s) => {
      s.language = s.language === "ar" ? "en" : "ar";
    })
  );
  el("btn-theme-toggle").addEventListener("click", () =>
    persistCurrentSettings((s) => {
      s.theme = s.theme === "dark" ? "light" : "dark";
    })
  );
  el("btn-dismiss-error").addEventListener("click", () => showError(""));

  el("btn-primary-connect").addEventListener("click", async () => {
    try {
      showError("");
      if (state.connected) {
        await api().Disconnect();
      } else {
        const target = state.activeProfileId || state.settings.activeProfileId || state.profiles?.[0]?.id || "";
        await api().Connect(target);
      }
      await refreshBootstrap();
    } catch (err) {
      showError(String(err));
      await refreshBootstrap();
    }
  });

  el("btn-verify-route").addEventListener("click", () => runVerifyRoute());
  el("btn-quick-warp").addEventListener("click", () => runQuickWarp(false));
  el("btn-close-verify").addEventListener("click", () => el("verify-panel").classList.add("hidden"));

  el("btn-scan-clients").addEventListener("click", async () => {
    await api().ScanTelegramClients();
    await refreshBootstrap();
  });
  el("btn-add-client").addEventListener("click", async () => {
    try {
      await api().AddCustomClientDialog();
      await refreshBootstrap();
    } catch (err) {
      showError(String(err));
    }
  });
  el("btn-copy-proxy-link").addEventListener("click", async () => {
    try {
      await api().CopyProxyLink();
      showToast(t().toastCopied);
    } catch (err) {
      showError(String(err));
    }
  });

  el("chk-call-ack").addEventListener("change", () =>
    persistCurrentSettings((s) => {
      s.callChecklistAck = el("chk-call-ack").checked;
    })
  );

  el("btn-ping-all").addEventListener("click", async () => {
    if (pingingAll) return;
    pingingAll = true;
    try {
      await api().PingAllProfiles();
      await refreshBootstrap();
    } finally {
      pingingAll = false;
    }
  });
  el("btn-import-conf").addEventListener("click", async () => {
    try {
      const p = await api().ImportConfFileDialog();
      if (p) {
        await refreshBootstrap();
        showToast(t().toastSaved);
      }
    } catch (err) {
      showError(String(err));
    }
  });
  el("btn-import-qr").addEventListener("click", async () => {
    try {
      const p = await api().ImportQRFileDialog();
      if (p) {
        await refreshBootstrap();
        showToast(t().toastSaved);
      }
    } catch (err) {
      showError(String(err));
    }
  });
  el("btn-paste-import").addEventListener("click", () => {
    el("paste-name").value = "";
    el("paste-conf").value = "";
    el("modal-paste").classList.remove("hidden");
  });
  el("btn-gen-warp").addEventListener("click", () => runQuickWarp(true));
  el("btn-new-profile").addEventListener("click", () => openEditor(null));

  el("set-killswitch").addEventListener("change", () =>
    persistCurrentSettings((s) => { s.killSwitch = el("set-killswitch").checked; })
  );
  el("set-guard-mode").addEventListener("change", () =>
    persistCurrentSettings((s) => { s.processGuardMode = el("set-guard-mode").value; })
  );
  el("set-socks-auth").addEventListener("change", () =>
    persistCurrentSettings((s) => { s.socksAuthEnabled = el("set-socks-auth").checked; })
  );
  el("btn-rotate-creds").addEventListener("click", async () => {
    await api().RegenerateSocksCredentials();
    await refreshBootstrap();
    showToast(t().toastCredsRotated);
  });
  el("set-socks-port").addEventListener("change", () =>
    persistCurrentSettings((s) => { s.socksPort = parseInt(el("set-socks-port").value, 10) || 48729; })
  );
  el("set-autoconnect-tg").addEventListener("change", () =>
    persistCurrentSettings((s) => { s.autoConnectOnTelegram = el("set-autoconnect-tg").checked; })
  );
  el("set-autodisconnect-tg").addEventListener("change", () =>
    persistCurrentSettings((s) => { s.disconnectWhenNoTelegram = el("set-autodisconnect-tg").checked; })
  );
  el("set-autofailover").addEventListener("change", () =>
    persistCurrentSettings((s) => { s.autoFailover = el("set-autofailover").checked; })
  );
  el("set-block-ipv6").addEventListener("change", () =>
    persistCurrentSettings((s) => { s.blockIpv6 = el("set-block-ipv6").checked; })
  );
  el("set-doh").addEventListener("change", () =>
    persistCurrentSettings((s) => { s.useDoh = el("set-doh").checked; })
  );
  el("set-http-proxy").addEventListener("change", () =>
    persistCurrentSettings((s) => {
      s.httpProxyEnabled = el("set-http-proxy").checked;
      s.httpProxyPort = parseInt(el("set-http-port").value, 10) || 48739;
    })
  );
  el("set-http-port").addEventListener("change", () =>
    persistCurrentSettings((s) => { s.httpProxyPort = parseInt(el("set-http-port").value, 10) || 48739; })
  );
  el("set-autoconnect-launch").addEventListener("change", () =>
    persistCurrentSettings((s) => { s.autoConnectOnLaunch = el("set-autoconnect-launch").checked; })
  );
  el("set-autostart").addEventListener("change", () =>
    persistCurrentSettings((s) => { s.startWithWindows = el("set-autostart").checked; })
  );
  el("set-min-tray").addEventListener("change", () =>
    persistCurrentSettings((s) => { s.minimizeToTray = el("set-min-tray").checked; })
  );

  el("btn-save-custom-doh").addEventListener("click", () =>
    persistCurrentSettings((s) => {
      s.customDohUrl = el("set-custom-doh-url").value.trim();
      s.customDohServerName = el("set-custom-doh-sni").value.trim();
      s.customDohDialAddr = el("set-custom-doh-ip").value.trim();
    }).then(() => showToast(t().toastSaved))
  );

  el("btn-export-backup").addEventListener("click", async () => {
    try {
      const ok = await api().ExportEncryptedBackupDialog(el("input-backup-pass").value);
      if (ok) showToast(t().toastBackupExported);
    } catch (err) {
      showError(String(err));
    }
  });
  el("btn-import-backup").addEventListener("click", async () => {
    try {
      state = await api().ImportEncryptedBackupDialog(el("input-backup-pass").value);
      renderAll();
      showToast(t().toastBackupImported);
    } catch (err) {
      showError(String(err));
    }
  });

  el("form-editor").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    try {
      await api().SaveProfile({
        id: el("ed-id").value,
        name: el("ed-name").value.trim(),
        privateKey: el("ed-priv").value.trim(),
        presharedKey: el("ed-psk").value.trim(),
        clientIp: el("ed-ip").value.trim(),
        dns: el("ed-dns").value.trim(),
        peerPublicKey: el("ed-pub").value.trim(),
        endpoint: el("ed-endpoint").value.trim(),
        keepAlive: parseInt(el("ed-keepalive").value, 10) || 25,
        mtu: parseInt(el("ed-mtu").value, 10) || 1280,
        awgParams: el("ed-awg-raw").value.trim(),
        useDoH: el("ed-use-doh").checked,
      });
      closeAllModals();
      await refreshBootstrap();
      showToast(t().toastSaved);
    } catch (err) {
      showError(String(err));
    }
  });
  el("btn-ed-auto-mtu").addEventListener("click", async () => {
    if (probingMtu) return;
    probingMtu = true;
    applyStaticLabels();
    try {
      const best = await api().DiscoverOptimalMTUForProfile({
        id: el("ed-id").value,
        name: el("ed-name").value.trim(),
        privateKey: el("ed-priv").value.trim(),
        presharedKey: el("ed-psk").value.trim(),
        clientIp: el("ed-ip").value.trim(),
        dns: el("ed-dns").value.trim(),
        peerPublicKey: el("ed-pub").value.trim(),
        endpoint: el("ed-endpoint").value.trim(),
        keepAlive: parseInt(el("ed-keepalive").value, 10) || 25,
        mtu: parseInt(el("ed-mtu").value, 10) || 1280,
        awgParams: el("ed-awg-raw").value.trim(),
        useDoH: el("ed-use-doh").checked,
      });
      el("ed-mtu").value = best;
      showToast(`MTU ${best}`);
    } catch (err) {
      showError(String(err));
    } finally {
      probingMtu = false;
      applyStaticLabels();
    }
  });
  el("btn-awg-off").addEventListener("click", () => { el("ed-awg-raw").value = ""; });
  el("btn-awg-junk").addEventListener("click", async () => {
    el("ed-awg-raw").value = await api().GetAwgPreset("universal_junk");
  });
  el("btn-awg-quic15").addEventListener("click", async () => {
    el("ed-awg-raw").value = await api().GetAwgPreset("quic_mimicry_15");
  });

  el("btn-paste-submit").addEventListener("click", async () => {
    try {
      await api().ImportConfText(el("paste-conf").value, el("paste-name").value);
      closeAllModals();
      await refreshBootstrap();
      showToast(t().toastSaved);
    } catch (err) {
      showError(String(err));
    }
  });
  el("btn-paste-qr-clip").addEventListener("click", async () => {
    try {
      const p = await api().ImportQRFromClipboard();
      if (p) {
        closeAllModals();
        await refreshBootstrap();
        showToast(t().toastSaved);
      }
    } catch (err) {
      showError(String(err));
    }
  });

  el("btn-close-editor").addEventListener("click", closeAllModals);
  el("btn-ed-cancel").addEventListener("click", closeAllModals);
  el("btn-close-paste").addEventListener("click", closeAllModals);
  el("btn-close-qr").addEventListener("click", closeAllModals);

  for (const id of ["modal-editor", "modal-paste", "modal-qr"]) {
    el(id).addEventListener("click", (ev) => {
      if (ev.target === el(id)) closeAllModals();
    });
  }
  window.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape") closeAllModals();
  });

  window.addEventListener("dragover", (ev) => ev.preventDefault());
  window.addEventListener("drop", async (ev) => {
    ev.preventDefault();
    try {
      await handleDroppedOrPastedFiles(ev.dataTransfer?.files);
    } catch (err) {
      showError(String(err));
    }
  });
  window.addEventListener("paste", async (ev) => {
    const tag = (document.activeElement?.tagName || "").toLowerCase();
    if (tag === "input" || tag === "textarea") return;
    try {
      const files = ev.clipboardData?.files;
      if (files && files.length) {
        await handleDroppedOrPastedFiles(files);
        return;
      }
      const txt = ev.clipboardData?.getData("text/plain") || "";
      if (txt.includes("[Interface]") && txt.includes("[Peer]")) {
        await api().ImportConfText(txt, "");
        await refreshBootstrap();
        showToast(t().toastSaved);
        return;
      }
      if (!txt.trim()) {
        const p = await api().ImportQRFromClipboard();
        if (p) {
          await refreshBootstrap();
          showToast(t().toastSaved);
        }
      }
    } catch (err) {
      showError(String(err));
    }
  });
}

function subscribeRuntimeEvents() {
  const rt = wailsRuntime();
  if (!rt?.EventsOn) return;

  rt.EventsOn("telemetry", (snap) => {
    if (!state || !snap) return;
    state.connected = snap.connected;
    state.connecting = snap.connecting;
    state.activeProfileId = snap.activeProfileId;
    state.lastError = snap.lastError;
    state.stats = snap.stats;
    state.clients = snap.clients;
    state.guardEvents = snap.guardEvents;
    state.rxHistory = snap.rxHistory;
    state.txHistory = snap.txHistory;
    renderStatusAndTelemetry();
    renderClients();
    renderSettingsAndLogs();
  });

  rt.EventsOn("stateChanged", (nextState) => {
    if (!nextState) return;
    state = nextState;
    renderAll();
  });

  rt.EventsOn("failover", (info) => {
    if (info?.profileName) {
      showToast(`${info.profileName} (${info.rttMs} ms)`);
    }
  });
}

window.addEventListener("DOMContentLoaded", async () => {
  wireEvents();
  subscribeRuntimeEvents();
  await refreshBootstrap();
});
