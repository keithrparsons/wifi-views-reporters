// Parse `netsh wlan show interfaces / drivers / networks mode=bssid` from Windows and render a report.
// Runs in the browser (window.Netsh, after wdutil.js) and in Node (require) for the tests.
// Like the Mac report, nothing here makes a network request.
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory(require("./wdutil.js"));
  else root.Netsh = factory(root.Wdutil);
})(typeof self !== "undefined" ? self : this, function (Wdutil) {
  "use strict";

  const KEY_VALUE = /^\s+([^:]*?)\s*: ?(.*)$/;
  const COLOCATED = /^\s*MldID\s*:\s*(\d+),\s*LinkID:\s*(\d+),\s*BSSID:\s*([0-9a-fA-F:]+),\s*Band:\s*([^,]+?),\s*Channel:\s*(\d+)/;

  // ---------------------------------------------------------------- parsing

  function addField(fields, key, value) {
    if (key) { fields[key] = value; return; }
    const keys = Object.keys(fields).filter(k => k !== "colocated" && k !== "bssids");
    if (!keys.length) return;
    const last = keys[keys.length - 1];
    if (!Array.isArray(fields[last])) fields[last] = [fields[last]];
    fields[last].push(value);
  }

  function parse(text) {
    const parsed = { interfaces: [], drivers: [], networks: [], locationBlocked: /location permission/i.test(text) };
    let mode = null, target = null, network = null;
    for (const raw of text.split(/\r?\n/)) {
      const line = raw.replace(/\s+$/, "");
      if (!line.trim()) continue;
      if (/^There (?:is|are) \d+ interfaces? on the system/.test(line)) { mode = "interfaces"; target = null; continue; }
      if (/^There (?:is|are) \d+ networks? currently visible/.test(line)) {
        // The networks listing opens with the same "Interface name" line that opens a driver block.
        const last = parsed.drivers[parsed.drivers.length - 1];
        if (last && Object.keys(last).length === 1) parsed.drivers.pop();
        mode = "networks"; target = network = null;
        continue;
      }
      const header = /^Interface name\s*:\s*(.*)$/.exec(line);
      if (header) { mode = "drivers"; target = { interface: header[1].trim() }; parsed.drivers.push(target); continue; }

      if (mode === "networks") {
        const ssid = /^SSID \d+\s*: ?(.*)$/.exec(line);
        if (ssid) { network = target = { ssid: ssid[1].trim(), bssids: [] }; parsed.networks.push(network); continue; }
        const bssid = /^\s+BSSID \d+\s*: ?(.*)$/.exec(line);
        if (bssid && network) { target = { bssid: bssid[1].trim() }; network.bssids.push(target); continue; }
      }
      if (!target && mode !== "interfaces") continue;
      if (/^\S/.test(line)) continue;
      const colocated = COLOCATED.exec(line);
      if (colocated) {
        (target.colocated = target.colocated || []).push({
          mldId: Number(colocated[1]), linkId: Number(colocated[2]), bssid: colocated[3],
          band: colocated[4].trim(), channel: Number(colocated[5]),
        });
        continue;
      }
      if (/^\s*Colocated APs/.test(line)) continue;
      const match = KEY_VALUE.exec(line);
      if (mode === "interfaces" && match && match[1] === "Name") { target = {}; parsed.interfaces.push(target); }
      if (!target) continue;
      if (match) addField(target, match[1], match[2].trim());
      else addField(target, null, line.trim());
    }
    return parsed;
  }

  // ---------------------------------------------------------------- decoding

  // RSN suite selectors 00-0f-ac:n [802.11-2020 Table 9-149 (ciphers), Table 9-151 (AKMs); OWE is RFC 8110].
  const AKMS = {
    1: "802.1X", 2: "PSK", 3: "FT over 802.1X", 4: "FT with PSK", 5: "802.1X SHA-256", 6: "PSK SHA-256",
    8: "SAE", 9: "FT over SAE", 12: "802.1X Suite B 192-bit", 18: "OWE",
  };
  const CIPHERS = { 1: "WEP-40", 2: "TKIP", 4: "CCMP-128", 5: "WEP-104", 8: "GCMP-128", 9: "GCMP-256", 10: "CCMP-256" };
  const GENERATIONS = { "802.11be": "Wi-Fi 7", "802.11ax": "Wi-Fi 6", "802.11ac": "Wi-Fi 5", "802.11n": "Wi-Fi 4" };
  const RADIO_ORDER = ["802.11b", "802.11a", "802.11g", "802.11n", "802.11ac", "802.11ax", "802.11be"];

  function decodeSuites(text) {
    const selector = name => Number((new RegExp(`${name}\\s*=\\s*00-0f-ac:(\\d+)`, "i").exec(text || "") || [])[1]);
    const akm = selector("akm"), cipher = selector("cipher");
    return {
      akm: Number.isNaN(akm) ? null : AKMS[akm] || `AKM suite ${akm}`,
      cipher: Number.isNaN(cipher) ? null : CIPHERS[cipher] || `cipher suite ${cipher}`,
    };
  }

  function generation(radio, band) {
    const name = GENERATIONS[radio];
    return name === "Wi-Fi 6" && band === "6 GHz" ? "Wi-Fi 6E" : name || null;
  }

  // ---------------------------------------------------------------- analysis

  const number = text => parseFloat(String(text || "").match(/-?[\d.]+/)?.[0]);
  const orNull = value => (Number.isNaN(value) ? null : value);
  const finding = (level, title, text) => ({ level, title, text });
  const listInWords = items => (items.length < 2 ? items.join("") : `${items.slice(0, -1).join(", ")} and ${items[items.length - 1]}`);

  function analyzeInterface(fields) {
    const band = fields.Band || null, channel = orNull(number(fields.Channel));
    const otherRadios = [];
    for (const ap of fields.colocated || []) {
      const same = ap.band === band && ap.channel === channel;
      if (!same && !otherRadios.some(r => r.band === ap.band && r.channel === ap.channel)) {
        otherRadios.push({ band: ap.band, channel: ap.channel });
      }
    }
    return {
      fields, name: fields.Name || "?", connected: fields.State === "connected",
      rssi: orNull(number(fields.Rssi)), signalPercent: orNull(number(fields.Signal)),
      band, channel, radio: fields["Radio type"] || null,
      generation: generation(fields["Radio type"], band),
      suites: decodeSuites(fields["Connected Akm-cipher"]),
      otherRadios,
    };
  }

  function analyzeDriver(fields) {
    const radios = String(fields["Radio types supported"] || "").split(/\s+/).filter(Boolean);
    const best = radios.slice().sort((a, b) => RADIO_ORDER.indexOf(b) - RADIO_ORDER.indexOf(a))[0] || null;
    const bands = [].concat(fields["Number of supported bands"] || []).slice(1)
      .map(line => (/^([\d.]+ GHz)/.exec(line) || [])[1]).filter(Boolean);
    const ciphers = [].concat(fields["Authentication and cipher supported in infrastructure mode"] || []).join("\n");
    return {
      fields, name: fields.Driver || "?", version: fields.Version || "?", date: fields.Date || "?",
      radios, best, generation: GENERATIONS[best] || null, bands,
      wpa3: /WPA3-Personal/.test(ciphers), wpa3Enterprise: /WPA3-Enterprise/.test(ciphers), owe: /OWE/.test(ciphers),
    };
  }

  function analyzeScan(networks, connectedBssid) {
    const byBand = {};
    const rows = [];
    for (const network of networks) {
      for (const b of network.bssids) {
        if (b.Band) byBand[b.Band] = (byBand[b.Band] || 0) + 1;
        rows.push({
          ssid: network.ssid, authentication: network.Authentication || "", bssid: b.bssid,
          signal: b.Signal || "", radio: b["Radio type"] || "", band: b.Band || "", channel: b.Channel || "",
          stations: b["Connected Stations"] || "", utilization: orNull(number(String(b["Channel Utilization"] || "").split("(")[1])),
          mld: Boolean(b["MLD Address"]),
        });
      }
    }
    const connected = rows.find(r => connectedBssid && r.bssid.toLowerCase() === connectedBssid.toLowerCase()) || null;
    return { networkCount: networks.length, bssidCount: rows.length, byBand, rows, connected };
  }

  function linkFindings(wifi) {
    const found = [];
    if (wifi.rssi !== null) {
      found.push(finding(wifi.rssi >= -67 ? "good" : "watch", "Signal",
        `RSSI ${wifi.rssi} dBm. The common design target for voice and video is -67 dBm. ` +
        "Windows does not report the noise floor, so this report cannot give SNR."));
    } else if (wifi.signalPercent !== null) {
      found.push(finding("info", "Signal",
        `This Windows version reports signal only as a percentage (${wifi.signalPercent}%), not in dBm, ` +
        "so it can't be rated against the -67 dBm design target."));
    }
    if (wifi.otherRadios.length) {
      const others = listInWords(wifi.otherRadios.map(r => `${r.band} channel ${r.channel}`));
      found.push(finding("info", "Other radios on this AP",
        `The AP lists radios on ${others} alongside this link on ${wifi.band} channel ${wifi.channel}. ` +
        "netsh does not say whether Windows is using more than one of those links at once."));
    }
    return found;
  }

  function driverFindings(driver) {
    const bands = listInWords(driver.bands.map(b => b.replace(" GHz", ""))) + (driver.bands.length ? " GHz" : "");
    const best = driver.best ? `up to ${driver.best}${driver.generation ? ` (${driver.generation})` : ""}` : "an unknown radio type";
    const security = driver.wpa3 ? ", and WPA3-Personal" : ", but not WPA3-Personal";
    return [finding("info", "Adapter",
      `${driver.name} supports ${best} on ${bands || "unlisted bands"}${security}. Driver ${driver.version}, dated ${driver.date}.`)];
  }

  function scanFindings(scan) {
    const found = [];
    const bands = Object.keys(scan.byBand).sort((a, b) => parseFloat(a) - parseFloat(b))
      .map(b => `${b} ${scan.byBand[b]}`).join(", ");
    found.push(finding("info", "Networks heard",
      `${scan.bssidCount} BSSIDs (AP radios) across ${scan.networkCount} networks: ${bands}.`));
    const c = scan.connected;
    if (c && c.utilization !== null) {
      found.push(finding(c.utilization < 30 ? "good" : "watch", "AP channel load",
        `The AP reports its channel busy ${c.utilization}% of the time, with ${c.stations || "?"} stations connected (BSS Load). ` +
        "As a rule of thumb, under 30% leaves plenty of airtime."));
    }
    return found;
  }

  function analyze(parsed) {
    const interfaces = parsed.interfaces.map(analyzeInterface);
    const driver = parsed.drivers.length ? analyzeDriver(parsed.drivers[0]) : null;
    const connected = interfaces.filter(i => i.connected);
    const scan = parsed.networks.length
      ? analyzeScan(parsed.networks, connected.length ? connected[0].fields["AP BSSID"] : null) : null;
    const findings = [];
    if (interfaces.length && !connected.length) {
      findings.push(finding("watch", "Not connected", "No Wi-Fi interface is connected, so there is no link to rate."));
    }
    for (const wifi of connected) findings.push(...linkFindings(wifi));
    if (driver) findings.push(...driverFindings(driver));
    if (scan) findings.push(...scanFindings(scan));
    return {
      empty: !interfaces.length && !driver && !scan,
      locationBlocked: parsed.locationBlocked,
      interfaces, driver, scan, findings,
    };
  }

  // ---------------------------------------------------------------- redaction

  function makeMask(report, redact) {
    if (!redact) return { text: value => String(value), ssid: value => value };
    const labels = new Map();
    for (const wifi of report.interfaces) {
      for (const name of [wifi.fields.SSID, wifi.fields.Profile]) if (name) labels.set(name, "(network name hidden)");
    }
    for (const row of report.scan ? report.scan.rows : []) {
      if (row.ssid && !labels.has(row.ssid)) labels.set(row.ssid, `Network ${labels.size + 1}`);
    }
    // Longest first, so "Home-Guest" is replaced before "Home"; very short names would mangle ordinary words.
    const names = [...labels.keys()].filter(name => name.length >= 3).sort((a, b) => b.length - a.length);
    // A four-part driver version such as 23.150.0.4 looks like an IPv4 address to the mask.
    const version = report.driver && /^\d+(?:\.\d+){3}$/.test(report.driver.version) ? report.driver.version : null;
    return {
      text: value => {
        let out = String(value);
        for (const name of names) out = out.split(name).join(labels.get(name));
        if (!version) return Wdutil.maskAddresses(out);
        return out.split(version).map(Wdutil.maskAddresses).join(version);
      },
      ssid: value => labels.get(value) || value,
    };
  }

  // ---------------------------------------------------------------- rendering

  const FIELD_NOTES = {
    "State": "Whether this adapter is joined to a network.",
    "SSID": "The network name.",
    "AP BSSID": "The MAC address of the AP radio this PC is joined to.",
    "Band": "The frequency band of the link.",
    "Channel": "Primary channel. netsh does not report the channel width.",
    "Connected Akm-cipher": "The key management and encryption suites negotiated, as 802.11 suite numbers.",
    "Radio type": "Which 802.11 generation the link is using.",
    "Authentication": "Authentication method for this network.",
    "Receive rate (Mbps)": "The data rate of the last frames this PC received.",
    "Transmit rate (Mbps)": "The data rate of the last frames this PC sent.",
    "Signal": "Windows' own 0-100% signal scale.",
    "Rssi": "Received signal strength from the AP, in dBm.",
  };

  const COMMANDS = [
    ["interfaces", "netsh wlan show interfaces"],
    ["driver", "netsh wlan show drivers"],
    ["scan", "netsh wlan show networks mode=bssid"],
  ];

  function render(report, options) {
    const { redact = true, logo = "", generated = new Date() } = options || {};
    const mask = makeMask(report, redact);
    const escapeHtml = Wdutil.escapeHtml;
    const show = value => escapeHtml(mask.text(Array.isArray(value) ? value.join(", ") : value));

    const kvTable = (fields, notes, skip) => {
      const rows = Object.keys(fields).filter(k => !(skip || []).includes(k)).map(k =>
        `<tr><th scope="row">${escapeHtml(k)}</th><td class="v">${show(fields[k]) || "<span class=\"none\">empty</span>"}</td>` +
        (notes ? `<td class="note">${escapeHtml(notes[k] || "")}</td>` : "") + "</tr>").join("");
      return rows ? `<table class="kv${notes ? " with-notes" : ""}"><tbody>${rows}</tbody></table>` : "<p class=\"none\">Nothing reported.</p>";
    };

    const wifi = report.interfaces.find(i => i.connected) || null;
    const adapter = (report.interfaces[0] && report.interfaces[0].fields.Description) || (report.driver && report.driver.name) || "?";
    const sources = COMMANDS.filter(([key]) => (key === "interfaces" ? report.interfaces.length : report[key]))
      .map(([, command]) => `<code>${command}</code>`).join("<br>");
    const date = generated.toLocaleString("en-US", { year: "numeric", month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });

    const head = `
<header class="wr-head">
  <div class="wr-logo" aria-label="WLAN Pros">${logo}</div>
  <div class="wr-title"><p class="eyebrow">Wi-Fi client report</p><h1>Windows Wi-Fi Report</h1></div>
  <dl class="wr-meta">
    <div><dt>Adapter</dt><dd>${show(adapter)}</dd></div>
    <div><dt>Source</dt><dd>${sources}</dd></div>
    <div><dt>Generated</dt><dd>${escapeHtml(date)}</dd></div>
    <div><dt>Identifiers</dt><dd>${redact ? "Hidden" : "Shown"}</dd></div>
  </dl>
</header>`;

    const tile = (label, value, sub) =>
      `<div class="tile"><p class="label">${escapeHtml(label)}</p><p class="value">${show(value)}</p><p class="sub">${show(sub)}</p></div>`;
    let tiles = "";
    if (wifi) {
      const f = wifi.fields, s = wifi.suites;
      tiles = `<section class="tiles">${[
        tile("Signal", wifi.rssi !== null ? `${wifi.rssi} dBm` : f.Signal || "?", wifi.rssi !== null ? `${f.Signal || "?"} on Windows' scale` : "no dBm reading"),
        tile("Channel", wifi.band ? `${wifi.band.replace(" GHz", "")} GHz · ${wifi.channel}` : "?", "width not reported"),
        tile("Radio", wifi.generation || wifi.radio || "?", wifi.radio || ""),
        tile("Receive", `${f["Receive rate (Mbps)"] || "?"} Mbps`, "last received rate"),
        tile("Transmit", `${f["Transmit rate (Mbps)"] || "?"} Mbps`, "last sent rate"),
        tile("Security", f.Authentication || "?", [s.akm, s.cipher || f.Cipher].filter(Boolean).join(" · ")),
      ].join("")}</section>`;
    } else if (report.interfaces.length) {
      tiles = "<section class=\"notice\"><strong>Wi-Fi is not connected.</strong> netsh reported no link, so there is nothing to rate.</section>";
    }

    const findings = report.findings.map(x =>
      `<li class="finding ${x.level}"><span class="chip">${Wdutil.LEVEL_LABELS[x.level]}</span>` +
      `<div><h3>${escapeHtml(x.title)}</h3><p>${show(x.text)}</p></div></li>`).join("");

    const interfaces = report.interfaces.map(i => {
      const fields = Object.assign({}, i.fields);
      delete fields.colocated;
      if (fields.SSID) fields.SSID = mask.ssid(fields.SSID);
      if (fields.Profile) fields.Profile = mask.ssid(fields.Profile);
      const s = i.suites;
      if (fields["Connected Akm-cipher"] && (s.akm || s.cipher)) fields["Connected Akm-cipher"] += ` → ${[s.akm, s.cipher].filter(Boolean).join(", ")}`;
      const colocated = (i.fields.colocated || []).map(ap =>
        `<tr><td class="mono">${show(ap.bssid)}</td><td>${escapeHtml(ap.band)}</td><td>${ap.channel}</td><td>${ap.mldId}</td><td>${ap.linkId}</td></tr>`).join("");
      return `<section><h2>Wi-Fi link: ${show(i.name)}</h2>${kvTable(fields, FIELD_NOTES)}` +
        (colocated ? `<h3>Co-located APs</h3><table class="list"><thead><tr><th>BSSID</th><th>Band</th><th>Channel</th><th>MLD ID</th><th>Link ID</th></tr></thead><tbody>${colocated}</tbody></table>` +
          "<p class=\"fine\">The AP's other radios, as netsh lists them. It does not show which of them this PC is using.</p>" : "") +
        "</section>";
    }).join("");

    let driver = "";
    if (report.driver) {
      const fields = Object.assign({}, report.driver.fields);
      delete fields.interface;
      driver = `<section><h2>Adapter and driver</h2>${kvTable(fields)}</section>`;
    }

    let scan = "";
    if (report.scan) {
      const connectedBssid = report.scan.connected && report.scan.connected.bssid;
      const rows = report.scan.rows.slice().sort((a, b) => number(b.signal) - number(a.signal)).map(r =>
        `<tr><td>${r.ssid ? show(mask.ssid(r.ssid)) : "<span class=\"none\">hidden</span>"}` +
        `${r.bssid === connectedBssid ? " <span class=\"yes\">Connected</span>" : ""}</td>` +
        `<td class="mono">${show(r.bssid)}</td><td class="mono">${show(r.signal)}</td><td>${show(r.radio)}</td>` +
        `<td>${show(r.band)}</td><td class="mono">${show(r.channel)}</td>` +
        `<td class="mono">${r.utilization === null ? "" : `${r.utilization}%`}</td><td class="mono">${show(r.stations)}</td></tr>`).join("");
      scan = `<section><h2>Networks heard</h2><table class="list"><thead><tr><th>Network</th><th>BSSID</th><th>Signal</th>` +
        `<th>Radio</th><th>Band</th><th>Channel</th><th>Load</th><th>Stations</th></tr></thead><tbody>${rows}</tbody></table>` +
        "<p class=\"fine\">Load and Stations come from each AP's BSS Load element; an AP that does not send one leaves them blank.</p></section>";
    }

    return `<article class="wr">${head}${tiles}
<section><h2>What stands out</h2><ul class="findings">${findings || "<li class=\"none\">Nothing to report.</li>"}</ul></section>
${interfaces}${driver}${scan}
<footer class="wr-foot"><p>A snapshot of one moment, read from Windows' own netsh output. Windows reports no noise floor, channel width or MCS, so this report does not guess at them.</p>
<p>Windows Wi-Fi Report · Keith Parsons · CWNE #3 · library.wlanpros.com</p></footer>
</article>`;
  }

  return { parse, decodeSuites, analyze, render };
});
