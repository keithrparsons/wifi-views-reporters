// Parse `sudo wdutil info` output from macOS and render it as a readable report.
// Runs in the browser (window.Wdutil) and in Node (require) for the tests.
// Nothing here makes a network request: what people paste stays on their machine.
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.Wdutil = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const KEY_VALUE = /^\s+([^:]*?)\s*: ?(.*)$/;
  const MAC = /\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b/g;
  const IPV4 = /\b(\d{1,3})(?:\.\d{1,3}){3}\b/g;
  const IPV6 = /\b([0-9a-fA-F]{1,4})(?::[0-9a-fA-F]{0,4}){2,7}\b/g;
  const GUID = /\b[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\b/g;
  // Tailscale's MagicDNS addresses are the same for everyone, so they identify nobody.
  const PUBLIC_ADDRESSES = ["100.100.100.100", "fd7a:115c:a1e0::53"];

  // The upper half of Mac Roman, taken from Python's mac_roman codec.
  const MAC_ROMAN_HIGH = "ÄÅÇÉÑÖÜáàâäãåçéèêëíìîïñóòôöõúùûü†°¢£§•¶ß®©™´¨≠ÆØ∞±≤≥¥µ∂∑∏π∫ªºΩæø¿¡¬√ƒ≈∆«»… ÀÃÕŒœ–—“”‘’÷◊ÿŸ⁄€‹›ﬁﬂ‡·‚„‰ÂÊÁËÈÍÎÏÌÓÔÒÚÛÙıˆ˜¯˘˙˚¸˝˛ˇ";

  // HE data subcarriers per channel width; 802.11be uses the same counts and adds 320 MHz.
  const DATA_SUBCARRIERS = { 20: 234, 40: 468, 80: 980, 160: 1960, 320: 3920 };
  // Coded bits per subcarrier for MCS 0-13: modulation bits times coding rate.
  const BITS_PER_SUBCARRIER = [0.5, 1, 1.5, 2, 3, 4, 4.5, 5, 6, 20 / 3, 7.5, 25 / 3, 9, 10];

  const FIVE_GHZ_CENTERS = {
    40: [38, 46, 54, 62, 102, 110, 118, 126, 134, 142, 151, 159, 167, 175],
    80: [42, 58, 106, 122, 138, 155, 171],
    160: [50, 114, 163],
  };

  const FIELD_NOTES = {
    "RSSI": "Received signal strength from the AP, as this Mac hears it.",
    "Noise": "Background RF energy on the channel. Lower (more negative) is better.",
    "CCA": "Clear Channel Assessment: the share of time the radio found the channel busy.",
    "Tx Rate": "The data rate of the last frames this Mac sent.",
    "MCS Index": "Modulation and Coding Scheme: how densely each symbol is packed. Higher needs a cleaner signal.",
    "NSS": "Number of spatial streams in use.",
    "Guard Interval": "Gap between symbols, in nanoseconds. 800 ns is the shortest (fastest) for Wi-Fi 6 and 7.",
    "Channel": "Band, primary channel and channel width.",
    "PHY Mode": "Which 802.11 generation the link is using.",
    "Security": "Authentication and encryption method for this network.",
    "Scan Cache Count": "How many BSSIDs (AP radios) the Mac currently remembers from its scans.",
    "Country Code": "Regulatory domain the radio is operating under.",
    "BTC Mode": "Bluetooth coexistence: whether Wi-Fi and Bluetooth are sharing airtime on the radio.",
    "Sniffer Supported": "Whether this adapter can do monitor-mode packet capture.",
    "Op Mode": "STA means a normal client connected to an AP.",
    "SSID": "The network name.",
    "BSSID": "The MAC address of the AP radio this Mac is joined to.",
  };

  const LEVEL_LABELS = { good: "Healthy", watch: "Worth a look", info: "Context" };
  const GENERATIONS = { be: "Wi-Fi 7", ax: "Wi-Fi 6", ac: "Wi-Fi 5", n: "Wi-Fi 4" };
  const DISPLAY_KEYS = { "Supports 6e": "Supports Wi-Fi 6E" };
  const REDACTED_BY_MACOS = "wdutil prints <redacted> itself, even with sudo, so no setting on this page can show it.";
  const NONE_INCLUDES_OWE = "macOS also reports Enhanced Open (OWE) as None, so this alone does not prove the link is unencrypted.";

  // ---------------------------------------------------------------- parsing

  function fixMojibake(text) {
    // wdutil's UTF-8 device names arrive decoded as Mac Roman, so ’ shows up as ‚Äô.
    const bytes = [];
    for (const ch of text) {
      const code = ch.codePointAt(0);
      if (code < 0x80) { bytes.push(code); continue; }
      const index = MAC_ROMAN_HIGH.indexOf(ch);
      if (index < 0) return text;
      bytes.push(0x80 + index);
    }
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(new Uint8Array(bytes));
    } catch (error) {
      return text;
    }
  }

  function isSectionHeader(line) {
    const stripped = line.trim();
    return stripped !== "" && !/^\s/.test(line) && stripped === stripped.toUpperCase() && /[A-Z]/.test(stripped);
  }

  function addField(fields, key, value) {
    if (key) { fields[key] = value; return; }
    const keys = Object.keys(fields);
    if (!keys.length) return;
    const last = keys[keys.length - 1];
    if (!Array.isArray(fields[last])) fields[last] = [fields[last]];
    fields[last].push(value);
  }

  function parse(text) {
    const sections = {};
    let section = null, target = null, afterBlank = false;
    for (const raw of text.split(/\r?\n/)) {
      const line = raw.replace(/\s+$/, "");
      if (/^\s*[—–-]{3,}\s*$/.test(line)) continue;
      if (isSectionHeader(line)) {
        section = sections[line.trim()] = sections[line.trim()] || { fields: {}, lines: [], devices: [] };
        target = section.fields;
        afterBlank = false;
        continue;
      }
      if (!section) continue;
      if (!line) { afterBlank = true; continue; }
      const match = KEY_VALUE.exec(line);
      if (match) addField(target, match[1], fixMojibake(match[2].trim()));
      else if (afterBlank) { target = { name: fixMojibake(line.trim()) }; section.devices.push(target); }
      else section.lines.push(line.trim());
      afterBlank = false;
    }
    return sections;
  }

  // ---------------------------------------------------------------- decoding

  function decodeChannel(text) {
    const match = /(\d)g(\d+)\/(\d+)/.exec(text || "");
    if (!match) return null;
    const channel = Number(match[2]), width = Number(match[3]);
    let band, base, center = null;
    if (match[1] === "2") {
      band = "2.4 GHz"; base = 2407;
      if (width === 20) center = channel;
    } else if (match[1] === "5") {
      band = "5 GHz"; base = 5000;
      center = width === 20 ? channel
        : (FIVE_GHZ_CENTERS[width] || []).find(c => Math.abs(c - channel) < width / 10) || null;
    } else {
      band = "6 GHz"; base = 5950;
      const span = width / 5;
      // 320 MHz has two overlapping channel sets, so the center can't be known from the primary alone.
      if (width === 20) center = channel;
      else if (width !== 320) center = Math.floor((channel - 1) / span) * span + 1 + width / 10 - 2;
    }
    const centerMhz = center === null ? null : base + 5 * center;
    return {
      band, channel, width,
      primaryMhz: base + 5 * channel,
      centerChannel: center, centerMhz,
      lowMhz: centerMhz === null ? null : centerMhz - width / 2,
      highMhz: centerMhz === null ? null : centerMhz + width / 2,
      psc: band === "6 GHz" ? (channel - 5) % 16 === 0 : null,
    };
  }

  function heRate(mcs, nss, width, giNs) {
    return DATA_SUBCARRIERS[width] * BITS_PER_SUBCARRIER[mcs] * nss / (12.8 + giNs / 1000);
  }

  function closestMcs(rate, nss, width, giNs) {
    let best = 0;
    BITS_PER_SUBCARRIER.forEach((_, mcs) => {
      if (Math.abs(heRate(mcs, nss, width, giNs) - rate) < Math.abs(heRate(best, nss, width, giNs) - rate)) best = mcs;
    });
    return best;
  }

  function summarizeSupportedChannels(entries) {
    const summary = { "2.4 GHz": {}, "5 GHz": {}, "6 GHz": {} };
    const text = Array.isArray(entries) ? entries.join(",") : entries || "";
    for (const item of text.split(",")) {
      const channel = decodeChannel(item.trim());
      if (!channel) continue;
      const widths = summary[channel.band];
      widths[channel.width] = (widths[channel.width] || 0) + 1;
    }
    return summary;
  }

  // wdutil lists every 20 MHz primary a wide channel can use, so 6g/160 has 56 entries for 7 channels.
  function countChannels(entries) {
    const centers = { "2.4 GHz": {}, "5 GHz": {}, "6 GHz": {} };
    const text = Array.isArray(entries) ? entries.join(",") : entries || "";
    for (const item of text.split(",")) {
      const channel = decodeChannel(item.trim());
      if (!channel || channel.centerChannel === null) continue;
      const widths = centers[channel.band];
      (widths[channel.width] = widths[channel.width] || new Set()).add(channel.centerChannel);
    }
    const counts = {};
    for (const band of Object.keys(centers)) {
      counts[band] = {};
      for (const width of Object.keys(centers[band])) counts[band][width] = centers[band][width].size;
    }
    return counts;
  }

  function phyLabel(phy, channel) {
    if (phy.includes("0x200")) return "802.11be / Wi-Fi 7 (wdutil prints '?' for 0x200)";
    const mode = /11(be|ax|ac|n)\b/.exec(phy);
    if (!mode) return phy;
    const sixE = mode[1] === "ax" && channel && channel.band === "6 GHz";
    return `802.11${mode[1]} / ${sixE ? "Wi-Fi 6E" : GENERATIONS[mode[1]]}`;
  }

  function awdlSlots(sequence) {
    const slots = sequence.trim().split(/\s+/);
    const channels = {};
    for (const slot of slots) {
      if (slot === "0") continue;
      const name = slot.replace(/\+/g, "");
      channels[name] = (channels[name] || 0) + 1;
    }
    return { total: slots.length, idle: slots.filter(s => s === "0").length, channels, sequence: slots };
  }

  // ---------------------------------------------------------------- analysis

  const number = text => parseFloat(String(text || "").match(/-?[\d.]+/)?.[0]);
  const asList = value => (Array.isArray(value) ? value : value === undefined ? [] : [value]);
  const finding = (level, title, text) => ({ level, title, text });

  function analyzeWifi(fields) {
    const rssi = number(fields.RSSI), noise = number(fields.Noise);
    // With Wi-Fi off, wdutil still prints RSSI and Noise, as 0 dBm.
    if (Number.isNaN(rssi) || /^Off\b/.test(fields.Power || "") || fields["Op Mode"] === "None") return null;
    const wifi = { fields, rssi, noise, snrDb: Number.isNaN(noise) ? null : rssi - noise };
    wifi.cca = number(fields.CCA);
    wifi.channel = decodeChannel(fields.Channel);
    wifi.phyLabel = phyLabel(fields["PHY Mode"] || "", wifi.channel);
    wifi.supported = summarizeSupportedChannels(fields["Supported Channels"]);
    wifi.channels = countChannels(fields["Supported Channels"]);
    wifi.rateCheck = null;
    const mcs = number(fields["MCS Index"]), nss = number(fields.NSS), gi = number(fields["Guard Interval"]);
    const tx = number(fields["Tx Rate"]);
    const width = wifi.channel && wifi.channel.width;
    // Only 6 GHz guarantees an HE or EHT link, which is what the rate table describes.
    if (wifi.channel && wifi.channel.band === "6 GHz" && DATA_SUBCARRIERS[width]
        && ![mcs, nss, gi, tx].some(Number.isNaN) && BITS_PER_SUBCARRIER[mcs] !== undefined) {
      const matchingMcs = closestMcs(tx, nss, width, gi);
      wifi.rateCheck = {
        tx, nss, width, gi, reportedMcs: mcs, reportedRate: heRate(mcs, nss, width, gi),
        matchingMcs, matchingRate: heRate(matchingMcs, nss, width, gi),
      };
    }
    return wifi;
  }

  function analyzeDevice(device) {
    const rssi = device.RSSI, manufacturer = device.Manufacturer || "";
    return {
      name: device.name, address: device.Address || "",
      paired: device.Paired === "Yes", cloud: device.CloudPaired === "Yes",
      connected: device.Connected === "Yes", apple: device.Apple === "Yes",
      // wdutil prints 0 dBm and "Ericsson (0x0)" when it has no value; showing them would mislead.
      rssi: rssi === undefined || rssi === "0 dBm" ? null : rssi,
      manufacturer: manufacturer.includes("0x0,") || !manufacturer ? null : manufacturer,
    };
  }

  function signalFindings(wifi) {
    const found = [];
    if (wifi.snrDb !== null) {
      found.push(finding(wifi.snrDb >= 25 && wifi.rssi >= -67 ? "good" : "watch", "Signal",
        `RSSI ${wifi.rssi} dBm with noise at ${wifi.noise} dBm gives ${wifi.snrDb} dB SNR. ` +
        "The common design target for voice and video is -67 dBm and 25 dB SNR."));
    }
    if (!Number.isNaN(wifi.cca)) {
      found.push(finding(wifi.cca < 30 ? "good" : "watch", "Channel busy time",
        `CCA reports the channel busy ${wifi.cca}% of the time. As a rule of thumb, under 30% leaves plenty of airtime.`));
    }
    const c = wifi.channel;
    if (c) {
      const span = c.centerChannel === null ? "" : ` (${c.lowMhz}-${c.highMhz} MHz, centered on channel ${c.centerChannel})`;
      const psc = c.psc ? " It is a Preferred Scanning Channel, so 6 GHz-only clients find it quickly." : "";
      found.push(finding("info", "Channel", `${c.band} channel ${c.channel} at ${c.width} MHz${span}.${psc}`));
    }
    const r = wifi.rateCheck;
    if (r && r.matchingMcs !== r.reportedMcs) {
      found.push(finding("info", "Tx Rate and MCS disagree",
        `A Tx Rate of ${r.tx} Mbps matches MCS ${r.matchingMcs} at ${r.nss} streams, ${r.width} MHz, ` +
        `${r.gi} ns guard interval (${r.matchingRate.toFixed(1)} Mbps). The reported MCS ${r.reportedMcs} would be ` +
        `${r.reportedRate.toFixed(1)} Mbps. The two fields are probably sampled at different moments; ` +
        "read MCS Index as a snapshot, not an average."));
    }
    return found;
  }

  function securityFindings(wifi) {
    if (!wifi || wifi.fields.Security !== "None") return [];
    // Seen 25 OCT 2026 on a Mac joined to an OWE-only network, and CoreWLAN, wdutil and system_profiler all said None.
    return [finding("info", "Security shows None",
      "macOS prints None both for an open network and for Enhanced Open (OWE), which encrypts each device's traffic " +
      "without a password. wdutil cannot tell the two apart. To know which this is, check the network's settings, " +
      "or use a Wi-Fi scanner that reads the network's beacon and look for the OWE key management.")];
  }

  function networkFindings(network, wifiFields) {
    const found = [];
    if (asList(network["DNS Addresses"]).includes("100.100.100.100")) {
      found.push(finding("info", "DNS goes through Tailscale",
        "System DNS is 100.100.100.100, which is Tailscale's MagicDNS, not the Wi-Fi network's DNS server" +
        (wifiFields.DNS && wifiFields.DNS !== "None" ? ` (${wifiFields.DNS})` : "") +
        ". A name-resolution problem here is a Tailscale question before it is a Wi-Fi one."));
    }
    if (network["Primary IPv6"] === "None" && wifiFields["IPv6 Router"] === "None") {
      const address = String(wifiFields["IPv6 Address"] || "").toLowerCase();
      const ula = /^f[cd]/.test(address)
        ? " The only address is a unique local address (fd00::/8), which does not reach the Internet." : "";
      found.push(finding("info", "No routed IPv6",
        `No IPv6 router is advertising on this network, so traffic uses IPv4 only.${ula}`));
    }
    return found;
  }

  function eventFindings(events) {
    const names = Object.keys(events);
    if (!names.length) return [];
    const noisy = names.filter(name => events[name].length && events[name].join() !== "None");
    if (!noisy.length) {
      return [finding("good", "No faults in the last hour",
        "macOS logged no Wi-Fi faults, recoveries or link tests in the hour before this snapshot.")];
    }
    return noisy.map(name => finding("watch", titleCase(name), events[name].join("; ")));
  }

  function awdlFindings(awdl) {
    if (awdl.fields["AWDL Enabled"] !== "Yes" || !awdl.slots) return [];
    const s = awdl.slots;
    const channels = Object.keys(s.channels).map(c => `channel ${c}`).join(", ");
    return [finding("watch", "AWDL is active",
      `AWDL (the link behind AirDrop, AirPlay and Continuity) is scheduled in ${s.total - s.idle} of ${s.total} slots on ` +
      `${channels}. AirDrop discovery is set to '${awdl.fields["AirDrop Disc Mode"] || "?"}'. On a radio that time-shares, ` +
      "those slots are taken from the main Wi-Fi link and show up as periodic latency spikes. " +
      "wdutil does not say whether this Mac's radio runs AWDL concurrently.")];
  }

  function bluetoothFindings(bluetooth, wifi) {
    if (!bluetooth.devices.length) return [];
    const connected = bluetooth.devices.filter(d => d.connected).map(d => d.name);
    let text = `${connected.length} connected: ${connected.join(", ") || "none"}.`;
    if (wifi && wifi.channel && wifi.channel.band !== "2.4 GHz") {
      text += ` Wi-Fi is on ${wifi.channel.band}, so Bluetooth's 2.4 GHz traffic cannot collide with it over the air.`;
    }
    return [finding("info", "Bluetooth", text)];
  }

  function analyze(parsed) {
    const section = name => parsed[name] || { fields: {}, lines: [], devices: [] };
    const wifiFields = section("WIFI").fields;
    const wifi = analyzeWifi(wifiFields);
    const bluetooth = { fields: section("BLUETOOTH").fields, devices: section("BLUETOOTH").devices.map(analyzeDevice) };
    const awdlFields = section("AWDL").fields;
    const awdl = { fields: awdlFields, slots: awdlFields["Channel Sequence"] ? awdlSlots(awdlFields["Channel Sequence"]) : null };
    const network = section("NETWORK").fields;
    const events = {};
    for (const name of Object.keys(parsed)) if (name.endsWith("LAST HOUR")) events[name] = parsed[name].lines;
    const findings = [
      ...(wifi ? signalFindings(wifi) : []), ...securityFindings(wifi), ...networkFindings(network, wifiFields), ...eventFindings(events),
      ...awdlFindings(awdl), ...bluetoothFindings(bluetooth, wifi),
    ];
    return {
      empty: !parsed.WIFI && !parsed.NETWORK,
      wifiFields, wifi, network, bluetooth, awdl, events, findings,
      power: section("POWER").fields,
    };
  }

  // ---------------------------------------------------------------- redaction

  function maskAddresses(text) {
    return String(text)
      .replace(MAC, "xx:xx:xx:xx:xx:xx")
      .replace(GUID, "(hidden)")
      .replace(IPV4, (match, first) => (PUBLIC_ADDRESSES.includes(match) ? match : `${first}.x.x.x`))
      .replace(IPV6, (match, first) => (PUBLIC_ADDRESSES.includes(match.toLowerCase()) ? match : `${first}:…(hidden)`));
  }

  function makeMask(report, redact) {
    if (!redact) return text => text;
    const names = report.bluetooth.devices
      .map((device, index) => [device.name, `Device ${index + 1}`])
      .filter(([name]) => name.length >= 3)
      .sort((a, b) => b[0].length - a[0].length);
    const ssid = report.wifiFields.SSID;
    return text => {
      let out = String(text);
      if (ssid && ssid.length >= 3 && ssid !== "<redacted>") out = out.split(ssid).join("(network name hidden)");
      for (const [name, label] of names) out = out.split(name).join(label);
      return maskAddresses(out);
    };
  }

  // ---------------------------------------------------------------- rendering

  const escapeHtml = value => String(value)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

  function titleCase(text) {
    return text.toLowerCase().replace(/\b(wifi|awdl)\b/g, m => (m === "wifi" ? "Wi-Fi" : "AWDL"))
      .replace(/(^|\s)([a-z])/g, (_, space, letter) => space + letter.toUpperCase());
  }

  function render(report, options) {
    const { redact = true, logo = "", generated = new Date() } = options || {};
    const mask = makeMask(report, redact);
    const show = value => escapeHtml(mask(Array.isArray(value) ? value.join(", ") : value));

    const kvTable = (fields, notes, skip) => {
      const rows = Object.keys(fields).filter(k => !(skip || []).includes(k)).map(k =>
        `<tr><th scope="row">${escapeHtml(k)}</th><td class="v">${show(fields[k]) || "<span class=\"none\">empty</span>"}</td>` +
        (notes ? `<td class="note">${escapeHtml(notes[k] || "")}</td>` : "") + "</tr>").join("");
      return rows ? `<table class="kv${notes ? " with-notes" : ""}"><tbody>${rows}</tbody></table>` : "<p class=\"none\">Nothing reported.</p>";
    };

    const wifi = report.wifi, f = report.wifiFields;
    const date = generated.toLocaleString("en-US", { year: "numeric", month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });

    const head = `
<header class="wr-head">
  <div class="wr-logo" aria-label="WLAN Pros">${logo}</div>
  <div class="wr-title"><p class="eyebrow">Wi-Fi client report</p><h1>Mac Wi-Fi Report</h1></div>
  <dl class="wr-meta">
    <div><dt>Interface</dt><dd>${escapeHtml(f["Interface Name"] || "?")}</dd></div>
    <div><dt>Source</dt><dd><code>sudo wdutil info</code></dd></div>
    <div><dt>Generated</dt><dd>${escapeHtml(date)}</dd></div>
    <div><dt>Identifiers</dt><dd>${redact ? "Hidden" : "Shown"}</dd></div>
  </dl>
</header>`;

    const tile = (label, value, sub) =>
      `<div class="tile"><p class="label">${escapeHtml(label)}</p><p class="value">${show(value)}</p><p class="sub">${show(sub)}</p></div>`;
    let tiles;
    if (wifi) {
      const c = wifi.channel;
      const phy = wifi.phyLabel.split(" (")[0];
      tiles = `<section class="tiles">${[
        tile("Signal", `${wifi.rssi} dBm`, Number.isNaN(wifi.noise) ? "" : `noise ${wifi.noise} dBm`),
        tile("SNR", wifi.snrDb === null ? "?" : `${wifi.snrDb} dB`, "signal above noise"),
        tile("Channel", c ? `${c.band.replace(" GHz", "")} GHz · ${c.channel}` : f.Channel || "?", c ? `${c.width} MHz wide` : ""),
        tile("Tx Rate", f["Tx Rate"] || "?", `MCS ${f["MCS Index"] || "?"} · ${f.NSS || "?"} streams`),
        tile("Busy", Number.isNaN(wifi.cca) ? "?" : `${wifi.cca}%`, "channel utilization (CCA)"),
        tile("Security", f.Security || "?", phy),
      ].join("")}</section>`;
    } else {
      tiles = `<section class="notice"><strong>Wi-Fi is off or not connected.</strong> wdutil reported no signal readings, so there is no link to rate. Power: ${show(f.Power || "unknown")}.</section>`;
    }

    const findings = report.findings.map(x =>
      `<li class="finding ${x.level}"><span class="chip">${LEVEL_LABELS[x.level]}</span>` +
      `<div><h3>${escapeHtml(x.title)}</h3><p>${show(x.text)}</p></div></li>`).join("");

    let wifiSection = "";
    if (Object.keys(f).length) {
      const fields = {};
      for (const key of Object.keys(f)) fields[DISPLAY_KEYS[key] || key] = f[key];
      if (wifi && fields["PHY Mode"]) fields["PHY Mode"] = `${fields["PHY Mode"]} → ${wifi.phyLabel}`;
      const c = wifi && wifi.channel;
      if (c) fields.Channel = `${f.Channel} → ${c.band}, channel ${c.channel}, ${c.width} MHz`;
      const notes = Object.assign({}, FIELD_NOTES);
      for (const key of ["SSID", "BSSID"]) if (f[key] === "<redacted>") notes[key] = REDACTED_BY_MACOS;
      if (wifi && f.Security === "None") notes.Security = NONE_INCLUDES_OWE;
      wifiSection = `<section><h2>Wi-Fi link</h2>${kvTable(fields, notes, ["Supported Channels"])}</section>`;
    }

    let capability = "";
    if (wifi && Object.values(wifi.supported).some(w => Object.keys(w).length)) {
      const rows = Object.keys(wifi.supported).map(band => {
        const widths = wifi.supported[band];
        const chips = Object.keys(widths).map(w => {
          const channels = wifi.channels[band][w];
          if (channels === undefined) return `<span class="cap"><b>${widths[w]}</b> primary channels × ${w} MHz</span>`;
          const primaries = channels === widths[w] ? "" : ` · ${widths[w]} primary channels`;
          return `<span class="cap"><b>${channels}</b> × ${w} MHz${primaries}</span>`;
        }).join("") || "<span class=\"none\">none</span>";
        return `<tr><th scope="row">${band}</th><td>${chips}</td></tr>`;
      }).join("");
      capability = `<section><h2>Adapter capability</h2><p class="lede">Channels this Mac's radio supports in country ${escapeHtml(f["Country Code"] || "?")}. Each wide channel counts once; wdutil lists every 20 MHz primary channel it can use, shown after the dot.</p><table class="kv caps"><tbody>${rows}</tbody></table></section>`;
    }

    let bluetooth = "";
    if (report.bluetooth.devices.length || Object.keys(report.bluetooth.fields).length) {
      const devices = report.bluetooth.devices.slice().sort((a, b) => (b.connected - a.connected) || (b.paired - a.paired));
      const rows = devices.map(d => `<tr><td>${show(d.name)}</td><td class="mono">${show(d.address)}</td>` +
        `<td>${d.connected ? "<span class=\"yes\">Connected</span>" : ""}</td><td>${d.paired ? "Paired" : d.cloud ? "iCloud" : "Seen"}</td>` +
        `<td class="mono">${show(d.rssi || "")}</td></tr>`).join("");
      bluetooth = `<section><h2>Bluetooth</h2>${kvTable(report.bluetooth.fields)}` +
        (rows ? `<table class="list"><thead><tr><th>Device</th><th>Address</th><th>Status</th><th>Pairing</th><th>RSSI</th></tr></thead><tbody>${rows}</tbody></table>` +
        "<p class=\"fine\">wdutil reports RSSI 0 dBm and manufacturer \"Ericsson (0x0)\" when it has no reading; those are left blank here.</p>" : "") +
        "</section>";
    }

    let awdl = "";
    if (Object.keys(report.awdl.fields).length) {
      const s = report.awdl.slots;
      const strip = s ? `<div class="slots" role="img" aria-label="${s.total - s.idle} of ${s.total} AWDL slots in use">${s.sequence.map(slot =>
        slot === "0" ? "<span class=\"slot idle\">·</span>" : `<span class="slot">${escapeHtml(slot.replace(/\+/g, ""))}</span>`).join("")}</div>` +
        `<p class="fine">${s.total - s.idle} of ${s.total} schedule slots in use. A number is the channel AWDL is scheduled on in that slot; a dot is a slot wdutil shows as 0, with no AWDL channel.</p>` : "";
      awdl = `<section><h2>AWDL (AirDrop, AirPlay and Continuity link)</h2>` +
        "<p class=\"lede\">AWDL, Apple Wireless Direct Link, is the Mac's direct Wi-Fi link to nearby Apple devices, with no AP in between. " +
        `AirDrop, AirPlay and Continuity features use it. The strip shows its schedule: the channel AWDL is on in each time slot.</p>${strip}${kvTable(report.awdl.fields)}</section>`;
    }

    const events = Object.keys(report.events).map(name =>
      `<tr><th scope="row">${escapeHtml(titleCase(name))}</th><td class="v">${show(report.events[name].join("; ") || "None")}</td></tr>`).join("");
    const sideBySide = `<div class="pair">
  <section><h2>Network</h2>${kvTable(report.network)}</section>
  <section><h2>Power and events</h2>${kvTable(report.power)}${events ? `<table class="kv"><tbody>${events}</tbody></table>` : ""}</section>
</div>`;

    return `<article class="wr">${head}${tiles}
<section><h2>What stands out</h2><ul class="findings">${findings || "<li class=\"none\">Nothing to report.</li>"}</ul></section>
${wifiSection}${capability}${sideBySide}${bluetooth}${awdl}
<footer class="wr-foot"><p>A snapshot of one moment, read from macOS's own diagnostics. Where this report says "probably", it is interpreting, not measuring.</p>
<p>Mac Wi-Fi Report · Keith Parsons · CWNE #3 · library.wlanpros.com</p></footer>
</article>`;
  }

  return {
    parse, fixMojibake, decodeChannel, heRate, closestMcs, summarizeSupportedChannels, countChannels, awdlSlots, analyze, render,
    escapeHtml, maskAddresses, LEVEL_LABELS,
  };
});
