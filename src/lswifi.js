// Parse lswifi scan output (its --json export or its text table) and render a nearby Wi-Fi report.
// Runs in the browser (window.Lswifi) and in Node (require) for the tests.
// Nothing here makes a network request: what people paste stays on their machine.
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.Lswifi = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const BANDS = ["2.4 GHz", "5 GHz", "6 GHz"];
  // lswifi draws its table borders from random runs of these characters, two spaces apart.
  const BORDER = /^[-=~+]+(?: {2,}[-=~+]+)+\s*$/;
  const COLUMNS = {
    "SSID": "ssid", "BSSID": "bssid", "RSSI": "rssi", "PHY": "phy", "CHANNEL": "channel", "FREQ.": "freq",
    "SS": "streams", "AMENDMENTS": "amendments", "AUTH": "akm", "ENCRYPTION": "cipher", "PMF": "pmf",
    "AP UPTIME": "uptime",
  };
  const GENERATIONS = ["Wi-Fi 7", "Wi-Fi 6E", "Wi-Fi 6", "Wi-Fi 5", "Wi-Fi 4"];
  const LEVEL_LABELS = { good: "Healthy", watch: "Worth a look", info: "Context" };

  // ---------------------------------------------------------------- parsing

  function bandOf(freqGHz) {
    if (freqGHz < 3) return "2.4 GHz";
    if (freqGHz < 5.925) return "5 GHz";
    return "6 GHz";
  }

  function generation(phy, band) {
    if (phy === "be") return "Wi-Fi 7";
    if (phy === "ax") return band === "6 GHz" ? "Wi-Fi 6E" : "Wi-Fi 6";
    if (phy === "ac") return "Wi-Fi 5";
    if (phy === "n") return "Wi-Fi 4";
    return phy ? `802.11${phy}` : "";
  }

  function number(value) {
    const n = parseFloat(value);
    return Number.isFinite(n) ? n : null;
  }

  function record(fields) {
    const freq = number(fields.freq) || 0;
    const band = freq ? bandOf(freq) : "";
    return {
      ssid: fields.ssid || "",
      bssid: (fields.bssid || "").toLowerCase(),
      rssi: number(fields.rssi),
      phy: fields.phy || "",
      channel: number(fields.channel),
      width: number(fields.width),
      freq,
      band,
      generation: generation(fields.phy || "", band),
      streams: number(fields.streams),
      amendments: fields.amendments || [],
      akm: fields.akm || "",
      cipher: fields.cipher || "",
      pmf: fields.pmf || "",
      uptime: fields.uptime || "",
      utilization: number(fields.utilization),
      stations: number(fields.stations),
    };
  }

  function fromJson(bss) {
    const security = String(bss.security || "");
    const slash = security.indexOf("/");
    return record({
      ssid: bss.ssid, bssid: bss.bssid, rssi: bss.rssi, phy: bss.phy_type, channel: bss.channel_number,
      width: bss.channel_width, freq: bss.channel_frequency, streams: bss.spatial_streams,
      amendments: bss.amendments, pmf: bss.pmf, uptime: bss.uptime, utilization: bss.utilization,
      stations: bss.stations,
      akm: slash < 0 ? security : security.slice(0, slash),
      cipher: slash < 0 ? "" : security.slice(slash + 1),
    });
  }

  function parseJson(text) {
    let data;
    try { data = JSON.parse(text); } catch (error) { return null; }
    const rows = (Array.isArray(data) ? data : (data && data.scan_data) || []).flat(Infinity)
      .filter(row => row && typeof row === "object" && "rssi" in row);
    return {
      records: rows.map(fromJson),
      version: (data && data.lswifi && data.lswifi.version) || "",
      timestamp: rows.length ? rows[0].timestamp || "" : "",
    };
  }

  function columnStarts(border) {
    return [...border.matchAll(/[-=~+]+/g)].map(m => m.index);
  }

  function cells(line, starts) {
    // Slice by code point so an emoji in an SSID doesn't shift the columns after it.
    const chars = Array.from(line);
    return starts.map((start, i) => chars.slice(start, starts[i + 1]).join("").trim());
  }

  function parseTable(text) {
    const lines = text.split(/\r?\n/);
    const records = [];
    for (let i = 0; i + 3 < lines.length; i++) {
      if (!BORDER.test(lines[i]) || !BORDER.test(lines[i + 3])) continue;
      const starts = columnStarts(lines[i]);
      const keys = cells(lines[i + 1], starts).map(name => COLUMNS[name]);
      for (i += 4; i < lines.length && !BORDER.test(lines[i]); i++) {
        const fields = {};
        cells(lines[i], starts).forEach((value, c) => { if (keys[c]) fields[keys[c]] = value === "--" ? "" : value; });
        if (!/^-?\d+$/.test(fields.rssi || "")) continue;
        const [channel, width] = (fields.channel || "").split("@");
        records.push(record({
          ...fields, channel, width,
          amendments: fields.amendments ? fields.amendments.split("/") : [],
        }));
      }
      i--;
    }
    return { records, version: "", timestamp: "" };
  }

  function parse(text) {
    const trimmed = (text || "").trim();
    if (/^[[{]/.test(trimmed)) return parseJson(trimmed) || { records: [], version: "", timestamp: "" };
    return parseTable(trimmed);
  }

  // ---------------------------------------------------------------- analysis

  function plural(n, word) {
    return `${n} ${word}${n === 1 ? "" : "s"}`;
  }

  function groupBy(items, key) {
    const groups = new Map();
    for (const item of items) {
      const k = key(item);
      if (!groups.has(k)) groups.set(k, []);
      groups.get(k).push(item);
    }
    return groups;
  }

  function channelUse(records) {
    const out = {};
    for (const band of BANDS) {
      const inBand = records.filter(r => r.band === band && r.channel !== null);
      if (!inBand.length) continue;
      out[band] = [...groupBy(inBand, r => r.channel)].map(([channel, rs]) => ({
        channel, count: rs.length, strongest: Math.max(...rs.map(r => r.rssi)), width: Math.max(...rs.map(r => r.width || 0)),
      })).sort((a, b) => a.channel - b.channel);
    }
    return out;
  }

  function bestGeneration(rs) {
    const gens = rs.map(r => r.generation);
    return GENERATIONS.find(g => gens.includes(g)) || gens.find(Boolean) || "";
  }

  function networks(records) {
    return [...groupBy(records, r => r.ssid)].map(([ssid, rs]) => ({
      ssid,
      bssids: rs.length,
      bands: BANDS.filter(b => rs.some(r => r.band === b)),
      best: Math.max(...rs.map(r => r.rssi)),
      generation: bestGeneration(rs),
      security: [...new Set(rs.map(r => r.akm).filter(Boolean))].join("; "),
      pmf: [...new Set(rs.map(r => r.pmf).filter(Boolean))].join("; "),
      roaming: Object.fromEntries(["k", "v", "r"].map(a => [a, rs.some(r => r.amendments.includes(a))])),
    }));
  }

  function channelList(rs) {
    return [...new Set(rs.map(r => r.channel))].sort((a, b) => a - b).map(c => `channel ${c}`).join(", ");
  }

  function findings(records, redacted) {
    const out = [];
    const add = (id, level, title, text) => out.push({ id, level, title, text });
    const two = records.filter(r => r.band === "2.4 GHz");

    if (redacted) {
      add("location", "watch", "macOS hid the network details",
        "Without a Location Services grant, macOS gives lswifi only signal and channel: no network names, BSSIDs, security or capabilities. The fix is in the box above; signal and channel use in this report are still real.");
    }
    const offGrid = two.filter(r => ![1, 6, 11].includes(r.channel));
    if (offGrid.length) {
      add("off-grid", "watch", "2.4 GHz networks between 1, 6 and 11",
        `${plural(offGrid.length, "BSSID")} on ${channelList(offGrid)}. A 2.4 GHz channel between 1, 6 and 11 overlaps the channels on both sides of it, so it collides with more networks than it would on 1, 6 or 11 (in countries that use the 1, 6, 11 plan).`);
    }
    const wide = two.filter(r => r.width >= 40);
    if (wide.length) {
      add("wide-24", "watch", "40 MHz channels in 2.4 GHz",
        `${plural(wide.length, "BSSID")} at 40 MHz in 2.4 GHz (${channelList(wide)}). 2.4 GHz has room for only three non-overlapping 20 MHz channels, so a 40 MHz channel there takes most of the band.`);
    }
    if (!redacted) {
      const open = records.filter(r => /^(NONE\??|OPEN)$/i.test(r.akm));
      if (open.length) {
        add("open", "watch", "Open networks",
          `${plural(open.length, "BSSID")} with no encryption: anyone in range can read unencrypted traffic.` +
          (open.some(r => r.akm === "NONE?") ? " On a Mac, NONE? means open or WEP: macOS doesn't say which." : ""));
      }
      const wep = records.filter(r => r.akm === "WEP" || /WEP/.test(r.cipher));
      if (wep.length) {
        add("wep", "watch", "WEP networks", `${plural(wep.length, "BSSID")} on WEP, which has been breakable in minutes since the mid-2000s.`);
      }
      const tkip = records.filter(r => /TKIP/.test(r.cipher));
      if (tkip.length) {
        add("tkip", "watch", "TKIP still offered",
          `TKIP is offered on ${plural(tkip.length, "BSSID")}. The Wi-Fi Alliance deprecated it, and clients that use it are held to 802.11a/g rates (54 Mbps).`);
      }
    }
    const busy = records.filter(r => r.utilization !== null && r.utilization >= 50);
    if (busy.length) {
      add("busy", "watch", "Busy channels",
        busy.map((r, i) => `${i ? "channel" : "Channel"} ${r.channel}: ${r.utilization}%`).join(", ") +
        ". Channel utilization from the BSS Load element, as each AP reports it. Above about half is a rule of thumb for crowded, not a hard limit.");
    }
    const six = records.filter(r => r.band === "6 GHz");
    if (six.length) {
      add("six", "info", "6 GHz in range", `${plural(six.length, "BSSID")} on 6 GHz. Only Wi-Fi 6E and Wi-Fi 7 clients can use them.`);
    }
    return out;
  }

  function analyze(parsed) {
    const records = [...parsed.records].sort((a, b) => b.rssi - a.rssi);
    const redacted = records.length > 0 && records.every(r => !r.bssid);
    const bands = {};
    for (const band of BANDS) {
      const n = records.filter(r => r.band === band).length;
      if (n) bands[band] = n;
    }
    return {
      empty: records.length === 0,
      redacted,
      version: parsed.version,
      timestamp: parsed.timestamp,
      records,
      counts: {
        bssids: records.length,
        networks: redacted ? 0 : new Set(records.map(r => r.ssid).filter(Boolean)).size,
        hidden: redacted ? 0 : records.filter(r => !r.ssid).length,
        bands,
        strongest: records[0] || null,
      },
      channels: channelUse(records),
      networks: redacted ? [] : networks(records),
      findings: findings(records, redacted),
    };
  }

  // ---------------------------------------------------------------- rendering

  function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
  }

  function signalClass(rssi) {
    if (rssi >= -67) return "good";
    if (rssi >= -75) return "fair";
    return "weak";
  }

  function namer(records, redact) {
    const aliases = new Map();
    for (const r of records) if (r.ssid && !aliases.has(r.ssid)) aliases.set(r.ssid, `Network ${aliases.size + 1}`);
    return ssid => {
      if (!ssid) return "<span class=\"none\">hidden</span>";
      return escapeHtml(redact ? aliases.get(ssid) : ssid);
    };
  }

  function maskBssid(bssid, redact) {
    if (!redact || !bssid) return escapeHtml(bssid);
    // The first three octets are the vendor's OUI: useful, and the same on every AP that vendor makes.
    return escapeHtml(bssid.split(":").slice(0, 3).join(":") + ":••:••:••");
  }

  function localTime(timestamp) {
    const date = new Date(timestamp);
    return Number.isNaN(date.getTime()) ? timestamp : date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  }

  function render(report, options) {
    const { redact, logo } = options;
    const name = namer(report.records, redact);
    const { counts } = report;

    const meta = [
      ["Scanned", report.timestamp ? escapeHtml(localTime(report.timestamp)) : "Time not in the paste"],
      ["Source", report.version ? `<code>${escapeHtml(report.version)}</code>` : "<code>lswifi</code> text output"],
      ["Heard", plural(counts.bssids, "BSSID")],
    ].map(([k, v]) => `<div><dt>${k}</dt><dd>${v}</dd></div>`).join("");
    const head = `
<header class="wr-head">
  <div class="wr-logo" aria-label="WLAN Pros">${logo}</div>
  <div class="wr-title"><p class="eyebrow">Wi-Fi scan report</p><h1>Nearby Wi-Fi</h1></div>
  <dl class="wr-meta">${meta}</dl>
</header>`;

    const tile = (label, value, sub) =>
      `<div class="tile"><p class="label">${label}</p><p class="value">${value}</p><p class="sub">${sub}</p></div>`;
    const strongest = counts.strongest;
    const tiles = `<section class="tiles">${[
      tile("BSSIDs", counts.bssids, "AP radios heard"),
      report.redacted ? tile("Networks", "?", "hidden by macOS") :
        tile("Networks", counts.networks, counts.hidden ? `plus ${plural(counts.hidden, "hidden BSSID")}` : "by name"),
      ...BANDS.filter(b => counts.bands[b]).map(b => tile(b, counts.bands[b], "BSSIDs")),
      tile("Strongest", `${strongest.rssi} dBm`, report.redacted ? `channel ${strongest.channel}` : name(strongest.ssid)),
    ].join("")}</section>`;

    const notice = report.redacted ? `<section class="notice"><strong>macOS hid network names, BSSIDs and security.</strong>
lswifi needs Location Services to see them; <code>sudo</code> does not help. Run it from the Terminal app (not a terminal inside another app), then open System Settings, Privacy &amp; Security, Location Services, and turn on Python (or Terminal, whichever is listed). Run the scan again.</section>` : "";

    const findingsHtml = report.findings.map(f =>
      `<li class="finding ${f.level}"><span class="chip">${LEVEL_LABELS[f.level]}</span>` +
      `<div><h3>${escapeHtml(f.title)}</h3><p>${escapeHtml(f.text)}</p></div></li>`).join("");

    const max = Math.max(1, ...Object.values(report.channels).flat().map(c => c.count));
    const channelHtml = Object.entries(report.channels).map(([band, list]) => `<h3 class="band">${band}</h3>
<div class="bars">${list.map(c => `<div class="bar-row"><span class="ch mono">${c.channel}</span>` +
      `<span class="track"><span class="bar" style="width:${(c.count / max) * 100}%"></span></span>` +
      `<span class="bar-note">${plural(c.count, "BSSID")} · strongest <span class="rssi ${signalClass(c.strongest)}">${c.strongest} dBm</span>` +
      `${c.width ? ` · up to ${c.width} MHz` : ""}</span></div>`).join("")}</div>`).join("");

    const yes = flag => flag ? "<span class=\"yes\">yes</span>" : "";
    const networksHtml = report.networks.length ? `<section><h2>Networks</h2>
<p class="lede">One row per network name. 11k, 11v and 11r are the roaming helpers an AP advertises; a row says yes when any of its BSSIDs does.</p>
<table class="list"><thead><tr><th>Network</th><th>BSSIDs</th><th>Bands</th><th>Best</th><th>Generation</th><th>Security</th><th>PMF</th><th>11k</th><th>11v</th><th>11r</th></tr></thead><tbody>${
      report.networks.map(n => `<tr><td>${name(n.ssid)}</td><td class="mono">${n.bssids}</td><td>${n.bands.join(", ")}</td>` +
        `<td><span class="rssi ${signalClass(n.best)}">${n.best}</span></td><td>${escapeHtml(n.generation)}</td>` +
        `<td class="mono">${escapeHtml(n.security)}</td><td>${escapeHtml(n.pmf)}</td>` +
        `<td>${yes(n.roaming.k)}</td><td>${yes(n.roaming.v)}</td><td>${yes(n.roaming.r)}</td></tr>`).join("")
    }</tbody></table></section>` : "";

    const columns = [
      ["Network", r => r.bssid ? name(r.ssid) : "", r => r.bssid],
      ["BSSID", r => `<span class="mono">${maskBssid(r.bssid, redact)}</span>`, r => r.bssid],
      ["RSSI", r => `<span class="rssi ${signalClass(r.rssi)}">${r.rssi}</span>`, () => true],
      ["Band", r => r.band, r => r.band],
      ["Channel", r => `<span class="mono">${r.channel}${r.width ? `@${r.width}` : ""}</span>`, r => r.channel !== null],
      ["Generation", r => escapeHtml(r.generation), r => r.generation],
      ["Security", r => `<span class="mono">${escapeHtml([r.akm, r.cipher].filter(Boolean).join(" / "))}</span>`, r => r.akm],
      ["PMF", r => escapeHtml(r.pmf), r => r.pmf],
      ["Load", r => r.utilization !== null ? `${r.utilization}%${r.stations !== null ? `, ${plural(r.stations, "client")}` : ""}` : "", r => r.utilization !== null],
      ["Uptime", r => escapeHtml(r.uptime), r => r.uptime],
    ].filter(([, , has]) => report.records.some(has));
    const bssidHtml = `<section><h2>Every BSSID heard</h2>
<p class="lede">Strongest first. RSSI is in dBm as this computer heard it: green from -67 up, amber to -75, red below (rules of thumb).</p>
<table class="list bss"><thead><tr>${columns.map(([h]) => `<th>${h}</th>`).join("")}</tr></thead><tbody>${
      report.records.map(r => `<tr>${columns.map(([, cell]) => `<td>${cell(r)}</td>`).join("")}</tr>`).join("")
    }</tbody></table></section>`;

    return `<article class="wr">${head}${tiles}${notice}
<section><h2>What stands out</h2><ul class="findings">${findingsHtml || "<li class=\"none\">Nothing to report.</li>"}</ul></section>
<section><h2>Channel use</h2><p class="lede">How many BSSIDs this computer heard on each channel. More BSSIDs on one channel means more radios sharing its airtime.</p>${channelHtml}</section>
${networksHtml}${bssidHtml}
<footer class="wr-foot"><p>A snapshot of one scan from one spot, read from lswifi by Josh Schmelzle. A scan shows what the APs advertise, not how busy the air is minute to minute.</p><p>WLAN Pros · Keith Parsons, CWNE #3</p></footer>
</article>`;
  }

  return { parse, analyze, render, bandOf, generation };
});
