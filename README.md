# Wi-Fi Views Reporters

Three free web pages that turn the Wi-Fi text your computer already prints into a clean, readable report. Paste the output in, press **Make report**, and read what each number means and what stands out. Print it or save it as a PDF to send to whoever is helping you.

Everything runs in your browser. Nothing is uploaded, and identifying details (MAC addresses, network names, IP addresses, device names) are hidden by default.

The working versions are hosted on the WLAN Pros Library:

| Report | What you paste | Hosted version |
|---|---|---|
| **Mac Wi-Fi Report** | `sudo wdutil info` from a Mac: your own connection, in detail (signal, noise, channel use, rate, MCS) | https://library.wlanpros.com/mac-wifi-report/ |
| **Windows Wi-Fi Report** | `netsh wlan` from a Windows PC: your own connection, the adapter, and every access point Windows can see | https://library.wlanpros.com/windows-wifi-report/ |
| **Nearby Wi-Fi Report** | `lswifi --json` on Windows, macOS or Linux: every network your laptop can hear, with channel use per band | https://library.wlanpros.com/nearby-wifi-report/ |

This repository is the source copy, for people who want to study it, run it offline, or change it and make it their own.

## Run it

Download or clone this repository, then double-click one of these files. It opens in your browser and works with no Internet connection.

- `mac-wifi-report.html`
- `windows-wifi-report.html`
- `nearby-wifi-report.html`

Each page has the command to run and a **Try an example** button. Offline, the pages fall back to your system fonts; everything else works the same.

### The commands

**Mac** (Terminal; asks for your Mac password):

```
sudo wdutil info | pbcopy
```

**Windows** (PowerShell; no admin needed):

```
& { netsh wlan show interfaces; netsh wlan show drivers; netsh wlan show networks mode=bssid } | clip
```

**Nearby networks** (needs [lswifi](https://github.com/joshschmelzle/lswifi), installed with `python3 -m pip install --user lswifi`):

```
lswifi --json | pbcopy      # Mac
lswifi --json | clip        # Windows
```

On a Mac, lswifi needs Location Services turned on for Python, or macOS hides network names, BSSIDs and security. The report tells you when that happens.

## Change it

Each HTML file at the top level is built from `src/`:

- `src/wdutil.js`, `src/netsh.js`, `src/lswifi.js`: reading the pasted text, the analysis, and the report. No network requests.
- `src/*-page.html`: the page around each report.
- `src/style.css`, `src/nearby.css`: the look.
- `src/examples/`: the made-up examples behind **Try an example**.

After you change anything in `src/`, rebuild the three pages:

```
python3 build.py
```

Then run the tests (Python 3 and Node.js 18 or newer, nothing to install):

```
python3 -m unittest test_build
node --test test/examples.test.mjs
```

## License

Copyright 2026 Keith Parsons / WLAN Pros. Licensed under the [Apache License 2.0](LICENSE): you may use, change and share this code, including in your own products, as long as you keep the copyright and license notices and mark the files you changed.

The license does not cover the WLAN Pros name or logo. If you share a changed version, take out the logo and the WLAN Pros branding. See [NOTICE](NOTICE).

lswifi is Josh Schmelzle's open-source scanner (BSD-3-Clause) and is not part of this repository; the Nearby Wi-Fi Report only reads its output.
