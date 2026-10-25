# Privacy Sentinel

A personal security toolkit that inspects the websites you visit, entirely on
your own computer.

- **Chrome/Edge extension** – scores every page you open and shows a warning
  badge. One click adds live details: DNS, HTTPS certificate, domain
  registration date/age and (optionally) Google Safe Browsing. A History tab
  lists the sites you have checked.
- **Desktop app** – paste any URL to analyze it, run the same live checks, or
  compute a file's SHA-256 fingerprint.
- **Python engine** – the shared analysis code (`host/security_engine.py`).

> Warnings are advisory and navigation is never blocked. A low score means "no
> known warning patterns", **not** "safe".

## How it works

```
Chrome extension  --native messaging-->  Python host (host/host.py)  -->  security_engine.py
 (extension/)                             runs locally, no server
```

The extension cannot run Python itself, so Chrome starts the small host program
registered by `host/install_host.py` and exchanges JSON messages with it.

## Install the extension (Windows, Chrome or Edge)

Requirements: Python 3.8+.

1. Download or clone this repository.
2. Open `chrome://extensions`, enable **Developer mode**, click **Load
   unpacked**, and select the `extension` folder. Copy the extension **ID**.
3. In a terminal:
   ```
   cd host
   python install_host.py --id PASTE_THE_EXTENSION_ID
   ```
   It must print `Self-test: OK` (use `--browser edge` for Edge, `--uninstall`
   to remove).
4. Fully restart the browser, pin the extension, and open any website.

Re-run step 3 if you move the folder or if the extension ID changes.

## Desktop app

```
cd host
python app_tk.py
```

Or download `PrivacySentinel.exe` from the **Releases** page. To build it
yourself, double-click `host/build_exe.bat` (needs Python; produces
`host/dist/PrivacySentinel.exe`).

`host/main.py` is an older Kivy version of the same app and is optional
(`pip install kivy`).

## Optional: Google Safe Browsing

Set an API key in the environment variable `PRIVACY_SENTINEL_GSB_KEY`. Without
it, that check reports "not configured". Keys are never stored in this repo.

## Privacy

- Local URL analysis never contacts the website.
- **Live checks run only when you click and confirm.** They send the hostname
  to your DNS resolver and rdap.org, connect directly to the site (so the site
  can see your IP), and send the address *without its query string* to Google
  Safe Browsing if a key is set.
- History stores only hostname, protocol, risk level, score and time – never
  paths or query strings – and can be paused or cleared in the popup.
- Scan results with full URLs are kept in memory only (`storage.session`).

## Limitations

- Heuristics inspect the URL's structure, not the page's content.
- The extension requires the local Python host; it is not on the Chrome Web
  Store.
- Unsigned `.exe` builds may trigger a Windows SmartScreen warning.

## Development

```
cd host
python -m unittest -v
```

## License

MIT – see [LICENSE](LICENSE).
