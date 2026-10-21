# Domain Hunter

Minimal desktop GUI (Python, PySide6) that searches [DNSniffer](https://dnsniffer.com) for real domains
containing a brand/organization keyword. Click a domain to open `https://<domain>/` in your default browser.

- Only real API results are shown, filtered to a case-insensitive literal match of your keyword and deduplicated.
- Requests run in a Qt worker thread; the progress bar is indeterminate (total unknown).
- No pagination is followed: only `q` and `limit=20` are sent.
- Keyword matches do not prove a domain is fraudulent.

## Run from source

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python main.py
```

## Build executables (PyInstaller, one-file; no Python needed on the target machine)

**Linux** → `dist/DomainHunter`

```bash
./build.sh
./dist/DomainHunter
```

**Windows** → `dist\DomainHunter.exe`. PyInstaller cannot cross-compile, so build on Windows:

```bat
build_windows.bat
```

No Windows machine? Push this project to GitHub. The workflow in `.github/workflows/build-windows.yml`
runs on every push (or via *Actions → Build Windows exe → Run workflow*). When it finishes, open the run and
download the **DomainHunter-windows** artifact at the bottom of the page; unzip it to get `DomainHunter.exe`.

## Verify the API format

The parser accepts a list of strings, or a list of objects with a `domain`/`name`/`hostname`/`domain_name`/`fqdn`
field, optionally wrapped in a `domains`/`results`/`data`/`items` key. Check it against the real endpoint:

```bash
curl -sS -G 'https://dnsniffer.com/api/v1/domains' --data-urlencode 'q=pallotti' --data-urlencode 'limit=20'
```

If the shape differs, adjust `LIST_KEYS` / `NAME_KEYS` (or `extract_domains`) in `main.py`. A "Unexpected response"
status in the app means the shape was not recognized.
