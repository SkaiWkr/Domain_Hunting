"""Domain Hunter - list real domains from DNSniffer that contain a brand keyword."""
import os
import re
import sys
import webbrowser

import requests
from PySide6.QtCore import QObject, Qt, QThread, Signal
from PySide6.QtWidgets import (QApplication, QHBoxLayout, QLabel, QLineEdit, QListWidget,
                               QListWidgetItem, QProgressBar, QPushButton, QVBoxLayout, QWidget)

API_URL = "https://dnsniffer.com/api/v1/domains"
LIMIT = 20
LIST_KEYS = ("domains", "results", "data", "items")
NAME_KEYS = ("domain", "name", "hostname", "domain_name", "fqdn")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")


def clean(raw):
    """Normalize a raw value to a lowercase hostname, or None if it is not a valid domain."""
    d = re.sub(r"^[a-z]+://", "", str(raw).strip().lower()).split("/")[0]
    d = d.removeprefix("*.").rstrip(".")
    try:
        ascii_d = d.encode("idna").decode()
    except UnicodeError:
        return None
    return d if DOMAIN_RE.match(ascii_d) else None


def extract_domains(payload):
    """Pull raw domain strings out of the API JSON. Raises ValueError if the shape is unknown."""
    items = payload
    for _ in range(2):  # allow one level of wrapping, e.g. {"data": {"domains": [...]}}
        if isinstance(items, dict):
            items = next((items[k] for k in LIST_KEYS if isinstance(items.get(k), (list, dict))), None)
    if not isinstance(items, list):
        raise ValueError("unrecognized JSON structure")
    out = []
    for it in items:
        if isinstance(it, dict):
            it = next((it[k] for k in NAME_KEYS if isinstance(it.get(k), str)), None)
        if isinstance(it, str):
            out.append(it)
    return out


def find_matches(payload, keyword):
    """Return (deduplicated domains containing keyword, number of raw entries returned)."""
    raw = extract_domains(payload)
    kw = keyword.lower()
    seen, matches = set(), []
    for r in raw:
        d = clean(r)
        if d and kw in d and d not in seen:
            seen.add(d)
            matches.append(d)
    return matches, len(raw)


class Worker(QObject):
    done = Signal(list, int)
    failed = Signal(str)

    def __init__(self, keyword):
        super().__init__()
        self.keyword = keyword

    def run(self):
        try:
            r = requests.get(API_URL, params={"q": self.keyword, "limit": LIMIT},
                             headers={"User-Agent": "DomainHunter/1.0", "Accept": "application/json"},
                             timeout=(5, 20))
            if r.status_code == 429:
                wait = r.headers.get("Retry-After")
                self.failed.emit("Rate limited by the server." + (f" Retry in {wait}s." if wait else " Try again shortly."))
                return
            r.raise_for_status()
            matches, total = find_matches(r.json(), self.keyword)
            self.done.emit(matches, total)
        except requests.Timeout:
            self.failed.emit("The request timed out. Try again.")
        except requests.ConnectionError:
            self.failed.emit("Network error. Check your connection.")
        except requests.HTTPError as e:
            self.failed.emit(f"Server returned HTTP {e.response.status_code}.")
        except ValueError as e:  # includes invalid JSON
            self.failed.emit(f"Unexpected response from server ({e}).")
        except Exception as e:  # noqa: BLE001
            self.failed.emit(f"Unexpected error: {e}")


QSS = """
QWidget { background:#080b0e; color:#d7e2ea; font-family:"Segoe UI","Inter","Noto Sans",sans-serif; font-size:14px; }
QLabel#title { font-size:26px; font-weight:700; color:#3ddc97; }
QLabel#status { color:#8aa0ad; }
QLabel#note { color:#5f7380; font-size:12px; }
QLineEdit { background:#11161b; border:1px solid #1f2a33; border-radius:8px; padding:9px 12px; selection-background-color:#22d3ee; selection-color:#080b0e; }
QLineEdit:focus { border:1px solid #22d3ee; }
QPushButton { background:#11161b; border:1px solid #1f2a33; border-radius:8px; padding:8px 14px; }
QPushButton:hover { border-color:#3ddc97; }
QPushButton:disabled { color:#475660; }
QPushButton#primary { background:#3ddc97; color:#04110b; border:none; font-weight:600; padding:9px 20px; }
QPushButton#primary:hover { background:#22d3ee; }
QPushButton#primary:disabled { background:#1f2a33; color:#475660; }
QPushButton#small { padding:3px 12px; font-size:12px; }
QProgressBar { background:#11161b; border:none; border-radius:2px; }
QProgressBar::chunk { background:#22d3ee; border-radius:2px; }
QListWidget { background:#0c1115; border:1px solid #1f2a33; border-radius:8px; padding:4px; outline:0; }
QListWidget::item { color:#22d3ee; padding:7px 8px; border-radius:6px; }
QListWidget::item:hover { background:#141c22; color:#3ddc97; }
QListWidget::item:selected { background:#141c22; color:#3ddc97; }
"""


class Window(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Domain Hunter")
        self.resize(560, 640)
        self.busy = False

        title = QLabel("Domain Hunter")
        title.setObjectName("title")
        self.input = QLineEdit(placeholderText="Search an organization or brand...")
        self.search_btn = QPushButton("Search")
        self.search_btn.setObjectName("primary")
        self.clear_btn = QPushButton("Clear")
        self.clear_btn.setObjectName("small")
        self.bar = QProgressBar()
        self.bar.setFixedHeight(4)
        self.bar.setTextVisible(False)
        self.status = QLabel("Enter a keyword to search.")
        self.status.setObjectName("status")
        self.list = QListWidget()
        self.list.viewport().setCursor(Qt.PointingHandCursor)
        f = self.list.font()
        f.setUnderline(True)
        self.list.setFont(f)
        note = QLabel("Keyword matches do not prove a domain is fraudulent.")
        note.setObjectName("note")

        row = QHBoxLayout()
        row.addWidget(self.input, 1)
        row.addWidget(self.search_btn)
        srow = QHBoxLayout()
        srow.addWidget(self.status, 1)
        srow.addWidget(self.clear_btn)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 18, 20, 14)
        lay.setSpacing(10)
        for w in (title,):
            lay.addWidget(w)
        lay.addLayout(row)
        lay.addWidget(self.bar)
        lay.addLayout(srow)
        lay.addWidget(self.list, 1)
        lay.addWidget(note)

        self._set_busy(False)
        self.search_btn.clicked.connect(self.start)
        self.input.returnPressed.connect(self.start)
        self.clear_btn.clicked.connect(self.clear)
        self.list.itemClicked.connect(self.open_item)

    def _set_busy(self, busy):
        self.busy = busy
        self.bar.setRange(0, 0) if busy else (self.bar.setRange(0, 1), self.bar.setValue(0))
        for w in (self.search_btn, self.clear_btn, self.input):
            w.setEnabled(not busy)

    def start(self):
        kw = self.input.text().strip()
        if self.busy:
            return
        if not kw:
            self.status.setText("Type a keyword first.")
            return
        self.list.clear()
        self.status.setText(f"Searching for “{kw}”…")
        self._set_busy(True)
        self.job = QThread(self)
        self.worker = Worker(kw)
        self.worker.moveToThread(self.job)
        self.job.started.connect(self.worker.run)
        self.worker.done.connect(self.on_done)
        self.worker.failed.connect(self.on_failed)
        self.worker.done.connect(self.job.quit)
        self.worker.failed.connect(self.job.quit)
        self.job.finished.connect(self.job.deleteLater)
        self.job.start()

    def on_done(self, domains, total):
        self._set_busy(False)
        for d in domains:
            item = QListWidgetItem(d)
            item.setData(Qt.UserRole, d.encode("idna").decode())
            item.setToolTip(f"Open https://{d}/")
            self.list.addItem(item)
        if domains:
            self.status.setText(f"{len(domains)} matching domain(s) found · {total} returned by API")
        else:
            self.status.setText(f"No matching domains found · {total} returned by API")

    def on_failed(self, msg):
        self._set_busy(False)
        self.status.setText(msg)

    def clear(self):
        self.list.clear()
        self.input.clear()
        self.status.setText("Enter a keyword to search.")
        self.input.setFocus()

    def open_item(self, item):
        webbrowser.open(f"https://{item.data(Qt.UserRole)}/")


def main():
    app = QApplication(sys.argv)
    app.setStyleSheet(QSS)
    w = Window()
    w.show()
    code = app.exec()
    if w.busy:  # a request is still in flight; don't wait for it
        os._exit(code)
    sys.exit(code)


if __name__ == "__main__":
    main()
