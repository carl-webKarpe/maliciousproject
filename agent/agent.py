#!/usr/bin/env python3
"""MalwareGuard endpoint agent.

Watches administrator-approved directories on an authorized Windows PC or
laptop, reports file creation, modification, renaming and deletion to the
MalwareGuard server, and carries out scans the server's administrators
request for files in those directories.

What it does NOT do: execute, delete or move files; read files outside the
approved directories; collect passwords, browser history, messages or
keystrokes; accept arbitrary commands from the server.

Commands
    python agent.py enroll --server http://192.168.1.10:8000 --token TOKEN
    python agent.py run
    python agent.py check
    python agent.py status
"""

from __future__ import annotations

import argparse
import ctypes
import getpass
import hashlib
import ipaddress
import json
import logging
import logging.handlers
import os
import platform
import queue
import socket
import sqlite3
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

AGENT_VERSION = "1.0.0"
AGENT_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG_PATH = AGENT_DIR / "data" / "agent_config.json"

# Browsers write downloads to a temporary name and rename it when complete.
TEMP_SUFFIXES = (".crdownload", ".part", ".partial", ".download", ".tmp", ".temp", ".opdownload", ".!ut", ".aria2")
TEMP_PREFIXES = ("~$", ".~lock", "~wrl")

DEFAULTS: Dict[str, Any] = {
    "server_url": "",
    "device_name": "",
    "device_id": "",
    "enrollment_token": "",
    "watch_directories": ["{DOWNLOADS}", "{DESKTOP}", "{DOCUMENTS}", "{PICTURES}", "{VIDEOS}", "{MUSIC}"],
    "recursive": False,
    "heartbeat_interval": 30,
    "send_interval": 5,
    "settle_seconds": 3,
    "max_hash_mb": 200,
    "log_directory": "logs",
    "ca_bundle": "",
    "allow_http_on_public_networks": False,
}

log = logging.getLogger("malwareguard.agent")


class AgentError(Exception):
    """A problem the operator can act on; printed without a traceback."""


# ---------------------------------------------------------------------------
# Configuration and local state
# ---------------------------------------------------------------------------

class Config:
    def __init__(self, path: Path):
        self.path = path
        self.data: Dict[str, Any] = dict(DEFAULTS)
        if path.exists():
            try:
                loaded = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise AgentError(f"Cannot read configuration {path}: {exc}")
            if not isinstance(loaded, dict):
                raise AgentError(f"Configuration {path} must contain a JSON object.")
            self.data.update(loaded)

    @property
    def data_dir(self) -> Path:
        return self.path.parent

    def __getitem__(self, key: str) -> Any:
        return self.data.get(key, DEFAULTS.get(key))

    def __setitem__(self, key: str, value: Any) -> None:
        self.data[key] = value

    def save(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, indent=2), encoding="utf-8")
        os.replace(tmp, self.path)

    def server_url(self) -> str:
        url = str(self["server_url"]).strip().rstrip("/")
        if not url:
            raise AgentError("server_url is not configured. Run INSTALL_AGENT.bat or `agent.py enroll`.")
        return url

    def log_dir(self) -> Path:
        configured = Path(os.path.expandvars(str(self["log_directory"])))
        return configured if configured.is_absolute() else self.data_dir / configured

    def watch_directories(self) -> List[Path]:
        # Resolve {DOWNLOADS}, {DESKTOP}, ... to their real locations, de-duplicate
        # (e.g. a cloud tool may point two names at one folder), and drop a folder
        # that is nested inside another watched one so it is not watched twice.
        resolved: List[Path] = []
        for entry in self["watch_directories"] or []:
            text = str(entry)
            for name, path in known_folders().items():
                text = text.replace("{" + name + "}", str(path))
            resolved.append(Path(os.path.expandvars(os.path.expanduser(text))))

        recursive = bool(self["recursive"])
        unique: List[Path] = []
        seen: set = set()
        for path in resolved:
            key = os.path.normcase(os.path.normpath(str(path)))
            if key in seen:
                continue
            # With recursive watches, a folder already covered by a parent watch
            # would double-report; skip it.
            if recursive and any(key.startswith(k + os.sep) for k in seen):
                continue
            seen.add(key)
            unique.append(path)
        return unique


# Windows Known Folder IDs. Resolved at runtime so redirected or cloud-synced
# folders (OneDrive, etc.) are found at their real location, not a fixed path.
_KNOWN_FOLDER_IDS = {
    "DOWNLOADS": ("374DE290-123F-4565-9164-39C4925E467B", "Downloads"),
    "DESKTOP": ("B4BFCC3A-DB2C-424C-B029-7FE99A87C641", "Desktop"),
    "DOCUMENTS": ("FDD39AD0-238F-46AF-ADB4-6C85480369C7", "Documents"),
    "PICTURES": ("33E28130-4E1E-4676-835A-98395C3BC3BB", "Pictures"),
    "VIDEOS": ("18989B1D-99B5-455B-841C-AB7C74E4DDFC", "Videos"),
    "MUSIC": ("4BD8D571-6D19-48D3-BE97-422220080E43", "Music"),
}


def _known_folder_path(guid_str: str) -> Optional[str]:
    if os.name != "nt":
        return None
    try:
        from ctypes import wintypes

        class GUID(ctypes.Structure):
            _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                        ("Data3", wintypes.WORD), ("Data4", wintypes.BYTE * 8)]

        guid = GUID.from_buffer_copy(uuid.UUID(guid_str).bytes_le)
        path_ptr = ctypes.c_wchar_p()
        if ctypes.windll.shell32.SHGetKnownFolderPath(ctypes.byref(guid), 0, None, ctypes.byref(path_ptr)) == 0:
            try:
                return path_ptr.value
            finally:
                ctypes.windll.ole32.CoTaskMemFree(path_ptr)
    except (OSError, AttributeError, ValueError):
        pass
    return None


def known_folders() -> Dict[str, Path]:
    """Map each placeholder name to the user's real folder for it."""
    home = Path.home()
    result: Dict[str, Path] = {}
    for name, (guid_str, fallback) in _KNOWN_FOLDER_IDS.items():
        resolved = _known_folder_path(guid_str)
        result[name] = Path(resolved) if resolved else home / fallback
    return result


def downloads_folder() -> Path:
    """The user's Downloads folder, honouring Windows folder redirection."""
    return known_folders()["DOWNLOADS"]


class CredentialStore:
    """Keeps the device credential in credential.dat.

    On Windows the credential is encrypted with DPAPI for the current user,
    so copying the file to another account or computer does not reveal it.
    Elsewhere (development only) the file is restricted to the owner.
    """

    def __init__(self, data_dir: Path):
        self.path = data_dir / "credential.dat"

    def save(self, credential: str) -> None:
        raw = credential.encode("utf-8")
        blob = _dpapi(raw, protect=True) if os.name == "nt" else raw
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_bytes(blob)
        if os.name != "nt":
            os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)

    def load(self) -> Optional[str]:
        if not self.path.exists():
            return None
        blob = self.path.read_bytes()
        raw = _dpapi(blob, protect=False) if os.name == "nt" else blob
        return raw.decode("utf-8")

    def clear(self) -> None:
        if self.path.exists():
            self.path.unlink()


def _dpapi(data: bytes, protect: bool) -> bytes:
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    buffer = ctypes.create_string_buffer(data, len(data))
    blob_in = DATA_BLOB(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))
    blob_out = DATA_BLOB()
    flags = 0x1  # CRYPTPROTECT_UI_FORBIDDEN
    if protect:
        ok = crypt32.CryptProtectData(ctypes.byref(blob_in), ctypes.c_wchar_p("MalwareGuard agent credential"),
                                      None, None, None, flags, ctypes.byref(blob_out))
    else:
        ok = crypt32.CryptUnprotectData(ctypes.byref(blob_in), None, None, None, None, flags, ctypes.byref(blob_out))
    if not ok:
        raise AgentError("Windows could not " + ("encrypt" if protect else "decrypt") +
                         " the device credential. If the agent moved to another user account, re-enroll it.")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        kernel32.LocalFree(ctypes.cast(blob_out.pbData, ctypes.c_void_p))


class EventQueue:
    """Durable outbox (SQLite). Events survive restarts and network outages;
    event_uid is the primary key, so duplicates are never queued twice."""

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._lock = threading.Lock()
        with self._lock:
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute(
                "CREATE TABLE IF NOT EXISTS outbox (event_uid TEXT PRIMARY KEY, payload TEXT NOT NULL, created REAL NOT NULL)"
            )

    def put(self, event: Dict[str, Any]) -> bool:
        with self._lock:
            cursor = self._db.execute(
                "INSERT OR IGNORE INTO outbox (event_uid, payload, created) VALUES (?, ?, ?)",
                (event["event_uid"], json.dumps(event), time.time()),
            )
            return cursor.rowcount == 1

    def peek(self, limit: int) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._db.execute("SELECT payload FROM outbox ORDER BY created LIMIT ?", (limit,)).fetchall()
        return [json.loads(row[0]) for row in rows]

    def remove(self, uids: List[str]) -> None:
        if not uids:
            return
        with self._lock:
            self._db.executemany("DELETE FROM outbox WHERE event_uid = ?", [(uid,) for uid in uids])

    def depth(self) -> int:
        with self._lock:
            return int(self._db.execute("SELECT COUNT(*) FROM outbox").fetchone()[0])

    def close(self) -> None:
        with self._lock:
            self._db.close()


# ---------------------------------------------------------------------------
# Server communication
# ---------------------------------------------------------------------------

class ServerError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code


class ConnectionProblem(Exception):
    """The server could not be reached (network, DNS, firewall, TLS)."""


class ApiClient:
    def __init__(self, config: Config, device_id: str = "", credential: str = ""):
        import requests  # imported lazily so `agent.py --help` works before install

        self._requests = requests
        self.base = config.server_url()
        self.device_id = device_id
        self.credential = credential
        self.session = requests.Session()
        self.session.headers["User-Agent"] = f"MalwareGuardAgent/{AGENT_VERSION}"
        ca_bundle = str(config["ca_bundle"]).strip()
        self.verify: Any = ca_bundle if ca_bundle else True
        check_transport_security(self.base, bool(config["allow_http_on_public_networks"]))

    def _headers(self) -> Dict[str, str]:
        if not self.device_id or not self.credential:
            return {}
        return {"X-Device-Id": self.device_id, "X-Device-Credential": self.credential}

    def _handle(self, response: Any) -> Dict[str, Any]:
        try:
            body = response.json()
        except ValueError:
            body = {}
        if response.status_code == 404 and "error" not in body:
            # A web page, not the MalwareGuard API: the address points at the wrong folder.
            raise ServerError(404, "not_found",
                              f"No MalwareGuard server at {self.base} (HTTP 404). Open {self.base}/api/health.php "
                              "in a browser; it must show \"ok\":true. With XAMPP the address is "
                              "http://IP/<project folder name inside htdocs>.")
        if response.status_code != 200 or not body.get("ok"):
            raise ServerError(response.status_code, str(body.get("error", "http_error")),
                              str(body.get("message", f"HTTP {response.status_code}")))
        return body

    def post(self, action: str, payload: Dict[str, Any], timeout: float = 15) -> Dict[str, Any]:
        try:
            response = self.session.post(f"{self.base}/api/agent.php", params={"action": action}, json=payload,
                                         headers=self._headers(), timeout=timeout, verify=self.verify)
        except self._requests.exceptions.RequestException as exc:
            raise ConnectionProblem(describe_connection_error(exc)) from exc
        return self._handle(response)

    def upload(self, request_id: int, path: Path, sha256: str) -> Dict[str, Any]:
        try:
            with open(path, "rb") as handle:
                response = self.session.post(
                    f"{self.base}/api/agent.php", params={"action": "scan_upload"},
                    data={"request_id": str(request_id), "sha256": sha256},
                    files={"file": (path.name, handle, "application/octet-stream")},
                    headers=self._headers(), timeout=(10, 300), verify=self.verify,
                )
        except self._requests.exceptions.RequestException as exc:
            raise ConnectionProblem(describe_connection_error(exc)) from exc
        return self._handle(response)

    def health(self) -> Tuple[int, Dict[str, Any]]:
        try:
            response = self.session.get(f"{self.base}/api/health.php", timeout=10, verify=self.verify)
        except self._requests.exceptions.RequestException as exc:
            raise ConnectionProblem(describe_connection_error(exc)) from exc
        try:
            return response.status_code, response.json()
        except ValueError:
            return response.status_code, {}


def check_transport_security(base_url: str, allow_public_http: bool) -> None:
    """Refuse plain HTTP to anything but private/LAN addresses: the device
    credential would otherwise travel unencrypted across the internet."""
    parsed = urlparse(base_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise AgentError(f"server_url must look like http://192.168.1.10:8000 or https://server.example (got {base_url!r}).")
    if parsed.scheme == "https" or allow_public_http:
        return
    try:
        addresses = {info[4][0] for info in socket.getaddrinfo(parsed.hostname, None)}
    except socket.gaierror:
        return  # reported later as a connection problem
    for address in addresses:
        ip = ipaddress.ip_address(address.split("%")[0])
        if not (ip.is_private or ip.is_loopback or ip.is_link_local):
            raise AgentError(
                f"{parsed.hostname} is a public address. Use https:// for servers outside your local network, "
                "or set allow_http_on_public_networks only if you understand the credential is sent unencrypted."
            )


def describe_connection_error(exc: Exception) -> str:
    text = str(exc)
    lowered = text.lower()
    if "ssl" in lowered or "certificate" in lowered:
        return f"TLS/certificate problem: {text[:200]}. Check ca_bundle in the agent configuration."
    if "refused" in lowered or "10061" in lowered:
        return "Connection refused: the server is reachable but nothing is listening on that port (is the server started? is the port correct?)."
    if "timed out" in lowered or "timeout" in lowered or "10060" in lowered:
        return ("Connection timed out: check the server IP address, that Windows Firewall on the server allows the port, "
                "and that the Wi-Fi/hotspot does not isolate clients.")
    if "name or service not known" in lowered or "getaddrinfo" in lowered or "11001" in lowered:
        return "The server name could not be resolved. Use the server's IP address in server_url."
    if "unreachable" in lowered or "10065" in lowered or "10051" in lowered:
        return "Network unreachable: this device is not on a network that can reach the server."
    return f"Cannot reach the server: {text[:200]}"


# ---------------------------------------------------------------------------
# File monitoring
# ---------------------------------------------------------------------------

def is_temporary_name(path: str) -> bool:
    name = os.path.basename(path).lower()
    return name.endswith(TEMP_SUFFIXES) or name.startswith(TEMP_PREFIXES)


def sha256_file(path: Path, max_bytes: int) -> Tuple[Optional[str], Optional[str]]:
    """Returns (hex digest, note). Large or unreadable files are not hashed."""
    try:
        size = path.stat().st_size
        if size > max_bytes:
            return None, f"not hashed: larger than {max_bytes // (1024 * 1024)} MB"
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest(), None
    except PermissionError:
        return None, "not hashed: file is locked or access was denied"
    except OSError as exc:
        return None, f"not hashed: {exc.strerror or exc}"


class PendingFile:
    __slots__ = ("event_type", "previous_path", "is_download", "last_change", "last_size")

    def __init__(self, event_type: str, previous_path: Optional[str], is_download: bool):
        self.event_type = event_type
        self.previous_path = previous_path
        self.is_download = is_download
        self.last_change = time.monotonic()
        self.last_size = -1


class FileMonitor:
    """Turns raw watchdog notifications into settled, de-duplicated events.

    A new file is reported only after its size has stopped changing for
    settle_seconds and it can be opened, so partial downloads are not hashed.
    Temporary download names (.crdownload, .part, ...) are ignored; their
    rename to the final name is reported as a new (potentially downloaded) file.
    """

    def __init__(self, agent: "Agent"):
        self.agent = agent
        self.pending: Dict[str, PendingFile] = {}
        self.lock = threading.Lock()
        self.observer: Any = None

    # watchdog callback -----------------------------------------------------
    def dispatch(self, event: Any) -> None:
        try:
            if getattr(event, "is_directory", False):
                return
            kind = event.event_type
            src = os.path.abspath(event.src_path)
            if self.agent.is_own_file(src):
                return
            if kind == "created":
                self._touch(src, "created", None, True)
            elif kind == "modified":
                self._touch(src, "modified", None, False)
            elif kind == "moved":
                dest = os.path.abspath(event.dest_path)
                with self.lock:
                    self.pending.pop(src, None)
                if is_temporary_name(dest):
                    return
                if is_temporary_name(src):
                    # A browser finished a download and renamed it.
                    self._touch(dest, "created", src, True, replace=True)
                else:
                    # Same folder, name changed = rename; different folder = move.
                    same_folder = os.path.normcase(os.path.dirname(src)) == os.path.normcase(os.path.dirname(dest))
                    self._touch(dest, "renamed" if same_folder else "moved", src, False, replace=True)
            elif kind == "deleted":
                with self.lock:
                    pending = self.pending.pop(src, None)
                if is_temporary_name(src) or (pending is not None and pending.event_type == "created"):
                    return  # never completed; nothing worth reporting
                self.agent.record_event("deleted", src, None, None, None, None, False)
        except Exception:  # never let one bad notification stop monitoring
            log.exception("Error while handling a file notification")

    def _touch(self, path: str, event_type: str, previous: Optional[str], is_download: bool, replace: bool = False) -> None:
        if is_temporary_name(path):
            return
        with self.lock:
            existing = self.pending.get(path)
            if existing is None or replace:
                self.pending[path] = PendingFile(event_type, previous, is_download)
            else:
                # A modification of a file we are already waiting on keeps the
                # original (stronger) event type, e.g. created + modified = created.
                existing.last_change = time.monotonic()

    # settle loop ---------------------------------------------------------
    def settle_once(self) -> None:
        settle = max(1.0, float(self.agent.config["settle_seconds"]))
        now = time.monotonic()
        ready: List[Tuple[str, PendingFile]] = []
        with self.lock:
            for path, item in list(self.pending.items()):
                if now - item.last_change < settle:
                    continue
                try:
                    size = os.path.getsize(path)
                except OSError:
                    del self.pending[path]  # vanished before it settled
                    continue
                if size != item.last_size:
                    item.last_size = size
                    item.last_change = now
                    continue
                if not can_open(path):
                    item.last_change = now  # still being written (locked)
                    continue
                ready.append((path, item))
                del self.pending[path]
        for path, item in ready:
            self._report(path, item)

    def _report(self, path: str, item: PendingFile) -> None:
        file_path = Path(path)
        try:
            stat = file_path.stat()
        except OSError:
            return
        max_bytes = int(self.agent.config["max_hash_mb"]) * 1024 * 1024
        digest, note = sha256_file(file_path, max_bytes)
        self.agent.record_event(item.event_type, path, item.previous_path, stat.st_size, digest, note,
                                item.is_download, mtime_ns=stat.st_mtime_ns)

    def start(self, directories: List[Path], recursive: bool) -> List[str]:
        from watchdog.events import FileSystemEventHandler
        from watchdog.observers import Observer

        monitor = self

        class Handler(FileSystemEventHandler):
            def on_any_event(self, event: Any) -> None:
                monitor.dispatch(event)

        self.observer = Observer()
        watched = []
        for directory in directories:
            if not directory.is_dir():
                log.warning("Approved directory does not exist and is not monitored: %s", directory)
                continue
            self.observer.schedule(Handler(), str(directory), recursive=recursive)
            watched.append(str(directory))
            log.info("Monitoring %s%s", directory, " (including subfolders)" if recursive else "")
        if not watched:
            raise AgentError("None of the configured watch_directories exist. Fix agent_config.json.")
        self.observer.start()
        return watched

    def stop(self) -> None:
        if self.observer is not None:
            self.observer.stop()
            self.observer.join(timeout=5)


def can_open(path: str) -> bool:
    try:
        with open(path, "rb"):
            return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Agent runtime
# ---------------------------------------------------------------------------

class Agent:
    def __init__(self, config: Config):
        self.config = config
        self.data_dir = config.data_dir
        self.stop_event = threading.Event()
        self.credentials = CredentialStore(self.data_dir)
        self.queue = EventQueue(self.data_dir / "queue.db")
        self.jobs: "queue.Queue[Dict[str, Any]]" = queue.Queue()
        self.active_jobs: set = set()
        self.monitor = FileMonitor(self)
        self.last_error = ""
        try:
            self.username = getpass.getuser()
        except Exception:
            self.username = ""
        self.backoff = 0.0
        self.auth_blocked = False
        self.max_upload = 50 * 1024 * 1024
        self.watched: List[str] = []
        self.approved_roots: List[str] = []
        self.api: Optional[ApiClient] = None

    # helpers -------------------------------------------------------------
    @property
    def device_id(self) -> str:
        return str(self.config["device_id"])

    def is_own_file(self, path: str) -> bool:
        """True for the agent's own queue, credential, config, PID and log
        files, so a watched folder that contains them does not report them."""
        candidate = os.path.normcase(path)
        log_root = os.path.normcase(str(self.config.log_dir().resolve())) + os.sep
        if candidate.startswith(log_root):
            return True
        data_root = os.path.normcase(str(self.data_dir.resolve())) + os.sep
        if os.path.dirname(candidate) + os.sep != data_root:
            return False
        name = os.path.basename(candidate)
        return name.startswith(("queue.db", "credential.", "agent.pid", "stop.request")) or \
            name.startswith(os.path.normcase(self.config.path.stem))

    def record_event(self, event_type: str, path: str, previous: Optional[str], size: Optional[int],
                     digest: Optional[str], note: Optional[str], is_download: bool, mtime_ns: int = 0) -> None:
        occurred = time.time()
        # Identical notifications for the same file state produce the same
        # uid, so neither the local queue nor the server stores them twice.
        identity = "|".join([
            self.device_id, event_type, path, previous or "", str(size), str(mtime_ns), digest or "",
            str(int(occurred)) if event_type == "deleted" else "",
        ])
        event = {
            "event_uid": hashlib.sha256(identity.encode("utf-8")).hexdigest(),
            "event_type": event_type,
            "path": path,
            "previous_path": previous,
            "size": size,
            "sha256": digest,
            "hash_note": note,
            "user_account": self.username,
            "is_potential_download": bool(is_download),
            # These events are observed in real time, so the moment the agent
            # receives the notification is both the detection time and the best
            # available event time. (Offline reconciliation would set them apart.)
            "occurred_at": int(occurred),
            "detected_at": int(occurred),
        }
        if self.queue.put(event):
            log.info("%s %s%s", event_type.upper(), path, f" (sha256 {digest[:12]}...)" if digest else "")

    def set_error(self, message: str) -> None:
        if message != self.last_error:
            log.warning(message)
        self.last_error = message

    # threads -------------------------------------------------------------
    def heartbeat_loop(self) -> None:
        while not self.stop_event.is_set():
            interval = int(self.config["heartbeat_interval"])
            try:
                self.send_heartbeat()
            except ConnectionProblem as exc:
                self.set_error(str(exc))
            except ServerError as exc:
                self.handle_server_error(exc)
            self.stop_event.wait(max(10, interval))

    def send_heartbeat(self) -> None:
        assert self.api is not None
        response = self.api.post("heartbeat", {
            "hostname": socket.gethostname(),
            "username": getpass.getuser(),
            "os_name": f"{platform.system()} {platform.release()} ({platform.version()})",
            "agent_version": AGENT_VERSION,
            "queue_depth": self.queue.depth(),
            "last_error": self.last_error,
            "monitored_paths": self.watched,
            "heartbeat_interval": int(self.config["heartbeat_interval"]),
        })
        if self.last_error or self.auth_blocked:
            log.info("Connection to the server restored.")
        self.last_error = ""
        self.auth_blocked = False
        self.max_upload = int(response.get("max_upload_bytes", self.max_upload))
        if response.get("rotate_credential"):
            self.rotate_credential()
        for job in response.get("scan_jobs", []):
            job_id = int(job.get("id", 0))
            if job_id and job_id not in self.active_jobs:
                self.active_jobs.add(job_id)
                self.jobs.put(job)

    def rotate_credential(self) -> None:
        assert self.api is not None
        response = self.api.post("rotate_credential", {})
        new_credential = str(response["device_credential"])
        self.credentials.save(new_credential)
        self.api.credential = new_credential
        log.info("Device credential rotated at the administrator's request.")

    def handle_server_error(self, exc: ServerError) -> None:
        if exc.status in (401, 403):
            self.auth_blocked = True
            self.set_error(f"Server rejected this device ({exc.code}): {exc}")
        else:
            self.set_error(f"Server error {exc.status} ({exc.code}): {exc}")

    def sender_loop(self) -> None:
        while not self.stop_event.is_set():
            wait = float(self.config["send_interval"])
            if not self.auth_blocked:
                batch = self.queue.peek(100)
                if batch:
                    try:
                        assert self.api is not None
                        response = self.api.post("events", {"events": batch}, timeout=30)
                        rejected = response.get("rejected", [])
                        for item in rejected:
                            log.warning("Server rejected event %s: %s", item.get("event_uid"), item.get("reason"))
                        self.queue.remove(list(response.get("accepted", [])) +
                                          [str(item.get("event_uid")) for item in rejected])
                        self.backoff = 0
                        if len(batch) == 100:
                            wait = 0.2  # more queued; keep draining
                    except ConnectionProblem as exc:
                        self.set_error(str(exc))
                        self.backoff = min(300.0, max(5.0, self.backoff * 2))
                        wait = self.backoff
                        log.info("%d event(s) queued; retrying in %.0fs", self.queue.depth(), wait)
                    except ServerError as exc:
                        self.handle_server_error(exc)
                        self.backoff = min(300.0, max(5.0, self.backoff * 2))
                        wait = self.backoff
            self.stop_event.wait(wait)

    def settle_loop(self) -> None:
        while not self.stop_event.is_set():
            self.monitor.settle_once()
            self.stop_event.wait(1.0)

    def job_loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                job = self.jobs.get(timeout=1.0)
            except queue.Empty:
                continue
            try:
                self.run_scan_job(job)
            finally:
                self.active_jobs.discard(int(job.get("id", 0)))

    def run_scan_job(self, job: Dict[str, Any]) -> None:
        assert self.api is not None
        job_id = int(job["id"])
        requested = str(job.get("path", ""))
        log.info("Scan requested by administrator: job %d for %s", job_id, requested)

        def fail(reason: str, message: str) -> None:
            log.warning("Scan job %d not performed: %s", job_id, message)
            try:
                self.api.post("scan_failed", {"request_id": job_id, "reason": reason, "message": message})
            except (ConnectionProblem, ServerError) as exc:
                log.warning("Could not report the failed scan job: %s", exc)

        try:
            real = os.path.realpath(requested)
        except (OSError, ValueError):
            return fail("invalid_path", "The path is not valid on this device.")
        if not self.is_approved_path(real):
            return fail("outside_approved", "The file is not inside a directory approved for monitoring on this device.")
        path = Path(real)
        if not path.is_file():
            return fail("file_missing", "The file no longer exists (it may have been moved or deleted).")
        size = path.stat().st_size
        if size > self.max_upload:
            return fail("too_large", f"The file is {size // 1048576} MB; the server accepts at most {self.max_upload // 1048576} MB.")
        digest, note = sha256_file(path, self.max_upload)
        if digest is None:
            return fail("read_error", note or "The file could not be read.")
        try:
            result = self.api.upload(job_id, path, digest)
        except ConnectionProblem as exc:
            self.set_error(str(exc))
            log.info("Scan job %d will be retried when the server offers it again.", job_id)
            return
        except ServerError as exc:
            return log.warning("Server could not complete scan job %d: %s", job_id, exc)
        log.info("Scan job %d completed: %s%s", job_id, str(result.get("threat_level", "")).upper(),
                 f" (VirusTotal {result['detection_ratio']})" if result.get("detection_ratio") else "")

    def is_approved_path(self, real_path: str) -> bool:
        candidate = os.path.normcase(real_path)
        return any(candidate.startswith(root) for root in self.approved_roots)

    # lifecycle -----------------------------------------------------------
    def run(self) -> None:
        credential = self.credentials.load()
        if not self.device_id or not credential:
            raise AgentError("This device is not enrolled yet. Run INSTALL_AGENT.bat or `agent.py enroll`.")
        self.api = ApiClient(self.config, self.device_id, credential)

        directories = self.config.watch_directories()
        self.watched = self.monitor.start(directories, bool(self.config["recursive"]))
        self.approved_roots = [os.path.normcase(os.path.realpath(p)) + os.sep for p in self.watched]

        pid_file = self.data_dir / "agent.pid"
        stop_file = self.data_dir / "stop.request"
        if stop_file.exists():
            stop_file.unlink()
        pid_file.write_text(str(os.getpid()), encoding="ascii")

        threads = [threading.Thread(target=fn, name=fn.__name__, daemon=True)
                   for fn in (self.heartbeat_loop, self.sender_loop, self.settle_loop, self.job_loop)]
        for thread in threads:
            thread.start()
        log.info("MalwareGuard agent %s running as device %s; server %s", AGENT_VERSION, self.device_id, self.api.base)

        try:
            while not self.stop_event.is_set():
                if stop_file.exists():
                    log.info("Stop requested by STOP_AGENT.bat.")
                    break
                time.sleep(1)
        except KeyboardInterrupt:
            log.info("Stop requested (Ctrl+C).")
        finally:
            self.stop_event.set()
            self.monitor.stop()
            for thread in threads:
                thread.join(timeout=10)
            self.queue.close()
            for path in (pid_file, stop_file):
                try:
                    path.unlink()
                except OSError:
                    pass
            log.info("Agent stopped. Undelivered events stay queued for the next start.")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def setup_logging(config: Config, verbose: bool = True) -> None:
    log_dir = config.log_dir()
    log_dir.mkdir(parents=True, exist_ok=True)
    formatter = logging.Formatter("%(asctime)s %(levelname)-7s %(message)s")
    file_handler = logging.handlers.RotatingFileHandler(log_dir / "agent.log", maxBytes=1_000_000, backupCount=5, encoding="utf-8")
    file_handler.setFormatter(formatter)
    log.addHandler(file_handler)
    if verbose:
        console = logging.StreamHandler(sys.stdout)
        console.setFormatter(formatter)
        log.addHandler(console)
    log.setLevel(logging.INFO)


def pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        # os.kill(pid, 0) would terminate the process on Windows; ask politely.
        handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        try:
            code = ctypes.c_ulong()
            ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
            return code.value == 259  # STILL_ACTIVE
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def cmd_enroll(config: Config, args: argparse.Namespace) -> int:
    if args.server is not None:
        # The installer always passes --server; a blank answer must not fall
        # back silently to whatever address is already in the config file.
        if not args.server.strip():
            raise AgentError("The server address is empty. Type it in full, for example http://127.0.0.1:8000 "
                             "(same PC as the server) or http://192.168.1.87:8000 (another PC).")
        config["server_url"] = args.server.strip().rstrip("/")
    if args.name:
        config["device_name"] = args.name
    token = (args.token or str(config["enrollment_token"])).strip()
    if not token:
        raise AgentError("Provide the enrollment token from the dashboard: --token TOKEN")
    # A folder copied from another computer carries that computer's device ID;
    # reusing it would collide with the other computer's registration.
    if not config["device_id"] or config.data.get("enrolled_hostname") != socket.gethostname():
        config["device_id"] = str(uuid.uuid4())

    api = ApiClient(config)
    try:
        response = api.post("enroll", {
            "enrollment_token": token,
            "device_id": config["device_id"],
            "display_name": config["device_name"] or socket.gethostname(),
            "hostname": socket.gethostname(),
            "username": getpass.getuser(),
            "os_name": f"{platform.system()} {platform.release()} ({platform.version()})",
            "agent_version": AGENT_VERSION,
        })
    except ConnectionProblem as exc:
        raise AgentError(f"{exc}\nRun `agent.py check` for connection diagnostics.")
    except ServerError as exc:
        raise AgentError(f"Enrollment refused: {exc}")

    CredentialStore(config.data_dir).save(str(response["device_credential"]))
    config["device_id"] = response["device_id"]
    config["enrolled_hostname"] = socket.gethostname()
    config["heartbeat_interval"] = int(response.get("heartbeat_interval", config["heartbeat_interval"]))
    config["enrollment_token"] = ""  # single-use; never keep it around
    config.save()
    print(f"Enrolled. Device ID: {config['device_id']}")
    print(f"Configuration: {config.path}")
    return 0


def cmd_check(config: Config, args: argparse.Namespace) -> int:
    base = config.server_url()
    parsed = urlparse(base)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    print(f"Server URL      : {base}")
    problems = 0
    try:
        check_transport_security(base, bool(config["allow_http_on_public_networks"]))
    except AgentError as exc:
        print(f"FAIL  {exc}")
        return 1

    try:
        address = socket.gethostbyname(host)
        print(f"Resolved        : {host} -> {address}")
    except socket.gaierror:
        print(f"FAIL  Cannot resolve {host!r}. Use the server's IP address instead.")
        return 1

    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect((address, port))
        local_ip = probe.getsockname()[0]
        probe.close()
        print(f"This device     : {local_ip}")
        if ipaddress.ip_address(local_ip).is_private and ipaddress.ip_address(address).is_private:
            same = ipaddress.ip_network(f"{local_ip}/24", strict=False) == ipaddress.ip_network(f"{address}/24", strict=False)
            if not same:
                print("NOTE  This device and the server appear to be on different subnets. That works only if a router "
                      "connects them; on a hotspot or simple Wi-Fi both must normally share the same subnet.")
    except OSError:
        print("FAIL  This device has no route to the server address (not connected to that network?).")
        problems += 1

    try:
        with socket.create_connection((address, port), timeout=5):
            print(f"OK    TCP port {port} is reachable")
    except ConnectionRefusedError:
        print(f"FAIL  Port {port} refused the connection: the server is not running or listens on another port/address.")
        print("      On the server, START_MALICIOUSPROJECT.bat must use APP_HOST=0.0.0.0 (or the server's LAN IP) for other PCs to connect.")
        return 1
    except OSError:
        print(f"FAIL  No answer on port {port}: wrong IP, Windows Firewall blocking the port on the server, "
              "or Wi-Fi/hotspot client isolation.")
        return 1

    api = ApiClient(config, config["device_id"], CredentialStore(config.data_dir).load() or "")
    try:
        status, body = api.health()
        if status == 200 and body.get("ok"):
            print(f"OK    Server health: {body.get('app', 'MalwareGuard')} (database ok)")
        else:
            print(f"FAIL  Server answered HTTP {status}: database={body.get('database')} schema={body.get('schema')}")
            problems += 1
    except ConnectionProblem as exc:
        print(f"FAIL  {exc}")
        return 1

    if api.device_id and api.credential:
        try:
            api.post("heartbeat", {"agent_version": AGENT_VERSION, "queue_depth": 0, "hostname": socket.gethostname()})
            print(f"OK    Authenticated as device {api.device_id}")
        except ServerError as exc:
            print(f"FAIL  Authentication: {exc}")
            problems += 1
        except ConnectionProblem as exc:
            print(f"FAIL  {exc}")
            problems += 1
    else:
        print("INFO  Not enrolled yet: run `agent.py enroll --token TOKEN`.")
    return 1 if problems else 0


def cmd_status(config: Config, args: argparse.Namespace) -> int:
    pid_file = config.data_dir / "agent.pid"
    pid = int(pid_file.read_text().strip()) if pid_file.exists() and pid_file.read_text().strip().isdigit() else 0
    queue_path = config.data_dir / "queue.db"
    depth = EventQueue(queue_path).depth() if queue_path.exists() else 0
    print(f"Configuration : {config.path}")
    print(f"Server        : {config['server_url'] or '(not set)'}")
    print(f"Device ID     : {config['device_id'] or '(not enrolled)'}")
    print(f"Credential    : {'stored' if CredentialStore(config.data_dir).path.exists() else 'missing'}")
    print(f"Running       : {'yes (PID %d)' % pid if pid_alive(pid) else 'no'}")
    print(f"Queued events : {depth}")
    for directory in config.watch_directories():
        print(f"Watching      : {directory}{'' if directory.is_dir() else '  (MISSING)'}")
    return 0


def cmd_run(config: Config, args: argparse.Namespace) -> int:
    # Log first, so problems are visible even when started without a console.
    setup_logging(config, verbose=not args.quiet)
    pid_file = config.data_dir / "agent.pid"
    if pid_file.exists():
        text = pid_file.read_text().strip()
        if text.isdigit() and pid_alive(int(text)):
            raise AgentError(f"The agent is already running (PID {text}). Use STOP_AGENT.bat first.")
    Agent(config).run()
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="MalwareGuard endpoint agent")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH), help="path to agent_config.json")
    sub = parser.add_subparsers(dest="command", required=True)
    enroll = sub.add_parser("enroll", help="register this device using a token from the dashboard")
    enroll.add_argument("--server", help="server URL, e.g. http://192.168.1.10:8000")
    enroll.add_argument("--token", help="enrollment token from Devices > Generate token")
    enroll.add_argument("--name", help="display name for this device")
    run = sub.add_parser("run", help="start monitoring")
    run.add_argument("--quiet", action="store_true", help="log to file only")
    sub.add_parser("check", help="diagnose the connection to the server")
    sub.add_parser("status", help="show local agent status")
    args = parser.parse_args(argv)

    try:
        config = Config(Path(args.config).resolve())
        handler = {"enroll": cmd_enroll, "run": cmd_run, "check": cmd_check, "status": cmd_status}[args.command]
        return handler(config, args)
    except AgentError as exc:
        if log.handlers:
            log.error("%s", exc)
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except ImportError as exc:
        print(f"ERROR: missing dependency ({exc.name}). Run INSTALL_AGENT.bat or: python -m pip install -r requirements.txt",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
