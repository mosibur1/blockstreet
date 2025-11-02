import asyncio
import base64
import gc
import gzip
import inspect
import json
import os
import random
import re
import secrets
import shutil
import signal
import socket
import statistics
import sys
import textwrap
import threading
import time
import traceback
import tracemalloc
import zlib

from collections import deque
from datetime import UTC, datetime, timedelta
from http.cookies import SimpleCookie
from queue import Queue as ThreadQueue

import brotli
import chardet
import psutil
import requests

from colorama import Fore, init as colorama_init
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad
from eth_account import Account
from eth_account.messages import encode_defunct
from fake_useragent import UserAgent
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

DEFAULT_TIMEOUT = 10
NAME_BOT = "Block Street"


class BoundedSet:
    """LRU-like bounded set to avoid unbounded memory growth for dedupe."""

    def __init__(self, maxlen: int = 10000):
        self._set = set()
        self._dq = deque()
        self.maxlen = maxlen

    def __contains__(self, item):
        return item in self._set

    def add(self, item):
        if item in self._set:
            return
        self._set.add(item)
        self._dq.append(item)
        if len(self._dq) > self.maxlen:
            old = self._dq.popleft()
            try:
                self._set.remove(old)
            except KeyError:
                pass

    def clear(self):
        self._set.clear()
        self._dq.clear()

    def __len__(self):
        return len(self._dq)


colorama_init(autoreset=True)
_global_ua = None


def now_ts():
    return datetime.now().strftime("[%Y:%m:%d ~ %H:%M:%S] |")


class ProxyManager:
    def __init__(
        self,
        proxy_list: list | None,
        test_url: str = "https://httpbin.org/ip",
        test_timeout: float = 4.0,
    ):
        self.proxy_pool = ThreadQueue()
        self._bad = set()
        self.test_url = test_url
        self.test_timeout = test_timeout
        if proxy_list:
            for p in proxy_list:
                p = p.strip()
                if p:
                    self.proxy_pool.put(p)

    def _quick_test(self, proxy: str) -> bool:
        try:
            proxies = {"http": proxy, "https": proxy}
            r = requests.get(self.test_url, proxies=proxies, timeout=self.test_timeout)
            r.raise_for_status()
            return True
        except Exception:
            return False

    def get_proxy(self, test_before_use: bool = True, attempts: int = 4) -> str | None:
        tried = []
        for _ in range(attempts):
            try:
                p = self.proxy_pool.get_nowait()
            except Exception:
                break
            if not p or p in self._bad:
                continue
            if test_before_use:
                if self._quick_test(p):
                    return p
                else:
                    self._bad.add(p)
                    continue
            return p
        return None

    def release_proxy(self, proxy: str):
        if not proxy or proxy in self._bad:
            return
        try:
            self.proxy_pool.put_nowait(proxy)
        except Exception:
            pass

    def mark_bad(self, proxy: str):
        if not proxy:
            return
        self._bad.add(proxy)


class blockstreet:
    BASE_URL = "https://api.blockstreet.money/api/"
    HEADERS = {
        "accept": "application/json, text/plain, */*",
        "accept-encoding": "br",
        "accept-language": "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
        "cache-control": "no-cache",
        "Content-Type": "application/json",
        "origin": "https://blockstreet.money",
        "pragma": "no-cache",
        "priority": "u=1, i",
        "referer": "https://blockstreet.money/",
        "sec-ch-ua": '"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
    }

    def __init__(
        self,
        use_proxy: bool = False,
        proxy_list: list | None = None,
        load_on_init: bool = True,
    ):
        """
        load_on_init: pass False for worker instances to avoid duplicate config/query logs.
        """
        self._suppress_local_session_log = not load_on_init
        if load_on_init:
            self.config = self.load_config()
            self.query_list = self.load_query("query.txt")
        else:
            self.config = {}
            self.query_list = []
        self.token = None
        self.session = None
        self.proxy = None
        self.proxy_list = (
            proxy_list
            if proxy_list is not None
            else self.load_proxies()
            if load_on_init
            else []
        )
        self.proxy_manager = (
            ProxyManager(self.proxy_list) if self.config.get("proxy") else None
        )

    def banner(self):
        self.log("")
        self.log("=======================================", Fore.CYAN)
        self.log(f"           🎉  {NAME_BOT} BOT 🎉             ", Fore.CYAN)
        self.log("=======================================", Fore.CYAN)
        self.log("🚀  by LIVEXORDS", Fore.CYAN)
        self.log("📢  t.me/livexordsscript", Fore.CYAN)
        self.log("=======================================", Fore.CYAN)
        self.log("")

    def log(self, message, color=Fore.RESET):
        safe_message = str(message).encode("utf-8", "backslashreplace").decode("utf-8")
        print(Fore.LIGHTBLACK_EX + now_ts() + " " + color + safe_message + Fore.RESET)

    def _request(
        self,
        method: str,
        url_or_path: str,
        *,
        headers: dict | None = None,
        params: dict | None = None,
        data=None,
        json_data=None,
        timeout: float | None = None,
        use_session: bool = True,
        allow_redirects: bool = True,
        stream: bool = False,
        parse: bool = False,
        retries: int = 2,
        backoff: float = 0.5,
        allow_proxy: bool = True,
        debug: bool = False,
    ):
        method = method.upper()
        headers = headers or {}
        timeout = timeout or DEFAULT_TIMEOUT
        if not url_or_path.lower().startswith("http"):
            url = self.BASE_URL.rstrip("/") + "/" + url_or_path.lstrip("/")
        else:
            url = url_or_path
        hdr = dict(getattr(self, "HEADERS", {}) or {})
        if headers:
            hdr.update(headers)
        last_exc = None
        for attempt in range(1, retries + 2):
            chosen_proxy = None
            resp = None
            try:
                proxies = None
                if allow_proxy and getattr(self, "proxy_manager", None):
                    if getattr(self, "proxy", None):
                        chosen_proxy = self.proxy
                        proxies = {"http": chosen_proxy, "https": chosen_proxy}
                    else:
                        chosen_proxy = self.proxy_manager.get_proxy(
                            block=True, timeout=0.5
                        )
                        if chosen_proxy:
                            self.proxy = chosen_proxy
                            self._proxy_use_count = 0
                            proxies = {"http": chosen_proxy, "https": chosen_proxy}
                if debug:
                    self.log(f"[DEBUG] {method} {url}", Fore.MAGENTA)
                    if proxies:
                        self.log(f"[DEBUG] Using proxy: {chosen_proxy}", Fore.MAGENTA)
                    if params:
                        self.log(f"[DEBUG] Params: {params}", Fore.MAGENTA)
                    if json_data:
                        self.log(f"[DEBUG] JSON: {json_data}", Fore.MAGENTA)
                    elif data:
                        self.log(f"[DEBUG] Data: {data}", Fore.MAGENTA)
                    if hdr:
                        pretty_headers = "\n".join(
                            [f"    {k}: {v}" for k, v in hdr.items()]
                        )
                        self.log(f"[DEBUG] Headers:\n{pretty_headers}", Fore.MAGENTA)
                call_args = dict(
                    headers=hdr,
                    params=params,
                    data=data,
                    json=json_data,
                    timeout=timeout,
                    allow_redirects=allow_redirects,
                    stream=stream,
                )
                if use_session and getattr(self, "session", None):
                    if proxies:
                        call_args["proxies"] = proxies
                    resp = self.session.request(method, url, **call_args)
                else:
                    if proxies:
                        call_args["proxies"] = proxies
                    resp = requests.request(method, url, **call_args)
                resp.raise_for_status()
                if debug:
                    ct = (resp.headers.get("Content-Type") or "").lower()
                    is_text = any(
                        x in ct for x in ("text", "json", "xml", "html", "javascript")
                    )
                    if not stream and is_text:
                        try:
                            preview = next(resp.iter_content(chunk_size=512))[
                                :250
                            ].decode("utf-8", "replace")
                        except Exception:
                            preview = (resp.text or "")[:250].replace("\n", " ")
                        self.log(f"[DEBUG] Response preview: {preview}", Fore.MAGENTA)
                    else:
                        preview = (resp.text or "")[:250].replace("\n", " ")
                        self.log(f"[DEBUG] Response preview: {preview}", Fore.MAGENTA)
                if chosen_proxy:
                    self._proxy_use_count = getattr(self, "_proxy_use_count", 0) + 1
                    rotate_after = (
                        int(self.config.get("proxy_rotate_every", 0))
                        if getattr(self, "config", None)
                        else 0
                    )
                    if rotate_after > 0 and self._proxy_use_count >= rotate_after:
                        try:
                            if getattr(self, "proxy_manager", None):
                                self.proxy_manager.release_proxy(self.proxy)
                        except Exception:
                            pass
                        self.proxy = None
                        self._proxy_use_count = 0
                decoded = None
                if parse:
                    try:
                        decoded = self.decode_response(resp)
                    except Exception as e:
                        self.log(f"[DEBUG] Parse failed: {e}", Fore.MAGENTA)
                return (resp, decoded)
            except requests.exceptions.RequestException as e:
                last_exc = e
                if chosen_proxy and getattr(self, "proxy_manager", None):
                    try:
                        if (
                            hasattr(self, "proxy_manager")
                            and self.proxy_manager is not None
                        ):
                            self.proxy_manager.mark_bad(chosen_proxy)
                            try:
                                self.log(
                                    f"🚫 Marked bad proxy: {chosen_proxy} | snapshot={self.proxy_manager.snapshot()}",
                                    Fore.YELLOW,
                                )
                            except Exception:
                                pass
                    except Exception:
                        pass
                    try:
                        self.log(
                            f"⚠️ Proxy {chosen_proxy} failure on attempt {attempt}: {e}",
                            Fore.YELLOW,
                        )
                    except Exception:
                        pass
                    self.proxy = None
                    self._proxy_use_count = 0
                else:
                    self.log(
                        f"⚠️ Request error attempt {attempt} for {method} {url}: {e}",
                        Fore.YELLOW,
                    )
                if attempt >= retries + 1:
                    self.log(
                        f"❌ Giving up on {method} {url} after {attempt} attempts",
                        Fore.RED,
                    )
                    raise
                sleep_for = (
                    backoff * 2 ** (attempt - 1) * random.uniform(0.9, 1.1)
                    + random.random() * 0.2
                )
                time.sleep(sleep_for)
                continue
            except Exception as e:
                if debug:
                    self.log(
                        f"[DEBUG] Unexpected error: {traceback.format_exc()}",
                        Fore.MAGENTA,
                    )
                if getattr(self, "proxy", None) and getattr(
                    self, "proxy_manager", None
                ):
                    try:
                        if (
                            hasattr(self, "proxy_manager")
                            and self.proxy_manager is not None
                        ):
                            self.proxy_manager.mark_bad(self.proxy)
                            try:
                                self.log(
                                    f"🚫 Marked bad proxy: {self.proxy} | snapshot={self.proxy_manager.snapshot()}",
                                    Fore.YELLOW,
                                )
                            except Exception:
                                pass
                    except Exception:
                        pass
                    self.proxy = None
                self.log(
                    f"❌ Unexpected error during request {method} {url}: {e}", Fore.RED
                )
                raise
        if last_exc:
            raise last_exc
        raise RuntimeError("request failed unexpectedly")

    def clear_locals(self):
        frame = inspect.currentframe().f_back
        local_vars = list(frame.f_locals.keys())
        for name in local_vars:
            if not name.startswith("__") and name != "self":
                try:
                    del frame.f_locals[name]
                except Exception:
                    pass
        try:
            gc.collect()
        except Exception:
            pass

    def get_ua(self):
        """
        Return a shared fake UserAgent instance (or None).
        Uses the module-global _global_ua so we don't recreate the UserAgent object.
        """
        global _global_ua
        if _global_ua is None:
            try:
                _global_ua = UserAgent()
            except Exception:
                _global_ua = None
        return _global_ua

    def rotate_proxy_and_ua(
        self, force_new_proxy: bool = True, quick_test: bool = True
    ):
        """
        Rotate User-Agent and (optionally) pick a new proxy from proxy_manager.
        Logs what's happening (UA chosen, proxy chosen, old proxy released, errors).
        - force_new_proxy: try to pick a new proxy (if config proxy=True and proxy_manager exists)
        - quick_test: passed to ProxyManager.get_proxy if supported (best-effort)
        Returns (ua_str, proxy_str)
        Safe to call at start of a loop or inside a task (not intended per-request).
        """
        if not hasattr(self, "_session_lock"):
            self._session_lock = threading.Lock()
        ua_applied = None
        proxy_applied = None
        try:
            with self._session_lock:
                try:
                    ua_obj = self.get_ua() if hasattr(self, "get_ua") else None
                    ua_str = None
                    if ua_obj:
                        try:
                            ua_str = ua_obj.random
                        except Exception:
                            ua_str = None
                    if not ua_str:
                        base = self.HEADERS.get("user-agent", "python-requests/unknown")
                        ua_str = f"{base} (+rot/{random.randint(1000, 9999)})"
                    try:
                        if getattr(self, "session", None):
                            self.session.headers.update({"User-Agent": ua_str})
                    except Exception as e:
                        try:
                            self.log(
                                f"⚠️ Failed to apply UA to session: {e}", Fore.YELLOW
                            )
                        except Exception:
                            pass
                    self.HEADERS["user-agent"] = ua_str
                    ua_applied = ua_str
                    try:
                        self.log(f"🔁 UA rotated -> {ua_str[:120]}", Fore.CYAN)
                    except Exception:
                        pass
                except Exception as e:
                    try:
                        self.log(f"⚠️ UA rotation error: {e}", Fore.YELLOW)
                    except Exception:
                        pass
                proxy_applied = getattr(self, "proxy", None)
                try:
                    if (
                        force_new_proxy
                        and self.config.get("proxy")
                        and getattr(self, "proxy_manager", None)
                    ):
                        old = getattr(self, "proxy", None)
                        newp = None
                        try:
                            newp = self.proxy_manager.get_proxy(
                                test_before_use=quick_test
                            )
                        except TypeError:
                            try:
                                newp = self.proxy_manager.get_proxy()
                            except Exception:
                                newp = None
                        except Exception:
                            newp = None
                        if newp:
                            try:
                                if getattr(self, "session", None):
                                    self.session.proxies = {"http": newp, "https": newp}
                                    try:
                                        self.session.cookies.clear()
                                    except Exception:
                                        pass
                            except Exception as e:
                                try:
                                    self.log(
                                        f"⚠️ Failed to set session proxies: {e}",
                                        Fore.YELLOW,
                                    )
                                except Exception:
                                    pass
                            self.proxy = newp
                            proxy_applied = newp
                            try:
                                self._proxy_use_count = 0
                            except Exception:
                                self._proxy_use_count = 0
                            if old and old != newp:
                                try:
                                    self.proxy_manager.release_proxy(old)
                                    try:
                                        self.log(
                                            f"🔁 Released old proxy -> {old}",
                                            Fore.MAGENTA,
                                        )
                                    except Exception:
                                        pass
                                except Exception:
                                    try:
                                        self.log(
                                            f"⚠️ Could not release old proxy {old}",
                                            Fore.YELLOW,
                                        )
                                    except Exception:
                                        pass
                            try:
                                self.log(f"🔁 Using proxy {newp}", Fore.CYAN)
                            except Exception:
                                pass
                        else:
                            proxy_applied = getattr(self, "proxy", None)
                            try:
                                self.log(
                                    f"ℹ️ Proxy rotate: no new proxy selected, keeping {proxy_applied or 'local'}",
                                    Fore.YELLOW,
                                )
                            except Exception:
                                pass
                    else:
                        proxy_applied = getattr(self, "proxy", None)
                        if proxy_applied:
                            try:
                                self.log(
                                    f"ℹ️ Keeping existing proxy: {proxy_applied}",
                                    Fore.YELLOW,
                                )
                            except Exception:
                                pass
                        else:
                            try:
                                self.log("🌐 Using local IP (no proxy)", Fore.YELLOW)
                            except Exception:
                                pass
                except Exception as e:
                    try:
                        self.log(f"⚠️ Proxy rotation error: {e}", Fore.YELLOW)
                    except Exception:
                        pass
        except Exception as e:
            try:
                self.log(f"❌ rotate_proxy_and_ua failed: {e}", Fore.RED)
            except Exception:
                pass
        return (ua_applied, proxy_applied)

    def load_config(self, suppress_log: bool = False):
        """
        Load config.json. If suppress_log=True, don't print the 'Config loaded' message.
        """
        try:
            with open("config.json", encoding="utf-8") as f:
                cfg = json.load(f)
            if not suppress_log:
                self.log("✅ Config loaded", Fore.GREEN)
            return cfg
        except FileNotFoundError:
            if not suppress_log:
                self.log("⚠️ config.json not found (using minimal)", Fore.YELLOW)
            return {}
        except Exception as e:
            if not suppress_log:
                self.log(f"❌ Config parse error: {e}", Fore.RED)
            return {}

    def load_query(self, path_file: str = "query.txt") -> list:
        try:
            with open(path_file, encoding="utf-8") as file:
                queries = [line.strip() for line in file if line.strip()]
            if not queries:
                self.log(f"⚠️ {path_file} empty", Fore.YELLOW)
            self.log(f"✅ {len(queries)} entries loaded", Fore.GREEN)
            return queries
        except FileNotFoundError:
            self.log(f"❌ {path_file} not found", Fore.RED)
            return []
        except Exception as e:
            self.log(f"❌ Query load error: {e}", Fore.RED)
            return []

    def login(self, index: int) -> bool:
        """
        Attempt to log in using a private key from self.query_list at `index`.
        Returns True on success, False otherwise.
        Note: keep networking helpers (self._request, self.prepare_session, etc.) unchanged.
        """
        RETRIES = 2
        BACKOFF = 0.5
        self.log("🔐 Attempting to log in...", Fore.GREEN)

        def _vv() -> str:
            """
            Generate a 32-hex string from 16 cryptographic random bytes,
            applying the same bit-mangling as the JS snippet (UUIDv4 style).
            """
            b = bytearray(secrets.token_bytes(16))
            b[6] = b[6] & 15 | 64
            b[8] = b[8] & 63 | 128
            hexstr = "".join(f"{x:02x}" for x in b)
            return hexstr

        def generate_vId() -> str:
            """
            Generate and return a vId string that matches the JS behavior:
            - produce a 32-hex-character string from _vv()
            - repeat until the second-last character == '1'
            (mirrors the `while(true){ if (vstr[vstr.length - 2] === v) return vstr; }` logic)
            """
            while True:
                vstr = _vv()
                if vstr[-2] == "1":
                    return vstr

        try:
            if index < 0 or index >= len(self.query_list):
                self.log("❌ Invalid login index. Please check again.", Fore.RED)
                return False
            if Account is None or encode_defunct is None:
                self.log(
                    "❌ Missing dependency: install eth-account and eth-utils (`pip install eth-account eth-utils`).",
                    Fore.RED,
                )
                return False
            self.prepare_session()
            raw_pk = self.query_list[index].strip()
            if not raw_pk:
                self.log("❌ Empty private key.", Fore.RED)
                return False
            self.log(
                f"📋 Using private key: {raw_pk[:8]}... (truncated for security)",
                Fore.CYAN,
            )
            signnonce_resp = None
            try:
                self.log(
                    "📡 Requesting signnonce (GET account/signnonce)...", Fore.CYAN
                )
                signnonce_resp, signnonce_data = self._request(
                    "GET",
                    "account/signnonce",
                    timeout=DEFAULT_TIMEOUT,
                    parse=True,
                    retries=RETRIES,
                    backoff=BACKOFF,
                )
            except Exception as e:
                self.log(f"❌ Failed to request signnonce: {e}", Fore.RED)
                if signnonce_resp is not None:
                    try:
                        self.log(
                            f"📄 Response content: {getattr(signnonce_resp, 'text', '')}",
                            Fore.RED,
                        )
                    except Exception:
                        pass
                return False
            try:
                nonce = signnonce_data.get("data", {}).get("signnonce", "")
                if not nonce:
                    raise ValueError("signnonce not found in signnonce response")
                nonce = nonce.strip()
                self.log(f"✅ Received signnonce: {nonce}", Fore.GREEN)
            except Exception as e:
                self.log(f"❌ Error processing signnonce response: {e}", Fore.RED)
                return False

            def _extract_clean_cookie(resp) -> str:
                cookie_pairs = []
                try:
                    jar = getattr(resp, "cookies", None)
                    if jar:
                        cd = jar.get_dict()
                        if cd:
                            return "; ".join((f"{k}={v}" for k, v in cd.items()))
                except Exception:
                    pass
                try:
                    raw_headers = None
                    try:
                        raw_headers = resp.raw.headers.get_all("Set-Cookie")
                    except Exception:
                        raw_headers = None
                    if raw_headers:
                        for hdr in raw_headers:
                            try:
                                sc = SimpleCookie()
                                sc.load(hdr)
                                for morsel in sc.values():
                                    cookie_pairs.append(f"{morsel.key}={morsel.value}")
                            except Exception:
                                continue
                    else:
                        header_val = resp.headers.get("Set-Cookie") or resp.headers.get(
                            "set-cookie"
                        )
                        if header_val:
                            sc = SimpleCookie()
                            parsed = False
                            try:
                                sc.load(header_val)
                                parsed = True
                            except Exception:
                                parsed = False
                            if parsed:
                                for morsel in sc.values():
                                    cookie_pairs.append(f"{morsel.key}={morsel.value}")
                            else:
                                parts = re.split(", (?=[^,=]+=[^,=]+)", header_val)
                                for p in parts:
                                    try:
                                        sc2 = SimpleCookie()
                                        sc2.load(p)
                                        for morsel in sc2.values():
                                            cookie_pairs.append(
                                                f"{morsel.key}={morsel.value}"
                                            )
                                    except Exception:
                                        continue
                except Exception:
                    pass
                if cookie_pairs:
                    return "; ".join(dict.fromkeys(cookie_pairs))
                return ""

            try:
                set_cookie_raw = _extract_clean_cookie(signnonce_resp)
                if set_cookie_raw:
                    self.HEADERS["cookie"] = set_cookie_raw
                    self.log(
                        f"🍪 Set Cookie header (clean): {set_cookie_raw}", Fore.CYAN
                    )
                else:
                    self.log(
                        "⚠️ No Set-Cookie found in signnonce response.", Fore.YELLOW
                    )
            except Exception as e:
                self.log(f"⚠️ Failed to parse/set cookie: {e}", Fore.YELLOW)
            try:
                acct = Account.from_key(raw_pk)
                expected_address = acct.address
                self.log(f"🔑 Derived address from PK: {expected_address}", Fore.CYAN)
                try:
                    issued_at = (
                        datetime.now(UTC)
                        .isoformat(timespec="milliseconds")
                        .replace("+00:00", "Z")
                    )
                    expiration = (
                        (datetime.now(UTC) + timedelta(minutes=2))
                        .isoformat(timespec="milliseconds")
                        .replace("+00:00", "Z")
                    )
                    message = f"blockstreet.money wants you to sign in with your Ethereum account:\n{expected_address}\n\nWelcome to Block Street\n\nURI: https://blockstreet.money\nVersion: 1\nChain ID: 1329\nNonce: {nonce}\nIssued At: {issued_at}\nExpiration Time: {expiration}"
                    self.log(
                        f"🧾 Message to sign (len={len(message)}): {message}", Fore.CYAN
                    )
                    try:
                        msg_obj = encode_defunct(text=message)
                        signed = Account.sign_message(msg_obj, raw_pk)
                        sig_hex = "0x" + signed.signature.hex()
                        self.log(
                            f"🧾 Signed locally with eth-account: {sig_hex[:32]}... (base64, truncated)",
                            Fore.CYAN,
                        )
                        try:
                            recovered_addr = Account.recover_message(
                                msg_obj, signature=sig_hex
                            )
                            if recovered_addr.lower() != expected_address.lower():
                                self.log(
                                    f"❌ Local verification failed: recovered {recovered_addr} != expected {expected_address}",
                                    Fore.RED,
                                )
                                return False
                            else:
                                self.log(
                                    f"✅ Local signature verification OK: {recovered_addr}",
                                    Fore.GREEN,
                                )
                        except Exception as e:
                            self.log(
                                f"⚠️ Local signature verification error: {e}",
                                Fore.YELLOW,
                            )
                            return False
                    except Exception as e:
                        self.log(f"❌ Local signing failed: {e}", Fore.RED)
                        return False
                except Exception as e:
                    self.log(f"❌ Error during signverify: {e}", Fore.RED)
                    if "verify_resp" in locals() and verify_resp is not None:
                        try:
                            self.log(
                                f"📄 Response content: {getattr(verify_resp, 'text', '')}",
                                Fore.RED,
                            )
                        except Exception:
                            pass
                    return False
                try:
                    payload = {
                        "address": expected_address,
                        "nonce": nonce,
                        "signature": sig_hex,
                        "chainId": 1329,
                        "issuedAt": issued_at,
                        "expirationTime": expiration,
                    }
                    rsa_keys = [
                        textwrap.dedent(
                            "-----BEGIN PUBLIC KEY-----\n                        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzpG+3W5mvFXBmJSDiDc\n                        VyEZrR7rsJHHNb7bPLPSdwDBDfrg3EaPH88WAhLMqHx2MwSPLcG44eU7ICJ/l0xL\n                        hZGx8NiqZnkwKrOKzBUyY6+ZlaOZZvRp9WTP+vVDeApW+3dftq8jJm9C1F+2v6cU\n                        8VXjEnH/QVx6I/7zhdf15aQxm28JTj5z1jlfER04qUWZV+EcktG/f7frjYw0YhsZ\n                        HqzeKwU0ggUiIDfcXlsNRbx4rrFwh1+c1Yy8ctb3+PQY8/EOgVgEEKPR1vFnC6me\n                        R4ooXjx9psXL2dt37+8BOi1Ja/ruG6uoCJKr7jMF7dND5p0kbbAZPHfZKoiYAKhc\n                        bwIDAQAB\n                        -----END PUBLIC KEY-----"
                        ),
                        textwrap.dedent(
                            "-----BEGIN PUBLIC KEY-----\n                        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxX8AFdH2X9GmVO50msDy\n                        zAcfdhNwNQsjHLSk1NVk/EkrEGngajAydd9/DN7FdtUck816riO20/uhwqFfEPb3\n                        Nd74t3DBM2TLvw4foVbssaR9SER2G0DJOi5bKEDNhaVeg03H1/X1/qZiKv38LSwY\n                        VgWi+yiVJ1n18elbE5NRD2Wv2ybqdZ2TIVOIrGtneUhbN0CrrxdeuO0/yqitohnC\n                        Bm+rwQO4FXqnD3MKmCTBQD8bBFWaHw2ow2CX8vXMuPJBYEk0b8tYMzbxWJUnoVDq\n                        tDjYj5L10R/MtFDRvaRG/E3igTcYF0QRPfvP78kCwY2QIXnRZEjliEfoku42YL0R\n                        ZwIDAQAB\n                        -----END PUBLIC KEY-----"
                        ),
                        textwrap.dedent(
                            "-----BEGIN PUBLIC KEY-----\n                        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxkEVgGx/dKn8axHe0B3T\n                        yCqHjE62ofCO8E8mCKsZj7Kx/wTHqKAZpF/55pFGkF3gr9sLLQcx21VfEZsGIJ8q\n                        YOndyZDuB06b5JE0Xu26g5iwMW/xkBtIm8eMr8L+ApHU2hml0KqHGdULeSNcLRiu\n                        CHGnP+W2zjLnzl47HTNPPEFkFbSe8RBVQ0SediY+RzLVFX89Tpt3NMMvYs8ng9wi\n                        /cDIbUXgMIpYdiHfaW28X9GoUXKJmP4pB5rEXk0J22bKcRsopECOudu5Am4dCrDn\n                        kbxrUxQR4dNSiyOKFkarARvkWOukcvNXHTg58z6+uzg9kVRSaVV2hShoY0Dwfg++\n                        qwIDAQAB\n                        -----END PUBLIC KEY-----"
                        ),
                    ]

                    def get_secret_params(millisecond: int):
                        id_str = str(millisecond * 2)
                        idx = int(id_str) % 3
                        salt = f"{id_str[2]}{id_str[5]}{id_str[8]}{id_str[0]}"
                        rsa_pub_pem = rsa_keys[idx]
                        return (rsa_pub_pem, id_str, idx, salt)

                    millisecond = int(time.time() * 1000)
                    rsa_pub_pem, id_str, idx, salt = get_secret_params(millisecond)
                    payload_json = json.dumps(
                        payload, separators=(",", ":"), ensure_ascii=False
                    )
                    aes_key = os.urandom(32)
                    aes_key_b64 = base64.b64encode(aes_key).decode()
                    iv = os.urandom(16)
                    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                    plaintext = json.dumps(
                        payload, separators=(",", ":"), ensure_ascii=False
                    ).encode("utf-8")
                    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
                    cipher_b64 = base64.b64encode(ciphertext).decode()
                    iv_b64 = base64.b64encode(iv).decode()
                    rsa_key = RSA.import_key(rsa_pub_pem.encode("utf-8"))
                    rsa_cipher = PKCS1_v1_5.new(rsa_key)
                    enc_aes_bytes = rsa_cipher.encrypt(aes_key_b64.encode("utf-8"))
                    enc_aes_b64 = base64.b64encode(enc_aes_bytes).decode("ascii")
                    send_headers = (
                        dict(self.HEADERS) if isinstance(self.HEADERS, dict) else {}
                    )
                    send_headers.pop("Content-Type", None)
                    send_headers.update(
                        {
                            "signature": enc_aes_b64,
                            "token": iv_b64,
                            "timestamp": str(millisecond),
                            "abs": generate_vId(),
                            "Content-Type": "application/x-www-form-urlencoded",
                        }
                    )
                    self.log(
                        "📡 Sending signverify (POST account/signverify) — encrypted client-side...",
                        Fore.CYAN,
                    )
                    verify_resp, verify_data = self._request(
                        "POST",
                        "account/signverify",
                        data=cipher_b64,
                        headers=send_headers,
                        timeout=DEFAULT_TIMEOUT,
                        parse=True,
                        retries=RETRIES,
                        backoff=BACKOFF,
                    )
                    if not isinstance(verify_data, dict):
                        self.log(
                            f"❌ Unexpected verify response format: {getattr(verify_resp, 'text', verify_data)}",
                            Fore.RED,
                        )
                        return False
                    rst = verify_data.get("data", {}).get("rst", False)
                    if not rst:
                        self.log(f"❌ signverify failed: {verify_data}", Fore.RED)
                        return False
                    self.log("✅ signverify success.", Fore.GREEN)
                except Exception as e:
                    self.log(
                        f"❌ Error during signverify (encryption flow): {e}", Fore.RED
                    )
                    if "verify_resp" in locals() and verify_resp is not None:
                        try:
                            self.log(
                                f"📄 Response content: {getattr(verify_resp, 'text', '')}",
                                Fore.RED,
                            )
                        except Exception:
                            pass
                    return False
                try:
                    self.log("📡 Requesting account/info...", Fore.CYAN)
                    info_resp, info_data = self._request(
                        "GET",
                        "account/info",
                        timeout=DEFAULT_TIMEOUT,
                        parse=True,
                        retries=1,
                    )
                    wallet_address = info_data.get("data", {}).get(
                        "wallet_address", "N/A"
                    )
                    invite_code = info_data.get("data", {}).get("invite_code", "N/A")
                    self.log("👤 Account Info:", Fore.GREEN)
                    self.log(f"    - Wallet Address: {wallet_address}", Fore.CYAN)
                    self.log(f"    - Invite Code: {invite_code}", Fore.CYAN)
                except Exception as e:
                    self.log(f"❌ Failed to fetch/process account/info: {e}", Fore.RED)
                    if "info_resp" in locals() and info_resp is not None:
                        try:
                            self.log(
                                f"📄 Response content: {getattr(info_resp, 'text', '')}",
                                Fore.RED,
                            )
                        except Exception:
                            pass
                    return False
                try:
                    self.log("📡 Requesting earn/info...", Fore.CYAN)
                    earn_resp, earn_data = self._request(
                        "GET",
                        "earn/info",
                        timeout=DEFAULT_TIMEOUT,
                        parse=True,
                        retries=1,
                    )
                    today_earn = earn_data.get("data", {}).get("today_earn", "N/A")
                    total_earn = earn_data.get("data", {}).get("total_earn", "N/A")
                    balance = earn_data.get("data", {}).get("balance", "N/A")
                    self.log("💰 Earnings Summary:", Fore.GREEN)
                    self.log(f"    - Today Earn: {today_earn}", Fore.CYAN)
                    self.log(f"    - Total Earn: {total_earn}", Fore.CYAN)
                    self.log(f"    - Balance: {balance}", Fore.CYAN)
                except Exception as e:
                    self.log(f"❌ Failed to fetch/process earn/info: {e}", Fore.RED)
                    if "earn_resp" in locals() and earn_resp is not None:
                        try:
                            self.log(
                                f"📄 Response content: {getattr(earn_resp, 'text', '')}",
                                Fore.RED,
                            )
                        except Exception:
                            pass
                    return False
                return True
            except Exception as e:
                self.log(f"❌ Error during signverify: {e}", Fore.RED)
                if "verify_resp" in locals() and verify_resp is not None:
                    try:
                        self.log(
                            f"📄 Response content: {getattr(verify_resp, 'text', '')}",
                            Fore.RED,
                        )
                    except Exception:
                        pass
                return False
        finally:
            try:
                self.clear_locals()
            except Exception:
                pass

    def suplay(self) -> bool:
        """
        Supply routine:
        - Do 1 full pass over SYMBOLS and record which symbols succeeded (available_symbols).
        - Then do up to 9 additional cycles (total 10) only for available_symbols.
        - If server returns 'insufficient' for a symbol, mark that symbol unavailable (do not abort).
        - After supply cycles, always call my/supply and attempt withdraws (withdraw step runs even if some supplies failed).
        - No new self attributes, no imports, no sleep, no prepare_session.
        """
        RETRIES = 2
        BACKOFF = 0.5
        SYMBOLS = ["BSD", "AAPL", "TSLA", "MSFT", "NVDA", "CRCL", "COIN", "SMTR"]
        AMOUNT = "0.01"
        try:
            self.log("📡 Fetching earn/info...", Fore.CYAN)
            earn_resp, earn_data = self._request(
                "GET",
                "earn/info",
                timeout=DEFAULT_TIMEOUT,
                parse=True,
                retries=RETRIES,
                backoff=BACKOFF,
            )
            if not isinstance(earn_data, dict):
                self.log("❌ Unexpected earn/info format.", Fore.RED)
                return False
            if earn_data.get("code") != 0:
                self.log(
                    f"❌ earn/info returned error code: {earn_data.get('code')}",
                    Fore.RED,
                )
                return False
            ed = earn_data.get("data") or {}
            today = str(ed.get("today_earn", "N/A"))
            total = str(ed.get("total_earn", "N/A"))
            balance_str = str(ed.get("balance", "0"))
            self.log("💰 Earn Info:", Fore.GREEN)
            self.log("    - Today Earn: " + today, Fore.CYAN)
            self.log("    - Total Earn: " + total, Fore.CYAN)
            self.log("    - Balance: " + balance_str, Fore.CYAN)
            try:
                balance_val = float(balance_str)
                amount_val = float(AMOUNT)
            except Exception:
                self.log("❌ Invalid balance format.", Fore.RED)
                return False
            required_per_cycle = amount_val * len(SYMBOLS)
            if balance_val < amount_val:
                self.log(
                    f"⚠ Balance too low to perform any supply (need at least {amount_val}).",
                    Fore.YELLOW,
                )
                available_symbols = []
            else:
                self.log(f"✅ Balance parsed OK ({balance_val}).", Fore.GREEN)
                available_symbols = list(SYMBOLS)
            any_failure = False
            exhausted_symbols = set()
            self.log(
                "🔁 Starting first full supply pass over all symbols...", Fore.MAGENTA
            )
            first_pass_success = set()
            for sym in SYMBOLS:
                if sym in exhausted_symbols:
                    continue
                if not isinstance(sym, str) or not sym.strip():
                    self.log(f"⚠ Skipping invalid symbol: {repr(sym)}", Fore.YELLOW)
                    any_failure = True
                    continue
                payload = {"symbol": sym, "amount": AMOUNT}
                try:
                    self.log(f"📤 [1st pass] Supplying {AMOUNT} {sym}...", Fore.CYAN)
                    sup_resp, sup_data = self._request(
                        "POST",
                        "supply",
                        json_data=payload,
                        timeout=DEFAULT_TIMEOUT,
                        parse=True,
                        retries=RETRIES,
                        backoff=BACKOFF,
                    )
                    if not isinstance(sup_data, dict):
                        text = getattr(sup_resp, "text", str(sup_data))
                        self.log(
                            f"❌ Unexpected supply response for {sym}: {text}", Fore.RED
                        )
                        any_failure = True
                        continue
                    if sup_data.get("code") == 0 and sup_data.get("data") is True:
                        self.log(
                            f"✅ [1st pass] Supplied {AMOUNT} {sym} — OK", Fore.GREEN
                        )
                        first_pass_success.add(sym)
                        try:
                            balance_val -= amount_val
                        except Exception:
                            pass
                    else:
                        raw_msg = ""
                        try:
                            raw_msg = str(
                                sup_data.get("message", "")
                                or sup_data.get("data", "")
                                or ""
                            )
                        except Exception:
                            raw_msg = ""
                        lowers = raw_msg.lower()
                        if any(
                            k in lowers
                            for k in (
                                "insufficient",
                                "not enough",
                                "insufficient balance",
                                "no supply",
                                "no liquidity",
                                "sold out",
                            )
                        ):
                            self.log(
                                f"⚠ {sym} appears exhausted: {raw_msg}", Fore.YELLOW
                            )
                            exhausted_symbols.add(sym)
                            continue
                        if any(
                            k in lowers
                            for k in (
                                "update ",
                                "insert ",
                                "delete ",
                                "select ",
                                "deadlock",
                                "stacktrace",
                                "`",
                            )
                        ):
                            short_msg = (
                                f"[REDACTED SERVER ERROR: code={sup_data.get('code')}]"
                            )
                            self.log(
                                f"❌ Supply failed for {sym}: {short_msg}", Fore.RED
                            )
                        else:
                            self.log(
                                f"❌ Supply failed for {sym}: {sup_data}", Fore.RED
                            )
                        any_failure = True
                except Exception as e:
                    self.log(
                        f"❌ Exception while supplying {sym} on first pass: {e}",
                        Fore.RED,
                    )
                    any_failure = True
                    continue
            available_symbols = [
                s
                for s in SYMBOLS
                if s in first_pass_success and s not in exhausted_symbols
            ]
            if not available_symbols:
                self.log(
                    "⚠ No symbols available after first pass; skipping further supply cycles.",
                    Fore.YELLOW,
                )
            else:
                self.log(
                    f"✅ Symbols available for further cycles: {', '.join(available_symbols)}",
                    Fore.CYAN,
                )
            cycles_left = 9
            cycle_no = 2
            while cycles_left > 0 and available_symbols and (balance_val >= amount_val):
                self.log(
                    f"🔁 Supply cycle {cycle_no}/10 for available symbols...",
                    Fore.MAGENTA,
                )
                removed_this_round = []
                for sym in list(available_symbols):
                    payload = {"symbol": sym, "amount": AMOUNT}
                    try:
                        self.log(
                            f"📤 Supplying {AMOUNT} {sym} (cycle {cycle_no})...",
                            Fore.CYAN,
                        )
                        sup_resp, sup_data = self._request(
                            "POST",
                            "supply",
                            json_data=payload,
                            timeout=DEFAULT_TIMEOUT,
                            parse=True,
                            retries=RETRIES,
                            backoff=BACKOFF,
                        )
                        if not isinstance(sup_data, dict):
                            text = getattr(sup_resp, "text", str(sup_data))
                            self.log(
                                f"❌ Unexpected supply response for {sym}: {text}",
                                Fore.RED,
                            )
                            any_failure = True
                            continue
                        if sup_data.get("code") == 0 and sup_data.get("data") is True:
                            self.log(
                                f"✅ Supplied {AMOUNT} {sym} — OK (cycle {cycle_no})",
                                Fore.GREEN,
                            )
                            try:
                                balance_val -= amount_val
                            except Exception:
                                pass
                        else:
                            raw_msg = ""
                            try:
                                raw_msg = str(
                                    sup_data.get("message", "")
                                    or sup_data.get("data", "")
                                    or ""
                                )
                            except Exception:
                                raw_msg = ""
                            lowers = raw_msg.lower()
                            if any(
                                k in lowers
                                for k in (
                                    "insufficient",
                                    "not enough",
                                    "insufficient balance",
                                    "no supply",
                                    "no liquidity",
                                    "sold out",
                                )
                            ):
                                self.log(
                                    f"⚠ {sym} exhausted during cycle {cycle_no}: {raw_msg}",
                                    Fore.YELLOW,
                                )
                                removed_this_round.append(sym)
                                continue
                            if any(
                                k in lowers
                                for k in (
                                    "update ",
                                    "insert ",
                                    "delete ",
                                    "select ",
                                    "deadlock",
                                    "stacktrace",
                                    "`",
                                )
                            ):
                                short_msg = f"[REDACTED SERVER ERROR: code={sup_data.get('code')}]"
                                self.log(
                                    f"❌ Supply failed for {sym}: {short_msg}", Fore.RED
                                )
                            else:
                                self.log(
                                    f"❌ Supply failed for {sym}: {sup_data}", Fore.RED
                                )
                            any_failure = True
                        if balance_val < amount_val:
                            self.log(
                                "⚠ Remaining balance insufficient for further supplies.",
                                Fore.YELLOW,
                            )
                    except Exception as e:
                        self.log(
                            f"❌ Exception while supplying {sym} in cycle {cycle_no}: {e}",
                            Fore.RED,
                        )
                        any_failure = True
                        continue
                if removed_this_round:
                    for r in removed_this_round:
                        if r in available_symbols:
                            available_symbols.remove(r)
                cycles_left -= 1
                cycle_no += 1
                if not available_symbols or balance_val < amount_val:
                    break
            if any_failure:
                self.log("⚠ Supply finished with some failed attempts.", Fore.YELLOW)
            else:
                self.log("✅ All supply cycles completed successfully.", Fore.GREEN)
            self.log("📡 Fetching my/supply to record supplied assets...", Fore.CYAN)
            mysup_resp, mysup_data = self._request(
                "GET",
                "my/supply",
                timeout=DEFAULT_TIMEOUT,
                parse=True,
                retries=RETRIES,
                backoff=BACKOFF,
            )
            supplies_list = []
            if not isinstance(mysup_data, dict):
                self.log("❌ Unexpected my/supply response format.", Fore.RED)
            elif mysup_data.get("code") != 0:
                self.log(
                    f"❌ my/supply returned error code: {mysup_data.get('code')}",
                    Fore.RED,
                )
            else:
                for entry in mysup_data.get("data") or []:
                    try:
                        sym = entry.get("symbol")
                        amt_str = str(entry.get("amount", "0"))
                        amt_val = float(amt_str)
                        supplies_list.append({"symbol": sym, "amount": amt_val})
                    except Exception:
                        continue
            if supplies_list:
                self.log("📤 Initiating withdraws for recorded supplies...", Fore.CYAN)
                withdraw_successes = []
                withdraw_failures = []
                for entry in supplies_list:
                    sym = entry.get("symbol")
                    amt_val = entry.get("amount", 0.0)
                    if not sym or not isinstance(sym, str):
                        continue
                    try:
                        if amt_val <= 0:
                            self.log(
                                f"⚠ Skipping withdraw for {sym} due to zero amount.",
                                Fore.YELLOW,
                            )
                            continue
                        withdraw_val = amt_val * 0.5
                        withdraw_str = f"{withdraw_val:.10f}".rstrip("0").rstrip(".")
                        w_payload = {"symbol": sym, "amount": withdraw_str}
                        self.log(f"📤 Withdrawing {withdraw_str} {sym} ...", Fore.CYAN)
                        w_resp, w_data = self._request(
                            "POST",
                            "withdraw",
                            json_data=w_payload,
                            timeout=DEFAULT_TIMEOUT,
                            parse=True,
                            retries=RETRIES,
                            backoff=BACKOFF,
                        )
                        if not isinstance(w_data, dict):
                            text = getattr(w_resp, "text", str(w_data))
                            self.log(
                                f"❌ Unexpected withdraw response for {sym}: {text}",
                                Fore.RED,
                            )
                            withdraw_failures.append((sym, "unexpected_response"))
                            continue
                        if w_data.get("code") == 0 and w_data.get("data") is True:
                            self.log(
                                f"✅ Withdrawn {withdraw_str} {sym} — OK", Fore.GREEN
                            )
                            withdraw_successes.append(sym)
                            try:
                                balance_val -= float(withdraw_val)
                            except Exception:
                                pass
                        else:
                            raw_msg = ""
                            try:
                                raw_msg = str(
                                    w_data.get("message", "")
                                    or w_data.get("data", "")
                                    or ""
                                )
                            except Exception:
                                raw_msg = ""
                            lowers = raw_msg.lower()
                            if any(
                                k in lowers
                                for k in (
                                    "insufficient",
                                    "not enough",
                                    "insufficient balance",
                                    "balance",
                                    "no liquidity",
                                )
                            ):
                                self.log(
                                    f"⚠ Server indicates insufficient balance for {sym} during withdraw: {raw_msg} — skipping this token.",
                                    Fore.YELLOW,
                                )
                                withdraw_failures.append((sym, "insufficient"))
                                continue
                            if any(
                                k in lowers
                                for k in (
                                    "update ",
                                    "insert ",
                                    "delete ",
                                    "select ",
                                    "deadlock",
                                    "stacktrace",
                                    "`",
                                )
                            ):
                                short_msg = f"[REDACTED SERVER ERROR: code={w_data.get('code')}]"
                                self.log(
                                    f"❌ Withdraw failed for {sym}: {short_msg}",
                                    Fore.RED,
                                )
                            else:
                                self.log(
                                    f"❌ Withdraw failed for {sym}: {w_data}", Fore.RED
                                )
                            withdraw_failures.append((sym, "other"))
                    except Exception as e:
                        self.log(
                            f"❌ Exception during withdraw for {sym}: {e}", Fore.RED
                        )
                        withdraw_failures.append((sym, "exception"))
                        continue
                if withdraw_successes:
                    self.log(
                        f"✅ Withdraw successes: {', '.join(withdraw_successes)}",
                        Fore.GREEN,
                    )
                if withdraw_failures:
                    failed_syms = ", ".join((f"{s}({t})" for s, t in withdraw_failures))
                    self.log(
                        f"⚠ Withdraw had failures for: {failed_syms} — attempted remaining tokens.",
                        Fore.YELLOW,
                    )
                if not withdraw_successes:
                    self.log(
                        "⚠ No withdraws succeeded (all tokens failed or nothing to withdraw).",
                        Fore.YELLOW,
                    )
            else:
                self.log("⚠ No supplies recorded; skipping withdraw step.", Fore.YELLOW)
            return True
        except Exception as e:
            self.log(f"❌ Fatal error in suplay(): {e}", Fore.RED)
            return False
        finally:
            try:
                self.clear_locals()
            except Exception:
                pass

    def swap(self) -> bool:
        """
        Swap routine (fallback rates only).
        - If server returns an error indicating insufficient balance (or similar),
        exit immediately and return False.
        - Otherwise proceed with forward swaps then reverse swaps as before.
        """
        RETRIES = 2
        BACKOFF = 0.5
        FROM_SYMBOL = "BSD"
        TO_SYMBOL = "AAPL"
        FROM_AMOUNT_STR = "0.01"
        RATE_BSD_TO_AAPL = 0.399179
        RATE_AAPL_TO_BSD = 2.50514
        try:
            self.log("📡 Fetching earn/info for balance check...", Fore.CYAN)
            earn_resp, earn_data = self._request(
                "GET",
                "earn/info",
                timeout=DEFAULT_TIMEOUT,
                parse=True,
                retries=RETRIES,
                backoff=BACKOFF,
            )
            if not isinstance(earn_data, dict):
                self.log("❌ Unexpected earn/info format.", Fore.RED)
                return False
            if earn_data.get("code") != 0:
                self.log(
                    f"❌ earn/info returned error code: {earn_data.get('code')}",
                    Fore.RED,
                )
                return False
            ed = earn_data.get("data") or {}
            balance_str = str(ed.get("balance", "0"))
            try:
                balance_val = float(balance_str)
            except Exception:
                self.log("❌ Invalid balance format; cannot parse float.", Fore.RED)
                return False
            self.log("💰 Current balance: " + balance_str, Fore.CYAN)
            try:
                from_amount_val = float(FROM_AMOUNT_STR)
            except Exception:
                self.log("❌ Invalid FROM_AMOUNT in code.", Fore.RED)
                return False
            if balance_val < from_amount_val:
                self.log(
                    f"⚠ Balance too low to perform any swap (need {from_amount_val}).",
                    Fore.YELLOW,
                )
                return False
            initial_balance = balance_val
            target_swap_total = initial_balance / 2.0
            max_iters_by_balance = int(balance_val // from_amount_val)
            max_iters_by_target = int(target_swap_total // from_amount_val)
            swap_iters = min(max_iters_by_balance, max_iters_by_target)
            if swap_iters <= 0:
                self.log(
                    "⚠ Nothing to swap based on the target/amount calculation.",
                    Fore.YELLOW,
                )
                return False
            self.log(
                f"🔁 Will attempt up to {swap_iters} forward swap iterations (BSD->{TO_SYMBOL}) of {FROM_AMOUNT_STR} each.",
                Fore.MAGENTA,
            )
            successful_swaps = 0
            failed_swaps = 0
            swapped_aapl_total = 0.0
            for i in range(swap_iters):
                to_amount_val = from_amount_val * RATE_BSD_TO_AAPL
                to_amount_str = f"{to_amount_val:.6f}".rstrip("0").rstrip(".")
                payload = {
                    "from_symbol": FROM_SYMBOL,
                    "to_symbol": TO_SYMBOL,
                    "from_amount": FROM_AMOUNT_STR,
                    "to_amount": to_amount_str,
                }
                try:
                    self.log(
                        f"📤 Swap #{i + 1}/{swap_iters}: {FROM_AMOUNT_STR} {FROM_SYMBOL} -> {to_amount_str} {TO_SYMBOL} ...",
                        Fore.CYAN,
                    )
                    swap_resp, swap_data = self._request(
                        "POST",
                        "swap",
                        json_data=payload,
                        timeout=DEFAULT_TIMEOUT,
                        parse=True,
                        retries=RETRIES,
                        backoff=BACKOFF,
                    )
                    if not isinstance(swap_data, dict):
                        text = getattr(swap_resp, "text", str(swap_data))
                        self.log(f"❌ Unexpected swap response: {text}", Fore.RED)
                        failed_swaps += 1
                        continue
                    if swap_data.get("code") == 0:
                        self.log(f"✅ Swap #{i + 1} response OK.", Fore.GREEN)
                        successful_swaps += 1
                        swapped_aapl_total += to_amount_val
                        balance_val -= from_amount_val
                    else:
                        raw_msg = ""
                        try:
                            raw_msg = str(
                                swap_data.get("message", "")
                                or swap_data.get("data", "")
                                or ""
                            )
                        except Exception:
                            raw_msg = ""
                        lowers = raw_msg.lower()
                        if any(
                            k in lowers
                            for k in (
                                "insufficient",
                                "not enough",
                                "insufficient balance",
                                "balance",
                            )
                        ):
                            self.log(
                                f"❌ Server indicates insufficient balance during swap: {raw_msg}",
                                Fore.RED,
                            )
                            return False
                        if any(
                            k in lowers
                            for k in (
                                "update ",
                                "insert ",
                                "delete ",
                                "select ",
                                "deadlock",
                                "stacktrace",
                                "`",
                            )
                        ):
                            short_msg = (
                                f"[REDACTED SERVER ERROR: code={swap_data.get('code')}]"
                            )
                            self.log(
                                f"❌ Swap #{i + 1} failed for {FROM_SYMBOL}->{TO_SYMBOL}: {short_msg}",
                                Fore.RED,
                            )
                        else:
                            self.log(f"❌ Swap #{i + 1} failed: {swap_data}", Fore.RED)
                        failed_swaps += 1
                    if balance_val < from_amount_val:
                        self.log(
                            "⚠ Remaining balance insufficient for further forward swaps. Stopping.",
                            Fore.YELLOW,
                        )
                        break
                except Exception as e:
                    self.log(f"❌ Exception during swap #{i + 1}: {e}", Fore.RED)
                    failed_swaps += 1
            self.log(
                f"🔁 Forward swap done: {successful_swaps} success, {failed_swaps} failed. Total AAPL received ~ {swapped_aapl_total:.6f}",
                Fore.MAGENTA,
            )
            if successful_swaps == 0:
                self.log(
                    "⚠ No successful forward swaps performed; aborting reverse swaps.",
                    Fore.YELLOW,
                )
                return True
            self.log(
                f"↩️ Starting reverse swaps (AAPL -> BSD) for {successful_swaps} iterations...",
                Fore.CYAN,
            )
            rev_success = 0
            rev_failed = 0
            returned_bsd_total = 0.0
            for i in range(successful_swaps):
                aapl_chunk = (
                    swapped_aapl_total / successful_swaps if successful_swaps else 0.0
                )
                if aapl_chunk <= 0:
                    self.log("⚠ No AAPL chunk to reverse-swap; skipping.", Fore.YELLOW)
                    break
                to_amount_rev_val = aapl_chunk * RATE_AAPL_TO_BSD
                to_amount_rev_str = f"{to_amount_rev_val:.6f}".rstrip("0").rstrip(".")
                payload = {
                    "from_symbol": TO_SYMBOL,
                    "to_symbol": FROM_SYMBOL,
                    "from_amount": f"{aapl_chunk:.6f}".rstrip("0").rstrip("."),
                    "to_amount": to_amount_rev_str,
                }
                try:
                    self.log(
                        f"📤 Reverse Swap #{i + 1}/{successful_swaps}: {payload['from_amount']} {TO_SYMBOL} -> {to_amount_rev_str} {FROM_SYMBOL} ...",
                        Fore.CYAN,
                    )
                    swap_resp, swap_data = self._request(
                        "POST",
                        "swap",
                        json_data=payload,
                        timeout=DEFAULT_TIMEOUT,
                        parse=True,
                        retries=RETRIES,
                        backoff=BACKOFF,
                    )
                    if not isinstance(swap_data, dict):
                        text = getattr(swap_resp, "text", str(swap_data))
                        self.log(
                            f"❌ Unexpected reverse swap response: {text}", Fore.RED
                        )
                        rev_failed += 1
                        continue
                    if swap_data.get("code") == 0:
                        self.log(f"✅ Reverse swap #{i + 1} OK.", Fore.GREEN)
                        rev_success += 1
                        returned_bsd_total += to_amount_rev_val
                        balance_val += to_amount_rev_val
                    else:
                        raw_msg = ""
                        try:
                            raw_msg = str(
                                swap_data.get("message", "")
                                or swap_data.get("data", "")
                                or ""
                            )
                        except Exception:
                            raw_msg = ""
                        lowers = raw_msg.lower()
                        if any(
                            k in lowers
                            for k in (
                                "insufficient",
                                "not enough",
                                "insufficient balance",
                                "balance",
                            )
                        ):
                            self.log(
                                f"❌ Server indicates insufficient balance during reverse swap: {raw_msg}",
                                Fore.RED,
                            )
                            return False
                        if any(
                            k in lowers
                            for k in (
                                "update ",
                                "insert ",
                                "delete ",
                                "select ",
                                "deadlock",
                                "stacktrace",
                                "`",
                            )
                        ):
                            short_msg = (
                                f"[REDACTED SERVER ERROR: code={swap_data.get('code')}]"
                            )
                            self.log(
                                f"❌ Reverse swap #{i + 1} failed: {short_msg}",
                                Fore.RED,
                            )
                        else:
                            self.log(
                                f"❌ Reverse swap #{i + 1} failed: {swap_data}",
                                Fore.RED,
                            )
                        rev_failed += 1
                except Exception as e:
                    self.log(
                        f"❌ Exception during reverse swap #{i + 1}: {e}", Fore.RED
                    )
                    rev_failed += 1
            final_estimate = balance_val
            profit_est = final_estimate - initial_balance
            try:
                profit_pct = (
                    profit_est / initial_balance * 100.0 if initial_balance else 0.0
                )
            except Exception:
                profit_pct = 0.0
            self.log("🔚 Swap routine finished.", Fore.GREEN)
            self.log(f"    - initial_balance: {initial_balance:.6f}", Fore.CYAN)
            self.log(f"    - final_estimate_balance: {final_estimate:.6f}", Fore.CYAN)
            self.log(
                f"    - net change (est): {profit_est:.8f} ({profit_pct:.6f}%)",
                Fore.CYAN,
            )
            self.log(
                f"    - forward_success: {successful_swaps}, forward_failed: {failed_swaps}",
                Fore.CYAN,
            )
            self.log(
                f"    - reverse_success: {rev_success}, reverse_failed: {rev_failed}",
                Fore.CYAN,
            )
            return True
        except Exception as e:
            self.log(f"❌ Fatal error in swap(): {e}", Fore.RED)
            return False
        finally:
            try:
                self.clear_locals()
            except Exception:
                pass

    def load_proxies(self, filename="proxy.txt"):
        try:
            if not os.path.exists(filename):
                return []
            with open(filename, encoding="utf-8") as file:
                proxies = list(
                    dict.fromkeys([line.strip() for line in file if line.strip()])
                )
            if not proxies:
                raise ValueError("Proxy file is empty.")
            return proxies
        except Exception as e:
            self.log(f"❌ Proxy load error: {e}", Fore.RED)
            return []

    def decode_response(self, response: object) -> object:
        if isinstance(response, str):
            try:
                return json.loads(response)
            except json.JSONDecodeError:
                return response
        content_encoding = getattr(response.headers, "get", lambda k, d=None: d)(
            "Content-Encoding", ""
        ).lower()
        data = response.content
        try:
            if content_encoding == "gzip":
                data = gzip.decompress(data)
            elif content_encoding in ["br", "brotli"]:
                data = brotli.decompress(data)
            elif content_encoding in ["deflate", "zlib"]:
                data = zlib.decompress(data)
        except Exception:
            pass
        content_type = getattr(response.headers, "get", lambda k, d=None: d)(
            "Content-Type", ""
        ).lower()
        charset = "utf-8"
        if "charset=" in content_type:
            charset = content_type.split("charset=")[-1].split(";")[0].strip()
        try:
            text = data.decode(charset)
        except Exception:
            detected = chardet.detect(data)
            text = data.decode(detected.get("encoding", "utf-8"), errors="replace")
        stripped = text.strip()
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                return json.loads(stripped)
            except json.JSONDecodeError:
                pass
        return text

    def prepare_session(self) -> None:
        try:
            if self.config.get("proxy") and (not getattr(self, "proxy_manager", None)):
                try:
                    self.proxy_manager = ProxyManager(
                        self.proxy_list or [], test_url=self.BASE_URL, test_timeout=4.0
                    )
                except Exception:
                    self.proxy_manager = None
        except Exception:
            pass

        class TimeoutHTTPAdapter(HTTPAdapter):
            def __init__(self, *args, **kwargs):
                self.timeout = kwargs.pop("timeout", 10)
                super().__init__(*args, **kwargs)

            def send(self, request, **kwargs):
                kwargs["timeout"] = kwargs.get("timeout", self.timeout)
                return super().send(request, **kwargs)

        session = requests.Session()
        retries = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST"],
            raise_on_status=False,
        )
        adapter = TimeoutHTTPAdapter(max_retries=retries, timeout=10)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        try:
            ua = self.get_ua()
            headers = (
                {**self.HEADERS, "User-Agent": ua.random} if ua else {**self.HEADERS}
            )
            session.headers.update(headers)
        except Exception as e:
            self.log(f"⚠️ UA warning: {e}", Fore.YELLOW)
        self.proxy = None
        if self.config.get("proxy") and self.proxy_manager:
            tried_proxies = set()
            total_proxies = len(self.proxy_list)
            result = {"proxy": None}

            def test_proxy(proxy: str):
                if result["proxy"]:
                    return
                test_sess = requests.Session()
                test_sess.headers.update(session.headers)
                test_sess.proxies = {"http": proxy, "https": proxy}
                try:
                    resp = test_sess.get("https://httpbin.org/ip", timeout=5)
                    resp.raise_for_status()
                    ip = resp.json().get("origin", "Unknown")
                    if not result["proxy"]:
                        result["proxy"] = proxy
                        self.log(f"✅ Proxy ok: {proxy}", Fore.GREEN)
                        time.sleep(0.5)
                except Exception:
                    pass

            threads = []
            shuffled_proxies = self.proxy_list[:]
            random.shuffle(shuffled_proxies)
            proxy_iter = iter(shuffled_proxies)
            while not result["proxy"] and len(tried_proxies) < total_proxies:
                threads.clear()
                for _ in range(2):
                    try:
                        proxy = next(proxy_iter)
                        if proxy in tried_proxies:
                            continue
                        tried_proxies.add(proxy)
                        t = threading.Thread(target=test_proxy, args=(proxy,))
                        threads.append(t)
                        t.start()
                    except StopIteration:
                        break
                for t in threads:
                    t.join()
            if result["proxy"]:
                session.proxies = {"http": result["proxy"], "https": result["proxy"]}
                self.proxy = result["proxy"]
                self._proxy_use_count = 0
            else:
                if not self._suppress_local_session_log:
                    self.log("⚠️ No working proxy, using local", Fore.YELLOW)
                session.proxies = {}
        else:
            session.proxies = {}
            if not self._suppress_local_session_log:
                self.log("🌐 Using local IP (no proxy)", Fore.YELLOW)
        self.session = session

    def close(self):
        try:
            if hasattr(self, "session") and self.session:
                try:
                    self.session.close()
                except Exception:
                    pass
                self.session = None
        finally:
            self.proxy = None
            if hasattr(self, "proxy_list"):
                self.proxy_list = []


tasks_config = {"swap": "Auto swap", "suplay": "Auto suplay"}


async def process_account(account, original_index, account_label, blu: blockstreet):
    display_account = account[:12] + "..." if len(account) > 12 else account
    blu.log(f"👤 {account_label}: {display_account}", Fore.YELLOW)
    try:
        blu.config = blu.load_config(suppress_log=True)
    except Exception:
        blu.config = blu.config or {}
    if blu.config.get("proxy") and (not getattr(blu, "proxy_manager", None)):
        try:
            blu.proxy_manager = ProxyManager(blu.proxy_list or [])
        except Exception:
            blu.proxy_manager = None
    await run_in_thread(blu.login, original_index)
    cfg = blu.config or {}
    enabled = [name for key, name in tasks_config.items() if cfg.get(key, False)]
    if enabled:
        blu.log("🛠️ Tasks enabled: " + ", ".join(enabled), Fore.CYAN)
    else:
        blu.log("🛠️ Tasks enabled: (none)", Fore.RED)
    for task_key, task_name in tasks_config.items():
        task_status = cfg.get(task_key, False)
        if task_status:
            if not hasattr(blu, task_key) or not callable(getattr(blu, task_key)):
                blu.log(f"⚠️ {task_key} missing", Fore.YELLOW)
                continue
            try:
                await run_in_thread(getattr(blu, task_key))
            except Exception as e:
                blu.log(f"❌ {task_key} error: {e}", Fore.RED)
    delay_switch = cfg.get("delay_account_switch", 10)
    blu.log(f"➡️ Done {account_label}. wait {delay_switch}s", Fore.CYAN)
    await asyncio.sleep(delay_switch)
    if blu.config.get("proxy") and getattr(blu, "proxy_manager", None) and blu.proxy:
        try:
            blu.proxy_manager.release_proxy(blu.proxy)
            blu.log("🔁 Proxy released", Fore.GREEN)
        except Exception:
            blu.log("⚠️ release proxy failed", Fore.YELLOW)
        finally:
            blu.proxy = None


async def stream_producer(
    file_path: str,
    queue: asyncio.Queue,
    stop_event: asyncio.Event,
    base_blu: blockstreet,
    poll_interval=0.8,
    dedupe=True,
):
    idx = 0
    seen = BoundedSet(maxlen=10000) if dedupe else None
    f = None
    inode = None
    first_open = True

    def handle_cmd(line: str):
        cmd = line[len("__CMD__") :].strip()
        if cmd.upper().startswith("SET "):
            body = cmd[4:].split("=", 1)
            if len(body) == 2:
                k, v = (body[0].strip(), body[1].strip())
                if v.lower() in ("true", "false"):
                    parsed = v.lower() == "true"
                else:
                    try:
                        parsed = int(v)
                    except:
                        try:
                            parsed = float(v)
                        except:
                            parsed = v
                base_blu.config[k] = parsed
                base_blu.log(f"⚙️ set {k}={parsed}", Fore.CYAN)
        elif cmd.upper() == "RELOAD_CONFIG":
            base_blu.config = base_blu.load_config()
            base_blu.log("🔁 reload config", Fore.CYAN)
        elif cmd.upper() == "SHUTDOWN":
            stop_event.set()
            base_blu.log("⛔ shutdown", Fore.MAGENTA)
        else:
            base_blu.log(f"⚠️ unknown cmd: {cmd}", Fore.YELLOW)

    while not stop_event.is_set():
        if f is None:
            try:
                f = open(file_path, encoding="utf-8")
                try:
                    inode = os.fstat(f.fileno()).st_ino
                except Exception:
                    inode = None
                if first_open:
                    first_open = False
                    f.seek(0)
                    for line in f:
                        line = line.strip()
                        if not line:
                            idx += 1
                            continue
                        if line.startswith("__CMD__"):
                            try:
                                handle_cmd(line)
                            except Exception:
                                base_blu.log("❌ cmd error", Fore.RED)
                            idx += 1
                            continue
                        if seen is not None:
                            if line in seen:
                                idx += 1
                                continue
                            seen.add(line)
                        await queue.put((idx, line))
                        idx += 1
                    f.seek(0, os.SEEK_END)
                else:
                    f.seek(0, os.SEEK_END)
            except FileNotFoundError:
                await asyncio.sleep(poll_interval)
                continue
        line = f.readline()
        if not line:
            await asyncio.sleep(poll_interval)
            try:
                st = os.stat(file_path)
                if inode is not None and st.st_ino != inode:
                    try:
                        f.close()
                    except:
                        pass
                    f = open(file_path, encoding="utf-8")
                    inode = os.fstat(f.fileno()).st_ino
                    f.seek(0, os.SEEK_END)
                elif f.tell() > st.st_size:
                    f.seek(0, os.SEEK_END)
            except FileNotFoundError:
                try:
                    if f:
                        f.close()
                except:
                    pass
                f = None
                inode = None
            continue
        line = line.strip()
        if not line:
            continue
        if line.startswith("__CMD__"):
            try:
                handle_cmd(line)
            except Exception:
                base_blu.log("❌ cmd error", Fore.RED)
            continue
        if seen is not None:
            if line in seen:
                continue
            seen.add(line)
        await queue.put((idx, line))
        idx += 1
    try:
        if f:
            f.close()
    except:
        pass


async def once_producer(file_path: str, queue: asyncio.Queue):
    idx = 0
    try:
        with open(file_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    idx += 1
                    continue
                if line.startswith("__CMD__"):
                    idx += 1
                    continue
                await queue.put((idx, line))
                idx += 1
    except FileNotFoundError:
        return


_BG_THREAD_TASKS: set = set()


async def run_in_thread(fn, *args, **kwargs):
    """
    Wrapper around asyncio.to_thread that registers the created task into
    _BG_THREAD_TASKS so main dapat menunggu semua background threads finish.
    Use this instead of direct asyncio.to_thread(...) for long-running background ops.
    """
    coro = asyncio.to_thread(fn, *args, **kwargs)
    task = asyncio.create_task(coro)
    _BG_THREAD_TASKS.add(task)
    try:
        return await task
    finally:
        _BG_THREAD_TASKS.discard(task)


async def worker(worker_id: int, base_blu: blockstreet, queue: asyncio.Queue):
    blu = blockstreet(
        use_proxy=base_blu.config.get("proxy", False),
        proxy_list=base_blu.proxy_list,
        load_on_init=False,
    )
    try:
        blu.query_list = list(base_blu.query_list)
    except Exception:
        blu.query_list = []
    blu.log(f"👷 Worker-{worker_id} started", Fore.CYAN)
    while True:
        try:
            original_index, account = await queue.get()
        except asyncio.CancelledError:
            break
        account_label = f"W{worker_id}-A{original_index + 1}"
        try:
            await process_account(account, original_index, account_label, blu)
        except Exception as e:
            blu.log(f"❌ {account_label} error: {e}", Fore.RED)
        finally:
            try:
                queue.task_done()
            except Exception:
                pass
    await run_in_thread(blu.close)
    base_blu.log(f"🧾 Worker-{worker_id} stopped", Fore.CYAN)


def estimate_network_latency(host="1.1.1.1", port=53, attempts=2, timeout=0.6):
    latencies = []
    for _ in range(attempts):
        try:
            t0 = time.time()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            s.close()
            latencies.append(time.time() - t0)
        except Exception:
            latencies.append(timeout)
    try:
        return statistics.median(latencies)
    except:
        return timeout


def auto_tune_config_respecting_thread(
    existing_cfg: dict | None = None, prefer_network_check: bool = True
) -> dict:
    cfg = dict(existing_cfg or {})
    try:
        phys = psutil.cpu_count(logical=False) or 1
        logical = psutil.cpu_count(logical=True) or phys
    except:
        phys = logical = 1
    try:
        total_mem_gb = psutil.virtual_memory().total / 1024**3
    except:
        total_mem_gb = 1.0
    try:
        disk_free_gb = shutil.disk_usage(os.getcwd()).free / 1024**3
    except:
        disk_free_gb = 1.0
    net_lat = estimate_network_latency() if prefer_network_check else 1.0
    user_thread = cfg.get("thread", None)
    if user_thread is None:
        if logical >= 8:
            rec_thread = min(32, logical * 2)
        else:
            rec_thread = max(1, logical)
    else:
        rec_thread = int(user_thread)
    if total_mem_gb < 1.0:
        per_t = 20
    elif total_mem_gb < 2.5:
        per_t = 75
    elif total_mem_gb < 8:
        per_t = 200
    else:
        per_t = 1000
    q_recommend = int(min(max(50, rec_thread * per_t), 1000))
    if total_mem_gb < 1 or phys <= 1:
        poll = 1.0
    elif net_lat < 0.05:
        poll = 0.2
    elif net_lat < 0.2:
        poll = 0.5
    else:
        poll = 0.8
    dedupe = bool(total_mem_gb < 2.0)
    run_mode = cfg.get("run_mode", "continuous")
    merged = dict(cfg)
    if "queue_maxsize" not in merged:
        merged["queue_maxsize"] = q_recommend
    if "poll_interval" not in merged:
        merged["poll_interval"] = poll
    if "dedupe" not in merged:
        merged["dedupe"] = dedupe
    if "run_mode" not in merged:
        merged["run_mode"] = run_mode
    merged["_autotune_meta"] = {
        "phys_cores": int(phys),
        "logical_cores": int(logical),
        "total_mem_gb": round(total_mem_gb, 2),
        "disk_free_gb": round(disk_free_gb, 2),
        "net_latency_s": round(net_lat, 3),
        "queue_recommendation": int(q_recommend),
        "poll_recommendation": float(poll),
    }
    return merged


async def dynamic_tuner_nonthread(
    base_blu, queue: asyncio.Queue, stop_event: asyncio.Event, interval=6.0
):
    base_blu.log("🤖 Tuner started (non-thread)", Fore.CYAN)
    while not stop_event.is_set():
        try:
            cpu = psutil.cpu_percent(interval=None)
            qsize = queue.qsize() if queue is not None else 0
            cur_q = int(base_blu.config.get("queue_maxsize", 200))
            cur_poll = float(base_blu.config.get("poll_interval", 0.8))
            cur_dedupe = bool(base_blu.config.get("dedupe", True))
            cap = max(50, cur_q)
            if qsize > 0.8 * cap and cpu < 85:
                new_q = min(cur_q * 2, 10000)
            elif qsize < 0.2 * cap and cur_q > 100:
                new_q = max(int(cur_q / 2), 50)
            else:
                new_q = cur_q
            if cpu > 80:
                new_poll = min(cur_poll + 0.2, 2.0)
            elif cpu < 30 and qsize > 0.2 * cap:
                new_poll = max(cur_poll - 0.1, 0.1)
            else:
                new_poll = cur_poll
            vm = psutil.virtual_memory()
            if vm.available / 1024**2 < 200 and cur_dedupe:
                new_dedupe = False
            else:
                new_dedupe = cur_dedupe
            changed = []
            if new_q != cur_q:
                base_blu.config["queue_maxsize"] = int(new_q)
                changed.append(f"q:{cur_q}->{new_q}")
            if abs(new_poll - cur_poll) > 0.01:
                base_blu.config["poll_interval"] = float(round(new_poll, 3))
                changed.append(f"p:{cur_poll}->{round(new_poll, 3)}")
            if new_dedupe != cur_dedupe:
                base_blu.config["dedupe"] = bool(new_dedupe)
                changed.append(f"d:{cur_dedupe}->{new_dedupe}")
            if changed:
                base_blu.log("🔧 Tuner: " + ", ".join(changed), Fore.MAGENTA)
        except Exception:
            base_blu.log("⚠️ tuner error", Fore.YELLOW)
        await asyncio.sleep(interval)
    base_blu.log("🤖 Tuner stopped", Fore.MAGENTA)


async def producer_once(file_path, queue: asyncio.Queue):
    idx = 0
    try:
        with open(file_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    idx += 1
                    continue
                if line.startswith("__CMD__"):
                    idx += 1
                    continue
                await queue.put((idx, line))
                idx += 1
    except FileNotFoundError:
        return


def cleanup_after_batch(base_blu, keep_refs: dict | None = None, deep=False):
    """
    Best-effort cleanup between batches:
    - clear caches, temp attrs, finished tasks
    - reset cookies
    - optional deep mode (reset all attrs except core)
    - run gc.collect()
    """
    try:
        try:
            for t in list(_BG_THREAD_TASKS):
                if getattr(t, "done", lambda: False)():
                    _BG_THREAD_TASKS.discard(t)
        except Exception:
            pass
        sess = getattr(base_blu, "session", None)
        if sess is not None:
            try:
                sess.cookies.clear()
            except Exception:
                pass
        if keep_refs is None:
            keep_refs = {}
        for k in ("last_items", "promo_data", "last_shop", "items_data"):
            if k not in keep_refs:
                try:
                    setattr(base_blu, k, None)
                except Exception:
                    pass
        if deep:
            for name in list(vars(base_blu).keys()):
                if name.startswith("_") or name in (
                    "logger",
                    "log",
                    "session",
                    "config",
                ):
                    continue
                try:
                    setattr(base_blu, name, None)
                except Exception:
                    pass
        try:
            gc.collect()
        except Exception:
            pass
        try:
            emoji = random.choice(["🧹", "♻️", "🧽", "🌀", "🚿"])
            base_blu.log(
                f"{emoji} cleanup done | {memory_monitor()}", Fore.LIGHTBLACK_EX
            )
        except Exception:
            pass
    except Exception as e:
        try:
            base_blu.log(f"⚠️ cleanup error: {e}", Fore.YELLOW)
        except Exception:
            pass


def memory_monitor():
    try:
        p = psutil.Process()
        mem = p.memory_info().rss
        return f"RSS={mem / 1024 / 1024:.2f} MB"
    except Exception:
        tracemalloc.start()
        s = tracemalloc.take_snapshot()
        total = sum([stat.size for stat in s.statistics("filename")])
        return f"tracemalloc_total={total / 1024 / 1024:.2f} MB"


async def main():
    base_blu = blockstreet()
    cfg_file = base_blu.config
    effective = auto_tune_config_respecting_thread(cfg_file)
    run_mode = "repeat"
    base_blu.config = effective
    base_blu.log(
        f"🎉 [LIVEXORDS] === Welcome to {NAME_BOT} Automation === [LIVEXORDS]",
        Fore.YELLOW,
    )
    cfg_summary = {
        "thread": int(effective.get("thread", 1)),
        "queue_maxsize": int(effective.get("queue_maxsize", 200)),
        "poll_interval": float(effective.get("poll_interval", 0.8)),
        "dedupe": bool(effective.get("dedupe", True)),
        "delay_loop": int(effective.get("delay_loop", 30)),
        "delay_account_switch": int(effective.get("delay_account_switch", 10)),
        "proxy": bool(effective.get("proxy", False)),
    }
    base_blu.log("")
    base_blu.log("🔧 Effective config:", Fore.CYAN)
    for k, v in cfg_summary.items():
        base_blu.log(f"    • {k:<20}: {v}", Fore.CYAN)
    base_blu.log("📊 Autotune metadata:", Fore.MAGENTA)
    meta = effective.get("_autotune_meta", {})
    for k, v in meta.items():
        base_blu.log(f"    • {k:<20}: {v}", Fore.MAGENTA)
    query_file = effective.get("query_file", "query.txt")
    queue_maxsize = int(effective.get("queue_maxsize", 200))
    poll_interval = float(effective.get("poll_interval", 0.8))
    dedupe = bool(effective.get("dedupe", True))
    num_threads = int(effective.get("thread", 1))
    base_blu.banner()
    base_blu.log(f"📂 {query_file} | q={queue_maxsize} | mode={run_mode}", Fore.YELLOW)
    stop_event = asyncio.Event()
    try:
        loop = asyncio.get_running_loop()
        try:
            loop.add_signal_handler(signal.SIGINT, lambda: stop_event.set())
            loop.add_signal_handler(signal.SIGTERM, lambda: stop_event.set())
        except Exception:
            pass
    except Exception:
        pass
    while True:
        try:
            base_blu.query_list = base_blu.load_query(
                base_blu.config.get("query_file", query_file)
            )
        except Exception:
            base_blu.query_list = base_blu.load_query(query_file)
        queue = asyncio.Queue(maxsize=queue_maxsize)
        tuner_task = asyncio.create_task(
            dynamic_tuner_nonthread(base_blu, queue, stop_event)
        )
        prod_task = asyncio.create_task(producer_once(query_file, queue))
        workers = [
            asyncio.create_task(worker(i + 1, base_blu, queue))
            for i in range(num_threads)
        ]
        try:
            await prod_task
            await queue.join()
        except asyncio.CancelledError:
            pass
        for w in workers:
            w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
        tuner_task.cancel()
        try:
            await tuner_task
        except:
            pass
        if _BG_THREAD_TASKS:
            base_blu.log(
                f"⏳ waiting for {len(_BG_THREAD_TASKS)} background thread(s) to finish...",
                Fore.CYAN,
            )
            await asyncio.gather(*list(_BG_THREAD_TASKS), return_exceptions=True)
        try:
            sys.stdout.flush()
        except Exception:
            pass
        try:
            cleanup_after_batch(base_blu)
        except Exception:
            pass
        try:
            prod_task = None
            workers = None
            queue = None
        except Exception:
            pass
        base_blu.log("🔁 batch done", Fore.CYAN)
        base_blu.log(f"🧾 {memory_monitor()}", Fore.MAGENTA)
        delay_loop = int(effective.get("delay_loop", 30))
        base_blu.log(f"⏳ sleep {delay_loop}s before next batch", Fore.CYAN)
        for _ in range(delay_loop):
            if stop_event.is_set():
                break
            await asyncio.sleep(1)
        if stop_event.is_set():
            break
    stop_event.set()
    base_blu.log("✅ shutdown", Fore.MAGENTA)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Interrupted by user. Exiting...")
