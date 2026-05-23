# -*- coding: utf-8 -*-
"""
MidONe Scanner SK v6.1 - Android App
Shir Khorshid CDN IP Scanner
Telegram: @mmdrlx
"""

import re
import threading
import time
import socket
import ssl
import statistics
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from collections import defaultdict

from kivy.utils import platform
from kivy.app import App
from kivy.clock import Clock
from kivy.core.clipboard import Clipboard
from kivy.lang import Builder
from kivy.uix.screenmanager import ScreenManager, Screen, FadeTransition
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.scrollview import ScrollView
from kivy.uix.label import Label
from kivy.properties import (
    StringProperty, NumericProperty,
    ListProperty, BooleanProperty, ObjectProperty
)
from kivy.metrics import dp
from kivy.uix.widget import Widget
from kivy.graphics import Color, RoundedRectangle

if platform == 'android':
    try:
        from android.permissions import request_permissions, Permission
        request_permissions([
            Permission.INTERNET,
            Permission.WRITE_EXTERNAL_STORAGE,
            Permission.READ_EXTERNAL_STORAGE,
        ])
    except Exception:
        pass

# ─────────────────────────────────────────────
#  SCANNER ENGINE
# ─────────────────────────────────────────────

CDN_MAP = {
    "Cloudflare": {
        "headers":  ["cf-ray", "cf-cache-status", "cf-request-id"],
        "server":   ["cloudflare"],
        "snis":     ["speed.cloudflare.com", "cloudflare.com"],
        "endpoint": "/__down?bytes=8000000",
    },
    "Akamai": {
        "headers":  ["x-check-cacheable", "x-serial", "x-true-cache-key", "akamai-origin-hop"],
        "server":   ["akamaighost", "akamai"],
        "snis":     ["a248.e.akamai.net", "a77.net.akamai.net", "a104.net.akamai.net",
                     "a184.net.akamai.net", "ds-aksb.akamaized.net", "ak.net.akamaized.net"],
        "endpoint": "/",
    },
    "Google": {
        "headers":  ["x-goog-generation", "x-guploader-uploadid", "x-goog-hash"],
        "server":   ["gws", "google frontend", "esf", "sffe"],
        "snis":     ["fonts.googleapis.com", "google.com", "www.google.com"],
        "endpoint": "/",
    },
    "Amazon": {
        "headers":  ["x-amz-cf-id", "x-amz-cf-pop", "x-amz-request-id"],
        "server":   ["amazons3", "cloudfront"],
        "snis":     ["d1.cloudfront.net", "aws.amazon.com"],
        "endpoint": "/",
    },
    "Azure": {
        "headers":  ["x-azure-ref", "x-msedge-ref", "x-ec-custom-error"],
        "server":   ["microsoft-azure", "ecd"],
        "snis":     ["ajax.aspnetcdn.com"],
        "endpoint": "/",
    },
    "Fastly": {
        "headers":  ["x-served-by", "x-fastly-request-id", "x-cache-hits"],
        "server":   ["varnish"],
        "snis":     ["global.fastly.net"],
        "endpoint": "/",
    },
    "Iranian": {
        "headers":  [],
        "server":   [],
        "snis":     ["aparat.com", "snapp.ir", "digikala.com",
                     "telewebion.com", "varzesh3.com", "bmi.ir"],
        "endpoint": "/",
    },
}

ALL_SNIS = []
for _v in CDN_MAP.values():
    for _s in _v["snis"]:
        if _s not in ALL_SNIS:
            ALL_SNIS.append(_s)

CFG = {
    "threads":            20,
    "connect_timeout":    2.5,
    "tls_timeout":        3.0,
    "read_timeout":       5.0,
    "test_duration":      5.0,
    "min_bytes":          4096,
    "throttle_threshold": 0.40,
    "reliability_tries":  5,
    "reliability_min":    3,
}

PRIVATE_RE = [
    r'^10\.', r'^192\.168\.', r'^172\.(1[6-9]|2\d|3[01])\.',
    r'^127\.', r'^0\.', r'^169\.254\.'
]


def is_private(ip):
    return any(re.match(p, ip) for p in PRIVATE_RE)


def parse_ips(text):
    raw = list(set(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text)))
    return [ip for ip in raw if not is_private(ip)]


def ssl_connect(ip, sni, timeout=3.0):
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, 443))
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ss = ctx.wrap_socket(sock, server_hostname=sni)
        return ss, sock
    except Exception:
        if sock:
            try:
                sock.close()
            except Exception:
                pass
        return None, None


def detect_cdn(ip):
    for probe in ["aparat.com", "a248.e.akamai.net", "speed.cloudflare.com"]:
        ss, sock = ssl_connect(ip, probe, CFG["connect_timeout"])
        if not ss:
            continue
        try:
            ss.sendall(
                f"HEAD / HTTP/1.1\r\nHost: {probe}\r\n"
                f"User-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n".encode()
            )
            buf = b""
            ss.settimeout(2.0)
            try:
                while len(buf) < 1024:
                    c = ss.recv(256)
                    if not c:
                        break
                    buf += c
                    if b"\r\n\r\n" in buf:
                        break
            except Exception:
                pass
            hdrs = buf.decode(errors="ignore").lower()
            srv = ""
            for line in hdrs.split("\r\n"):
                if line.startswith("server:"):
                    srv = line.split(":", 1)[1].strip()
                    break
            for name, info in CDN_MAP.items():
                if name == "Iranian":
                    continue
                if any(h in hdrs for h in info["headers"]):
                    return name, info["snis"] + [s for s in ALL_SNIS if s not in info["snis"]]
                if any(sv in srv for sv in info["server"]):
                    return name, info["snis"] + [s for s in ALL_SNIS if s not in info["snis"]]
        except Exception:
            pass
        finally:
            try:
                ss.close()
            except Exception:
                pass
            try:
                sock.close()
            except Exception:
                pass
    return "Unknown", ALL_SNIS


def stage_tls(ip, sni):
    try:
        t = time.time()
        ss, sock = ssl_connect(ip, sni, CFG["tls_timeout"])
        if not ss:
            return False, 9999
        hs = round((time.time() - t) * 1000)
        ss.sendall(
            f"HEAD / HTTP/1.1\r\nHost: {sni}\r\n"
            f"User-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n".encode()
        )
        buf = b""
        ss.settimeout(2.0)
        try:
            while len(buf) < 512:
                c = ss.recv(256)
                if not c:
                    break
                buf += c
                if b"HTTP/" in buf:
                    break
        except Exception:
            pass
        try:
            ss.close()
        except Exception:
            pass
        try:
            sock.close()
        except Exception:
            pass
        if buf and b"HTTP/" in buf:
            return True, hs
        if hs < CFG["tls_timeout"] * 900:
            return True, hs
    except Exception:
        pass
    return False, 9999


def stage_reliability(ip, sni):
    success, lats = 0, []
    for _ in range(CFG["reliability_tries"]):
        ok, ms = stage_tls(ip, sni)
        if ok:
            success += 1
            lats.append(ms)
        time.sleep(0.1)
    reliable = success >= CFG["reliability_min"]
    avg_lat = round(statistics.mean(lats)) if lats else 9999
    return reliable, success, avg_lat


def stage_bandwidth(ip, sni, endpoint="/"):
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(CFG["connect_timeout"])
        sock.connect((ip, 443))
        sock.settimeout(CFG["read_timeout"])
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ss = ctx.wrap_socket(sock, server_hostname=sni)
        ss.sendall(
            f"GET {endpoint} HTTP/1.1\r\nHost: {sni}\r\n"
            f"User-Agent: Mozilla/5.0\r\nAccept: */*\r\n"
            f"Connection: close\r\n\r\n".encode()
        )
        start = time.time()
        total = 0
        first_byte = None
        samples = []
        last_t = start
        while True:
            try:
                chunk = ss.recv(65536)
                if not chunk:
                    break
                now = time.time()
                if first_byte is None:
                    first_byte = now - start
                total += len(chunk)
                if now - last_t >= 1.0:
                    samples.append((total / 1024) / max(now - start, 0.001))
                    last_t = now
                if now - start > CFG["test_duration"]:
                    break
            except socket.timeout:
                break
        try:
            ss.close()
        except Exception:
            pass
        elapsed = time.time() - start
        if elapsed > 0 and total >= CFG["min_bytes"]:
            speed = (total / 1024) / elapsed
            latency = round((first_byte or 0) * 1000)
            jitter = round(statistics.stdev(samples), 1) if len(samples) > 1 else 0
            throttled = False
            throttle_pct = 0
            if len(samples) >= 3:
                mid = len(samples) // 2
                f_avg = statistics.mean(samples[:mid])
                s_avg = statistics.mean(samples[mid:])
                if f_avg > 0:
                    drop = (f_avg - s_avg) / f_avg
                    throttle_pct = round(drop * 100)
                    throttled = drop > CFG["throttle_threshold"]
            return {
                "speed": round(speed, 1),
                "latency": latency,
                "jitter": jitter,
                "throttled": throttled,
                "throttle_pct": throttle_pct,
                "ok": True,
            }
    except Exception:
        pass
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass
    return {"ok": False}


def calc_score(speed, latency, jitter, throttled, reliability=5):
    s = min(speed / 500, 1.0) * 55
    l = max(0, 1 - latency / 800) * 20
    j = max(0, 1 - jitter / max(speed, 1)) * 10
    t = 0 if throttled else 5
    rel = (reliability / CFG["reliability_tries"]) * 10
    return round(s + l + j + t + rel, 1)


def get_grade(speed, throttled, rel=5):
    if throttled:
        return "THROTTLED", [1, 0.27, 0.27, 1]
    if speed > 300 and rel >= 4:
        return "S ***", [0, 1, 0.53, 1]
    if speed > 200:
        return "A **", [0.27, 1, 0.27, 1]
    if speed > 100:
        return "B *", [1, 1, 0.27, 1]
    if speed > 50:
        return "C", [1, 0.67, 0.27, 1]
    return "D", [1, 0.27, 0.27, 1]


def run_scan(ips, mode, progress_cb, result_cb, done_cb, stop_event):
    results = []
    total = len(ips)
    done_count = [0]
    lock = threading.Lock()

    if mode == 1:
        # ── Simple ──
        def test_one(ip):
            if stop_event.is_set():
                return None
            sni = "google.com"
            ok, _ = stage_tls(ip, sni)
            if not ok:
                return None
            bw = stage_bandwidth(ip, sni, "/")
            if bw["ok"]:
                sc = calc_score(bw["speed"], bw["latency"], bw["jitter"], bw["throttled"])
                grade, color = get_grade(bw["speed"], bw["throttled"])
                return {
                    "ip": ip, "sni": sni, "cdn": "Auto",
                    "speed": bw["speed"], "latency": bw["latency"],
                    "jitter": bw["jitter"], "throttled": bw["throttled"],
                    "throttle_pct": bw["throttle_pct"],
                    "reliability": 5, "score": sc,
                    "grade": grade, "color": color,
                }
            return None

        def wrapped_m1(ip):
            r = test_one(ip)
            with lock:
                done_count[0] += 1
                Clock.schedule_once(lambda dt: progress_cb(done_count[0], total))
            if r:
                Clock.schedule_once(lambda dt, _r=r: result_cb(_r))
            return r

        with ThreadPoolExecutor(max_workers=CFG["threads"]) as ex:
            for f in as_completed({ex.submit(wrapped_m1, ip): ip for ip in ips}):
                r = f.result()
                if r:
                    results.append(r)

    else:
        # ── Auto-SNI ──
        def pipeline(ip):
            if stop_event.is_set():
                return []
            res = []
            cdn_name, ordered_snis = detect_cdn(ip)
            cdn_endpoint = CDN_MAP.get(cdn_name, {}).get("endpoint", "/")
            valid = []
            for sni in ordered_snis:
                if stop_event.is_set():
                    break
                ok, _ = stage_tls(ip, sni)
                if not ok:
                    continue
                reliable, rel_count, avg_lat = stage_reliability(ip, sni)
                if reliable:
                    valid.append((sni, rel_count, avg_lat))
            for sni, rel_count, avg_lat in valid:
                if stop_event.is_set():
                    break
                bw = stage_bandwidth(ip, sni, cdn_endpoint)
                if bw["ok"]:
                    sc = calc_score(bw["speed"], bw["latency"], bw["jitter"],
                                    bw["throttled"], rel_count)
                    grade, color = get_grade(bw["speed"], bw["throttled"], rel_count)
                    r = {
                        "ip": ip, "sni": sni, "cdn": cdn_name,
                        "speed": bw["speed"], "latency": bw["latency"],
                        "jitter": bw["jitter"], "throttled": bw["throttled"],
                        "throttle_pct": bw["throttle_pct"],
                        "reliability": rel_count, "score": sc,
                        "grade": grade, "color": color,
                    }
                    Clock.schedule_once(lambda dt, _r=r: result_cb(_r))
                    res.append(r)
            with lock:
                done_count[0] += 1
                Clock.schedule_once(lambda dt: progress_cb(done_count[0], total))
            return res

        with ThreadPoolExecutor(max_workers=CFG["threads"]) as ex:
            for f in as_completed({ex.submit(pipeline, ip): ip for ip in ips}):
                results.extend(f.result())

    results.sort(key=lambda x: x["score"], reverse=True)
    Clock.schedule_once(lambda dt: done_cb(results))


def save_results_to_file(results):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    try:
        if platform == 'android':
            from android.storage import primary_external_storage_path
            base = os.path.join(primary_external_storage_path(), "MidONeScanner")
        else:
            base = os.path.expanduser("~/MidONeScanner")
        os.makedirs(base, exist_ok=True)
        fn = os.path.join(base, f"scan_{ts}.txt")
    except Exception:
        fn = os.path.join(os.path.expanduser("~"), f"scan_{ts}.txt")

    top5 = [r for r in results if not r["throttled"]][:5]
    with open(fn, "w", encoding="utf-8") as f:
        f.write(f"MidONe Scanner SK v6.1 | t.me/mmdrlx | {datetime.now()}\n\n")
        f.write("=== TOP 5 ===\n")
        for i, r in enumerate(top5, 1):
            f.write(
                f"{i}. IP:{r['ip']}  SNI:{r['sni']}  CDN:{r['cdn']}  "
                f"Speed:{r['speed']} KB/s  Score:{r['score']}\n"
            )
        f.write("\n=== ALL RESULTS ===\n")
        f.write(f"{'IP':<17}{'CDN':<12}{'SNI':<30}{'Speed':>10}{'Rel':>5}{'Score':>8}\n")
        f.write("-" * 80 + "\n")
        for r in results:
            thr = " [THR]" if r["throttled"] else ""
            f.write(
                f"{r['ip']:<17}{r['cdn']:<12}{r['sni']:<30}"
                f"{r['speed']:>7.1f} KB/s  {r['reliability']}/5"
                f"{r['score']:>8}{thr}\n"
            )
    return fn


# ─────────────────────────────────────────────
#  KV UI
# ─────────────────────────────────────────────

KV = r"""
#:import get_color_from_hex kivy.utils.get_color_from_hex

<RoundedCard@BoxLayout>:
    canvas.before:
        Color:
            rgba: self.bg_color
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(12)]
    bg_color: get_color_from_hex('#1A1A2E')
    padding: dp(12)
    spacing: dp(8)

<ModeButton@Button>:
    background_color: 0,0,0,0
    background_normal: ''
    color: 1,1,1,1
    font_size: '14sp'
    bold: True
    canvas.before:
        Color:
            rgba: self.btn_color
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(10)]
    btn_color: get_color_from_hex('#263238')

<ActionButton@Button>:
    background_color: 0,0,0,0
    background_normal: ''
    color: 1,1,1,1
    font_size: '15sp'
    bold: True
    size_hint_y: None
    height: dp(52)
    canvas.before:
        Color:
            rgba: self.btn_color
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(14)]
    btn_color: get_color_from_hex('#00C853')

<SmallButton@Button>:
    background_color: 0,0,0,0
    background_normal: ''
    font_size: '12sp'
    size_hint_x: None
    width: dp(70)
    height: dp(32)
    size_hint_y: None
    canvas.before:
        Color:
            rgba: self.btn_color
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(8)]
    btn_color: get_color_from_hex('#263238')

<StatCard@BoxLayout>:
    orientation: 'vertical'
    canvas.before:
        Color:
            rgba: self.bg_color
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(10)]
    bg_color: get_color_from_hex('#1B5E20')
    padding: dp(6)
    spacing: dp(2)

<ResultRow@BoxLayout>:
    orientation: 'vertical'
    size_hint_y: None
    height: dp(88)
    padding: [dp(10), dp(6)]
    spacing: dp(3)
    canvas.before:
        Color:
            rgba: self.bg_color
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [dp(10)]
    bg_color: get_color_from_hex('#1A1A2E')

<ScanScreen>:
    name: 'scan'
    canvas.before:
        Color:
            rgba: get_color_from_hex('#0A0A1A')
        Rectangle:
            pos: self.pos
            size: self.size

    BoxLayout:
        orientation: 'vertical'
        spacing: 0

        # ── TOP BAR ──
        BoxLayout:
            size_hint_y: None
            height: dp(56)
            padding: [dp(14), dp(8)]
            spacing: dp(8)
            canvas.before:
                Color:
                    rgba: get_color_from_hex('#12122A')
                Rectangle:
                    pos: self.pos
                    size: self.size

            Label:
                text: '[b][color=FFD700]MidONe Scanner SK[/color][/b]  [color=888888]v6.1[/color]'
                markup: True
                font_size: '17sp'
                halign: 'left'
                text_size: self.size

            Label:
                text: '[color=40C4FF]@mmdrlx[/color]'
                markup: True
                font_size: '13sp'
                halign: 'right'
                text_size: self.size
                size_hint_x: None
                width: dp(90)

        # ── BODY ──
        ScrollView:
            do_scroll_x: False

            BoxLayout:
                orientation: 'vertical'
                padding: dp(14)
                spacing: dp(10)
                size_hint_y: None
                height: self.minimum_height

                # Mode Card
                BoxLayout:
                    orientation: 'vertical'
                    size_hint_y: None
                    height: dp(110)
                    spacing: dp(8)
                    padding: dp(12)
                    canvas.before:
                        Color:
                            rgba: get_color_from_hex('#1A1A2E')
                        RoundedRectangle:
                            pos: self.pos
                            size: self.size
                            radius: [dp(12)]

                    Label:
                        text: '[b][color=FFD700]Scan Mode[/color][/b]'
                        markup: True
                        font_size: '14sp'
                        size_hint_y: None
                        height: dp(24)
                        halign: 'left'
                        text_size: self.size

                    BoxLayout:
                        orientation: 'horizontal'
                        spacing: dp(10)
                        size_hint_y: None
                        height: dp(52)

                        ModeButton:
                            id: btn_mode1
                            text: '[b]⚡ Simple[/b]'
                            markup: True
                            btn_color: get_color_from_hex('#1565C0') if app.scan_mode==1 else get_color_from_hex('#263238')
                            on_release: app.set_mode(1)

                        ModeButton:
                            id: btn_mode2
                            text: '[b]🧠 Auto-SNI[/b]'
                            markup: True
                            btn_color: get_color_from_hex('#1565C0') if app.scan_mode==2 else get_color_from_hex('#263238')
                            on_release: app.set_mode(2)

                # IP Input Card
                BoxLayout:
                    orientation: 'vertical'
                    size_hint_y: None
                    height: dp(200)
                    spacing: dp(6)
                    padding: dp(12)
                    canvas.before:
                        Color:
                            rgba: get_color_from_hex('#1A1A2E')
                        RoundedRectangle:
                            pos: self.pos
                            size: self.size
                            radius: [dp(12)]

                    BoxLayout:
                        size_hint_y: None
                        height: dp(34)
                        spacing: dp(6)

                        Label:
                            text: '[b][color=FFD700]IP Addresses[/color][/b]'
                            markup: True
                            font_size: '14sp'
                            halign: 'left'
                            text_size: self.size

                        SmallButton:
                            text: '[color=40C4FF]PASTE[/color]'
                            markup: True
                            on_release: app.paste_ips()

                        SmallButton:
                            text: '[color=FF5252]CLEAR[/color]'
                            markup: True
                            on_release: app.clear_ips()

                    TextInput:
                        id: ip_input
                        hint_text: '1.1.1.1\n8.8.8.8\n104.16.0.0\n...'
                        multiline: True
                        background_color: get_color_from_hex('#0D1117')
                        foreground_color: [0.88, 0.88, 1, 1]
                        hint_text_color: [0.4, 0.4, 0.5, 1]
                        cursor_color: [0.4, 0.76, 1, 1]
                        font_size: '13sp'
                        padding: [dp(10), dp(8)]

                # Scan Button
                ActionButton:
                    id: btn_scan
                    text: app.scan_btn_text
                    markup: True
                    btn_color: get_color_from_hex('#00C853') if not app.is_scanning else get_color_from_hex('#D50000')
                    on_release: app.toggle_scan()

                # Progress Card
                BoxLayout:
                    orientation: 'vertical'
                    size_hint_y: None
                    height: dp(72)
                    spacing: dp(6)
                    padding: dp(12)
                    canvas.before:
                        Color:
                            rgba: get_color_from_hex('#1A1A2E')
                        RoundedRectangle:
                            pos: self.pos
                            size: self.size
                            radius: [dp(12)]

                    BoxLayout:
                        size_hint_y: None
                        height: dp(22)

                        Label:
                            id: lbl_status
                            text: '[color=90A4AE]Ready to scan...[/color]'
                            markup: True
                            font_size: '13sp'
                            halign: 'left'
                            text_size: self.size

                        Label:
                            id: lbl_count
                            text: ''
                            font_size: '13sp'
                            halign: 'right'
                            text_size: self.size
                            color: [1, 0.84, 0, 1]

                    ProgressBar:
                        id: progress_bar
                        value: 0
                        max: 100

                # Stats Row
                BoxLayout:
                    orientation: 'horizontal'
                    spacing: dp(8)
                    size_hint_y: None
                    height: dp(64)

                    StatCard:
                        bg_color: get_color_from_hex('#1B5E20')
                        Label:
                            id: stat_ok
                            text: '[b]OK  0[/b]'
                            markup: True
                            halign: 'center'
                            color: [0.65, 1, 0.65, 1]
                            font_size: '15sp'
                        Label:
                            text: 'Passed'
                            halign: 'center'
                            color: [0.5, 0.9, 0.5, 0.7]
                            font_size: '11sp'
                            size_hint_y: None
                            height: dp(18)

                    StatCard:
                        bg_color: get_color_from_hex('#B71C1C')
                        Label:
                            id: stat_fail
                            text: '[b]FAIL  0[/b]'
                            markup: True
                            halign: 'center'
                            color: [1, 0.7, 0.7, 1]
                            font_size: '15sp'
                        Label:
                            text: 'Failed'
                            halign: 'center'
                            color: [0.9, 0.5, 0.5, 0.7]
                            font_size: '11sp'
                            size_hint_y: None
                            height: dp(18)

                    StatCard:
                        bg_color: get_color_from_hex('#E65100')
                        Label:
                            id: stat_thr
                            text: '[b]THR  0[/b]'
                            markup: True
                            halign: 'center'
                            color: [1, 0.88, 0.6, 1]
                            font_size: '15sp'
                        Label:
                            text: 'Throttled'
                            halign: 'center'
                            color: [0.9, 0.7, 0.5, 0.7]
                            font_size: '11sp'
                            size_hint_y: None
                            height: dp(18)

                # Go to results button (only when done)
                ActionButton:
                    id: btn_results
                    text: '[b]📊  View Results[/b]'
                    markup: True
                    btn_color: get_color_from_hex('#1565C0')
                    opacity: 1 if app.has_results else 0
                    disabled: not app.has_results
                    on_release: app.show_results()

<ResultsScreen>:
    name: 'results'
    canvas.before:
        Color:
            rgba: get_color_from_hex('#0A0A1A')
        Rectangle:
            pos: self.pos
            size: self.size

    BoxLayout:
        orientation: 'vertical'

        # ── TOP BAR ──
        BoxLayout:
            size_hint_y: None
            height: dp(56)
            padding: [dp(10), dp(8)]
            spacing: dp(8)
            canvas.before:
                Color:
                    rgba: get_color_from_hex('#12122A')
                Rectangle:
                    pos: self.pos
                    size: self.size

            Button:
                text: '← Back'
                size_hint_x: None
                width: dp(70)
                background_color: 0,0,0,0
                color: get_color_from_hex('#40C4FF')
                font_size: '14sp'
                on_release: app.go_scan()

            Label:
                id: lbl_res_title
                text: '[b][color=FFD700]Results[/color][/b]'
                markup: True
                font_size: '16sp'
                halign: 'center'
                text_size: self.size

            Button:
                text: 'COPY'
                size_hint_x: None
                width: dp(60)
                background_color: 0,0,0,0
                color: get_color_from_hex('#00E676')
                font_size: '13sp'
                bold: True
                on_release: app.copy_top5()

            Button:
                text: 'SAVE'
                size_hint_x: None
                width: dp(55)
                background_color: 0,0,0,0
                color: get_color_from_hex('#FFD740')
                font_size: '13sp'
                bold: True
                on_release: app.save_results()

        # ── FILTER BAR ──
        BoxLayout:
            size_hint_y: None
            height: dp(40)
            padding: [dp(12), dp(4)]
            spacing: dp(8)
            canvas.before:
                Color:
                    rgba: get_color_from_hex('#0E0E20')
                Rectangle:
                    pos: self.pos
                    size: self.size

            Label:
                id: lbl_count_res
                text: '0 results'
                font_size: '13sp'
                color: [0.6, 0.7, 0.8, 1]
                halign: 'left'
                text_size: self.size

            Button:
                id: btn_sort
                text: 'SORT: SCORE'
                size_hint_x: None
                width: dp(110)
                background_color: 0,0,0,0
                color: get_color_from_hex('#40C4FF')
                font_size: '12sp'
                bold: True
                on_release: app.toggle_sort()

            Button:
                text: 'NO THR'
                size_hint_x: None
                width: dp(80)
                background_color: 0,0,0,0
                color: get_color_from_hex('#FFD740')
                font_size: '12sp'
                bold: True
                on_release: app.toggle_filter()

        # ── LIST ──
        ScrollView:
            do_scroll_x: False
            BoxLayout:
                id: results_box
                orientation: 'vertical'
                padding: [dp(10), dp(6)]
                spacing: dp(6)
                size_hint_y: None
                height: self.minimum_height

        # ── BOTTOM BAR (TOP 5) ──
        BoxLayout:
            id: top5_bar
            orientation: 'vertical'
            size_hint_y: None
            height: dp(0)
            opacity: 0
            padding: [dp(10), dp(4)]
            canvas.before:
                Color:
                    rgba: get_color_from_hex('#0D2137')
                Rectangle:
                    pos: self.pos
                    size: self.size
"""


# ─────────────────────────────────────────────
#  APP CLASS
# ─────────────────────────────────────────────

class ScanScreen(Screen):
    pass


class ResultsScreen(Screen):
    pass


class MidOneScannerApp(App):
    scan_mode = NumericProperty(1)
    is_scanning = BooleanProperty(False)
    has_results = BooleanProperty(False)
    scan_btn_text = StringProperty('[b]🚀  START SCAN[/b]')

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.results = []
        self.filtered_results = []
        self.stop_event = threading.Event()
        self.stats = {"ok": 0, "fail": 0, "thr": 0}
        self.sort_by = "score"
        self.filter_throttled = False
        self.total_ips = 0

    def build(self):
        Builder.load_string(KV)
        self.sm = ScreenManager(transition=FadeTransition(duration=0.2))
        self.sm.add_widget(ScanScreen())
        self.sm.add_widget(ResultsScreen())
        return self.sm

    # ── Scan Screen helpers ──

    def set_mode(self, mode):
        self.scan_mode = mode

    def paste_ips(self):
        try:
            text = Clipboard.paste()
            inp = self.sm.get_screen('scan').ids.ip_input
            inp.text = (inp.text + "\n" + text).strip() if inp.text.strip() else text
        except Exception as e:
            self._toast(f"Paste error: {e}")

    def clear_ips(self):
        self.sm.get_screen('scan').ids.ip_input.text = ""

    def toggle_scan(self):
        if self.is_scanning:
            self._stop_scan()
        else:
            self._start_scan()

    def _start_scan(self):
        ids = self.sm.get_screen('scan').ids
        ips = parse_ips(ids.ip_input.text)
        if not ips:
            self._toast("No valid public IPs found!")
            return

        self.results = []
        self.filtered_results = []
        self.stats = {"ok": 0, "fail": 0, "thr": 0}
        self.total_ips = len(ips)
        self.stop_event.clear()
        self.is_scanning = True
        self.has_results = False
        self.scan_btn_text = '[b]⛔  STOP SCAN[/b]'

        ids.progress_bar.value = 0
        ids.lbl_status.text = '[color=40C4FF]Scanning...[/color]'
        ids.lbl_count.text = f'0 / {len(ips)}'
        self._update_stats()

        threading.Thread(
            target=run_scan,
            kwargs=dict(
                ips=ips,
                mode=self.scan_mode,
                progress_cb=self._on_progress,
                result_cb=self._on_result,
                done_cb=self._on_done,
                stop_event=self.stop_event,
            ),
            daemon=True,
        ).start()

    def _stop_scan(self):
        self.stop_event.set()
        self.is_scanning = False
        self.scan_btn_text = '[b]🚀  START SCAN[/b]'
        self._toast("Scan stopped")

    def _on_progress(self, done, total):
        ids = self.sm.get_screen('scan').ids
        pct = int((done / total) * 100) if total > 0 else 0
        ids.progress_bar.value = pct
        ids.lbl_status.text = f'[color=40C4FF]Scanning {pct}%[/color]'
        ids.lbl_count.text = f'{done} / {total}'

    def _on_result(self, result):
        self.results.append(result)
        if result["throttled"]:
            self.stats["thr"] += 1
        else:
            self.stats["ok"] += 1
        self._update_stats()

    def _on_done(self, results):
        self.results = results
        self.is_scanning = False
        self.scan_btn_text = '[b]🚀  START SCAN[/b]'
        self.has_results = bool(results)

        ids = self.sm.get_screen('scan').ids
        ids.progress_bar.value = 100
        ids.lbl_status.text = f'[color=00E676]Done!  {len(results)} found[/color]'
        ids.lbl_count.text = ''
        self._update_stats()

        if results:
            self._toast(f"Done! {len(results)} results — tap View Results")

    def _update_stats(self):
        ids = self.sm.get_screen('scan').ids
        total_tried = self.stats["ok"] + self.stats["fail"] + self.stats["thr"]
        ids.stat_ok.text = f'[b]OK  {self.stats["ok"]}[/b]'
        ids.stat_fail.text = f'[b]FAIL  {self.stats["fail"]}[/b]'
        ids.stat_thr.text = f'[b]THR  {self.stats["thr"]}[/b]'

    # ── Results Screen ──

    def show_results(self):
        self.sm.current = 'results'
        self._refresh_results()

    def go_scan(self):
        self.sm.current = 'scan'

    def _refresh_results(self):
        data = self.results[:]
        if self.filter_throttled:
            data = [r for r in data if not r["throttled"]]
        data.sort(key=lambda x: x[self.sort_by], reverse=True)
        self.filtered_results = data

        box = self.sm.get_screen('results').ids.results_box
        box.clear_widgets()

        self.sm.get_screen('results').ids.lbl_count_res.text = f'{len(data)} results'
        self.sm.get_screen('results').ids.lbl_res_title.text = (
            f'[b][color=FFD700]Results[/color][/b]  '
            f'[color=888888]{len(data)} IPs[/color]'
        )

        for i, r in enumerate(data[:150]):
            row = self._make_result_row(i + 1, r)
            box.add_widget(row)

    def _make_result_row(self, rank, r):
        grade_color = self._rgba_to_hex(r["color"])
        thr_note = f'  [color=FF5252][b][THR -{r["throttle_pct"]}%][/b][/color]' if r["throttled"] else ''
        rel_bar = '█' * r["reliability"] + '░' * (5 - r["reliability"])

        row = BoxLayout(
            orientation='vertical',
            size_hint_y=None,
            height=dp(90),
            padding=[dp(10), dp(6)],
            spacing=dp(3),
        )
        with row.canvas.before:
            Color(rgba=[0.1, 0.1, 0.18, 1])
            row._bg = RoundedRectangle(pos=row.pos, size=row.size, radius=[dp(10)])
        row.bind(pos=lambda w, v: setattr(w._bg, 'pos', v),
                 size=lambda w, v: setattr(w._bg, 'size', v))

        # Line 1: rank + IP + grade
        l1 = BoxLayout(size_hint_y=None, height=dp(26))
        l1.add_widget(Label(
            text=f'[b][color=FFFFFF]#{rank}  {r["ip"]}[/color][/b]{thr_note}',
            markup=True, font_size='14sp', halign='left', text_size=(None, None),
        ))
        l1.add_widget(Label(
            text=f'[b][color={grade_color}]{r["grade"]}[/color][/b]',
            markup=True, font_size='14sp', halign='right', text_size=(None, None),
            size_hint_x=None, width=dp(100),
        ))
        row.add_widget(l1)

        # Line 2: speed / latency / score
        l2 = BoxLayout(size_hint_y=None, height=dp(22))
        l2.add_widget(Label(
            text=f'[color=00E676]⚡ {r["speed"]} KB/s[/color]',
            markup=True, font_size='13sp', halign='left', text_size=(None, None),
        ))
        l2.add_widget(Label(
            text=f'[color=40C4FF]🕐 {r["latency"]}ms[/color]',
            markup=True, font_size='13sp', halign='center', text_size=(None, None),
        ))
        l2.add_widget(Label(
            text=f'[color=FFD740]★ {r["score"]}[/color]',
            markup=True, font_size='13sp', halign='right', text_size=(None, None),
        ))
        row.add_widget(l2)

        # Line 3: CDN / SNI / reliability
        l3 = BoxLayout(size_hint_y=None, height=dp(18))
        l3.add_widget(Label(
            text=f'[color=888888]CDN:{r["cdn"]}  [{rel_bar}][/color]',
            markup=True, font_size='11sp', halign='left', text_size=(None, None),
        ))
        l3.add_widget(Label(
            text=f'[color=666666]SNI:{r["sni"]}[/color]',
            markup=True, font_size='11sp', halign='right', text_size=(None, None),
        ))
        row.add_widget(l3)

        return row

    def toggle_sort(self):
        if self.sort_by == "score":
            self.sort_by = "speed"
            self.sm.get_screen('results').ids.btn_sort.text = "SORT: SPEED"
        else:
            self.sort_by = "score"
            self.sm.get_screen('results').ids.btn_sort.text = "SORT: SCORE"
        self._refresh_results()

    def toggle_filter(self):
        self.filter_throttled = not self.filter_throttled
        btn = self.sm.get_screen('results').ids.btn_sort
        # reuse same refresh
        self._refresh_results()

    def copy_top5(self):
        top5 = [r for r in self.results if not r["throttled"]][:5]
        if not top5:
            self._toast("No clean results!")
            return
        text = "\n".join([f"{r['ip']}  SNI:{r['sni']}" for r in top5])
        try:
            Clipboard.copy(text)
            self._toast("✅ Top 5 IPs copied!")
        except Exception:
            self._toast(top5[0]["ip"] + " ...")

    def save_results(self):
        if not self.results:
            self._toast("No results!")
            return
        try:
            fn = save_results_to_file(self.results)
            self._toast(f"✅ Saved: {os.path.basename(fn)}")
        except Exception as e:
            self._toast(f"Save error: {e}")

    # ── Helpers ──

    def _toast(self, msg):
        # Simple overlay label as toast
        from kivy.uix.label import Label
        from kivy.animation import Animation
        lbl = Label(
            text=msg,
            font_size='13sp',
            color=[1, 1, 1, 1],
            size_hint=(None, None),
        )
        lbl.texture_update()
        lbl.size = (lbl.texture_size[0] + dp(24), lbl.texture_size[1] + dp(16))
        lbl.pos = (
            (self.sm.width - lbl.width) / 2,
            dp(60),
        )
        with lbl.canvas.before:
            Color(rgba=[0.1, 0.1, 0.2, 0.92])
            RoundedRectangle(pos=lbl.pos, size=lbl.size, radius=[dp(8)])
        self.sm.add_widget(lbl)
        anim = Animation(opacity=0, duration=0.5, t='in_quad')
        anim.bind(on_complete=lambda *a: self.sm.remove_widget(lbl))
        Clock.schedule_once(lambda dt: anim.start(lbl), 2.0)

    @staticmethod
    def _rgba_to_hex(color):
        if isinstance(color, str):
            return color.lstrip('#')
        try:
            r, g, b, _ = color
            return '%02X%02X%02X' % (int(r * 255), int(g * 255), int(b * 255))
        except Exception:
            return 'FFFFFF'


if __name__ == '__main__':
    MidOneScannerApp().run()
