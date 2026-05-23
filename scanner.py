"""
MidONe Scanner SK - Core Engine
Ported from MidONeScanner.py for Android/Kivy
"""

import socket, ssl, time, re, statistics, threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from datetime import datetime

CDN_MAP = {
    "Cloudflare": {
        "headers":  ["cf-ray","cf-cache-status","cf-request-id"],
        "server":   ["cloudflare"],
        "snis":     ["speed.cloudflare.com","cloudflare.com"],
        "endpoint": "/__down?bytes=8000000",
    },
    "Akamai": {
        "headers":  ["x-check-cacheable","x-serial","x-true-cache-key","akamai-origin-hop"],
        "server":   ["akamaighost","akamai"],
        "snis":     ["a248.e.akamai.net","a77.net.akamai.net","a104.net.akamai.net",
                     "a184.net.akamai.net","ds-aksb.akamaized.net","ak.net.akamaized.net"],
        "endpoint": "/",
    },
    "Google": {
        "headers":  ["x-goog-generation","x-guploader-uploadid","x-goog-hash"],
        "server":   ["gws","google frontend","esf","sffe"],
        "snis":     ["fonts.googleapis.com","google.com","www.google.com"],
        "endpoint": "/",
    },
    "Amazon": {
        "headers":  ["x-amz-cf-id","x-amz-cf-pop","x-amz-request-id"],
        "server":   ["amazons3","cloudfront"],
        "snis":     ["d1.cloudfront.net","aws.amazon.com"],
        "endpoint": "/",
    },
    "Azure": {
        "headers":  ["x-azure-ref","x-msedge-ref","x-ec-custom-error"],
        "server":   ["microsoft-azure","ecd"],
        "snis":     ["ajax.aspnetcdn.com"],
        "endpoint": "/",
    },
    "Fastly": {
        "headers":  ["x-served-by","x-fastly-request-id","x-cache-hits"],
        "server":   ["varnish"],
        "snis":     ["global.fastly.net"],
        "endpoint": "/",
    },
    "Iranian": {
        "headers":  [],
        "server":   [],
        "snis":     ["aparat.com","snapp.ir","digikala.com",
                     "telewebion.com","varzesh3.com","bmi.ir"],
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

PRIVATE = [r'^10\.', r'^192\.168\.', r'^172\.(1[6-9]|2\d|3[01])\.',
           r'^127\.', r'^0\.', r'^169\.254\.']

def is_private(ip):
    return any(re.match(p, ip) for p in PRIVATE)

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
    except:
        if sock:
            try: sock.close()
            except: pass
        return None, None

def detect_cdn(ip):
    for probe in ["aparat.com","a248.e.akamai.net","speed.cloudflare.com"]:
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
                    if not c: break
                    buf += c
                    if b"\r\n\r\n" in buf: break
            except: pass
            hdrs = buf.decode(errors="ignore").lower()
            srv  = ""
            for line in hdrs.split("\r\n"):
                if line.startswith("server:"):
                    srv = line.split(":",1)[1].strip(); break
            for name, info in CDN_MAP.items():
                if name == "Iranian": continue
                if any(h in hdrs for h in info["headers"]):
                    return name, info["snis"]+[s for s in ALL_SNIS if s not in info["snis"]]
                if any(sv in srv for sv in info["server"]):
                    return name, info["snis"]+[s for s in ALL_SNIS if s not in info["snis"]]
        except: pass
        finally:
            try: ss.close()
            except: pass
            try: sock.close()
            except: pass
    return "Unknown", ALL_SNIS

def stage_tls(ip, sni):
    try:
        t = time.time()
        ss, sock = ssl_connect(ip, sni, CFG["tls_timeout"])
        if not ss:
            return False, 9999
        hs = round((time.time()-t)*1000)
        ss.sendall(
            f"HEAD / HTTP/1.1\r\nHost: {sni}\r\n"
            f"User-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n".encode()
        )
        buf = b""
        ss.settimeout(2.0)
        try:
            while len(buf) < 512:
                c = ss.recv(256)
                if not c: break
                buf += c
                if b"HTTP/" in buf: break
        except: pass
        try: ss.close()
        except: pass
        try: sock.close()
        except: pass
        if buf and b"HTTP/" in buf:
            return True, hs
        if hs < CFG["tls_timeout"]*900:
            return True, hs
    except: pass
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
    avg_lat  = round(statistics.mean(lats)) if lats else 9999
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
        start=time.time(); total=0; first_byte=None; samples=[]; last_t=start
        while True:
            try:
                chunk = ss.recv(65536)
                if not chunk: break
                now = time.time()
                if first_byte is None: first_byte = now-start
                total += len(chunk)
                if now-last_t >= 1.0:
                    samples.append((total/1024)/max(now-start,0.001))
                    last_t = now
                if now-start > CFG["test_duration"]: break
            except socket.timeout: break
        try: ss.close()
        except: pass
        elapsed = time.time()-start
        if elapsed > 0 and total >= CFG["min_bytes"]:
            speed   = (total/1024)/elapsed
            latency = round((first_byte or 0)*1000)
            jitter  = round(statistics.stdev(samples),1) if len(samples)>1 else 0
            throttled=False; throttle_pct=0
            if len(samples) >= 3:
                mid   = len(samples)//2
                f_avg = statistics.mean(samples[:mid])
                s_avg = statistics.mean(samples[mid:])
                if f_avg > 0:
                    drop = (f_avg-s_avg)/f_avg
                    throttle_pct = round(drop*100)
                    throttled = drop > CFG["throttle_threshold"]
            return {"speed":round(speed,1),"latency":latency,"jitter":jitter,
                    "throttled":throttled,"throttle_pct":throttle_pct,"ok":True}
    except: pass
    finally:
        if sock:
            try: sock.close()
            except: pass
    return {"ok":False}

def calc_score(speed, latency, jitter, throttled, reliability=5):
    s   = min(speed/500,1.0)*55
    l   = max(0,1-latency/800)*20
    j   = max(0,1-jitter/max(speed,1))*10
    t   = 0 if throttled else 5
    rel = (reliability/CFG["reliability_tries"])*10
    return round(s+l+j+t+rel,1)

def get_grade(speed, throttled, rel=5):
    if throttled:             return "THROTTLED", "#FF4444"
    if speed>300 and rel>=4: return "S ***",      "#00FF88"
    if speed>200:            return "A **",        "#44FF44"
    if speed>100:            return "B *",         "#FFFF44"
    if speed>50:             return "C",           "#FFAA44"
    return "D",                                    "#FF4444"

def scan_mode1(ips, progress_cb=None, result_cb=None, done_cb=None, stop_event=None):
    """Simple scan - SNI: google.com"""
    sni = "google.com"
    endpoint = "/"
    results = []
    total = len(ips)

    def test_one(ip):
        if stop_event and stop_event.is_set():
            return None
        ok, _ = stage_tls(ip, sni)
        if not ok: return None
        bw = stage_bandwidth(ip, sni, endpoint)
        if bw["ok"]:
            sc = calc_score(bw["speed"],bw["latency"],bw["jitter"],bw["throttled"])
            grade, color = get_grade(bw["speed"], bw["throttled"])
            r = {
                "ip": ip, "sni": sni, "cdn": "Auto",
                "speed": bw["speed"], "latency": bw["latency"],
                "jitter": bw["jitter"], "throttled": bw["throttled"],
                "throttle_pct": bw["throttle_pct"],
                "reliability": 5, "score": sc,
                "grade": grade, "color": color
            }
            if result_cb: result_cb(r)
            return r
        return None

    done_count = [0]
    lock = threading.Lock()

    def wrapped(ip):
        res = test_one(ip)
        with lock:
            done_count[0] += 1
            if progress_cb:
                progress_cb(done_count[0], total)
        return res

    with ThreadPoolExecutor(max_workers=CFG["threads"]) as ex:
        for f in as_completed({ex.submit(wrapped, ip): ip for ip in ips}):
            res = f.result()
            if res: results.append(res)

    results.sort(key=lambda x: x["score"], reverse=True)
    if done_cb: done_cb(results)
    return results

def scan_mode2(ips, progress_cb=None, result_cb=None, done_cb=None, stop_event=None):
    """Auto-SNI scan - CDN detect + all SNIs + reliability"""
    all_results = []
    total = len(ips)
    done_count = [0]
    lock = threading.Lock()

    def pipeline(ip):
        if stop_event and stop_event.is_set():
            return []
        res = []
        cdn_name, ordered_snis = detect_cdn(ip)
        cdn_endpoint = CDN_MAP.get(cdn_name,{}).get("endpoint","/")
        valid = []
        for sni in ordered_snis:
            if stop_event and stop_event.is_set(): break
            ok, _ = stage_tls(ip, sni)
            if not ok: continue
            reliable, rel_count, avg_lat = stage_reliability(ip, sni)
            if reliable:
                valid.append((sni, rel_count, avg_lat))
        for sni, rel_count, avg_lat in valid:
            if stop_event and stop_event.is_set(): break
            bw = stage_bandwidth(ip, sni, cdn_endpoint)
            if bw["ok"]:
                sc = calc_score(bw["speed"],bw["latency"],bw["jitter"],
                                bw["throttled"],rel_count)
                grade, color = get_grade(bw["speed"], bw["throttled"], rel_count)
                r = {
                    "ip": ip, "sni": sni, "cdn": cdn_name,
                    "speed": bw["speed"], "latency": bw["latency"],
                    "jitter": bw["jitter"], "throttled": bw["throttled"],
                    "throttle_pct": bw["throttle_pct"],
                    "reliability": rel_count, "score": sc,
                    "grade": grade, "color": color
                }
                if result_cb: result_cb(r)
                res.append(r)
        with lock:
            done_count[0] += 1
            if progress_cb:
                progress_cb(done_count[0], total)
        return res

    with ThreadPoolExecutor(max_workers=CFG["threads"]) as ex:
        for f in as_completed({ex.submit(pipeline, ip): ip for ip in ips}):
            all_results.extend(f.result())

    all_results.sort(key=lambda x: x["score"], reverse=True)
    if done_cb: done_cb(all_results)
    return all_results

def parse_ips(text):
    raw = list(set(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text)))
    return [ip for ip in raw if not is_private(ip)]

def save_results(results, mode_auto=False):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fn = f"scan_{ts}.txt"
    try:
        from android.storage import primary_external_storage_path
        path = primary_external_storage_path()
        fn = f"{path}/MidONeScanner/scan_{ts}.txt"
        import os
        os.makedirs(f"{path}/MidONeScanner", exist_ok=True)
    except:
        import os
        fn = os.path.join(os.path.expanduser("~"), f"scan_{ts}.txt")

    top5 = [r for r in results if not r["throttled"]][:5]
    with open(fn, "w", encoding="utf-8") as f:
        f.write(f"MidONe Scanner SK v6.1 | t.me/mmdrlx | {datetime.now()}\n\n")
        f.write("TOP 5:\n")
        for i, r in enumerate(top5, 1):
            f.write(f"{i}. {r['ip']}  SNI:{r['sni']}  CDN:{r['cdn']}  "
                    f"{r['speed']} KB/s  Score:{r['score']}\n")
        f.write("\nALL RESULTS:\n")
        f.write(f"{'IP':<17}{'CDN':<12}{'SNI':<30}{'Speed':>10}{'Rel':>5}{'Score':>8}\n")
        f.write("-"*80 + "\n")
        for r in results:
            thr = " [THR]" if r["throttled"] else ""
            f.write(f"{r['ip']:<17}{r['cdn']:<12}{r['sni']:<30}"
                    f"{r['speed']:>7.1f} KB/s"
                    f"  {r['reliability']}/5"
                    f"{r['score']:>8}{thr}\n")
    return fn
