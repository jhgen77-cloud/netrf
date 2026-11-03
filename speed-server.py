#!/usr/bin/env python3
"""NetRF 무선 구간 속도 측정 서버 — 같은 망 PC 에 띄우면 앱이 와이파이 구간만의 속도를 잰다(인터넷 회선과 상관없이).

Cloudflare 측정 서버와 같은 규약:
  GET  /__down?bytes=N   N 바이트(0 으로 채움)를 보낸다 — 최대 100 MB
  POST /__up             받은 것을 버리고 200
파이썬 3.6+ 표준 라이브러리만 쓴다. 받은 내용은 저장하지 않는다.

쓰는 법:  python3 speed-server.py                       (포트 8098, 사설망만 받음, 30 분 쉬면 끝)
          python3 speed-server.py --allow 10.20.0.0/16  (무선 대역만 받기)
          python3 speed-server.py --idle 0              (저절로 끝나지 않게 — 도커·상시 운영)
앱 ⚙ → 무선 구간 서버에  http://<이 PC IP>:8098  을 넣는다(사설 IP 만). 시작할 때 창에 주소가 뜬다.
"""
import argparse
import ipaddress
import os
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import parse_qs, urlparse

CHUNK = b"\0" * (256 * 1024)
MAX = 100_000_000
LOG_MIN = 1_000_000  # 1 MB 이상만 기록(핑용 작은 요청은 뺀다)
PRIVATE = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8"
SKIP_IF = ("lo", "docker", "br-", "veth", "virbr")


def log(msg):
    print(f"{time.strftime('%H:%M:%S')}  {msg}", flush=True)


class Server(ThreadingMixIn, HTTPServer):
    daemon_threads = True

    def __init__(self, addr, handler, allow, max_conn, quiet):
        HTTPServer.__init__(self, addr, handler)
        self.allow = allow
        self.quiet = quiet
        self.slots = threading.BoundedSemaphore(max_conn)
        self.lock = threading.Lock()
        self.active = 0
        self.last = time.time()
        self.rejected = set()
        self.busy_logged = 0

    def verify_request(self, request, client_address):
        ip = ipaddress.ip_address(client_address[0])
        if any(ip in net for net in self.allow):
            return True
        if ip not in self.rejected:  # 주소마다 한 번만(스캐너가 창을 도배하지 않게)
            self.rejected.add(ip)
            log(f"rejected {ip} (not in --allow)")
        return False

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):  # 동시 연결이 꽉 차면 바로 끊는다
            if time.time() - self.busy_logged > 10:
                self.busy_logged = time.time()
                log(f"busy: dropped {client_address[0]} (--max-conn reached)")
            self.shutdown_request(request)
            return
        with self.lock:
            self.active += 1
            self.last = time.time()
        ThreadingMixIn.process_request(self, request, client_address)

    def process_request_thread(self, request, client_address):
        try:
            ThreadingMixIn.process_request_thread(self, request, client_address)
        finally:
            with self.lock:
                self.active -= 1
                self.last = time.time()
            self.slots.release()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # 연결을 이어 쓴다(핑이 연결 맺는 시간을 재지 않게)
    timeout = 30  # 30 초 동안 아무것도 오가지 않는 연결은 끊는다

    def handle(self):
        try:
            super().handle()
        except (ConnectionError, socket.timeout):
            pass  # 앱이 이어 쓰던 연결을 끊음(윈도우에서는 WinError 10053) 또는 말이 없음

    def do_GET(self):
        u = urlparse(self.path)
        if u.path != "/__down":
            self.send_error(404)
            return
        try:
            n = max(0, min(MAX, int(parse_qs(u.query).get("bytes", ["0"])[0])))
        except ValueError:
            n = 0
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(n))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        total, start, cut = n, time.time(), False
        try:
            while n > 0:
                k = min(n, len(CHUNK))
                self.wfile.write(CHUNK[:k])
                n -= k
        except (ConnectionError, socket.timeout):
            cut = True  # 앱이 시간이 다 돼 끊음
        self.report("down", total - n, time.time() - start, cut)
        if cut:
            self.close_connection = True

    def do_POST(self):
        if urlparse(self.path).path != "/__up":
            self.send_error(404)
            return
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        total, start = n, time.time()
        try:
            while n > 0:
                b = self.rfile.read(min(n, 256 * 1024))
                if not b:
                    break
                n -= len(b)
        except (ConnectionError, socket.timeout):
            self.report("up", total - n, time.time() - start, True)
            self.close_connection = True
            return
        self.report("up", total - n, time.time() - start, n > 0)
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def report(self, kind, nbytes, secs, cut):
        # 서버 쪽에서 본 참고값 — 내려받기는 소켓 버퍼 때문에 짧으면 높게 나온다. 정답은 앱 값.
        if self.server.quiet or nbytes < LOG_MIN:
            return
        mbps = nbytes * 8 / max(secs, 1e-6) / 1e6
        log(f"{self.client_address[0]:<15} {kind:<4} {nbytes / 1e6:6.1f} MB  ~{mbps:4.0f} Mbps"
            + ("  (끊김)" if cut else ""))

    def log_message(self, *args):
        pass


def run(cmd):
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          universal_newlines=True, timeout=15).stdout


def links():
    """켜진 인터페이스의 [(IP, 초당 비트 또는 None, 와이파이인지)] — 모르면 []."""
    res = []
    try:
        if os.name == "nt":
            ps = ("Get-NetIPAddress -AddressFamily IPv4 | ForEach-Object { "
                  "$a = Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue; "
                  "if ($a -and $a.Status -eq 'Up') { '{0}|{1}|{2}' -f $_.IPAddress, $a.Speed, $a.NdisPhysicalMedium } }")
            for line in run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps]).splitlines():
                p = line.strip().split("|")
                if len(p) == 3:
                    res.append((p[0], int(p[1]) if p[1].isdigit() else None, p[2] == "9"))  # 9 = 802.11
        else:
            for line in run(["ip", "-o", "-4", "addr", "show", "up"]).splitlines():
                f = line.split()
                dev, ip = f[1], f[3].split("/")[0]
                if dev.startswith(SKIP_IF):
                    continue
                try:
                    with open(f"/sys/class/net/{dev}/speed") as fh:
                        mb = int(fh.read().strip())
                    speed = mb * 1_000_000 if mb > 0 else None
                except (OSError, ValueError):
                    speed = None
                res.append((ip, speed, os.path.isdir(f"/sys/class/net/{dev}/wireless")))
    except Exception:
        return []
    return [r for r in res if not r[0].startswith(("127.", "169.254."))]


def banner(a):
    print(f"NetRF speed server — port {a.port}  (Ctrl+C 로 끝)", flush=True)
    if os.path.exists("/.dockerenv"):
        print(f"  docker: put  http://<host IP>:{a.port}  in the app")
        found = []
    else:
        found = [l for l in links() if a.bind in ("0.0.0.0", l[0])]
        if not found:
            print(f"  put  http://<this PC IP>:{a.port}  in the app (ipconfig / ip addr shows the IP)")
    for ip, speed, wireless in found:
        rate = (f"{speed / 1e9:g} Gbps" if speed and speed >= 1e9
                else f"{speed / 1e6:.0f} Mbps" if speed else "speed ?")
        line = f"  http://{ip}:{a.port}   {rate} {'Wi-Fi' if wireless else 'wired'}"
        if wireless:
            line += "   WARNING: server on Wi-Fi, results include its own radio hop"
        elif speed and speed < 1e9:
            line += f"   WARNING: link under 1 Gbps, results capped near {speed / 1e6 * 0.94:.0f} Mbps"
        print(line)
    idle = f"stops after {a.idle:g} min idle" if a.idle > 0 else "no idle stop"
    print(f"  allow {', '.join(str(n) for n in a.allow)} | max {a.max_conn} connections | {idle}")
    # 11-02 회사 로그에서 업로드 줄마다 "(cut)" 이 보여 고장처럼 보였다 — 10초가 되면 앱이 하던 요청을 끊는 것(정상).
    # 느린 망은 4 MB 한 덩이를 10초 안에 다 못 보내 연결마다 한 줄씩, 그 줄이 모두 "(끊김)" 이 된다.
    print("  측정 끝마다 '(끊김)' 줄이 연결 수(4)만큼 나오는 건 정상 — 10초가 되면 앱이 하던 요청을 끊습니다", flush=True)


def watch_idle(srv, minutes):
    while True:
        time.sleep(5)
        with srv.lock:
            idle = srv.active == 0 and time.time() - srv.last > minutes * 60
        if idle:
            log(f"no requests for {minutes:g} min - stopping (--idle 0 keeps it running)")
            srv.shutdown()
            return


def networks(text):
    if text.strip().lower() == "any":
        return [ipaddress.ip_network("0.0.0.0/0")]
    try:
        return [ipaddress.ip_network(t.strip(), strict=False) for t in text.split(",") if t.strip()]
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e))


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--port", type=int, default=8098)
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--allow", type=networks, default=networks(PRIVATE),
                    help="받을 단말 대역(쉼표로 여러 개) 또는 any — 기본: 사설망")
    ap.add_argument("--max-conn", type=int, default=16, help="동시 연결 수(기본 16)")
    ap.add_argument("--idle", type=float, default=30, help="이만큼(분) 요청이 없으면 끝, 0 = 안 끝냄(기본 30)")
    ap.add_argument("--quiet", action="store_true", help="측정마다 찍는 줄을 끈다")
    a = ap.parse_args()
    srv = Server((a.bind, a.port), Handler, a.allow, a.max_conn, a.quiet)
    banner(a)
    if a.idle > 0:
        threading.Thread(target=watch_idle, args=(srv, a.idle), daemon=True).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    srv.server_close()


if __name__ == "__main__":
    main()
