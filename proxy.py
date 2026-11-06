"""Forward HTTP proxy for devices that only speak plain HTTP.

Set the device's proxy to  HOST:1235  (plain)  or  HOST:1234  (lite).  Optional env PROXY_AUTH=user:pass.
 - Every request to http://site/... is fetched from https://site/... (falls back to http://).
 - plain (1235): transparent. Body is passed through, https:// links inside HTML become http://,
                 Secure cookies / HSTS / CSP are neutralised so the device keeps working.
 - lite  (1234): HTML is simplified (no JS/CSS/ads), images are shrunk to small JPEGs, long pages are split
                 into pages (links http://gw.local/p/...), per-client cookie jar. Settings: http://gw.local/set
 - CONNECT (devices that do know TLS) is tunnelled untouched on both ports.
Run: python proxy.py            (starts both ports)
"""
import base64, hashlib, os, re, select, socket, sys, threading
from http.cookiejar import DefaultCookiePolicy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, urljoin, parse_qsl, urlencode
import requests
from requests.adapters import HTTPAdapter
from bs4 import BeautifulSoup
import gateway as G

AUTH = os.environ.get("PROXY_AUTH", "")       # optional "user:pass" (Proxy-Authorization: Basic)
HOP = {"connection", "proxy-connection", "keep-alive", "te", "trailer", "transfer-encoding", "upgrade",
       "proxy-authorization", "proxy-authenticate"}
scheme_cache = G.Cache(2000, 6 * 3600)          # host -> "https" | "http"
chunks_cache = G.Cache(300, 1800)               # token -> (title, [pages])
settings = G.Cache(500, 24 * 3600)              # client key -> option dict

plain_sess = requests.Session()
plain_sess.cookies.set_policy(DefaultCookiePolicy(allowed_domains=[]))     # never keep cookies server-side
plain_sess.mount("https://", HTTPAdapter(pool_connections=20, pool_maxsize=40))
plain_sess.mount("http://", HTTPAdapter(pool_connections=20, pool_maxsize=40))


def candidates(url):
    sp = urlsplit(url)
    if sp.scheme == "http" and sp.port in (None, 80):
        order = ["https", "http"]
        if scheme_cache.get(sp.hostname) == "http":
            order = ["http", "https"]
        return [(s, sp._replace(scheme=s).geturl()) for s in order]
    return [(sp.scheme, url)]


def upstream(session, method, url, headers, body):
    err = None
    for sch, u in candidates(url):
        try:
            G.safe_url(u)
            r = session.request(method, u, headers=headers, data=body, timeout=(6, 25), stream=True,
                                allow_redirects=False)
            scheme_cache.put(urlsplit(u).hostname, sch)
            return r, u
        except (requests.exceptions.SSLError, requests.exceptions.ConnectionError,
                requests.exceptions.ConnectTimeout) as e:
            err = e
    raise err or ValueError("no route")


def make_handler(mode):
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"
        server_version = "gw"

        def log_message(self, *a):
            pass

        def ckey(self):
            return hashlib.md5((self.client_address[0] + self.headers.get("User-Agent", "")).encode()).hexdigest()[:12]

        def opts(self):
            o = settings.get(self.ckey())
            return dict(G.DEF, px=True, **(o or {}))

        # ---------- helpers
        def send_page(self, html, status=200):
            raw = html.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(raw)

        def read_body(self):
            n = int(self.headers.get("Content-Length") or 0)
            return self.rfile.read(n) if n else None

        def out_headers(self):
            h = {}
            for k, v in self.headers.items():
                kl = k.lower()
                if kl in HOP or kl in ("host", "accept-encoding", "content-length"):
                    continue
                if mode == "lite" and kl in ("cookie", "user-agent", "referer", "accept"):
                    continue
                h[k] = v
            h["Accept-Encoding"] = "gzip, deflate"
            return h

        def authed(self):
            if not AUTH:
                return True
            h = self.headers.get("Proxy-Authorization", "")
            if h.lower().startswith("basic "):
                try:
                    if base64.b64decode(h[6:]).decode() == AUTH:
                        return True
                except Exception:
                    pass
            self.send_response(407)
            self.send_header("Proxy-Authenticate", 'Basic realm="proxy"')
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            return False

        # ---------- request entry
        def handle_any(self):
            try:
                self._handle()
            except (BrokenPipeError, ConnectionResetError):
                pass
            except Exception as e:
                try:
                    self.send_page(G.shell("Error", "<p>%s</p>" % str(e)[:200]), 502)
                except Exception:
                    pass

        do_GET = do_POST = do_HEAD = do_PUT = do_DELETE = do_OPTIONS = do_PATCH = handle_any

        def _handle(self):
            if not self.authed():
                return
            url = self.path
            if url.startswith("/"):           # someone talking to us directly, not as a proxy
                host = self.headers.get("Host", "")
                if host.split(":")[0] == "gw.local":
                    url = "http://gw.local" + url
                else:
                    return self.send_page(G.shell("Proxy", "<p>Set this address as the HTTP proxy "
                                                   "(ports 1235 plain, 1234 lite).</p>"))
            sp = urlsplit(url)
            if sp.hostname == "gw.local":
                return self.gw_local(sp)
            body = self.read_body()
            if mode == "plain":
                return self.plain(url, body)
            return self.lite(url, body)

        # ---------- plain mode
        def plain(self, url, body):
            r, final = upstream(plain_sess, self.command, url, self.out_headers(), body)
            self.send_response(r.status_code)
            ctype = r.headers.get("Content-Type", "")
            is_html = "html" in ctype.lower()
            for k, v in r.raw.headers.items():
                kl = k.lower()
                if kl in HOP or kl in ("content-encoding", "content-length", "strict-transport-security",
                                       "content-security-policy", "content-security-policy-report-only",
                                       "set-cookie", "alt-svc"):
                    continue
                if kl == "location":
                    v = G.httpify(urljoin(final, v))
                self.send_header(k, v)
            for c in r.raw.headers.getlist("Set-Cookie"):
                c = re.sub(r";\s*secure", "", c, flags=re.I)
                c = re.sub(r";\s*samesite=none", "", c, flags=re.I)
                self.send_header("Set-Cookie", c)
            self.send_header("Connection", "close")
            if is_html and self.command != "HEAD":
                data = r.raw.read(G.MAX_BYTES, decode_content=True)
                data = re.sub(rb"https://", b"http://", data)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            else:
                self.end_headers()
                if self.command != "HEAD":
                    for chunk in r.raw.stream(65536, decode_content=True):
                        self.wfile.write(chunk)
            r.close()

        # ---------- lite mode
        def lite(self, url, body):
            key, o = self.ckey(), self.opts()
            s = G.client_session(key)
            hdr = self.out_headers()
            hdr["Accept"] = "text/html,image/*;q=0.8,*/*;q=0.5"
            method, cur = self.command, url
            for _ in range(8):
                r, final = upstream(s, method, cur, hdr, body)
                if r.status_code in (301, 302, 303, 307, 308) and r.headers.get("Location"):
                    cur = urljoin(final, r.headers["Location"])
                    r.close()
                    if r.status_code in (301, 302, 303):
                        method, body = "GET", None
                    continue
                break
            ctype = r.headers.get("Content-Type", "").lower()
            if r.status_code == 418:
                r.close()
                return self.send_page(G.shell("Blocked", "<p>Blocked by filter.</p>"), 403)
            if "html" in ctype and self.command != "HEAD":
                data = r.raw.read(G.MAX_BYTES, decode_content=True)
                r.close()
                enc = r.encoding if "charset" in ctype else None
                soup = BeautifulSoup(data, "lxml", from_encoding=enc)
                title = soup.title.get_text(strip=True) if soup.title else final
                pages = G.paginate(G.simplify(soup, final, o), int(o["s"]))
                tok = hashlib.md5((key + final).encode()).hexdigest()[:10]
                chunks_cache.put(tok, (title, pages, final))
                return self.send_page(self.render(tok, 0))
            if ctype.startswith("image/") and "svg" not in ctype and self.command != "HEAD":
                if o["i"] != "1":
                    r.close()
                    return self.send_empty()
                data = r.raw.read(G.MAX_BYTES, decode_content=True)
                r.close()
                try:
                    out = G.convert_image(data, int(o["w"]), o["g"] == "1")
                except Exception:
                    return self.send_empty()
                self.send_response(200)
                self.send_header("Content-Type", "image/jpeg")
                self.send_header("Content-Length", str(len(out)))
                self.send_header("Cache-Control", "max-age=3600")
                self.send_header("Connection", "close")
                self.end_headers()
                return self.wfile.write(out)
            # anything else (files, text, json): pass through
            self.send_response(r.status_code)
            for k, v in r.raw.headers.items():
                if k.lower() in ("content-type", "content-disposition", "last-modified"):
                    self.send_header(k, v)
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                for chunk in r.raw.stream(65536, decode_content=True):
                    self.wfile.write(chunk)
            r.close()

        def send_empty(self):
            self.send_response(204)
            self.send_header("Connection", "close")
            self.end_headers()

        def render(self, tok, n):
            title, pages, final = chunks_cache.get(tok) or ("", ["<p>Page expired, reload it.</p>"], "")
            n = max(0, min(n, len(pages) - 1))
            nav = ""
            if len(pages) > 1:
                nav = "<hr>"
                if n:
                    nav += '<a href="http://gw.local/p/%s/%d">&lt;</a> ' % (tok, n - 1)
                nav += "%d/%d " % (n + 1, len(pages))
                if n < len(pages) - 1:
                    nav += '<a href="http://gw.local/p/%s/%d">&gt;</a>' % (tok, n + 1)
            top = '<a href="http://gw.local/set">Set</a><hr>' if n == 0 else ""
            return G.shell(title, top + pages[n] + nav)

        def gw_local(self, sp):
            parts = sp.path.strip("/").split("/")
            if parts[0] == "p" and len(parts) == 3 and parts[2].isdigit():
                return self.send_page(self.render(parts[1], int(parts[2])))
            if parts[0] == "set":
                cur = dict(settings.get(self.ckey()) or {})
                for k, v in parse_qsl(sp.query):
                    if k in G.DEF:
                        cur[k] = v
                settings.put(self.ckey(), cur)
                o = self.opts()
                rows = [("Images", "i", [("on", "1"), ("off", "0")]),
                        ("Gray", "g", [("on", "1"), ("off", "0")]),
                        ("Width", "w", [("64", "64"), ("96", "96"), ("128", "128"), ("176", "176"), ("240", "240")]),
                        ("Page size", "s", [("2500", "2500"), ("5000", "5000"), ("9000", "9000")]),
                        ("Mode", "m", [("lite", "lite"), ("full", "full")])]
                body = "<h3>Settings</h3>"
                for label, k, vals in rows:
                    body += "<p>%s: " % label + " ".join(
                        ("<b>[%s]</b>" if o[k] == v else "%s") % ('<a href="http://gw.local/set?%s">%s</a>' % (urlencode({k: v}), t)
                                                                     if o[k] != v else t)
                        for t, v in vals) + "</p>"
                return self.send_page(G.shell("Settings", body))
            return self.send_page(G.shell("Gateway", "<p>gw.local</p>"), 404)

        # ---------- CONNECT (TLS-capable devices): blind tunnel
        def do_CONNECT(self):
            if not self.authed():
                return
            try:
                host, _, port = self.path.rpartition(":")
                G.safe_url("https://" + host)
                up = socket.create_connection((host, int(port or 443)), timeout=10)
            except Exception:
                self.send_error(502)
                return
            self.send_response(200, "Connection established")
            self.end_headers()
            c = self.connection
            socks = [c, up]
            try:
                while True:
                    r, _, x = select.select(socks, [], socks, 60)
                    if x or not r:
                        break
                    for s in r:
                        d = s.recv(65536)
                        if not d:
                            return
                        (up if s is c else c).sendall(d)
            except OSError:
                pass
            finally:
                up.close()
    return H


class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128


def main():
    ports = {"lite": 1234, "plain": 1235}
    for a in sys.argv[1:]:
        if "=" in a:
            k, v = a.split("=")
            ports[k] = int(v)
    for mode, port in ports.items():
        srv = Server(("0.0.0.0", port), make_handler(mode))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        print("proxy %s on :%d" % (mode, port), flush=True)
    threading.Event().wait()


if __name__ == "__main__":
    main()
