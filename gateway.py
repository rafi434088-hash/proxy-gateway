"""HTTP->HTTPS browsing proxy for simple / low-memory devices. Run: python gateway.py [port]

Query params (all optional, kept short):
  u=URL  i=0 (no images)  w=WIDTH (128)  g=1 (grayscale)  s=CHARS/page (5000)  p=page
  m=lite (default: simplified text pages) | m=full (whole page structure, no scripts/CSS)
Per-client cookie jar (keyed by client IP + User-Agent) so logins work. GET and POST forms work.
"""
import gzip, hashlib, io, ipaddress, re, socket, sys, threading, time
from collections import OrderedDict
from urllib.parse import urljoin, urlparse, quote, urlencode
import requests
from requests.adapters import HTTPAdapter
from bs4 import BeautifulSoup, Comment
from flask import Flask, request, Response
from PIL import Image

app = Flask(__name__)
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36"
MAX_BYTES = 3_000_000
DEF = {"i": "1", "w": "128", "g": "0", "s": "5000", "m": "lite"}
KEEP = {"h1", "h2", "h3", "h4", "p", "a", "img", "ul", "ol", "li", "br", "b", "i", "table", "tr",
        "td", "th", "pre", "blockquote", "form", "input", "button", "textarea", "select", "option", "label"}
DROP_LITE = {"script", "style", "iframe", "noscript", "svg", "canvas", "video", "audio", "object",
             "embed", "nav", "footer", "head", "link", "meta", "aside", "header"}
DROP_FULL = {"script", "style", "noscript", "svg", "canvas", "object", "head", "link", "meta", "base"}
KEEP_ATTRS = ("class", "id", "colspan", "rowspan", "align", "dir", "width", "height")
FORM_TYPES = {"hidden", "text", "search", "submit", "password", "checkbox", "radio", "email",
              "number", "tel", "url", "date"}


class Cache:
    def __init__(self, cap, ttl):
        self.d, self.cap, self.ttl, self.lock = OrderedDict(), cap, ttl, threading.Lock()

    def get(self, k):
        with self.lock:
            v = self.d.get(k)
            if v and time.time() - v[0] < self.ttl:
                self.d.move_to_end(k)
                return v[1]
            self.d.pop(k, None)

    def put(self, k, val):
        with self.lock:
            self.d[k] = (time.time(), val)
            while len(self.d) > self.cap:
                self.d.popitem(last=False)


page_cache = Cache(150, 600)
img_cache = Cache(300, 3600)
dns_cache = Cache(500, 300)
clients = Cache(200, 6 * 3600)     # per-client requests.Session (cookie jar)


def client_key():
    ip = request.headers.get("CF-Connecting-IP") or request.remote_addr or ""
    return hashlib.md5((ip + request.headers.get("User-Agent", "")).encode()).hexdigest()[:12]


def client_session(key=None):
    k = key or client_key()
    s = clients.get(k)
    if s is None:
        s = requests.Session()
        s.headers.update({"User-Agent": UA, "Accept-Language": "he,en;q=0.8", "Accept-Encoding": "gzip, deflate"})
        s.mount("https://", HTTPAdapter(pool_connections=10, pool_maxsize=20))
        s.mount("http://", HTTPAdapter(pool_connections=10, pool_maxsize=20))
    clients.put(k, s)       # refresh TTL
    return s


def safe_url(u):
    u = u.strip()
    if not re.match(r"^https?://", u, re.I):
        u = "https://" + u
    host = urlparse(u).hostname
    if not host:
        raise ValueError("bad url")
    if dns_cache.get(host) is None:
        for info in socket.getaddrinfo(host, None):
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                raise ValueError("blocked address")
        dns_cache.put(host, True)
    return u


def opts():
    return {k: request.args.get(k, d) for k, d in DEF.items()}


def q(o, **extra):
    d = {k: v for k, v in o.items() if v != DEF[k]}
    d.update(extra)
    return urlencode(d)


def httpify(u):
    return re.sub(r"^https://", "http://", u, flags=re.I)


def go_link(u, o, p=0):
    if o.get("px"):
        return httpify(u)
    return "/go?" + q(o, u=u, **({"p": p} if p else {}))


def img_link(u, o):
    if o.get("px"):
        return httpify(u)
    d = {"u": u}
    for k in ("w", "g"):
        if o[k] != DEF[k]:
            d[k] = o[k]
    return "/img?" + urlencode(d)


def shell(title, body):
    return ('<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8">'
            '<title>%s</title></head><body dir="auto">%s</body></html>' % (title[:60], body))


def reply(html, status=200, cache=True):
    raw = html.encode("utf-8")
    h = {"Cache-Control": "max-age=60" if cache else "no-store"}
    if "gzip" in request.headers.get("Accept-Encoding", "") and len(raw) > 800:
        raw = gzip.compress(raw, 6)
        h["Content-Encoding"] = "gzip"
    return Response(raw, status=status, mimetype="text/html", headers=h)


def home_form():
    return ('<form action="/go"><input name="u" size="18"><input type="submit" value="Go"></form>'
            '<form action="/search"><input name="q" size="18"><input type="submit" value="?"></form>')


@app.route("/")
def index():
    return reply(shell("Gateway", home_form()))


@app.route("/search")
def search():
    return go_to("https://html.duckduckgo.com/html/?" + urlencode({"q": request.args.get("q", "")}), opts(), 0)


@app.route("/form")
def form_submit():
    a = request.args.to_dict()
    base = a.pop("_u", "")
    o = {k: a.pop("_" + k, d) for k, d in DEF.items()}
    return go_to(base + ("&" if "?" in base else "?") + urlencode(a), o, 0)


@app.route("/go", methods=["GET", "POST"])
def go():
    try:
        p = int(request.args.get("p", 0) or 0)
    except ValueError:
        p = 0
    post = request.form.to_dict(flat=False) if request.method == "POST" else None
    return go_to(request.args.get("u", ""), opts(), p, post)


def fetch(u, post=None, referer=None, key=None):
    """GET/POST with manual redirects (every hop is SSRF-checked). Returns (response, bytes, final_url)."""
    s = client_session(key)
    for _ in range(8):
        u = safe_url(u)
        hdr = {"Referer": referer} if referer else {}
        if post is not None:
            r = s.post(u, data=post, headers=hdr, timeout=(6, 20), stream=True, allow_redirects=False)
        else:
            r = s.get(u, headers=hdr, timeout=(6, 20), stream=True, allow_redirects=False)
        if r.status_code in (301, 302, 303, 307, 308) and r.headers.get("Location"):
            r.close()
            u = urljoin(u, r.headers["Location"])
            if r.status_code in (301, 302, 303):
                post = None
            continue
        data = r.raw.read(MAX_BYTES, decode_content=True)
        r.close()
        return r, data, u
    raise ValueError("too many redirects")


def go_to(u, o, page, post=None):
    try:
        u = safe_url(u)
        key = (client_key(), u, o["i"], o["w"], o["g"], o["s"], o["m"])
        pages = None if post is not None else page_cache.get(key)
        if pages is None:
            r, data, final = fetch(u, post, referer=u)
            ctype = r.headers.get("Content-Type", "")
            if r.status_code == 418:
                return reply(shell("Blocked", "<p>Blocked by filter.</p>" + home_form()), 403)
            if "html" not in ctype and "xml" not in ctype and ctype:
                return reply(shell("File", '<p>%s</p><a href="/dl?u=%s">Download</a>' % (ctype, quote(final, safe=""))))
            enc = r.encoding if "charset" in ctype.lower() else None
            soup = BeautifulSoup(data, "lxml", from_encoding=enc)
            title = soup.title.get_text(strip=True) if soup.title else final
            pages = (final, title, paginate(simplify(soup, final, o), int(o["s"])))
            if post is None:
                page_cache.put(key, pages)
        final, title, chunks = pages
    except Exception as e:
        return reply(shell("Error", "<p>%s</p>" % str(e)[:200] + home_form()), 502)
    page = max(0, min(page, len(chunks) - 1))
    nav = ""
    if len(chunks) > 1:
        nav = "<hr>"
        if page:
            nav += '<a href="%s">&lt;</a> ' % go_link(final, o, page - 1)
        nav += "%d/%d " % (page + 1, len(chunks))
        if page < len(chunks) - 1:
            nav += '<a href="%s">&gt;</a>' % go_link(final, o, page + 1)
    flip_i = dict(o, i="0" if o["i"] == "1" else "1")
    flip_m = dict(o, m="full" if o["m"] == "lite" else "lite")
    hidden = "".join('<input type="hidden" name="%s" value="%s">' % (k, v) for k, v in o.items() if v != DEF[k])
    top = ('<form action="/go"><input name="u" value="%s" size="14">%s<input type="submit" value="Go"></form>'
           '<a href="/">Home</a> <a href="%s">Img %s</a> <a href="%s">%s</a><hr>') % (
        final.replace('"', "%22"), hidden, go_link(final, flip_i, page), "off" if o["i"] == "1" else "on",
        go_link(final, flip_m, page), "Full" if o["m"] == "lite" else "Lite")
    return reply(shell(title, top + chunks[page] + nav), cache=False)


def paginate(html, size):
    out, cur = [], html
    while len(cur) > size:
        cut = max(cur.rfind(t, 0, size) for t in ("</p>", "</li>", "<br>", "</tr>", "</h2>", "</h3>", "</div>"))
        cut = cut + 5 if cut > size // 2 else size
        out.append(cur[:cut])
        cur = cur[cut:]
    out.append(cur)
    return out


def simplify(soup, base, o):
    full = o["m"] == "full"
    b = soup.find("base", href=True)
    if b:
        base = urljoin(base, b["href"])
    prefix = ""
    mr = soup.find("meta", attrs={"http-equiv": re.compile("refresh", re.I)})
    if mr:
        m = re.search(r"url\s*=\s*['\"]?([^'\"]+)", mr.get("content") or "", re.I)
        if m:
            prefix += '<a href="%s">&gt;&gt; redirect</a><br>' % go_link(urljoin(base, m.group(1).strip()), o)
    if full:        # stylesheets are served through /css (url() and @import rewritten, fonts dropped)
        for l in soup.find_all("link", href=True)[:40]:
            if "stylesheet" in [x.lower() for x in (l.get("rel") or [])][:3] and len(prefix) < 3000:
                prefix += '<link rel="stylesheet" href="/css?%s">' % urlencode({"u": urljoin(base, l["href"]), "w": o["w"]})
    for c in soup.find_all(string=lambda s: isinstance(s, Comment)):
        c.extract()
    for t in soup.find_all(DROP_FULL if full else DROP_LITE):
        t.decompose()
    body = soup.body or soup
    if not full:
        body = soup.find("main") or soup.find("article") or body
    for t in list(body.find_all(True)):
        if t.name is None:      # already decomposed
            continue
        if not full and t.name not in KEEP:
            t.unwrap()
            continue
        attrs = {}
        if t.name == "a":
            h = (t.get("href") or "").strip()
            if not h or h.startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
                t.unwrap()
                continue
            attrs["href"] = go_link(urljoin(base, h), o)
        elif t.name == "img":
            src = t.get("src") or t.get("data-src") or (t.get("srcset") or "").split(",")[0].split(" ")[0]
            alt = (t.get("alt") or "").strip()
            if o["i"] != "1" or not src or src.startswith("data:"):
                t.replace_with("[%s]" % alt[:30] if alt else "")
                continue
            attrs["src"] = img_link(urljoin(base, src), o)
            if alt:
                attrs["alt"] = alt[:40]
        elif t.name in ("iframe", "frame"):
            if not t.get("src"):
                t.decompose()
                continue
            attrs["src"] = go_link(urljoin(base, t["src"]), o)
        elif t.name in ("video", "audio", "source", "embed", "track"):
            if t.get("src"):
                attrs["src"] = "/dl?" + urlencode({"u": urljoin(base, t["src"])})
            if t.get("poster") and o["i"] == "1":
                attrs["poster"] = img_link(urljoin(base, t["poster"]), o)
            if t.get("type"):
                attrs["type"] = t["type"]
            if t.name in ("video", "audio"):
                attrs["controls"] = "controls"
        elif t.name == "form":
            action = urljoin(base, t.get("action") or base)
            if o.get("px"):
                attrs = {"action": httpify(action), "method": (t.get("method") or "get").lower()}
            elif (t.get("method") or "get").lower() == "post":
                attrs = {"action": "/go?" + q(o, u=action), "method": "post"}
            else:
                attrs = {"action": "/form"}
                for k, v in [("_" + k, o[k]) for k in DEF if o[k] != DEF[k]] + [("_u", action)]:
                    t.insert(0, soup.new_tag("input", attrs={"type": "hidden", "name": k, "value": v}))
        elif t.name == "input":
            typ = (t.get("type") or "text").lower()
            if (t.get("name") or "").startswith("_") or typ in FORM_TYPES:
                for k in ("type", "name", "value", "checked"):
                    if t.get(k) is not None:
                        attrs[k] = t[k]
            else:
                t.decompose()
                continue
        elif t.name == "button":
            for k in ("type", "name", "value"):
                if t.get(k) is not None:
                    attrs[k] = t[k]
        elif t.name in ("textarea", "select"):
            if t.get("name"):
                attrs["name"] = t["name"]
        elif t.name == "option":
            if t.get("value") is not None:
                attrs["value"] = t["value"]
            if t.get("selected") is not None:
                attrs["selected"] = "selected"
        elif t.name == "label" and t.get("for"):
            attrs["for"] = t["for"]
        for k in (KEEP_ATTRS if full else ("id",) if t.name in ("input", "textarea", "select") else ()):
            v = t.get(k)
            if v and k not in attrs:
                attrs[k] = " ".join(v) if isinstance(v, list) else v
        t.attrs = attrs
    for t in body.find_all(["a", "p", "li", "td", "tr", "h1", "h2", "h3", "h4", "b", "i", "ul", "ol", "table", "div", "span"]):
        if t.name and not t.get_text(strip=True) and not t.find(["img", "input", "button", "textarea", "select"]):
            t.decompose()
    html = prefix + str(body)
    html = re.sub(r"</?(body|html|main|article)[^>]*>", "", html)
    html = re.sub(r"[ \t\r\n]+", " ", html)
    html = re.sub(r"(<br\s*/?>\s*){2,}", "<br>", html)
    return html.strip()


def convert_image(data, w, gray):
    im = Image.open(io.BytesIO(data))
    im.draft("RGB", (w * 2, w * 2))        # fast JPEG decode at reduced size
    im.seek(0)
    if im.mode in ("RGBA", "LA", "P"):
        im = im.convert("RGBA")
        bg = Image.new("RGB", im.size, "white")
        bg.paste(im, mask=im.split()[3])
        im = bg
    im = im.convert("L" if gray else "RGB")
    if im.width > w:
        im = im.resize((w, max(1, im.height * w // im.width)), Image.BILINEAR)
    buf = io.BytesIO()
    im.save(buf, "JPEG", quality=30, optimize=True, subsampling=2)
    return buf.getvalue()


@app.route("/img")
def img():
    try:
        u = safe_url(request.args.get("u", ""))
        w = max(16, min(int(request.args.get("w", DEF["w"])), 800))
        gray = request.args.get("g", "0") == "1"
        key = (u, w, gray)
        out = img_cache.get(key)
        if out is None:
            r, data, _ = fetch(u, referer=u)
            out = convert_image(data, w, gray)
            img_cache.put(key, out)
        return Response(out, mimetype="image/jpeg", headers={"Cache-Control": "max-age=3600"})
    except Exception:
        return Response(status=404)


CSS_URL = re.compile(r"url\(\s*['\"]?([^'\")]+?)['\"]?\s*\)", re.I)
CSS_IMPORT = re.compile(r"@import\s+(?:url\(\s*)?['\"]?([^'\");\s]+)['\"]?\s*\)?[^;]*;", re.I)


@app.route("/css")
def css():
    try:
        u = safe_url(request.args.get("u", ""))
        w = request.args.get("w", DEF["w"])
        out = img_cache.get(("css", u, w))
        if out is None:
            r, data, final = fetch(u, referer=u)
            text = data[:400_000].decode(r.encoding or "utf-8", "replace")
            text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)

            def imp(m):
                return '@import url("/css?%s");' % urlencode({"u": urljoin(final, m.group(1)), "w": w})

            def res(m):
                ref = m.group(1).strip()
                if ref.startswith("data:"):
                    return "none"
                if re.search(r"\.(woff2?|ttf|otf|eot)(\?|#|$)", ref, re.I):
                    return "none"
                return 'url("/img?%s")' % urlencode({"u": urljoin(final, ref), "w": w})

            text = CSS_IMPORT.sub(imp, text)
            text = re.sub(r"@font-face\s*\{[^}]*\}", "", text)
            text = CSS_URL.sub(lambda m: m.group(0) if m.group(0).startswith('url("/css?') else res(m), text)
            out = re.sub(r"\s+", " ", text).strip().encode("utf-8")
            img_cache.put(("css", u, w), out)
        return Response(out, mimetype="text/css", headers={"Cache-Control": "max-age=3600"})
    except Exception:
        return Response("", mimetype="text/css")


@app.route("/dl")
def dl():
    try:
        u = safe_url(request.args.get("u", ""))
        s = client_session()
        for _ in range(8):      # manual redirects so every hop is SSRF-checked
            r = s.get(safe_url(u), timeout=(6, 30), stream=True, allow_redirects=False)
            if r.status_code in (301, 302, 303, 307, 308) and r.headers.get("Location"):
                u = urljoin(u, r.headers["Location"])
                r.close()
                continue
            break
        h ={k: v for k, v in r.headers.items() if k.lower() in ("content-type", "content-length", "content-disposition")}
        return Response(r.iter_content(65536), headers=h)
    except Exception as e:
        return Response(str(e), status=502)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8095
    try:
        from waitress import serve
        serve(app, host="0.0.0.0", port=port, threads=16)
    except ImportError:
        app.run(host="0.0.0.0", port=port, threaded=True)
