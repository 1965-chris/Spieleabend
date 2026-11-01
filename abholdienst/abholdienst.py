# Abholdienst der Spieleabend-App – holt auf Wunsch Spielangaben bei Spiele-Offensive ab.
# Diese Datei legt die App selbst ins Repo und hält sie aktuell; gestartet wird sie von .github/workflows/abholdienst.yml.
# Regeln: nur Seiten, die die robots.txt des Shops erlaubt; Spiele werden über die Sitemap gefunden, die der Shop dafür anbietet
# (keine Suchseiten); der Dienst stellt sich als „Spieleabend-Abholdienst“ vor und lässt zwischen zwei Abrufen eine Pause.
ABHOLDIENST_VERSION = 5
import base64, datetime, gzip, html, json, os, re, time, urllib.error, urllib.request, urllib.robotparser

REPO, ZWEIG, TOKEN = os.environ['GITHUB_REPOSITORY'], os.environ['GITHUB_REF_NAME'], os.environ['GH_TOKEN']
BASIS, NAME = 'https://www.spiele-offensive.de', 'Spieleabend-Abholdienst'
UA = ('Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 '
      'Mobile/15E148 Safari/604.1 ' + NAME + '/' + str(ABHOLDIENST_VERSION))
AUFTRAEGE, ERGEBNISSE = 'abholdienst/auftraege', 'abholdienst/ergebnisse'
LINK = re.compile(r'^https?://(?:www\.)?spiele-offensive\.de(/Spiel/[^?#\s"<>]+-(\d+)\.html)$', re.I)
PAUSE, MAX_TREFFER, MAX_BILD = 0.8, 4, 160_000
WERBUNG = re.compile(r'versandkostenfrei|g(?:ü|ue)nstig (?:bestellen|kaufen)|\bhier\b[^.!?\n]{0,50}\bbestellen|jetzt (?:online )?(?:bestellen|kaufen)|zuletzt aktualisiert', re.I)


def gh(methode, pfad, daten=None):
    req = urllib.request.Request(f'https://api.github.com/repos/{REPO}{pfad}', method=methode,
        data=None if daten is None else json.dumps(daten).encode(),
        headers={'Authorization': 'Bearer ' + TOKEN, 'Accept': 'application/vnd.github+json', 'Content-Type': 'application/json', 'User-Agent': NAME})
    for versuch in range(4):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read() or b'null')
        except urllib.error.HTTPError as e:
            if e.code == 404 and methode == 'GET': return None
            if e.code in (409, 422, 500, 502, 503) and versuch < 3: time.sleep(2 + 2 * versuch); continue
            raise


_letzter = 0.0
def holen(url, roh=False, grenze=3_000_000, zeit=25):
    global _letzter
    warten = PAUSE - (time.time() - _letzter)
    if warten > 0: time.sleep(warten)
    req = urllib.request.Request(url, headers={'User-Agent': UA, 'Accept-Language': 'de-DE,de;q=0.9', 'Accept': 'text/html,application/xml,image/*,*/*'})
    try:
        with urllib.request.urlopen(req, timeout=zeit) as r:
            b = r.read(grenze)
            if b[:2] == b'\x1f\x8b': b = gzip.decompress(b)
            return (b, r.headers.get_content_type()) if roh else b.decode(r.headers.get_content_charset() or 'utf-8', 'replace')
    finally:
        _letzter = time.time()


_robots = None
def robots():
    global _robots
    if _robots is None:
        _robots = urllib.robotparser.RobotFileParser()
        try: _robots.parse(holen(BASIS + '/robots.txt').splitlines())
        except urllib.error.HTTPError as e: _robots.parse([] if e.code < 500 else ['User-agent: *', 'Disallow: /'])
    return _robots
def erlaubt(url): return robots().can_fetch(NAME, url)


# ---------- Verzeichnis aller Spielseiten aus der Sitemap ----------
_katalog, _katalog_info = None, {}
def katalog():
    global _katalog
    if _katalog is not None: return _katalog
    _katalog, warte, gesehen = {}, [u.replace('http://', 'https://', 1) for u in (robots().site_maps() or [])], set()
    while warte and len(gesehen) < 30:
        u = warte.pop(0)
        if u in gesehen or not erlaubt(u): continue
        gesehen.add(u)
        try: x = holen(u, grenze=60_000_000, zeit=90)
        except Exception as e: _katalog_info.setdefault('fehler', []).append(f'{u.rsplit("/", 1)[-1]}: {type(e).__name__}'); continue
        for loc in re.findall(r'<loc>\s*([^<\s]+)\s*</loc>', x):
            loc = html.unescape(loc).replace('http://', 'https://', 1)
            m = LINK.match(loc)
            if m: _katalog[BASIS + m.group(1)] = m.group(2)
            elif re.search(r'sitemap', loc, re.I) and loc not in gesehen: warte.append(loc)
    _katalog_info.update({'dateien': len(gesehen), 'spiele': len(_katalog)})
    return _katalog


def woerter(s):
    s = s.lower()
    for a, b in (('ä', 'ae'), ('ö', 'oe'), ('ü', 'ue'), ('ß', 'ss'), ('é', 'e'), ('è', 'e'), ('á', 'a'), ('&', ' und ')): s = s.replace(a, b)
    return re.findall(r'[a-z0-9]+', s)


def suchen(name):
    """Die besten Spielseiten zu einem Namen – alle Wörter des Namens müssen in der Adresse vorkommen."""
    q = woerter(name)
    if not q: return []
    bewertet = []
    for url, artikel in katalog().items():
        slug = woerter(url.rsplit('/', 1)[1][:-len(artikel) - 6])
        fehlt = sum(1 for w in q if not any(s == w or (len(w) >= 4 and s.startswith(w)) for s in slug))
        if fehlt: continue
        extra = sum(1 for s in slug if s not in q)
        bewertet.append(((extra, slug[:len(q)] != q, len(slug), url), url, artikel))
    bewertet.sort()
    return [(u, a) for _, u, a in bewertet[:MAX_TREFFER]]


# ---------- Eine Spielseite lesen ----------
def meta(t, *namen):
    for n in namen:
        for m in re.finditer(r'<meta\b[^>]*>', t, re.I):
            tag = m.group(0)
            if re.search(r'(?:property|name|itemprop)\s*=\s*["\']' + re.escape(n) + r'["\']', tag, re.I):
                c = re.search(r'content\s*=\s*"([^"]*)"', tag, re.I) or re.search(r"content\s*=\s*'([^']*)'", tag, re.I)
                if c and c.group(1).strip(): return html.unescape(c.group(1)).strip()
    return ''


def zeilen(t):
    t = re.sub(r'(?is)<(script|style|noscript|svg|head)\b.*?</\1>', ' ', t)
    t = re.sub(r'(?i)<br\s*/?>|</(p|div|li|h[1-6]|tr|section|article|ul|table)>', '\n', t)
    t = html.unescape(re.sub(r'<[^>]+>', ' ', t))
    return [z for z in (re.sub(r'\s+', ' ', x).strip() for x in t.split('\n')) if z]


def kuerzen(text, n=2000):
    text = '\n'.join(re.sub(r'[ \t]+', ' ', z).strip() for z in text.split('\n')).strip()
    if len(text) <= n: return text
    s = text[:n]; p = max(s.rfind('. '), s.rfind('! '), s.rfind('? '))
    return s[:p + 1] if p > n // 3 else s.rsplit(' ', 1)[0] + ' …'


def spielseite(url, artikel):
    t = holen(url)
    z = zeilen(t); T = ' '.join(z)
    name = meta(t, 'og:title')
    if not name:
        h = re.search(r'(?is)<h1\b[^>]*>(.*?)</h1>', t) or re.search(r'(?is)<title\b[^>]*>(.*?)</title>', t)
        name = re.sub(r'\s+', ' ', html.unescape(re.sub(r'<[^>]+>', ' ', h.group(1)))).strip() if h else ''
    name = name.split('|')[0].strip()
    name = re.sub(r'\s*[-–]\s*(?:Spiel|Kennerspiel|Kinderspiel) des Jahres \d{4}.*$', '', name, flags=re.I)
    name = re.sub(r'\s+Spiel$', '', name).strip()
    d = {'link': url, 'name': name, 'spielerMin': None, 'spielerMax': None, 'alterAb': None, 'dauer': None}
    m = re.search(r'f(?:ü|ue)r\s+(\d{1,2})\s*(?:bis|-|–)\s*(\d{1,3})\s*Spieler', T) or re.search(r'f(?:ü|ue)r\s+(\d{1,2})\s*Spieler', T)
    if m: d['spielerMin'] = int(m.group(1)); d['spielerMax'] = int(m.group(m.lastindex))
    m = re.search(r'im Alter (?:von|ab)\s*(\d{1,2})', T) or re.search(r'\bab\s*(\d{1,2})\s*Jahren', T)
    if m: d['alterAb'] = int(m.group(1))
    m = re.search(r'Spieldauer\s*:?\s*(?:von\s*)?(?:ca\.?|circa|etwa|rund)?\s*(\d{1,3})(?:\s*(?:-|–|bis)\s*(\d{1,3}))?\s*Min', T, re.I)
    if m: d['dauer'] = max(int(x) for x in m.groups() if x)
    beschr = meta(t, 'og:description', 'description', 'twitter:description')
    if beschr and WERBUNG.search(beschr): beschr = ''          # „… hier versandkostenfrei und günstig bestellen“ ist keine Beschreibung
    if not beschr or len(beschr) < 60:
        sperre = re.compile(r'cookie|datenschutz|warenkorb|versand|newsletter|€|\bEUR\b|bewertung|kundentest|rezension|zahlung|lieferzeit|javascript|anmelden|konto|bestellen|aktualisiert', re.I)
        gut = [i for i, x in enumerate(z) if len(x) >= 80 and not sperre.search(x)]
        satz = next((i for i, x in enumerate(z) if re.search(r'Spiel f(?:ü|ue)r\s+\d', x)), None)
        nah = [i for i in gut if satz is not None and abs(i - satz) <= 8 and not (re.search(r'Spiel f(?:ü|ue)r\s+\d', z[i]) and len(z[i]) < 160)]
        beschr = '\n'.join(z[i] for i in sorted(nah)) if nah else (z[gut[0]] if gut else '')   # alle Absätze der Beschreibung, nicht nur einer
    beschr = '\n'.join(re.sub(r'\s*\d+,\d{2}\s*(?:€|EUR).*$', '', x) for x in (beschr or '').split('\n')).strip()
    d['beschreibung'] = kuerzen(beschr)
    d['verlag'] = ''
    for i, x in enumerate(z):                      # „Herstellerinformationen“ → Verlag (ohne GmbH & Co.)
        if not re.search(r'Herstellerinformation|^Hersteller\b|^Verlag\b', x, re.I): continue
        rest = re.sub(r'^.*?(?:Herstellerinformationen?|Hersteller|Verlag)\s*:?\s*', '', x, flags=re.I).strip()
        for k in [rest] + z[i + 1:i + 3]:
            k = re.sub(r'\s*(?:GmbH|AG|KG|OHG|e\.\s?K\.|Ltd\.?|Inc\.?|S\.A\.S?\.?)\b.*$', '', k).strip(' ,-')
            k = re.sub(r'[\s-]*Verlags?$', '', k).strip(' ,-')
            if 2 <= len(k) <= 50 and not re.search(r'\d|@|www\.|stra(?:ß|ss)e|str\.|http', k, re.I): d['verlag'] = k; break
        if d['verlag']: break
    d['kategorien'] = list(dict.fromkeys(re.sub(r'\s+', ' ', html.unescape(re.sub(r'<[^>]+>', '', x))).strip()
        for x in re.findall(r'(?is)<a\b[^>]*href="[^"]*/Kategorie/[^"]*"[^>]*>(.*?)</a>', t)))[:30]
    bild = meta(t, 'og:image')
    bild = bild[bild.rfind('http'):] if 'http' in bild else ''
    if not re.match(r'^https://(?:mediaservice\.happyshops\.com|www\.spiele-offensive\.de)/', bild):
        bild = f'https://mediaservice.happyshops.com/ANY/Article/{int(artikel):012d}/{artikel}.jpg'
    d['bild'] = None
    try:
        b, typ = holen(bild, roh=True)
        if 1000 < len(b) <= MAX_BILD and typ in ('image/jpeg', 'image/png', 'image/webp'):
            d['bild'] = {'typ': typ, 'daten': base64.b64encode(b).decode()}
    except Exception:
        pass
    return d


def fehlertext(e):
    if isinstance(e, urllib.error.HTTPError):
        return 'Diese Spielseite gibt es bei Spiele-Offensive nicht (mehr).' if e.code == 404 else f'Spiele-Offensive hat die Anfrage abgelehnt (Code {e.code}).'
    return f'Die Seite ließ sich nicht abholen ({type(e).__name__}).'


def abholen(auftrag):
    link, name = str(auftrag.get('link') or '').strip(), str(auftrag.get('name') or '').strip()[:80]
    if link:
        m = LINK.match(link)
        if not m: return {'ok': False, 'fehler': 'Das ist kein Link zu einer Spielseite bei Spiele-Offensive (…/Spiel/…).'}
        seiten = [(BASIS + m.group(1), m.group(2))]
    elif name:
        try: seiten = suchen(name)
        except Exception as e: return {'ok': False, 'fehler': 'Das Verzeichnis des Shops ließ sich nicht lesen.', 'info': {**_katalog_info, 'grund': type(e).__name__}}
        if not seiten:
            if not _katalog: return {'ok': False, 'fehler': 'Das Verzeichnis des Shops ließ sich nicht lesen – bitte den Weg über den Link nehmen.', 'info': _katalog_info}
            return {'ok': False, 'fehler': f'Bei Spiele-Offensive nichts zu „{name}“ gefunden.', 'info': _katalog_info}
    else:
        return {'ok': False, 'fehler': 'Kein Spiel angegeben.'}
    treffer, letzter_fehler = [], None
    for url, artikel in seiten:
        if not erlaubt(url): letzter_fehler = 'Spiele-Offensive erlaubt das Abholen dieser Seite nicht.'; continue
        try: treffer.append(spielseite(url, artikel))
        except Exception as e: letzter_fehler = fehlertext(e)
    if not treffer: return {'ok': False, 'fehler': letzter_fehler or 'Nichts gefunden.', 'info': _katalog_info}
    return {'ok': True, 'quelle': 'Spiele-Offensive', 'treffer': treffer, 'info': _katalog_info}


def main():
    jetzt = datetime.datetime.now(datetime.timezone.utc)
    for f in gh('GET', f'/contents/{AUFTRAEGE}?ref={ZWEIG}') or []:
        if f.get('type') != 'file' or not f['name'].endswith('.json'): continue
        id_ = f['name'][:-5]
        try: auftrag = json.loads(base64.b64decode((gh('GET', f"/contents/{AUFTRAEGE}/{f['name']}?ref={ZWEIG}") or {}).get('content', '')))
        except Exception: auftrag = {}
        if re.fullmatch(r'[a-z0-9]{4,40}', id_):
            ergebnis = {'id': id_, 'zeit': jetzt.isoformat(), 'version': ABHOLDIENST_VERSION, **abholen(auftrag)}
            print(id_, 'ok' if ergebnis['ok'] else ergebnis['fehler'], [t['name'] for t in ergebnis.get('treffer', [])], ergebnis.get('info', ''))
            pfad = f'{ERGEBNISSE}/{id_}.json'
            alt = gh('GET', f'/contents/{pfad}?ref={ZWEIG}')
            gh('PUT', f'/contents/{pfad}', {'message': 'Abholdienst: ' + (', '.join(t['name'] for t in ergebnis.get('treffer', [])) or 'Ergebnis')[:70],
                'branch': ZWEIG, 'content': base64.b64encode(json.dumps(ergebnis, ensure_ascii=False).encode()).decode(), **({'sha': alt['sha']} if alt else {})})
        gh('DELETE', f"/contents/{AUFTRAEGE}/{f['name']}", {'message': 'Abholdienst: Auftrag erledigt', 'sha': f['sha'], 'branch': ZWEIG})
    # Liegengebliebene Ergebnisse (älter als ein Tag) aufräumen
    for f in gh('GET', f'/contents/{ERGEBNISSE}?ref={ZWEIG}') or []:
        if f.get('type') != 'file': continue
        try:
            e = json.loads(base64.b64decode(gh('GET', f"/contents/{ERGEBNISSE}/{f['name']}?ref={ZWEIG}")['content']))
            alt = jetzt - datetime.datetime.fromisoformat(e['zeit']) > datetime.timedelta(days=1)
        except Exception:
            alt = True
        if alt: gh('DELETE', f"/contents/{ERGEBNISSE}/{f['name']}", {'message': 'Abholdienst: aufgeräumt', 'sha': f['sha'], 'branch': ZWEIG})


if __name__ == '__main__':
    main()
