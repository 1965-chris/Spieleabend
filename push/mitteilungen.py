# Mitteilungen der Spieleabend-App – schickt Push-Mitteilungen an die Geräte, die sie erlaubt haben.
# Diese Datei legt die App selbst ins Repo (push/mitteilungen.py) und hält sie aktuell; gestartet wird sie von .github/workflows/mitteilungen.yml.
# Gemeldet wird: neue Nachricht an den Admin (an die Admin-Geräte), Antwort vom Admin (an den Haushalt), Antwort des Haushalts (an den Admin),
# neuer Termin (an die eingeladenen Haushalte), Chat (Gruppe: alle im Spielkreis; direkt: die Geräte der Person, sonst ihr Haushalt). Der geheime Schlüssel liegt nur als GitHub-Secret PUSH_SCHLUESSEL vor, nie im Repo.
# Nebenbei, auf Wunsch aus der App: Fingerabdrücke der Dixit-Karten für den Kartensortierer (aus den Kartenübersichten des Verlags; gespeichert werden nur grobe Farbmuster, keine Bilder).
MITTEILUNGEN_VERSION = 3
import base64, datetime, hashlib, hmac, json, os, re, sys, time, urllib.error, urllib.request
from urllib.parse import urlparse

FRISCH = 3 * 86400           # ältere Ereignisse nicht mehr melden (z. B. nach verlorenem Zustand)
STAND_DATEI, TEST_ORDNER = 'push/stand.json', 'push/test'
NACHRICHT_ZEICHEN = {'fehler': '🐞', 'wunsch': '💡', 'kreis': '🏠', 'sonst': '💬'}
TERMIN_ZEICHEN = {'spiele': '🎲', 'kino': '🎬', 'bowling': '🎳', 'essen': '🍽️', 'grillen': '🔥', 'sonst': '✨'}
TAGE = ['Mo', 'Di', 'Mi', 'Do', 'Fr', 'Sa', 'So']


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()


def unb64u(s):
    s = str(s).strip()
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))


# ---------- Web Push: Verschlüsselung (RFC 8291) und Absender-Ausweis (VAPID, RFC 8292) ----------
def _hkdf(salz, ikm, info, laenge):
    prk = hmac.new(salz, ikm, hashlib.sha256).digest()
    return hmac.new(prk, info + b'\x01', hashlib.sha256).digest()[:laenge]


def schluessel_laden(text):
    from cryptography.hazmat.primitives.asymmetric import ec
    roh = unb64u(text)
    if len(roh) != 32: raise ValueError('Der Schlüssel hat nicht die richtige Länge.')
    return ec.derive_private_key(int.from_bytes(roh, 'big'), ec.SECP256R1())


def oeffentlich_roh(privat):
    from cryptography.hazmat.primitives import serialization
    return privat.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def verschluesseln(nutzlast, p256dh, auth, _salz=None, _privat=None):
    """Inhalt für genau ein Gerät verschlüsseln (aes128gcm, ein Datensatz)."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    ua_public, auth_secret = unb64u(p256dh), unb64u(auth)
    as_privat = _privat or ec.generate_private_key(ec.SECP256R1())
    as_public = oeffentlich_roh(as_privat)
    geraet = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ua_public)
    ecdh = as_privat.exchange(ec.ECDH(), geraet)
    ikm = _hkdf(auth_secret, ecdh, b'WebPush: info\x00' + ua_public + as_public, 32)
    salz = _salz or os.urandom(16)
    cek = _hkdf(salz, ikm, b'Content-Encoding: aes128gcm\x00', 16)
    nonce = _hkdf(salz, ikm, b'Content-Encoding: nonce\x00', 12)
    geheim = AESGCM(cek).encrypt(nonce, nutzlast + b'\x02', None)
    return salz + (4096).to_bytes(4, 'big') + bytes([len(as_public)]) + as_public + geheim


def vapid(endpunkt, privat, absender, jetzt=None):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    u = urlparse(endpunkt)
    kopf = b64u(json.dumps({'typ': 'JWT', 'alg': 'ES256'}, separators=(',', ':')).encode())
    inhalt = b64u(json.dumps({'aud': f'{u.scheme}://{u.netloc}', 'exp': int(jetzt or time.time()) + 12 * 3600, 'sub': absender}, separators=(',', ':')).encode())
    r, s = decode_dss_signature(privat.sign(f'{kopf}.{inhalt}'.encode(), ec.ECDSA(hashes.SHA256())))
    return f'vapid t={kopf}.{inhalt}.{b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))}, k={b64u(oeffentlich_roh(privat))}'


def senden(abo, daten, privat, absender):
    """Eine Mitteilung an ein Gerät. Antwort: HTTP-Code (201 = angenommen, 404/410 = Gerät hat sie abbestellt)."""
    koerper = verschluesseln(json.dumps(daten, ensure_ascii=False).encode(), abo['p256dh'], abo['auth'])
    req = urllib.request.Request(abo['endpoint'], data=koerper, method='POST', headers={
        'TTL': '86400', 'Urgency': 'normal', 'Content-Encoding': 'aes128gcm', 'Content-Type': 'application/octet-stream',
        'Authorization': vapid(abo['endpoint'], privat, absender)})
    try:
        with urllib.request.urlopen(req, timeout=20) as r: return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


# ---------- GitHub ----------
REPO = os.environ.get('GITHUB_REPOSITORY', '')
ZWEIG = os.environ.get('GITHUB_REF_NAME', 'main')
TOKEN = os.environ.get('GH_TOKEN', '')
API = os.environ.get('GITHUB_API_URL', 'https://api.github.com')


def gh(methode, pfad, daten=None, roh=False):
    req = urllib.request.Request(f'{API}/repos/{REPO}{pfad}', method=methode,
        data=None if daten is None else json.dumps(daten).encode(),
        headers={'Authorization': 'Bearer ' + TOKEN, 'Accept': 'application/vnd.github.raw' if roh else 'application/vnd.github+json',
                 'Content-Type': 'application/json', 'User-Agent': 'Spieleabend-Mitteilungen'})
    for versuch in range(4):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                b = r.read()
                return b if roh else json.loads(b or b'null')
        except urllib.error.HTTPError as e:
            if e.code == 404 and methode == 'GET': return None
            if e.code in (409, 422, 500, 502, 503) and versuch < 3: time.sleep(2 + 2 * versuch); continue
            raise


def json_lesen(pfad):
    b = gh('GET', f'/contents/{pfad}?ref={ZWEIG}', roh=True)
    if b is None: return None
    try: return json.loads(b.decode('utf-8'))
    except Exception: return None


def schreiben(pfad, daten, nachricht):
    alt = gh('GET', f'/contents/{pfad}?ref={ZWEIG}')
    gh('PUT', f'/contents/{pfad}', {'message': nachricht, 'branch': ZWEIG,
        'content': base64.b64encode(json.dumps(daten, ensure_ascii=False, indent=1).encode()).decode(), **({'sha': alt['sha']} if alt else {})})


# ---------- Dixit-Karten: Fingerabdrücke für den Kartensortierer der App ----------
# Jede Karte wird auf 10 × 15 Farbfelder verkleinert (ohne 6 % Rand), daraus Helligkeit und zwei Farbachsen, jeweils
# auf Mittelwert 0 gebracht – so stört es wenig, ob das Licht heller, dunkler oder gelblicher ist. Die App rechnet genauso.
KARTEN_ORDNER, KARTEN_QUELLE, KARTEN_ZEIT = 'karten', 'https://cdn.svc.asmodee.net/', 200
RASTER_B, RASTER_H, RAND = 10, 15, 0.06


def karten_pakete():
    try:
        import fitz, numpy, scipy.ndimage, PIL  # noqa: F401
    except ImportError:
        import importlib, site, subprocess
        subprocess.run([sys.executable, '-m', 'pip', 'install', '--quiet', '--user', '--break-system-packages',
                        'pymupdf', 'numpy', 'scipy', 'pillow'], check=True)
        p = site.getusersitepackages()
        if p not in sys.path: sys.path.insert(0, p)
        importlib.invalidate_caches()


def merkmal(zellen):
    """zellen: 150 × 3 Mittelwerte (R, G, B) – Zeile für Zeile von oben links. Ergebnis: 450 Zahlen als int8."""
    import numpy as np
    a = np.asarray(zellen, dtype=np.float64).reshape(-1, 3)
    hell = a.mean(1); rg = a[:, 0] - a[:, 1]; gb = (a[:, 0] + a[:, 1]) / 2 - a[:, 2]
    hell = (hell - hell.mean()) / max(hell.std(), 4.0)
    rg, gb = rg - rg.mean(), gb - gb.mean()
    s = max(rg.std(), gb.std(), 6.0)
    v = np.stack([hell, 0.7 * rg / s, 0.7 * gb / s], 1).reshape(-1)
    return np.clip(np.round(v * 32), -127, 127).astype(np.int8)


def fingerabdruck(bild):
    """bild: PIL-Bild einer ganzen Karte."""
    import numpy as np
    from PIL import Image
    w, h = bild.size
    innen = bild.convert('RGB').crop((round(w * RAND), round(h * RAND), w - round(w * RAND), h - round(h * RAND)))
    zellen = np.asarray(innen.resize((RASTER_B, RASTER_H), Image.BOX), dtype=np.float64)
    return merkmal(zellen)


def kartig(r, W, H):
    w, h = r[2] - r[0], r[3] - r[1]
    return h > 0 and w > 0 and 0.55 <= w / h <= 0.80 and 0.0015 * W * H <= w * h <= 0.45 * W * H


def flaechen(seite):
    """Karten auf einer gerenderten Seite finden: alles, was sich deutlich vom Seitenhintergrund abhebt."""
    import numpy as np
    import scipy.ndimage as nd
    rand = np.concatenate([seite[:4].reshape(-1, 3), seite[-4:].reshape(-1, 3), seite[:, :4].reshape(-1, 3), seite[:, -4:].reshape(-1, 3)])
    hg = np.median(rand, 0)
    maske = np.abs(seite.astype(np.int16) - hg).max(2) > 28
    maske = nd.binary_fill_holes(nd.binary_closing(maske, iterations=2))
    lab, _ = nd.label(maske)
    return [(s[1].start, s[0].start, s[1].stop, s[0].stop) for s in nd.find_objects(lab) if s]


def karten_finden(seiten):
    """seiten: [(Bild als H×W×3, Rechtecke der eingebetteten Bilder in Pixeln)]. Ergebnis: [(Seite, Rechteck)] in Lesereihenfolge."""
    kand, methoden = [], set()
    for nr, (bild, bilder) in enumerate(seiten):
        H, W = bild.shape[:2]
        eins = []
        for r in bilder:
            r = (max(0, r[0]), max(0, r[1]), min(W, r[2]), min(H, r[3]))
            if kartig(r, W, H) and not any(abs(r[0] - x[0]) < 3 and abs(r[1] - x[1]) < 3 and abs(r[2] - x[2]) < 3 for x in eins): eins.append(r)
        if len(eins) >= 4: methoden.add('bilder')
        else: eins = [r for r in flaechen(bild) if kartig(r, W, H)]; methoden.add('flaechen') if eins else None
        kand += [(nr, r) for r in eins]
    if not kand: return [], ''
    hoehen = sorted(r[3] - r[1] for _, r in kand)
    mh = hoehen[len(hoehen) // 2]
    kand = [(nr, r) for nr, r in kand if abs((r[3] - r[1]) - mh) <= 0.12 * mh]
    # Lesereihenfolge: Seite, Zeile (gleiche Höhe ± halbe Karte), dann von links
    kand.sort(key=lambda x: (x[0], x[1][1]))
    reihen, zeile = [], None
    for nr, r in kand:
        if zeile is None or nr != zeile[0] or r[1] - zeile[1] > mh / 2: zeile = (nr, r[1]); reihen.append([])
        reihen[-1].append((nr, r))
    return [x for reihe in reihen for x in sorted(reihe, key=lambda y: y[1][0])], '+'.join(sorted(methoden))


def pdf_seiten(daten):
    import fitz
    import numpy as np
    doc = fitz.open(stream=daten, filetype='pdf')
    for seite in doc:
        z = min(200 / 72, 5000 / max(seite.rect.width, seite.rect.height))
        pix = seite.get_pixmap(matrix=fitz.Matrix(z, z), alpha=False, colorspace=fitz.csRGB)
        bild = np.frombuffer(pix.samples, np.uint8).reshape(pix.height, pix.stride)[:, :pix.width * 3].reshape(pix.height, pix.width, 3)
        bilder = []
        try:
            for i in seite.get_image_info():
                x0, y0, x1, y1 = i['bbox']
                bilder.append((round(x0 * z), round(y0 * z), round(x1 * z), round(y1 * z)))
        except Exception:
            pass
        yield bild.copy(), bilder


def herunterladen(url):
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Spieleabend)'})
    with urllib.request.urlopen(req, timeout=60) as r:
        daten = r.read(120 * 1024 * 1024 + 1)
    if len(daten) > 120 * 1024 * 1024: raise ValueError('Die Datei ist zu groß.')
    return daten


def karten_berechnen(seiten):
    from PIL import Image
    gefunden, methode = karten_finden(seiten)
    abdruecke = [base64.b64encode(fingerabdruck(Image.fromarray(seiten[nr][0]).crop(r)).tobytes()).decode() for nr, r in gefunden]
    return abdruecke, methode


def karten_auftrag(auftrag, start, laden=herunterladen, seiten_aus=pdf_seiten):
    karten_pakete()
    ergebnis = {}
    for e in (auftrag.get('liste') or [])[:12]:
        k = re.sub(r'[^a-z0-9-]', '', str(e.get('k', '')).lower())[:30]
        url = str(e.get('url', ''))
        if not k or not url.startswith(KARTEN_QUELLE) or not url.lower().endswith('.pdf'): continue
        if time.time() - start > KARTEN_ZEIT:
            ergebnis[k] = {'fehler': 'Die Zeit hat nicht gereicht – bitte nochmal anstoßen, dann geht es weiter.'}; continue
        try:
            seiten = list(seiten_aus(laden(url)))
            abdruecke, methode = karten_berechnen(seiten)
            if not abdruecke: raise ValueError('In der Kartenübersicht wurden keine Karten gefunden.')
            schreiben(f'{KARTEN_ORDNER}/dixit-{k}.json', {'format': 1, 'k': k, 'quelle': url, 'raster': [RASTER_B, RASTER_H], 'rand': RAND,
                       'anzahl': len(abdruecke), 'methode': methode, 'seiten': len(seiten), 'karten': abdruecke, 'zeit': int(time.time() * 1000)},
                      f'Kartensortierer: {k} ({len(abdruecke)} Karten)')
            ergebnis[k] = {'anzahl': len(abdruecke), 'methode': methode, 'seiten': len(seiten)}
            print('Karten', k, len(abdruecke), methode, len(seiten), 'Seiten')
        except Exception as ex:
            ergebnis[k] = {'fehler': f'{type(ex).__name__}: {ex}'[:240]}
            print('Karten', k, 'Fehler', ex)
    return ergebnis


# ---------- Wer bekommt was? ----------
def zeit_text(z):
    try:
        d = datetime.datetime.strptime(z, '%Y-%m-%dT%H:%M')
        return f'{TAGE[d.weekday()]}, {d.day:02d}.{d.month:02d}. um {d.hour:02d}:{d.minute:02d} Uhr'
    except Exception:
        return ''


def kurz(text, n=140):
    text = re.sub(r'\s+', ' ', str(text or '')).strip()
    return text if len(text) <= n else text[:n - 1].rsplit(' ', 1)[0] + ' …'


def abo_ok(p, schluessel):
    return (isinstance(p, dict) and str(p.get('endpoint', '')).startswith('https://') and p.get('p256dh') and p.get('auth')
            and p.get('schluessel') == schluessel)


def abos_sammeln(haushalte, verwaltung, schluessel):
    """Geräte mit erlaubten Mitteilungen: Geräte-ID -> {abo, hid}. Ein Gerät, das den Haushalt gewechselt hat, zählt beim neuesten."""
    abos = {}
    for h in haushalte.values():
        for g in h.get('geraete') or []:
            p, gid = g.get('push'), str(g.get('id', ''))
            if not gid or not abo_ok(p, schluessel): continue
            alt = abos.get(gid)
            if not alt or (g.get('zuletzt') or 0) > alt['zuletzt']:
                abos[gid] = {'abo': p, 'hid': h.get('id'), 'zuletzt': g.get('zuletzt') or 0, 'personen': [str(x) for x in (g.get('personen') or [])]}
    for x in verwaltung.get('adminGeraete') or []:            # Admin-Gerät ohne eigenen Haushalt
        p, gid = x.get('push'), str(x.get('id', ''))
        if gid and gid not in abos and abo_ok(p, schluessel): abos[gid] = {'abo': p, 'hid': None, 'zuletzt': x.get('stand') or 0, 'personen': []}
    return abos


def ereignisse(haushalte, termine, verwaltung, abos):
    """Alle Ereignisse mit Schlüssel, Zeitpunkt, Empfängern und Text – gemeldet wird nur, was neu ist."""
    admin = {str(x.get('id')) for x in verwaltung.get('adminGeraete') or []}
    an_admin = sorted(g for g in abos if g in admin)
    def an_haushalte(hids, ohne_admin=False, ohne=()):
        return sorted(g for g, a in abos.items() if a['hid'] in hids and g not in ohne and not (ohne_admin and g in admin))
    liste = []
    for h in haushalte.values():
        name = h.get('name') or 'Ein Haushalt'
        for n in h.get('nachrichten') or []:
            if not n.get('id'): continue
            zeichen = NACHRICHT_ZEICHEN.get(n.get('art'), '💬')
            von = f" ({n['von']})" if n.get('von') else ''
            liste.append({'k': 'n:' + str(n['id']), 'zeit': (n.get('erstellt') or 0) / 1000, 'an': an_admin,
                'titel': f'Neue Nachricht von {name}{von}', 'text': f"{zeichen} {kurz(n.get('text'))}", 'ziel': 'nachrichten', 'tag': 'n-' + str(n['id'])})
            for v in n.get('verlauf') or []:
                if not v.get('id'): continue
                if v.get('admin'):
                    an, titel = an_haushalte({h.get('id')}, ohne_admin=True), 'Antwort vom Admin'
                else:
                    an, titel = an_admin, f"Antwort von {name}{(' (' + v['von'] + ')') if v.get('von') else ''}"
                liste.append({'k': 'v:' + str(v['id']), 'zeit': (v.get('zeit') or 0) / 1000, 'an': an, 'titel': titel,
                    'text': kurz(v.get('text')), 'ziel': 'nachrichten', 'tag': 'n-' + str(n['id'])})
    # Chat
    kreise = {str(k.get('id')): k for k in verwaltung.get('kreise') or [] if k.get('id')}
    for h in haushalte.values():
        hname = h.get('name') or 'Ein Haushalt'
        namen = {str(p.get('id')): p.get('name') for p in h.get('spieler') or []}
        for c in h.get('chat') or []:
            if not c.get('id') or not str(c.get('text', '')).strip(): continue
            von, an, geraet = str(c.get('von') or ''), str(c.get('an') or ''), str(c.get('geraet') or '')
            wer = namen.get(von) or 'Jemand'
            # nicht an das schreibende Gerät und nicht an andere Geräte, die allein dieser Person gehören
            def ohne_absender(gids):
                return sorted(g for g in gids if g != geraet and not (abos[g]['hid'] == h.get('id') and abos[g]['personen'] == [von]))
            if an.startswith('k:'):
                k = kreise.get(an[2:])
                if not k or 'chat' in (k.get('aus') or []): continue
                empf = ohne_absender(g for g, a in abos.items() if a['hid'] in set(k.get('haushalte') or []))
                liste.append({'k': 'c:' + str(c['id']), 'zeit': (c.get('zeit') or 0) / 1000, 'an': empf,
                    'titel': f"💬 {kurz(k.get('name') or 'Spielkreis', 60)}", 'text': f"{wer}: {kurz(c.get('text'))}", 'ziel': 'chat:' + an, 'tag': 'c-' + an})
            elif an.startswith('p:') and an.count(':') == 2:
                _, zhid, zpid = an.split(':')
                im_haus = [g for g, a in abos.items() if a['hid'] == zhid]
                persoenlich = [g for g in im_haus if zpid in abos[g]['personen']]
                empf = ohne_absender(persoenlich or im_haus)
                liste.append({'k': 'c:' + str(c['id']), 'zeit': (c.get('zeit') or 0) / 1000, 'an': empf,
                    'titel': f"💬 {wer} ({hname})", 'text': kurz(c.get('text')), 'ziel': f"chat:p:{h.get('id')}:{von}", 'tag': f"c-p-{h.get('id')}-{von}"})
    for t in termine.values():
        if not t.get('id'): continue
        eingeladen = set(t.get('haushalte') or []) or set(haushalte)
        optionen = [o for o in t.get('optionen') or [] if o.get('zeit')]
        wer = (haushalte.get(t.get('erstelltVon')) or {}).get('name') or 'Jemand'
        wann = zeit_text(optionen[0]['zeit']) if len(optionen) == 1 else (f'{len(optionen)} Termine zur Auswahl' if optionen else '')
        liste.append({'k': 't:' + str(t['id']), 'zeit': (t.get('erstellt') or 0) / 1000,
            'an': an_haushalte(eingeladen, ohne={str(t.get('geraet') or '')}),
            'titel': f"Neuer Termin: {TERMIN_ZEICHEN.get(t.get('art'), '🎲')} {kurz(t.get('titel') or 'Spieleabend', 60)}",
            'text': f"{wer} lädt ein{(' – ' + wann) if wann else ''}. Bitte in der App abstimmen.", 'ziel': 'termin:' + str(t['id']), 'tag': 't-' + str(t['id'])})
    return liste


def main():
    jetzt = time.time()
    owner, repo = (REPO.split('/') + [''])[:2]
    absender = f'https://{owner.lower()}.github.io/{repo}/'
    haushalte, termine = {}, {}
    for f in gh('GET', f'/contents/daten?ref={ZWEIG}') or []:
        n = f.get('name', '')
        if f.get('type') != 'file' or not n.endswith('.json'): continue
        if n.startswith('haushalt-'):
            d = json_lesen(f'daten/{n}')
            if d and d.get('id'): haushalte[str(d['id'])] = d
        elif n.startswith('termin-'):
            d = json_lesen(f'daten/{n}')
            if d: d.setdefault('id', n[7:-5]); termine[str(d['id'])] = d
    verwaltung = json_lesen('daten/verwaltung.json') or {}
    schluessel = (verwaltung.get('push') or {}).get('schluessel') or ''
    stand_alt = json_lesen(STAND_DATEI)
    stand = dict(stand_alt or {})
    stand.update({'version': MITTEILUNGEN_VERSION, 'fehler': ''})

    privat = None
    geheim = os.environ.get('PUSH_SCHLUESSEL', '').strip()
    if not schluessel:
        stand['fehler'] = 'In der App ist noch kein Schlüssel für Mitteilungen erzeugt.'
    elif not geheim:
        stand['fehler'] = 'Das GitHub-Secret PUSH_SCHLUESSEL fehlt.'
    else:
        try:
            privat = schluessel_laden(geheim)
            if b64u(oeffentlich_roh(privat)) != schluessel:
                privat, stand['fehler'] = None, 'Das GitHub-Secret PUSH_SCHLUESSEL passt nicht zum Schlüssel der App – bitte den zuletzt angezeigten Schlüssel eintragen.'
        except Exception:
            stand['fehler'] = 'Das GitHub-Secret PUSH_SCHLUESSEL ist kein gültiger Schlüssel.'

    abos = abos_sammeln(haushalte, verwaltung, schluessel)
    liste = ereignisse(haushalte, termine, verwaltung, abos)
    gesehen = set(stand.get('gesehen') or [])
    erstes_mal = stand_alt is None or 'gesehen' not in stand_alt
    abgelaufen = dict(stand.get('abgelaufen') or {})
    gesendet = list(stand.get('gesendet') or [])

    def zustellen(gids, daten):
        ok = 0
        for gid in gids:
            code = senden(abos[gid]['abo'], daten, privat, absender)
            print(f"  {daten['titel'][:40]!r} -> {gid}: {code}")
            if 200 <= code < 300: ok += 1
            elif code in (404, 410): abgelaufen[gid] = int(jetzt * 1000)
        return ok

    if not erstes_mal and privat:
        for e in liste:
            if e['k'] in gesehen or not e['an'] or jetzt - e['zeit'] > FRISCH: continue
            ok = zustellen(e['an'], {'titel': e['titel'], 'text': e['text'], 'ziel': e['ziel'], 'tag': e['tag']})
            gesendet.append({'zeit': int(jetzt * 1000), 'titel': e['titel'], 'an': len(e['an']), 'ok': ok})
    stand['gesehen'] = sorted({e['k'] for e in liste})       # nur, was es noch gibt – so wächst die Datei nicht

    # Test-Mitteilungen aus der App
    for f in gh('GET', f'/contents/{TEST_ORDNER}?ref={ZWEIG}') or []:
        if f.get('type') != 'file': continue
        auftrag = json_lesen(f'{TEST_ORDNER}/{f["name"]}') or {}
        if auftrag.get('art') == 'karten':
            try: ergebnis, fehler = karten_auftrag(auftrag, jetzt), ''
            except Exception as ex: ergebnis, fehler = {}, f'{type(ex).__name__}: {ex}'[:300]
            stand['karten'] = {'id': f['name'][:-5], 'zeit': int(time.time() * 1000), 'ergebnis': ergebnis, 'fehler': fehler}
            gh('DELETE', f'/contents/{TEST_ORDNER}/{f["name"]}', {'message': 'Kartensortierer: erledigt', 'sha': f['sha'], 'branch': ZWEIG})
            continue
        gid = str(auftrag.get('geraet') or '')
        if not privat: ergebnis = stand['fehler']
        elif gid not in abos: ergebnis = 'Dieses Gerät hat (noch) keine Mitteilungen erlaubt – oder der Abgleich lief noch nicht.'
        else:
            code = senden(abos[gid]['abo'], {'titel': 'Test-Mitteilung', 'text': 'So sehen Mitteilungen vom Spieleabend aus. 🎲', 'ziel': 'einstellungen', 'tag': 'test'}, privat, absender)
            if code in (404, 410): abgelaufen[gid] = int(jetzt * 1000)
            ergebnis = 'ok' if 200 <= code < 300 else f'Der Mitteilungsdienst hat abgelehnt (Code {code}).'
        stand['test'] = {'id': f['name'][:-5], 'geraet': gid, 'zeit': int(jetzt * 1000), 'ergebnis': ergebnis}
        print('Test', gid, ergebnis)
        gh('DELETE', f'/contents/{TEST_ORDNER}/{f["name"]}', {'message': 'Mitteilungen: Test erledigt', 'sha': f['sha'], 'branch': ZWEIG})

    stand['abgelaufen'] = {g: z for g, z in abgelaufen.items() if jetzt * 1000 - z < 60 * 86400000}
    stand['gesendet'] = gesendet[-30:]
    stand['geraete'] = len(abos)
    if stand != stand_alt:
        stand['zeit'] = int(jetzt * 1000)
        schreiben(STAND_DATEI, stand, 'Mitteilungen: ' + ('eingerichtet' if erstes_mal else 'verschickt'))
    print('Geräte mit Mitteilungen:', len(abos), '| Fehler:', stand['fehler'] or '–')


if __name__ == '__main__':
    main()
