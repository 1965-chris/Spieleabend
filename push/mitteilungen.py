# Mitteilungen der Spieleabend-App – schickt Push-Mitteilungen an die Geräte, die sie erlaubt haben.
# Diese Datei legt die App selbst ins Repo (push/mitteilungen.py) und hält sie aktuell; gestartet wird sie von .github/workflows/mitteilungen.yml.
# Gemeldet wird: neue Nachricht an den Admin (an die Admin-Geräte), Antwort vom Admin (an den Haushalt), Antwort des Haushalts (an den Admin),
# neuer Termin (an die eingeladenen Haushalte), Chat (Gruppe: alle im Spielkreis; direkt: die Geräte der Person, sonst ihr Haushalt). Der geheime Schlüssel liegt nur als GitHub-Secret PUSH_SCHLUESSEL vor, nie im Repo.
# Nebenbei, auf Wunsch aus der App: Fingerabdrücke der Dixit-Karten für den Kartensortierer (aus den Kartenübersichten des Verlags; gespeichert werden nur grobe Farbmuster, keine Bilder).
MITTEILUNGEN_VERSION = 6
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
# Die Kartenbilder kommen direkt aus dem PDF (eingebettete Bilder). Jede Karte wird auf 10 × 15 Farbfelder verkleinert (ohne 6 % Rand), daraus Helligkeit und zwei Farbachsen, jeweils
# auf Mittelwert 0 gebracht – so stört es wenig, ob das Licht heller, dunkler oder gelblicher ist. Die App rechnet genauso.
KARTEN_ORDNER, KARTEN_QUELLE, KARTEN_ZEIT = 'karten', 'https://cdn.svc.asmodee.net/', 200
RASTER_B, RASTER_H, RAND = 10, 15, 0.06


def karten_pakete():
    try:
        import pikepdf, numpy, PIL  # noqa: F401
    except ImportError:
        import importlib, site, subprocess
        subprocess.run([sys.executable, '-m', 'pip', 'install', '--quiet', '--user', '--break-system-packages',
                        'pikepdf', 'numpy', 'pillow'], check=True)
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


def pdf_kartenbilder(daten):
    """Alle eingebetteten Bilder mit ihrer Lage auf der Seite; Karten sind die, die einzeln vorkommen, hochkant sind
    und alle etwa gleich groß dargestellt werden (Schatten kommen 84-mal vor, Logo und Zierbilder haben andere Maße)."""
    import io, math
    import pikepdf
    from PIL import Image, ImageChops
    pdf = pikepdf.open(io.BytesIO(daten))
    def mal(m, n):
        a, b, c, d, e, f = m; A, B, C, D, E, F = n
        return [a * A + b * C, a * B + b * D, c * A + d * C, c * B + d * D, e * A + f * C + E, e * B + f * D + F]
    gefunden = []
    def gehen(inhalt, res, ctm, seite, tiefe):
        if tiefe > 8: return
        stapel, xobj = [], (res.get('/XObject') if res is not None else None) or {}
        for operanden, op in pikepdf.parse_content_stream(inhalt):
            op = str(op)
            if op == 'q': stapel.append(ctm)
            elif op == 'Q': ctm = stapel.pop() if stapel else ctm
            elif op == 'cm' and len(operanden) == 6: ctm = mal([float(x) for x in operanden], ctm)
            elif op == 'Do' and operanden:
                x = xobj.get(operanden[0])
                if x is None: continue
                art = x.get('/Subtype')
                if art == '/Image': gefunden.append((seite, x.objgen, x, ctm))
                elif art == '/Form':
                    m = [float(v) for v in x.get('/Matrix', [1, 0, 0, 1, 0, 0])]
                    gehen(x, x.get('/Resources', res), mal(m, ctm), seite, tiefe + 1)
    for nr, s in enumerate(pdf.pages):
        gehen(s, s.get('/Resources'), [1, 0, 0, 1, 0, 0], nr, 0)
    zahl = {}
    for _, og, _, _ in gefunden: zahl[og] = zahl.get(og, 0) + 1
    kand = []
    for seite, og, x, m in gefunden:
        if zahl[og] > 2: continue                                   # z. B. der Schatten unter jeder Karte
        w, h = int(x.get('/Width', 0)), int(x.get('/Height', 0))
        if w < 40 or h < 40: continue
        drehung = round(math.degrees(math.atan2(m[1], m[0])) / 90) % 4      # wie das Bild auf der Seite liegt (kleine Schräglagen egal)
        if drehung % 2: w, h = h, w
        if not 0.6 <= w / h <= 0.8: continue
        bh = math.hypot(m[2], m[3]) if drehung % 2 == 0 else math.hypot(m[0], m[1])      # dargestellte Höhe
        cx, cy = m[0] / 2 + m[2] / 2 + m[4], m[1] / 2 + m[3] / 2 + m[5]
        kand.append({'seite': seite, 'x': x, 'drehung': drehung, 'bh': bh, 'cx': cx, 'cy': cy})
    if not kand: return [], ''
    hoehen = sorted(k['bh'] for k in kand); mh = hoehen[len(hoehen) // 2]
    kand = [k for k in kand if abs(k['bh'] - mh) <= 0.25 * mh]           # manche liegen etwas größer (aufgefächert)
    # Lesereihenfolge: Seite, Zeile (von oben), dann von links
    kand.sort(key=lambda k: (k['seite'], -k['cy']))
    reihen, zeile = [], None
    for k in kand:
        if zeile is None or k['seite'] != zeile[0] or zeile[1] - k['cy'] > mh / 2: zeile = (k['seite'], k['cy']); reihen.append([])
        reihen[-1].append(k)
    bilder = []
    for k in [k for r in reihen for k in sorted(r, key=lambda y: y['cx'])]:
        img = pikepdf.PdfImage(k['x']).as_pil_image()
        if img.mode == 'CMYK':
            # Adobe-CMYK-JPEGs dreht PIL beim Lesen um, im PDF gelten aber die gespeicherten Werte (außer /Decode dreht sie selbst um)
            filt = k['x'].get('/Filter')
            adobe = str(filt if not isinstance(filt, pikepdf.Array) else (filt[-1] if len(filt) else '')) == '/DCTDecode' and b'Adobe' in k['x'].read_raw_bytes()[:4000]
            dec = k['x'].get('/Decode')
            umgedreht = dec is not None and len(dec) >= 2 and float(dec[0]) > float(dec[1])
            if adobe != umgedreht: img = ImageChops.invert(img)
        img = img.convert('RGB')
        if k['drehung']: img = img.rotate(90 * k['drehung'], expand=True)
        bilder.append(img)
    return bilder, 'pdf-bilder'


# Mirrors (Nr. 10): Die Kartenübersicht ist ein einziges Seitenbild, die Karten liegen schräg und teils hell auf hellem Grund.
# Deshalb sind ihre Fingerabdrücke hier fest hinterlegt (aus der Übersicht ausgeschnitten und von Hand geprüft) – nur Farbmuster, keine Bilder.
FERTIG_KARTEN = {'mirrors': (
    'Ivz+XwwEbw8CNv/yCvXs3vbvB/js5//26+zn3/PrGPL1cRMFaBD8WxP/+gf94+3pCPfr/ycb5PLs4vPrEvj6Ugb3OAD6GRAKCfr9'
    '/OfnD/fxB/v08vHp5fXr+snjB9Dm997v993uA9HoA+boFuvtE/fx/enl8Ofm7t7r7d/u5v7/AAoZEv8TCNvmG97nBvPv99/j9dvf'
    '8Nvo89fq6fj8HR5AGRc1GwshIfTvF/b1+drfA+nq4vn74QUB6f0BBhlB+Q4sDBoyGfcAEd7rBNvg5xgVE+r3/PP7CPb5FB0p/h4p'
    'EBshFRIfCtfj9/v63hINAN/qIfYBHA4RIikuGjs/FRIPHgAE++Pn4xsY3BgT7PLuK/D5RvoJIBchHRkgFQ4MAuPo8O/u4//71xsV'
    '8gj93vXtB+vtJP0FCxMRFBQSBOvu5QL+3R0Y3SAa3v732f710wH3++DnKwMKFQsL7+nn3R4Y3SAa0yAV3wQC2QMN3wkB1QD49Pn3'
    '9AP7+gf++SMX6B8TzxcL0QwG5RIM2gD45QP86wgBAQwFJSMV+yUW/x8T4w8F4BEI2xEK2g8F4BMG3f344g4D+x4SFhgOAxAE+hUJ'
    '+wr6GPLeAgjzGOzYFerYCvfn+QP5FezeC/jo/w/27AEEHObYF+ncEOvfGObWDfLk+/fyEezkBPPt8v75Avfv9f/6+/v2BPTsBPTs'
    '9/349f/49f75+vr28/78Avfs+Pv0/Prz9P/36AIA7QL96QMD6AMB9P759//46gEB9//2Avft7QD94gQH8QD88AD97gH7CvPo+fv1'
    '7v/7+fvz+f317AH+7v/79/729f338//48v71+vvv5QMF8/718f754QQH9/729/3z8f/24gMH8f745QIC5wYK4gQE6gL+3wYK4AQH'
    '3wMH3wUJ4AMI6P/98f769hYh/Q4W8wwU6AYK5AMD6AIB7AD74wIC4AIE4wIFCBonFRYeAxkl9BAb6QQG6AL+7QL/6QUG6gD+5wMB'
    'EhsoJhEVGhYf8wgF7f/57AEEf/0Gf/kIQQIH5QMD+RQfKjo8FiUs5g4Y4QMJ9u3zKeDtbAYQfe/57QD8BBkkFyooCR0o8RAX5wEB'
    'CNbmIQAXLhlAA9/r4wQFBx0p/g8QAhci+BQc7/j8AuPsPQ89WxpkAu3u3gsJ9QgMHwkLHgIG9/v+LMTOOcfQO/r/KAQGGdngCeXj'
    'NB75NR34Nxv1JyD88iYENQn2OhDyPBfzMR/5OBz1LRARNxX9MRgFLgb+KPv9HP/+HAMBMhX/MxUBMxUFIhURIxIOMg4WKP4FHvkJ'
    'HPkII/sEKgMECQ0EKP4HJAMKIAELKQ8aEg0MEfUUEvUTFfcQIv8MEfsPFPYPEfsbDvgaGQL/Fgb3BvUQA/AeB/IbHAIVFP0XBfEZ'
    'CgsRCfgQGAMMC/cGAfQQ/e4h/+4gAA4Y9vYW9BAQEfgNGf78DgUL7gLs//MV/e8hAvEeCAsHJv39F/0BFfsIGfsICPoG5AHnAfAe'
    '/+8fCv0OIP8MHvwCD/wICPIa//IW9fIR8/cF/u4f/PAY+/QRBPkaBvIZBPMcAfEd//Ec8PoB+vIV/e4e5/v32v/t/fsTAvAe8fsP'
    '9QgN6QME5fr5+PUM+PQP5fv87AII8fcN6f8L5gkG5Qbs+P4H3ADs8fz87vv83/7v9fgG2ATj5QXt7Qf0xwLZ0AHh3AHl4QHu7f/1'
    '3wHr2gDqwALb0QLX0QHX0wHX0gHX0QLYzwLb1wLk1wHZ1gLYzgHY1AHY0QDY0wHY0AHXzwHXzgHX0gHZzwHXzAHXzgDX1AHY0wDY'
    'HggzBAclHPcaLvkY/QYtEwg/EOXtMuLmNOrqK/Lu/RsQ0wcD+fMWA/AZyAL+zAL/3PX3FuL6HxQUKCwZIEIL/CkH6RgX8ggE+v/1'
    'BgAB8QMY1/T2ACYLDjs2CkoMBjgbDzo2CTMr8xYAFQT2APz37Pb14BYMCkM2DhMI7ycS/kMx/jIdCg8DGgX8Ofj0DfTy6v769zck'
    'HgIDIgcE/yEO8h8JBwwDHAH7J/78J/4KKQAD8wUBEQEBKQIDJAMDFAcEIAIDLAECJfkTM/kbNfoUPQID+AD6HgICJgIDKAMDMgID'
    'PgIDKfgRHu8iJ/UXLwID6/fy5vDvEPv8JgIDJwIDLgIDJwEEDvUOOAAFNQIA4urq4e/t7u/z7v389AD/8wH+JgIDLQIDKgD89//7'
    '0vn06vP18Nnf6unp3Pz39QH6BwH/GgcI/AH+Av340fr10/j02PPx9ePm3/r4+gD77fv2//755vfx2/Pw4uvqzv750/j01/f28uvu'
    '4O3r6d3h5+Hj7tne7eDj3/Pw2fX0yv/70vn03fPw2vHu2+3s5OXn79ne9tje1ffz3+rq1vPyygD8z/v20/j02PTy79rd9Nbd0/76'
    '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'
    '4/Pt7evpGvr2Dg4EFw4GB/76/AYBAAYDEPL06QH94vHu7O7pJ/Tv7/j2AQcBDAH+8v776ggCE/Dz6wH94vHt7e/pDOTlFgoB6AQA'
    'B//85wQA7gQAE/Hy7//95O/r7O/p/eXm/gH84AsEA/v58QD96gcDEPP07//95PLw6fH19eXnBPD1+wUEAvz78QH++/77CPj56wH9'
    'Akpc/zRD7zwxEhIY/wD/B/sB/wED/Pv+CgAC7QMAJGVZ7SQrAkRLISU74ggC5gsJDfgACvb3FhETAB4e8DY29wwt9BAeCQUHGvn5'
    '8wL/+AD98wP+AgQHGwMO3wkG7QYJ7RIMBurqJenuJPj7EgIB8AYAAAQB8QcHzvv13/Hw6urp7O3p9Onn/efqHu/wQfL2HPr84Q0F'
    'y/341ffz7Ofn4fHt7+roIe3uPu31Te73VPL5M/P5yAP71vXz7eno0vr13PHx5+3rEfLyNicvNfMIUu/30Pz34e3t5e/tzfn3zfn3'
    '0/j1WhMJWy0oIPoHBPn10fj16e3q3Pn1/Pv5Hv0AQgQCaB0SBwEYD/38Cfr52vPy7PLxDAcJCy018z5KLBYfRPv/Mvv9Gfn4Afr4'
    'Ae73+e33/en0+fD38u/47+/54vT95PT97/H6Cenz6vX89Pb6/PX55Pf87fP6AfT5Ae71CO/48fX/1/kBAfT3D+vwAeju+Pr46wcA'
    'IP3+Gu/yE+zxF+/0+/T+DevvCev1Aw0WDigtHiQwDwcYD/sCHe/yEu/xEPHy/w0S+Ckw+DAwOi8hUCMdzhkQC/gBCOLrDuftEO/x'
    'TxEJfxsLOzAhCC0axQ75JCIQBvDv++jrC9/pEeXsUwj9fxUEORMC0hQCtw752xT60QD35QH6C+TrB+LpGQD9ZhUHCB4mJzk43g0G'
    'xwP3zwoA9xsUJh4sB/oACPTvMAX72xoM5hkPAwoQ+zUS/hkjBi0v9yoxAQAGBOTo7vLt6Ar83RsW3ysc+TQu9yox9iox9CInAPj5'
    'COXoBOTo5PXv5wj75hgQ8igv8yMn5A4K4vvz8u/tDPH0C+bqBObn+uvq5QP45BQL5P319PHtCO/v7fb73PcA8/T7B+vuBObn+evq'
    '8Pnx/vXvEPX0//j4/vLx4Pj/3PgB8Pj9G/HxAenpA/DtEfTxEfLxAe/v/PLw+/H94PX/1/oBEfz/L/n2DfHwBPLz8Pb65/j/3vgA'
    'HBALHwsHJAMBJAMCIwUCIAsGIgcEJQMBHBELEiIYIAsGIwYCJ/38Jvn5JPj4Ivj3JPr5J/38IgYDGhUOJAMBJPn5Jff2IfT0Fu3u'
    'Fe3uGvDvIPPzJPj3IAcEI/X1IfPzF/X37xYWzycm3CUj8BITDPDwIPLzHfHwH/LwGvT19hcZ1Cwr2icqzCsqzS4v3CwrEfHyFejo'
    'H/LyAv8C2CAi1icpziYn1Csr0Csr4y0t+QcHFenqFOvt+QIExSIjriQlyyEg3Ccotisn0Ckq5wsLFejp7OHnAvT3yR8hxCMjsiEi'
    '3CMguiQlziQlAvT2DuPiA+bp9uTn9wEDsSEivCQlxRcZ4yMi/AMFAuTmEuTlC+/x7+Xq6d/lBOns/fr79ff4/g8M6+Dm/+ToDe7w'
    'Cff5BfDyAent3uTt1eHp1eHo6v4D/gQDB+/xBPX5Kfr6Efj69fP3/vD0A/Dz+e/z6/X6AA8RCvv8Kfr6Kfr6Kfr6KPr6G/j6EPj5'
    '+PT5BPf3BggJEgQCF/HuI/j3H/XzGvLwFvHtEu/p+uvq9erqB/Pu+SEaC+vpDu3mDu3mDu3mDu3mDu3m+uvq+evpDOvl0gED+Ofm'
    '+U8p9D4g7i0U6yAM6RoJ6RoI6hwK7CQP8DAW9UQj9EAi7ywU6RoJ5gb85vft5vXr5vnw5g0A6h8N8DIZ8TMZ6h8M5v7z4uTf3Onn'
    '2urq3Onn4uXf5gb67CUP7SkS5xAC4eXg2err2Ozt2Ozt2Ozt2evr4uvk6hsJ6yEN5QD13efl2Ozt2Ozt2Ozt2Ozt2Ozt3ebl5xAC'
    '6hwJ6PLo4Ojm3unn3unn3Orp2+vr2uvr3Ojl5gr+5fTr5+nh3ujn3uro3+nn3+nn3+nn3unn5OPe5wj7D+7uH+3uDOnp9+nq6ufk'
    '3+jk3+jk3ujn4uPf5wv9MvsKI/b9JPL4M/L8QPD0MPH4He71DOnq6+bi4efhMf8PMf8VKQAWIPwKKvf9LvT4J/T7LvD1Mu/xAe3r'
    'Ev4XIAAYKwEZMAEVMgARMv8PLgATKAEYLP8UMP8PFAIU/wQZFRIfLgIUMAERMAETMAERHwwlKQYbKwISEAYR9ff0IAcUJwYTKAYS'
    'KQUSKQURGxokDwsTIAcSFQoSAv79EgMHHwkSHwkSHwoRIAoRGwsU9/0IFQoVEA0QEA0QEw0RFwwSFwwSFgwRFw0RFQwRBgQDDwwO'
    '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'
    'KxASMfn4J/b2I/b2IPf2Ivr18gwCtRMPHBodHi0yAO3r4ujg0uTo0wME9P/89Ar5CRkPGP8VIAg7FwotKPr3FAv4/f8CwxUayv4D'
    '4wr09xYFEQELFBsxEh45KfP0EAH09xodBi0x8/L45gf04g3x5ggDshcSshcTHvT2GfHxAiwvFSsu5vD05gn34A7xCvXyC/r78wEK'
    'GPn6FvD0MgoJGBUWvw0K6Qn33w7x9e/pBe3v5PX6E/b4CPn4MP39NAEC4xYPAvnx3wrw7fvv8+jk6OroDv4BBf8ENv//OwH/8mFB'
    '/Qb96vvv6vv59Orl6+ro6CQq/RogOgMCOgQDuBsU/f767fnw5wH/7+bk6urp9xIUAAX9MgIAEf/5kxsWA/T0BOTnAvHy8+jk8ubk'
    '6uzQByAY/vnj/AL4sgwJD+nsB9/kEuTp8Ofi8uPi++vZ9uza/OrmqRURBfn8Fff/Bg4oA/P9A+7yCOXsA/T02vr32+zvtgwLHevv'
    'HgsSBBcwEfkEGfT6HebrFPT7FwYUH/4IIOrtFNviFwUREyArAvH8DubtEvL5JwQlJwogKwoNFPT1+Pf8DQMRDh4s4Q4SHPj9EP4E'
    'FAL6A//4CQH5FwT7GwX8GgX8GAT7GgX8EAP6EQP7+fz3/P33+vz2GAX8GgX8GQX8GQX8FwX7BwD5GQT7CQH5//74DAL6FAP7GQX8'
    'GgX8GgX8GgX8FwX8GQX7GAX8FwT8EAL6CwH6FgT7FgT7FwX8FwX8GQX8FgT7GwX8GwX8GwX8EQP6FgT7GgX8GgX8EAP7CAD6EwP7'
    'FgT7GwX8GwX8GQX7DQL6GwX8FwX7BwD5FAT7GgX8GgX8FQT8GgX8FAT7+P34EgP6BP/4FwT7GwX8FgT7GQX8GwX8GwX8GwX8CQH5'
    'EAP6GQX8FwT8GAX8FwT7FwT7GgX8EQP7FQT7EAP6GQX8GwX8GwX8GwX8FwX8A//4DAH6DwL6Bf/4CQH5DgL6FAT7EQP7DgL6CgD5'
    '69/h7+fmAvTwB/r19e7uBvjz+vDuB/fyCfnz+O3rutrfzejn2e/y2e/51vYB7uTl4+Tk8erp5+fnzOLjqNjerNjeuev28g0LAQoI'
    'zObnr9rftt/twegCze8Xx+oN1/Ul+QAJ6RgXwT1MxC1CxRU32/824Pw13vs32vg43vs3yAcewDxJvjdIuC0/syM32f833fo32vk4'
    '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'
    'GABBBgQg/AkH5QX96gD/2AD+1P78x/v23AEB2AH78Ary8wjy+An03AP8BAUICAYNCAcNCQgM2wIG2gD76An14Qb16Aj97gP99gMC'
    '/gUH/QUH/QUI3gIB7QH/+wr/BQj06TEj9BkNB/nwBf71//748wD4+P726wT+LA4NChD+7QkB8QX9/P337v329PvzBfHo//Pr9AD4'
    'JxIP+wj+/gH8/gD6FP759QL87AP9/Pjw8v/3+wD5HREK7gX97AP97wP9HfnwGPvyDf73CAP5C/32CAD3Dg0C7wP96gP9FP3zU/Hk'
    'X+vdXO3fXuzcYeraYeraAgP8/QD7+AH8+v/4Avv0EvbsQu3fUuvdTe7fYera+gH8+QH77wL7E/747wX+9AL7///5APz2AvvzGPTp'
    '7wMX6gQF+gH8/wH6KwD5Jv32BgH56wP98wQJAgAP3gIP9vwS9gD97gP97AP9DgD9HPz07AQC7AQt4AEp4AMO4AAC//rxTureMPbr'
    '/gD57QP93wET2v8m3QAmGwBSGwBTAv834f7+JPHmBv316QL94gED0/0U4gEE0//8/AYcIP5SIgBZCAA/7QAg1QD/4AH88QT9CAD4'
    'GN/hGd/hHeLj4BoY3Rwf9/LxF9/gGN/hIubmKOrpHOnsHubpG+Tk1x8b2BwdAPHvIeXlHOHiGeDiHeboKOvqJ+rqGvLw4Rwf2h0e'
    '3wwIIOnpGN/kGePlHuTlJerpJ+noG/Ty2x0e1h0c1Bsa/+HlBszVIOXmK+/tDdXcJO3tJe7t2B0Y2h0d1B0a6Pf5H+PkFe7uGuXo'
    'Fu3vD+ztCuHt8AkH1x0b0h4YzhEOD+n4EePmFenqFt/jD/v+E+LjBuXn2x0byR8U0hsZAOfpBwr+FO7s7gL84CwW3yoQ5evq4xga'
    '2xwf2B0cyBcN/xsJEBEDFAoBFwgBJf797AX/zSAV2hwe1x0d0xoa0RkX+w4FMfv7IvP7JfP56REG5Bwf3Rwf1x0c1R0V1RcYzhkY'
    'H/0H/wUlIPgC+RII5Bwh1B0a8hAJBhgTzAP/1BoaGvH3FPoPHPH99AYi1CAY+xIYGwgECxoX+xURyA8PKuzqLPwDE/wWAv4i/QUG'
    'Hf4AGf79DwUB6QX/6A4KMvPwKfT3H/cCGQH4DP73FPz3E/r1H/bvFgwIARcSL/T1MPPyH/oHJf31/gH4+QH85vnzqfnz4f/57QUZ'
    'KQQmKwIeKgMjKQQmJwYoIgkrIQQcJAITJvsGM/HtKQQmKgMiL/sML/gEK/4RIwUfJQIUJv4MMfPyJ/f8LAEcLvsOM/H0L/X2ERMY'
    'FgsSL/X0HQ0TJ/kBJfkBMvkHNPDxMO/xAxD/1g/+1w/+9Q4BDhIXIgD/Ju/xJwIQKfr/B/790g4Czw792wj50gv7/T0jHwr9Me3o'
    'KP0ICCdC/gUI0xYC1w4C0g39+/7zEQwGI/PvMe/sFg8+BSQu7Ar72C4T4gkD/PvxCPn2DwQC6wL1L+3o/wcK9jAh8B0IBAoH7gv+'
    '1hQB5CkjBgP/CgAAF/Tp7Rkb2hT/7gT74Q7+4gT42yEI3AX48gb2A/vo/ffn3SgTzwj58xwd1RYB3hkE1AX23/356vzuFfXnF/Tm'
    '0QP22Az62iMT1//05P7yzwLy6/bwC/ntFAkPAx42x9nZ1fDp0cnTzM/X/+bj9e3p7PPu+vvzDfjyCfoF693k0dra6tTh8NPg//IF'
    '9v4W5PP11/j89Bw2/g8a+ert6+Lh+ePoBeLsCAgSAwUT6uPi7xch4BIZ6gL+AuvvBOTj4/T9F+Hl8+7wJ+flAurk+vfn5ujX4Pfm'
    'P/f4H/z8IBgUJxgV8Pv7+/gA/PgEA/j3E/b1P/f3/uPt7uv1CCQeIBIS4yMbDBs9ABBLu/348OvzB+Dt7PDy9Ojy9BkVBRAPAQED'
    'HSkjECUjvfv37Ofv7+3w9u/xBOv0C/r5IwQU9wsSwPT7AhEPxgL45+bo9O3w7+/xBe33GQgdOwklLQ0l7BcYBCchDyMd+e729e3w'
    '9PDx/vjxEhsVFhMdHBcgDiYrAi4p3xsY4eXt7+3w6/DxAvz2JgwjDwEV+PcFFBcoEicj7RgX5+/y6+3x6PHy/ff+Hgkl3fP6B/r3'
    '5Csm4BQJ4/To9O/u6O3xM+nxB/0DASAd4gcF4PLyFiMd7Pr36uHk+unnNOryUPn4DPTz7isl7U84/xUa6RD90ykJ+xwTAgH3UPn5'
    'UPn4C+jk+Pf7/EMd+igT7isR3jgL5Qf4EefqUPn5UPn4Cunj0tbS9wEJABkHBxDu+/L2BPDv/+7rUPn5T/n4Au/t3fP10fsC4Anv'
    '6Qnc0fjt4PPt+vHuUPn5Pvj3+/Pyyvn84PH25Pf02Pfv3vz13e3x+vP1Rvj3D/Dw+e3v+e3v+uzu+u3u/Ozt/Ovt/OvtA+ztGu/v'
    '1ggpHePeI+TZH+XZKdrJIufcItzMJdTCJNPBDO/4xQYlFvX9Jvv1H/jwH/fwGvr3IPfxLfDmJvXsBAASygEZFAMUPPjuOfjvNfry'
    'LPz3L/v2MPr2J/r08gQb5/Ds/wYfMPbtJ/PpKPTpKfbtLvfwIfr1H/v1+fwH1f8S/f4JJvPpJfPpJPPpJPPpI/PpHPTrFPr23QQc'
    '8wQZH/PqH/PpHPPpGfLpF/PpFvPpEvLqFvf02wck9f0HEvLqEvLqAvrz7hII5RoU7wwEC/LqE/n55PsH3AUY3PkA/fj42ykn8Cod'
    '6SUb8CUZ/P34CQAK0QgU5iExxRQi6hki2zIy0ysm4iIY6iMl2zIy2TM1zyQszAwQzikp3ywt6RUeuAsJvAUE5Bog9hUZCgUJ1QH8'
    't//35v/+EAAF+vT24O3r4ero8u/wEwAFBQAE+QAAvv/2//8DBwAE8QEC/wAE/wEE4gEBEgAEDwAEDgAE0f/6DwAFBQAF1QD8EgAF'
    'EAAFyAD7/wABEQAEEQAE9f8ADgAG2//88f//DgAECwAE6QD++P8ADv8EFAAEDgAE9gACvP/3CwADDQAEDwAE8QD+6f//CgAEDwAE'
    'Fhn/GB0EAR4I+B0K/BcNBRYJHBr+Ff8FCu36KOLyCxYJHBkKKhoDDhkI/xYI8hQLBRUKIfL9GeDyLuPy/BYLGxkHHRcEIRkDEBcH'
    'AhYK6hQOIe/8Bd7xJ+XzChkKDBkFFRoDEBcF9BUMBxsLARAMFu38Beb4Fur6CR0H8hsM/RoOBh0I+xwK7xkOCRcOA/YD9uX26/UE'
    'HB0HChYNCRwVCCog9gwJ6wwJ6xEKEfgEDuP3+/H//QYE3f78xQH9vgYE5Orn9t/b6unk4Pv2Af4C7/0HDt3VENTO++LcENjS/ePi'
    'TuDmDObr5efj3g4H9Q8K89vY2OXlAtrW/9jTCd7af0lCK8w8adEz7u3sAQYE4vv33u7t4eLh9ev5dwFocB5kPBNVPNkuJ/395f8B'
    '8AD1/QP6HQoNJQoVKwsiFgQXDP8EAgQB6QD27vQB7v/34//45AD86AT88AcC7wT95f/44wD36AD45/AD9P724wD54P/54gD45AD4'
    '4v/64QD44v/45v75BvAC+v/z5gD34//46AD26QD29Pr5Avn4CPr2Afj63fIG/v/z4//54v/46QD17AD13gD83P/82AD9zPwDy/QK'
    'LgT/DQkO1xYo+hUiEBI5KRMbDBUa3BUh0BEmAAYdLgoFDBca9Bso8RRNARRQARVM7Bk57how8hokCg4YPA0ELRAM+xIoABUw+RQ5'
    '/RE4BRQyABQs+BUaOA8JFgL9QBAIRhQLSBQMSBQNQxEKRBEJQhEKMgwFDf/6IwYAKw0FMREJKgsDIQX/LAwFIgcAIAX+LAwEGgH9'
    'FAL9Cvz3GQX/JA0EFQH7Iw0FHgkCFgP9IAoDHQcBHQkBFwP8Iw0FHQcAGQX/Ef/7/O7u8ezuCPn1B/v3A//6Ef35HwkCD/34B/r2'
    'BPb09/Hw/Pb0EAH7HAcA/P33HAcAGAX+Ev35Ef369e3t+fPx7+3t8+zsBwH86P73BvXzBPbz+O/u+vXy/PHv7u7t6+vr7fHu8vjz'
    '0vz0A/bz7+7t7e/t9PHv7PDt+e7t7u3r7/Xx6vv14/by+PDu/e/u+u7t8+rr+ezr7fHv8/Hu5fjxzfz00ffy4Pnz7vDu6uno5uno'
    '5ezr5urp7PDu0/fzzfrzz/nyzfvz3vfy6fHt7+zr5uzr3vLu1vr0zfnz0vbxy/vzy/vzy/v00/rz2fPu2fPv1/nzy/31xv73xv73'
    '3Q0M5A8M7hAL6AQK8QP/ABTsBBHsBADlA9vZ1ggN4A0KARIMFA0GEfLr8fX9++3n9+jW9vvc+u3Z4/j9CxEJA/8AEAv1Fgb1FNPh'
    '6f4A5P/28ALo9g3i5A/45QsECNvmE/DrHevtLOz3C+Xx6QP64wX74A3+3xEA5/8CDsXaG9fjF9Lh/+nu7/jx8Pz2+AH++wQB2wsF'
    '+dnrD87fL/T4COjsBOjeLgEDWA0VVwsUVAgQ7BITE9TkDtLiHuTu/u3pBOjeDfDqTQEHUAMKUQMJGgoQG97p/M7x/tXlA+ngBOje'
    'A+ngLfn7RvT6QOrzNPb8BuXwEunt/PDu8BIX9y85/v36H+/vOuruMf8XMP4E5Qb/8vn49gUD4zNCI1RbEA0IJfPzKtv9MPD/JAgL'
    '+AwD7v/17QYD5BEU3Roe8Pv4JuYILwciKgAIDf8DABQSCBIN9/zz/Pbz2R4u3x0uECUuGAgbCxUn+A8e3xMU5xUV+xEL3wsK5QoF'
    '4xYP4wkF4wX75Aj/8w0ExRwk0Boe+xgW4A0I5gP85wL66RgT8RYQ9RMP1RkcxRwkyRwi5w4M5Qf/4gb84Qb94Ab+5goE1BkcxRwk'
    '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'
    '7/4SJewLCuv0+O758+/4+e74+O/47u32D+LmDvLz5gUQIQATJu72+u/4+u73++74+u748O32K+XpEv753gILK/ANP/D5MPQAN/P/'
    'OfP/OfUECwAqHvwDCQH3/9kAN90KRPD6RPUBQ/UCMvcLKAEZDwo4ABwr6h/s5t/7CucB7/kN6gAf8gMm8wUrAwIaIAUmHBNE8Sfq'
    '4/8g6wEj6wAj6gEl9f4bKwIfKgMcKgMcCws/AR8n8PkVCQA3BQA3C/82BP0YSAIZPAQkKAQh8wkN6hUB3uvwENHQJN3ZMeHfC/cJ'
    'Fv8YGQwX/xr76hrt2BPt5+LjAenfKPP8POv9NNXi/fT49ijq5R7r1hHv1hHv5u7vMdbiNtzrONvoGOny/fv5+Cjr3xns1xLv1hHv'
    '0+/3Fev1EPwBCPj7+fL37fD2+Bzv5B7r2xXt1hHvy/T+CvsDGAAJAO/0yvX51PP47RLx7SPr4Bns1hHvz/b+LgMdH/sOB/b12PL3'
    '2+/26A/06yHx6CDs2BPv2vL45fn7/iP0/Cvq6g7z1gD37xjw4BoA6CLy3hns3/kG6Qr56CHr7SXr8ibq7CTq5Rz21xUA8BkA6xD/'
    'C/r/Evr/EPr/DPr+C/r/Cfn///j9+/f89/b8A/n+CPsAGfn/F/P5B/r/Dvf8CPH3EPb8D/X7C/T6E/j9D/n/FPr/Ce30Fu/1H+/2'
    'GOryE/X7EvT7DfT5Fvj8Hvj+Evr/CevzL+30Mu/2Ne/2Ge/1FfT8EfcBGvf8HPj+HPj9F+zzMO30Ke/3C+31JuzzGfwMEwcgG/kC'
    '7Pn+B/T5KOvyLezzH+nx/ujwJevyF/cC9RIe6wcX1vwA+Pb6G+nwJuvyG+jvIOnxGejwDgQMABcfxBIXGA4HHgoF/u/18vX3/u7x'
    '7Pr55P/8Avz/I+f1De77GhIJHhIJCO3y0xYKyicTyykTyigT7ff2DdbhCtjkFw0GJQ8IGf792AwEyigTyScTyCYS6Pz6DeXtDO72'
    'CwYCGAYC/Pr8yhoNyCcSySgTySgT9/v8COzz7/f8GPL4Cuz0/uXuzB0OzCsUzSwUzSwU7BUMAvkAA/n+JPj+I/f99OfuyiYTzCsT'
    'zCsTzSwU4BwOIvj+JPj+Hvb8+OPs5PP2yicTzSwUyygTzSwU1CYSIvj+Ivj++uPr5Ojw4AQAyygTzSwTyigTyysT0ikTI/j+I/j+'
    '4vXz3Pv52/z53Pr33ff03fj12/v42/z52vz54vf03Pv44Pj26vbz8e3r7eno6Orp5ezr4PXy6enp6Onp3vn33vj0MvbxDe7sJfLu'
    '6eno6+jn5+np6Onn5e3s2vz57e/tRPjyEvDsMfXw6+nn6efn6Ofm5ezq3fr23fj18OvqDO7sJvXxQffxB/X06ufo7Ofn6Oro3fn2'
    '3vbz6Onn6+zqCxISKCsoHzI28PHxAPr67fLw3Pn23fn25ezr7/r8GTlBKjQzLiwr8PPzFiog8f753vn23fz47wAE9v0ADS81FDE3'
    'ByQoFh4qGCId4vDu3Pv42vz6+fMCFBMcHC0uNDUyIysrDhMb5f333Pv22f762/z5Ae/9CQ4OICYiISAdGhMUBAkQ6QkMEfz5Jffz'
    'Ffn2Avvw6/jv9gf2AwUNDAQSDAga/BIgMwD/R/byMvjv4Pvs4Pvs+fX0FwkdCBUkBBcoARUlEhQWS/j0O/ny6/rs5/joCfcAJ/4X'
    'AAsZ9xEe/B0iChMdVPn1Wfz5OgD/DAYLKPkJRPj2FwcN+RUf+hkgMQYLSPn18/r29gYFFiAg/f/9A+7s7ff36QcN7gYKGfj0Lfjz'
    'IOPpSPDwMOjrKubqNertO+zuDNzlB9rkB9nk+tbi+9bi/Nbi+tXhA9nkHe3zAtvl/dbi+9XhGuHnGeLnQe7vDdvkCeDqI/wAPQkJ'
    'KwAB4+/4KevtS/vzLersDdnk/9ThCeTtHwoLMwkIAwgODgIERfz0G+PoIOLoDtzlC9rkD+DpH/f76wIKBQkOOQP/5AIF4PP6FN/m'
    'GuLoGODnF+DnFuLpDQIGNv736AcLzQUOvwMJGuXqLOnrMuztIeTpLO3uGQL/5gMH3QEG4vn9GPLwGPPwIxQLJg4GNggBLwH54wYJ'
    '2gYR0AIH0QcJBQoD+wYAIRIJFxYNBRoSAwQC3gYQ2QYR0AQKzwQH7hYO5xcNBRkQBxwS/wkL7gUM+QMI3AcSyQQLxgMJ4g8L9hgP'
    '4hAL9A8LCwUD9QQJ5AUN3AcSzQUOvwQLzAgM8QoI9h0T7RcP+BgP3hYOzA8N3BAQ3w8P1REQ5xQP4w4K/BgPDBIKBxUM4xgPzxcO'
    '1RUM1RQL+BUM5g4H4BUMBB0S+xwR7RsR8hcN4hUM3BgO4RUM8BQM9hgO+RkPCx4S/RwSABsRBBwRAB0SAh0S/BsQCB4TCR0SDRwR'
    '2RP93hkA3Bf/0Aj24xH8Bfr3+fTs2vfy3hkA2hX+3BEA6RgL6BIG5ffu7gD99P/+7Pjy5/j04hL/4BIF4/8E7gAM7wAP4/n59AED'
    '6///3vv77fMB9f0P5wAG4/r75fr96/n84/r74/r74/r64vr75/f98PDt+evl9/b06e7k6vTw5fj46/X06uHe+uvo4/n68vHu5vTx'
    '8vf1/O3i6vPv6vXyMOTZPOHVLN3S5fn6/fwL5/r/4/r7+PHt9Pj4CuzmPeDTPuLVMODU5/b17Pn37fr34/r7IfDtPfj2HhAZ7vno'
    '9evf7vHu/vXzAfHtAgADCgkQKw8Z/u3l0/Hq8uzhyPPnzO/nDvDqOAEDKhQfKhUhKRUhGw8X4/Hryungz+7m3vr4FA0UKRYiKBYh'
    'KRUhKRYhHg8Z1+jf1u/o1OfdEwsTA/r6JREaKRciKRciKRci8fn34PTw7Pv83eXdD/j3DPf2HxAZKRciKRYhKRciIQYJAgEEHBAa'
    '1PPtJxUhKRYiKRciKRUiKRciGw8YCgMIKRUhIxEaEQQGKRciKRciKRciCwoRIBIcKRciKhYiKhYiKRQeEf7+KhYhKRUiCAgP4/r7'
    '1//y1QDz0/foywT8yg0P1QD13Pbo3RcVCCUpHwgByg8PyQcGzgsP3AME5Pfu2PTo2PPl1u/nGxQWNAsF3z9C5iMt5fXu2fHo2u3l'
    '2evkz+bi1Pf2MQsGNQsF5TY95vDp3/Dpyunm2+Xi1enn1wwYBx8rMwsFKwgB3hAS6Ojl6+roz+fn6efm2+7u3CpAEx4nLQkCKQgB'
    '1gIH8Ofm8ufn9ebo9ubn9+bo2vkDDBkgIAcBKggB1yAp8uPo+ubq/eruHf/9IQD/D/P2GwMAHggEKgcA5D5K7PwJCe7yEf//IwUC'
    'KAgFJAYEEPv5JwcAJgf/5EFH6P4JB+vwDPn6Dfn5Dfj5+///1wcQFQYC0vX630ND5PP6Au3z+woTD/8BA/z9CgMFCQAC+ervDf79'
    '6iwq6+70B+rvCe7yBe/zBfDzEfv7Dfz8Dvn6KAgD9CckB/n7EvP2Gfn6KQUBOAwGNgsFJAcDLgcDKwUB5jc0HQwJLAwINgsGMAgD'
    'LwcDKwUBKQMBI/79G/f6/w0OA/j8AP8CIAL/KgMBJgD/HPn6D+7yBeXu/d3q4T498xUWEvz9G/j6GPb4Gfb5AuLs+9vp+tnn8NDi'
    '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'
    'Bdvo/trpCtDlA+/wDO/wBgsC9SgV/CMRAhIGDu/wAcnmDNLnGtPhGO/0J/IJFggH8SkW/A4F+Dcg+RkLAMjmB9DlLPERMfYYMPYT'
    'JPcfDf0M8hUJ9CkW8CQS/Mjm+c3kFv4oHPk4IfcsGPk2DvYh8AkA7wkB7gsA99npDen99wAWCBIVDBsUBQ0WAPYe8gn/7gsB8Af+'
    'LO/uK/IBE+sADvT8Iv7xGfkjB/gp8AP+7g0C9AL7LPHwG/LmKPbmFgH1PO3gNer4HPYn9AAI7xAE+P35K+/wEPfyB/nyDwX4HPb0'
    'S+fbCw0g7i4a3CwX+Qb/Ku/vDv/6+wX4Cff+H97p6iMP2hQFyxAJ4g0DG/TzLu/uFQD6CxUKAgX5DwHz+vLl2vYH3w8YzyQQE/bz'
    'Le/vHf/69BEHDxEH7B4N1CQRzyURuwsAtQP6tPr0HQD7Fw0B6BMH6RsO0SAOyg8Cr/fzuwr/xRoK0SAOH//3Afbt8gv/8P729Af/'
    '2icSyBcJswD6uAb90v34GO/s+vbwGPvxAg0B2yAN4CwWzR8O6A0BF/bzL+/vBO3vJe3s+e7sBPTy2Qb89f33G/HwMO/wLe/vLO/u'
    'FhgRFBgRFhwSGhoTGBoSDhsSGh4TGhoSFRgSGRkTGBgSFxAQDhMNFvgCC/YC/g0JEhgSGxgTGhcUGxYTFRMTHBsTGhkTFRARCA0M'
    'ABAOFBgSFhMSGhMTFBoVFhYPI+vtLM/e8uL9zuUBweUA3O8ADfoD+AwHDBgSFxUSKP8BNs3hO7DQOLbI++vmRsnXIwkGFBIPExUR'
    'FxcTCRcPDBUS9OEu5+UA5ev1F8/tIdv58QsHEBkQFBEQGRUSBwIQ8OIX+/IQHBENHhIPDhEOGRkQFhMRGxISEQ4O6f3wAeoS+vH7'
    '4fvwDgr6GhoQGRURGxASFhEREQwO5/zwGgwGJQsO6AAF+P3wGw4JHRASHhMRGREQFREQ4f3yFQkGGBASERAPx/r6BQHzGBwPFxwP'
    'GhEQIBER2v73AwD1DAj+DQn+1QAC8v7y5QL8zPX00fX01vn21ffz8vzv4fv07Pvw4vnw/f7v3vXxyfDwwO3uzPLv1/fxyvLxxvHy'
    '1ffx6/zw4Pjx6vzv5vbvHPDwE/DvHfHvBfPvEPHw6/fx6/nw5ffw8fbv6vLv7vDx3e7vzufpxeDjt9jdxOPix97futrbtNbatdXZ'
    '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'
)}


def fertige_karten(k):
    roh = base64.b64decode(''.join(FERTIG_KARTEN[k]))
    return [base64.b64encode(roh[i:i + 450]).decode() for i in range(0, len(roh), 450)]


def herunterladen(url):
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Spieleabend)'})
    with urllib.request.urlopen(req, timeout=60) as r:
        daten = r.read(120 * 1024 * 1024 + 1)
    if len(daten) > 120 * 1024 * 1024: raise ValueError('Die Datei ist zu groß.')
    return daten


def karten_auftrag(auftrag, start, laden=herunterladen, bilder_aus=pdf_kartenbilder):
    karten_pakete()
    ergebnis = {}
    for e in (auftrag.get('liste') or [])[:12]:
        k = re.sub(r'[^a-z0-9-]', '', str(e.get('k', '')).lower())[:30]
        url = str(e.get('url', ''))
        if not k or not url.startswith(KARTEN_QUELLE) or not url.lower().endswith('.pdf'): continue
        if time.time() - start > KARTEN_ZEIT:
            ergebnis[k] = {'fehler': 'Die Zeit hat nicht gereicht – bitte nochmal anstoßen, dann geht es weiter.'}; continue
        try:
            bilder, methode = bilder_aus(laden(url))
            if len(bilder) >= 20: abdruecke = [base64.b64encode(fingerabdruck(b).tobytes()).decode() for b in bilder]
            elif k in FERTIG_KARTEN: abdruecke, methode = fertige_karten(k), 'hinterlegt'
            else: raise ValueError(f'In der Kartenübersicht wurden nur {len(bilder)} Kartenbilder gefunden.')
            schreiben(f'{KARTEN_ORDNER}/dixit-{k}.json', {'format': 1, 'k': k, 'quelle': url, 'raster': [RASTER_B, RASTER_H], 'rand': RAND,
                       'anzahl': len(abdruecke), 'methode': methode, 'karten': abdruecke, 'zeit': int(time.time() * 1000)},
                      f'Kartensortierer: {k} ({len(abdruecke)} Karten)')
            ergebnis[k] = {'anzahl': len(abdruecke), 'methode': methode}
            print('Karten', k, len(abdruecke), methode)
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
