// Spieleabend – Mitteilungen. Diese Datei legt die App selbst ins Repo und hält sie aktuell.
// Sie zeigt eingehende Mitteilungen an, setzt die Zahl am App-Symbol und öffnet beim Antippen die passende Seite.
// Sie speichert nichts zwischen und greift nicht in das Laden der App ein.
const SW_VERSION = 1;
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));

// Zahl am App-Symbol: hochzählen bei jeder Mitteilung, die App setzt sie beim Öffnen auf den echten Stand
async function zahl(plus, setzen){
  let n = 0;
  try{
    const c = await caches.open('spieleabend-zahl');
    const r = await c.match('zahl'); n = r ? Number(await r.text()) || 0 : 0;
    n = setzen != null ? setzen : n + plus;
    await c.put('zahl', new Response(String(n)));
  }catch(e){ n = setzen != null ? setzen : 1; }
  try{
    // (Der Test-Browser ohne Bildschirm stürzt hier ab – echte Handys und Computer nicht.)
    if (self.navigator.setAppBadge && !/HeadlessChrome/.test(self.navigator.userAgent)){ if (n > 0) await self.navigator.setAppBadge(n); else await self.navigator.clearAppBadge(); }
  }catch(e){}
  return n;
}

self.addEventListener('push', e => {
  let d = {};
  try{ d = e.data ? e.data.json() : {}; }catch(err){ try{ d = { text:e.data.text() }; }catch(x){} }
  e.waitUntil((async () => {
    await zahl(1);
    await self.registration.showNotification(d.titel || 'Spieleabend', {
      body:d.text || '', tag:d.tag || undefined, renotify:!!d.tag, icon:'icon.png', badge:'icon.png', data:{ ziel:d.ziel || '' }
    });
  })());
});

self.addEventListener('notificationclick', e => {
  e.notification.close();
  const ziel = (e.notification.data && e.notification.data.ziel) || '';
  e.waitUntil((async () => {
    const fenster = await self.clients.matchAll({ type:'window', includeUncontrolled:true });
    for (const f of fenster){
      try{ await f.focus(); f.postMessage({ art:'ziel', ziel }); return; }catch(err){}
    }
    await self.clients.openWindow('./' + (ziel ? '#ziel=' + encodeURIComponent(ziel) : ''));
  })());
});

self.addEventListener('message', e => {
  if (e.data && e.data.art === 'zahl') e.waitUntil(zahl(0, Math.max(0, Number(e.data.n) || 0)));
});
