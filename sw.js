const CACHE = 'wash-v1';
const PRECACHE = [
    './',
    './index.html',
    './src/styles/themes.css',
    './src/styles/main.css',
    './src/styles/components.css',
    './src/styles/saas.css',
    './src/scripts/app.js',
    './src/scripts/detector.js',
    './src/scripts/entityScanner.js',
    './src/scripts/i18n.js',
    './src/assets/favicon.svg',
    './src/data/entities.json',
    './src/data/i18n/en.json',
    './src/data/i18n/es.json',
    './src/data/i18n/fr.json',
    './src/data/i18n/nl.json',
];

self.addEventListener('install', e => {
    e.waitUntil(
        caches.open(CACHE)
            .then(c => c.addAll(PRECACHE))
            .then(() => self.skipWaiting())
    );
});

self.addEventListener('activate', e => {
    e.waitUntil(
        caches.keys().then(keys =>
            Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
        ).then(() => self.clients.claim())
    );
});

self.addEventListener('fetch', e => {
    if (e.request.method !== 'GET') return;
    e.respondWith(
        caches.match(e.request).then(cached => {
            if (cached) return cached;
            return fetch(e.request).then(res => {
                if (!res || res.status !== 200 || res.type === 'opaque') return res;
                const clone = res.clone();
                caches.open(CACHE).then(c => c.put(e.request, clone));
                return res;
            }).catch(() => caches.match('./index.html'));
        })
    );
});
