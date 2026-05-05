self.addEventListener('install', (event) => {
    self.skipWaiting();
    console.log('SW: File loaded successfully from server.');
});

self.addEventListener('activate', (event) => {
    console.log('SW: Activated successfully.');
    event.waitUntil(self.clients.claim());
});

self.addEventListener('fetch', (event) => {
    // يمكن تركه فارغاً مؤقتاً
});