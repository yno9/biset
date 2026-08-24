(()=>{var worker=globalThis;worker.addEventListener("install",()=>{worker.skipWaiting()});worker.addEventListener("activate",(event)=>{event.waitUntil(worker.clients.claim())});})();
