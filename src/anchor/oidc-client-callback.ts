/** HTTPS redirect target for the file:// Biset Client's OIDC public client. */
export function oidcClientCallback(): Response {
  return new Response(`<!doctype html><meta charset="utf-8"><title>Biset login</title><p id="status">Bisetへ戻っています…</p><script src="/oauth/client-callback.js" defer></script>`, {
    headers: callbackHeaders('text/html; charset=utf-8'),
  })
}

export function oidcClientCallbackScript(): Response {
  return new Response(CALLBACK_SCRIPT, { headers: callbackHeaders('text/javascript; charset=utf-8') })
}

const CALLBACK_SCRIPT = `(() => {
  const status = document.getElementById('status');
  const fail = message => { if (status) status.textContent = message; };
  if (!window.opener) { fail('Biset Clientを開けませんでした。'); return; }
  const params = new URL(location.href).searchParams;
  const state = params.get('state');
  const code = params.get('code');
  const error = params.get('error');
  if (!state || (!code && !error)) { fail('不正なOIDC callbackです。'); return; }
  window.opener.postMessage({
    type: 'biset.oidc.callback.v1', state,
    ...(code ? { code } : {}),
    ...(error ? { error, errorDescription: params.get('error_description') || '' } : {})
  }, '*');
  if (status) status.textContent = 'Biset Clientへ戻りました。この画面を閉じてください。';
})();`

function callbackHeaders(contentType: string): Record<string, string> {
  return {
    'content-type': contentType,
    'cache-control': 'no-store',
    'content-security-policy': "default-src 'none'; script-src 'self'; style-src 'none'; img-src 'none'; connect-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
  }
}
