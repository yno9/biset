// window.fetch called after being lifted out into a bare variable (`const f
// = fetch; f(url)`) throws "Illegal invocation" in Chromium -- fetch is
// implemented as a method that requires `this` to still be the window/
// worker global, not a free function. Every `opts.fetch ?? fetch` default
// across identity/web*/*.ts hit exactly this live (account-create.ts's
// createGenesis, tested over file://) once `opts.fetch` was left unset.
//
// A function, not a pre-bound constant: tests swap `globalThis.fetch` for a
// stub (test/protocol/support/webvh-log-fixture.ts's withFetch), which a
// value captured once at module-load time would never see.
export function defaultFetch(): typeof fetch {
  return fetch.bind(globalThis)
}
