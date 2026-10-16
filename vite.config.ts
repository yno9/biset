// The browser app: one self-contained index.html (script and style inlined) that also works from
// file://, where an external module script is blocked. sw.js stays a separate esbuild bundle
// (`pnpm build:sw`): a Service Worker cannot be inlined.
//
//   BISET_CONFIG   another deployment's config (e.g. ops/mail-did-md/config.json for mail.did.md)
//   BISET_OUT_DIR  where its page is written (default dist)
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import react from '@vitejs/plugin-react'
import { build as esbuild } from 'esbuild'
import { defineConfig, type Plugin } from 'vite'
import { viteSingleFile } from 'vite-plugin-singlefile'

const configPath = process.env.BISET_CONFIG ?? 'config.json'
function readConfig(): unknown {
  try { return JSON.parse(readFileSync(configPath, 'utf8')) } catch {
    if (process.env.BISET_CONFIG) throw new Error(`cannot read ${configPath}`)
    return {}
  }
}

const biset = (): Plugin => ({
  name: 'biset',
  // The deployment's config reaches the page as a global, before the app script runs.
  transformIndexHtml: () => [{ tag: 'script', children: `window.__BISET_CONFIG__ = ${JSON.stringify(readConfig())};`, injectTo: 'head-prepend' }],
  // Dev: the Service Worker and config.json that the dev server of old (scripts/serve.mjs) served.
  configureServer(server) {
    server.middlewares.use(async (request, response, next) => {
      const path = new URL(request.url ?? '/', 'http://localhost').pathname
      if (path === '/sw.js') {
        const built = await esbuild({ entryPoints: ['src/client/app/sw.ts'], bundle: true, write: false, platform: 'browser', format: 'iife', target: 'es2022' })
        response.writeHead(200, { 'content-type': 'application/javascript' }).end(built.outputFiles[0]!.text)
      } else if (path === '/config.json') {
        response.writeHead(200, { 'content-type': 'application/json', 'access-control-allow-origin': '*' }).end(JSON.stringify(readConfig()))
      } else next()
    })
  },
})

export default defineConfig({
  root: resolve('src/client/app'),
  base: './',
  publicDir: false,
  plugins: [react(), biset(), viteSingleFile()],
  server: { port: 3000 },
  build: {
    outDir: resolve(process.env.BISET_OUT_DIR ?? 'dist'),
    emptyOutDir: false,
    target: 'es2022',
  },
})
