// The browser app: one self-contained index.html (script and style inlined) that also works from
// file://, where an external module script is blocked. sw.js stays a separate esbuild bundle
// (`pnpm build:sw`): a Service Worker cannot be inlined.
//
//   BISET_CONFIG   another deployment's config (e.g. ops/mail-did-md/config.json for did.md)
//   BISET_OUT_DIR  where its page is written (default dist)
import { execSync } from 'node:child_process'
import { copyFileSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { basename, dirname, resolve } from 'node:path'
import react from '@vitejs/plugin-react'
import { build as esbuild } from 'esbuild'
import { defineConfig, type Plugin } from 'vite'
import { viteSingleFile } from 'vite-plugin-singlefile'

// The version shown in the account's foot is the latest git tag (`v1.1` is shown as 1.1), set by hand when a release is meant; a build with no tag
// at all is `dev`. Nothing here makes a tag.
function appVersion(): string {
  try {
    const tag = execSync('git describe --tags --abbrev=0', { stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim()
    const found = /^v?(\d+)\.(\d+)/.exec(tag)
    return found ? `${found[1]}.${found[2]}` : 'dev'
  } catch { return 'dev' }
}

const configPath = process.env.BISET_CONFIG ?? 'config.json'
function readConfig(): unknown {
  try { return JSON.parse(readFileSync(configPath, 'utf8')) } catch {
    if (process.env.BISET_CONFIG) throw new Error(`cannot read ${configPath}`)
    return {}
  }
}

// The font is this app's own: the @fontsource package (a dev dependency) holds it as woff2 with the unicode-range rules, and the build puts them
// at /fonts next to the page, with one stylesheet (fonts.css) that the page adds from script. Nothing is asked of a font service.
const nodeRequire = createRequire(import.meta.url)
const FONTS: { pkg: string; css: string; keep?: RegExp }[] = [
  { pkg: '@fontsource-variable/noto-sans-jp', css: 'wght.css' }, // every unicode-range piece (Latin and Japanese): the browser fetches only those a text uses
  { pkg: '@fontsource/zen-kaku-gothic-antique', css: 'latin-900.css' }, // the "biset" logotype of the new-user page: Latin only, weight 900
]
function fontFiles(): { css: string; files: Map<string, string> } {
  const files = new Map<string, string>()
  const rules: string[] = []
  for (const { pkg, css, keep } of FONTS) {
    const root = dirname(nodeRequire.resolve(`${pkg}/package.json`))
    const text = readFileSync(resolve(root, css), 'utf8')
    for (const [, label, rule] of text.matchAll(/\/\*\s*([^*]+?)\s*\*\/\s*(@font-face\s*\{[^}]*\})/g)) {
      if (keep && !keep.test(label!)) continue
      // The names the page's CSS uses ("Recursive", "Noto Sans"), not fontsource's "... Variable".
      rules.push(rule!.replace(/font-family:\s*'([^']+) Variable'/, "font-family: '$1'").replace(/url\(\.\/files\/([^)]+)\)/g, (_all, name: string) => { files.set(name, resolve(root, 'files', name)); return `url(/fonts/${name})` }))
    }
  }
  return { css: `${rules.join('\n')}\n`, files }
}

const biset = (): Plugin => ({
  name: 'biset',
  // The deployment's config reaches the page as a global, before the app script runs.
  transformIndexHtml: () => [{ tag: 'script', children: `window.__BISET_CONFIG__ = ${JSON.stringify(readConfig())};`, injectTo: 'head-prepend' }],
  // The fonts, next to the page.
  closeBundle() {
    const out = resolve(process.env.BISET_OUT_DIR ?? 'dist', 'fonts')
    const { css, files } = fontFiles()
    // What an earlier build left there (other fonts, other versions) goes: the folder is exactly what the stylesheet names.
    rmSync(out, { recursive: true, force: true })
    mkdirSync(out, { recursive: true })
    writeFileSync(resolve(out, 'fonts.css'), css)
    for (const [name, from] of files) copyFileSync(from, resolve(out, name))
  },
  // Dev: the Service Worker and config.json that the dev server of old (scripts/serve.mjs) served, and the fonts.
  configureServer(server) {
    server.middlewares.use(async (request, response, next) => {
      const path = new URL(request.url ?? '/', 'http://localhost').pathname
      if (path === '/fonts/fonts.css') {
        response.writeHead(200, { 'content-type': 'text/css' }).end(fontFiles().css)
      } else if (path.startsWith('/fonts/')) {
        const from = fontFiles().files.get(basename(path))
        if (from) response.writeHead(200, { 'content-type': 'font/woff2' }).end(readFileSync(from))
        else next()
      } else if (path === '/sw.js') {
        const built = await esbuild({ entryPoints: ['src/client/app/sw.ts'], bundle: true, write: false, platform: 'browser', format: 'iife', target: 'es2022', define: { __BUILD_ID__: JSON.stringify('dev'), __PRECACHE__: '[]' } })
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
  define: { __BISET_VERSION__: JSON.stringify(appVersion()) },
  plugins: [react(), biset(), viteSingleFile()],
  // lft is a sibling checkout (linked in package.json): its source is served and compiled from there.
  server: { port: 3000, fs: { allow: [resolve('.'), resolve('../lft')] } },
  build: {
    outDir: resolve(process.env.BISET_OUT_DIR ?? 'dist'),
    emptyOutDir: false,
    target: 'es2022',
  },
})
