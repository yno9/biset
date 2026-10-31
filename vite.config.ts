// The browser app: one self-contained index.html (script and style inlined) that also works from
// file://, where an external module script is blocked. sw.js stays a separate esbuild bundle
// (`pnpm build:sw`): a Service Worker cannot be inlined.
//
//   BISET_CONFIG   another deployment's config (e.g. ops/mail-did-md/config.json for did.md)
//   BISET_OUT_DIR  where its page is written (default dist)
import { execSync } from 'node:child_process'
import { copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
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

// The licences of what is in the page. The packages whose code went into the bundle (and the fonts, which are in the page or beside it) are written
// as a comment at the head of index.html: the notice and licence text that their licences ask to travel with the copies. Packages that
// share one licence text are listed under it.
const LICENSED_ASSETS = ['@fontsource/zen-kaku-gothic-antique', '@fontsource-variable/outfit', '@fontsource-variable/noto-sans-jp']
function packageOf(id: string): string | undefined {
  const path = id.replace(/^\0/, '').replace(/\?.*$/, '')
  const at = path.lastIndexOf('node_modules/')
  if (at < 0) return undefined
  const [scopeOrName, name] = path.slice(at + 'node_modules/'.length).split('/')
  const dir = scopeOrName!.startsWith('@') ? `${scopeOrName}/${name}` : scopeOrName!
  return path.slice(0, at) + 'node_modules/' + dir
}
function licenseNotice(moduleIds: Iterable<string>): string {
  const roots = new Set<string>()
  for (const id of moduleIds) { const root = packageOf(id); if (root) roots.add(root) }
  for (const name of LICENSED_ASSETS) roots.add(dirname(nodeRequire.resolve(`${name}/package.json`)))
  const byText = new Map<string, string[]>()
  for (const root of [...roots].sort()) {
    const info = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8')) as { name: string; version: string; license?: string }
    const file = readdirSync(root).find(name => /^(licen[sc]e|copying)(\..*)?$/i.test(name))
    const text = (file ? readFileSync(resolve(root, file), 'utf8').trim() : `Licence: ${info.license ?? 'not stated'} (no licence file in the package)`).replace(/-->/g, '--&gt;')
    byText.set(text, [...(byText.get(text) ?? []), `${info.name}@${info.version}`])
  }
  return ['Third-party licences', ...[...byText].map(([text, names]) => `${names.join(', ')}\n\n${text}`)].join('\n\n----------------------------------------\n\n')
}

const bundledModules = new Set<string>()

const comail = (): Plugin => ({
  name: 'comail',
  // The modules whose code is in the bundle, for the licence notice.
  renderChunk(_code, chunk) { for (const [id, rendered] of Object.entries(chunk.modules)) if (rendered.renderedLength > 0) bundledModules.add(id); return null },
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
    // The licences, at the head of the page.
    const page = resolve(process.env.BISET_OUT_DIR ?? 'dist', 'index.html')
    if (existsSync(page) && bundledModules.size > 0) writeFileSync(page, readFileSync(page, 'utf8').replace('<head>', () => `<head>\n<!--\n${licenseNotice(bundledModules)}\n-->`))
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
  plugins: [react(), comail(), viteSingleFile()],
  // lft is a sibling checkout (linked in package.json): its source is served and compiled from there.
  server: { port: 3000, fs: { allow: [resolve('.'), resolve('../lft')] } },
  build: {
    outDir: resolve(process.env.BISET_OUT_DIR ?? 'dist'),
    emptyOutDir: false,
    target: 'es2022',
  },
})
