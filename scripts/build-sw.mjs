// The Service Worker next to the page it caches: its build id is the hash of that page, so the file changes exactly when the app does (the
// browser then installs the new worker and the page offers the update). BISET_OUT_DIR is where the page was built (default dist).
import { createHash } from 'node:crypto'
import { readdirSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { build } from 'esbuild'

const outDir = resolve(process.env.BISET_OUT_DIR ?? 'dist')
let page
try { page = readFileSync(resolve(outDir, 'index.html')) } catch { throw new Error(`build the page first: ${outDir}/index.html is missing`) }
// The font kept for offline use from the first visit: the stylesheet and the Latin pieces (the Japanese ones are fetched, and kept, as a text uses them).
let fonts = []
try { fonts = readdirSync(resolve(outDir, 'fonts')).filter(name => name === 'fonts.css' || (name.endsWith('.woff2') && /-latin-wght-|-118-/.test(name))).sort().map(name => `/fonts/${name}`) } catch { /* a build without fonts */ }
const buildId = createHash('sha256').update(page).update(fonts.join()).digest('hex').slice(0, 16)
await build({
  entryPoints: ['src/client/app/sw.ts'], bundle: true, outfile: resolve(outDir, 'sw.js'), platform: 'browser', format: 'iife', target: 'es2022',
  minifySyntax: true, minifyWhitespace: true, define: { __BUILD_ID__: JSON.stringify(buildId), __PRECACHE__: JSON.stringify(fonts) }, logLevel: 'error',
})
console.log(`wrote ${outDir}/sw.js (${buildId})`)
