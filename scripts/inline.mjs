import { readFileSync, writeFileSync } from 'fs'

const html = readFileSync('src/index.html', 'utf8')
const js = readFileSync('dist/app.js', 'utf8')
const css = readFileSync('src/style.css', 'utf8')

let config = {}
try { config = JSON.parse(readFileSync('config.json', 'utf8')) } catch {}

const configScript = `<script>window.__BISET_CONFIG__ = ${JSON.stringify(config)};</script>`

const inlined = html
  .replace(
    '<link rel="stylesheet" href="style.css">\n<!-- CSS inlined by build -->',
    `<style>\n${css}\n</style>`
  )
  .replace(
    '<!-- JS inlined by build -->',
    `${configScript}\n<script>\n${js}\n</script>`
  )

writeFileSync('dist/index.html', inlined)
console.log(`inlined: dist/index.html (${(inlined.length / 1024).toFixed(0)}kb)`)
