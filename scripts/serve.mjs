import { serve } from 'bun'
import { readFileSync } from 'fs'

serve({
  port: 3000,
  fetch(req) {
    const url = new URL(req.url)
    if (url.pathname === '/' || url.pathname === '/index.html') {
      try {
        return new Response(readFileSync('dist/index.html'), {
          headers: { 'Content-Type': 'text/html' },
        })
      } catch {
        return new Response('run bun build first', { status: 503 })
      }
    }
    if (url.pathname === '/sw.js') {
      try {
        return new Response(readFileSync('dist/sw.js'), {
          headers: { 'Content-Type': 'application/javascript' },
        })
      } catch {
        return new Response('run bun build first', { status: 503 })
      }
    }
    if (url.pathname === '/config.json') {
      try {
        return new Response(readFileSync('config.json'), {
          headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
        })
      } catch {
        return new Response('{}', { headers: { 'Content-Type': 'application/json' } })
      }
    }
    return new Response('not found', { status: 404 })
  },
})

console.log('http://localhost:3000')
