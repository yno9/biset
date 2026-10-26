// Dev only: draws the same names in several palettes (avatars.html), the way ui/generated-avatar.tsx draws a person. The five after "Now"
// are made from the colours of https://digitalcommons.jp/events (its CSS: --teal #00ab00, --blue #1d4ed8, --peach #de9b61, --yellow #ffd600,
// and the purple #8d46e7 of its page; its page background is the peach at 12% over white).
import { createRoot } from 'react-dom/client'
import Avatar from 'boring-avatars'

const PALETTES: Array<{ name: string; note: string; colors: string[] }> = [
  { name: 'Now', note: 'what the app uses today (for comparison)', colors: ['#e8604a', '#4a90d9', '#5caf6e', '#9b59b6', '#e67e22'] },
  { name: 'Digital Commons', note: "the site's own five: green, blue, peach, yellow, purple", colors: ['#00ab00', '#1d4ed8', '#de9b61', '#ffd600', '#8d46e7'] },
  { name: 'Softened', note: 'each of them 30% toward white', colors: ['#4cc44c', '#6183e4', '#e8b990', '#ffe24c', '#af7eee'] },
  { name: 'Dusty', note: 'each of them dulled with grey, a little lightened', colors: ['#45a945', '#5673c4', '#c7a07d', '#dac245', '#986ecc'] },
  { name: 'Ink', note: 'each of them 30% toward black (deep)', colors: ['#007800', '#143797', '#9b6c44', '#b29600', '#6331a2'] },
  { name: 'Peach and blue', note: 'two families: peach and its tint, blue and its tint, with the yellow', colors: ['#de9b61', '#e67e22', '#45a945', '#7795e8', '#ffd600'] },
]
const NAMES = ['alice', 'bob', 'carol@example.org', 'dave', 'erin@did.md', 'frank', 'grace', 'heidi', 'ivan', 'judy', 'mallory', 'niaj']
const GROUPS = ['alice bob', 'carol dave erin', 'frank grace', 'heidi ivan judy']

const App = () => (
  <>
    <h1 style={{ fontSize: 18 }}>Avatar palettes</h1>
    {PALETTES.map(palette => (
      <section key={palette.name}>
        <h2>{palette.name} <code>{palette.note}: {palette.colors.join(' ')}</code></h2>
        <div className="swatches">{palette.colors.map(color => <span key={color} style={{ background: color }} title={color} />)}</div>
        <div className="row">
          {NAMES.map(name => <div className="av" key={name}><span><Avatar name={name} variant="beam" size="100%" colors={palette.colors} /></span>{name.split('@')[0]}</div>)}
          <div className="gap" />
          {GROUPS.map(name => <div className="av" key={name}><span><Avatar name={name} variant="bauhaus" size="100%" colors={palette.colors} /></span>group</div>)}
        </div>
      </section>
    ))}
  </>
)

createRoot(document.getElementById('root')!).render(<App />)
