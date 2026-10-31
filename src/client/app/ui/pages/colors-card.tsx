// The Config tab's colours: for each part the person may colour (color-settings.ts), its colours as pickers, a few faces drawn in them, and a way
// back to the defaults.
import { GeneratedAvatar } from '../generated-avatar.tsx'
import { COLOR_PARTS, resetPartColors, setPartColors, usePartChosen, usePartColors, type ColorPart } from '../color-settings.ts'

const SAMPLES = ['alice', 'bob', 'carol', 'dave']

function PartColors({ part }: { part: ColorPart }) {
  const colors = usePartColors(part.id)
  const chosen = usePartChosen(part.id)
  return (
    <div className="colors-part" id={`colors-${part.id}`}>
      <div className="colors-head">
        <span className="acc-config-title">{part.label}</span>
        {chosen ? <button type="button" className="cmd-page-btn" onClick={() => resetPartColors(part.id)}>Reset</button> : null}
      </div>
      <div className="colors-pickers">
        {colors.map((color, index) => (
          <input key={index} type="color" value={color} aria-label={`${part.label} colour ${index + 1}`}
            onChange={event => setPartColors(part.id, colors.map((current, at) => at === index ? event.target.value : current))} />
        ))}
      </div>
      {/* Faces in these colours; only the avatar is drawn this way so far. */}
      {part.id === 'avatar' ? <div className="colors-samples">{SAMPLES.map(name => <span key={name} className="colors-face"><GeneratedAvatar name={name} /></span>)}</div> : null}
    </div>
  )
}

export function ColorsCard() {
  return (
    <div className="acc-card-wrap" id="cmd-acc-colors-card">
      {COLOR_PARTS.map(part => <PartColors key={part.id} part={part} />)}
    </div>
  )
}
