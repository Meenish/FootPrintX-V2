import { DASI_LEVEL_TONE } from './lib/labels.js';

const BANDS = [
  { from: 0, to: 20, label: 'Low' },
  { from: 20, to: 40, label: 'Guarded' },
  { from: 40, to: 60, label: 'Elevated' },
  { from: 60, to: 80, label: 'High' },
  { from: 80, to: 100, label: 'Severe' },
];
const CONFIDENCE_TEXT = { high: 'High confidence', medium: 'Medium confidence', low: 'Low confidence', none: 'Not assessed' };

/**
 * The DASI gauge shows the score AND its uncertainty: the hatched band runs
 * from the score to the upper bound — what the score could be if the unknowns
 * (e.g. two-step verification status) turned out unfavourable.
 */
export function DasiGauge({ snapshot, size = 'large' }) {
  if (!snapshot || snapshot.score == null) {
    return (
      <div className={`gauge gauge-${size} gauge-empty`}>
        <p className="gauge-number" aria-hidden="true">—</p>
        <p className="gauge-caption">Not assessed yet. Connect a mailbox and run a scan to calculate your index.</p>
      </div>
    );
  }
  const score = snapshot.score;
  const upper = Math.max(score, snapshot.upper_bound ?? snapshot.upper ?? score);
  const level = BANDS.find((b) => score >= b.from && score < b.to) || BANDS[4];
  const tone = DASI_LEVEL_TONE[snapshot.level] || 'neutral';
  const label = `Digital Attack Surface Index ${score} out of 100, ${level.label}. ${upper > score ? `Could be up to ${upper} given unknown factors. ` : ''}${CONFIDENCE_TEXT[snapshot.confidence] || ''}.`;
  return (
    <div className={`gauge gauge-${size} tone-${tone}`} role="img" aria-label={label}>
      <div className="gauge-head" aria-hidden="true">
        <span className="gauge-number">{score}</span>
        <span className="gauge-of">/100</span>
        <span className="gauge-level">{level.label}</span>
      </div>
      <div className="gauge-track" aria-hidden="true">
        {BANDS.map((b) => (
          <span key={b.label} className={`gauge-band band-${b.label.toLowerCase()}`} style={{ left: `${b.from}%`, width: `${b.to - b.from}%` }} />
        ))}
        {upper > score && <span className="gauge-unknown" style={{ left: `${score}%`, width: `${upper - score}%` }} />}
        <span className="gauge-marker" style={{ left: `${score}%` }} />
      </div>
      <div className="gauge-scale" aria-hidden="true"><span>0</span><span>Higher means more observed risk</span><span>100</span></div>
      <p className="gauge-caption" aria-hidden="true">
        {upper > score ? <>Could be up to <strong>{upper}</strong> once unknowns are resolved. </> : null}
        {CONFIDENCE_TEXT[snapshot.confidence]}.
      </p>
    </div>
  );
}
