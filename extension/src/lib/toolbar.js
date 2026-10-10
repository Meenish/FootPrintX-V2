// Toolbar presentation for each check state. Colour is never the only cue:
// each state has its own icon glyph, badge text and descriptive title.
import { TOOLBAR, REPUTATION_STATUS as S } from '@footprintx/shared/threat';

const BADGE_COLORS = { red: '#B42318', amber: '#B54708', green: '#067647', grey: '#475467' };
const ICON = (color) => ({ 16: `icons/${color}-16.png`, 32: `icons/${color}-32.png`, 48: `icons/${color}-48.png`, 128: `icons/${color}-128.png` });

export function toolbarFor(state) {
  const status = state?.status || S.NOT_CHECKED;
  const t = TOOLBAR[status] || TOOLBAR[S.NOT_CHECKED];
  const host = state?.displayHost || state?.hostname;
  let detail = t.label;
  if (status === S.NOT_CHECKED && state?.reasons?.[0]?.code) {
    detail = { NOT_LINKED: 'Not linked', PREMIUM_REQUIRED: 'Protection off (Premium feature)', PREMIUM_EXPIRED: 'Protection off (Premium ended)', PROTECTION_PAUSED: 'Protection paused', LOCAL_PAGE: 'Local page (not checked)', UNSUPPORTED_PAGE: 'Page not checked', FOOTPRINTX: 'FootprintX' }[state.reasons[0].code] || t.label;
  }
  if (status === S.UNAVAILABLE && state?.errorCode === 'OFFLINE') detail = 'Check unavailable (offline)';
  if (state?.source === 'stale_cache') detail = `${t.label} (saved result, could not re-check)`;
  return {
    color: t.color,
    iconPaths: ICON(t.color),
    badge: t.badge,
    badgeColor: BADGE_COLORS[t.color],
    title: `FootprintX — ${detail}${host ? `: ${host}` : ''}`,
  };
}
