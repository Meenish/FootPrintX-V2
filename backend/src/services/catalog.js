// Service catalog: canonical names, categories (used for DASI impact) and the
// registry of official security pages used in recommendations.
//
// OFFICIAL LINK POLICY (docs/DASI.md, "Recommendations"):
//   * Every URL below was checked on REGISTRY_VERIFIED_ON against the
//     provider's own help documentation, which is recorded in `source`.
//   * kind "settings_page": a deep link the provider's documentation itself
//     uses for that setting.
//   * kind "help_page": the provider's official help article for that action;
//     the user navigates to the setting from there.
//   * Services that could not be verified (e.g. sites that block automated
//     access to their help centers) have NO link. The UI then tells the user to
//     type the service's address themselves instead of following email links.
//   Never add a URL here without checking it against official documentation.

export const REGISTRY_VERIFIED_ON = '2026-10-10';

const G = 'https://support.google.com/accounts/answer/';
const GH = 'https://docs.github.com/en/';

const OFFICIAL = {
  'google.com': {
    name: 'Google Account',
    links: {
      enable_mfa: { url: 'https://myaccount.google.com/signinoptions/two-step-verification', kind: 'settings_page', source: `${G}185839` },
      change_password: { url: 'https://myaccount.google.com/signinoptions/password', kind: 'settings_page', source: `${G}6294825` },
      review_sessions: { url: 'https://myaccount.google.com/device-activity', kind: 'settings_page', source: `${G}6294825` },
      review_activity: { url: 'https://myaccount.google.com/notifications', kind: 'settings_page', source: `${G}6294825` },
      review_connected_apps: { url: 'https://myaccount.google.com/linkedapps', kind: 'settings_page', source: `${G}13533235` },
      update_recovery: { url: 'https://myaccount.google.com/recovery/email', kind: 'settings_page', source: `${G}183723` },
      help: { url: `${G}6294825`, kind: 'help_page', source: `${G}6294825` },
    },
  },
  'github.com': {
    name: 'GitHub',
    links: {
      enable_mfa: { url: `${GH}authentication/securing-your-account-with-two-factor-authentication-2fa/configuring-two-factor-authentication`, kind: 'help_page' },
      change_password: { url: `${GH}authentication/keeping-your-account-and-data-secure/updating-your-github-access-credentials`, kind: 'help_page' },
      review_sessions: { url: `${GH}authentication/keeping-your-account-and-data-secure/viewing-and-managing-your-sessions`, kind: 'help_page' },
      review_connected_apps: { url: `${GH}apps/oauth-apps/using-oauth-apps/reviewing-your-authorized-oauth-apps`, kind: 'help_page' },
    },
  },
  'gitlab.com': {
    name: 'GitLab',
    links: { enable_mfa: { url: 'https://docs.gitlab.com/user/profile/account/two_factor_authentication/', kind: 'help_page' } },
  },
  'microsoft.com': {
    name: 'Microsoft account',
    links: {
      enable_mfa: { url: 'https://support.microsoft.com/en-us/account-billing/how-to-use-two-step-verification-with-your-microsoft-account-c7910146-672f-01e9-50a0-93b4585e7eb4', kind: 'help_page' },
      change_password: { url: 'https://support.microsoft.com/help/4026838', kind: 'help_page' },
    },
  },
  'apple.com': {
    name: 'Apple Account',
    links: {
      enable_mfa: { url: 'https://support.apple.com/en-us/102660', kind: 'help_page' },
      help: { url: 'https://account.apple.com/', kind: 'settings_page', source: 'https://support.apple.com/en-us/102660' },
    },
  },
  'adobe.com': {
    name: 'Adobe',
    links: {
      enable_mfa: { url: 'https://helpx.adobe.com/manage-account/using/secure-your-adobe-account.html', kind: 'help_page' },
      security: { url: 'https://account.adobe.com/security', kind: 'settings_page', source: 'https://helpx.adobe.com/manage-account/using/secure-your-adobe-account.html' },
    },
  },
  'spotify.com': {
    name: 'Spotify',
    links: {
      change_password: { url: 'https://www.spotify.com/account/login-methods-v2/password/', kind: 'settings_page', source: 'https://support.spotify.com/us/article/change-password/' },
      help: { url: 'https://support.spotify.com/us/article/change-password/', kind: 'help_page' },
    },
  },
  'yahoo.com': {
    name: 'Yahoo',
    links: {
      enable_mfa: { url: 'https://help.yahoo.com/kb/SLN5013.html', kind: 'help_page' },
      security: { url: 'https://login.yahoo.com/account/security', kind: 'settings_page', source: 'https://help.yahoo.com/kb/SLN5013.html' },
    },
  },
  'atlassian.com': {
    name: 'Atlassian',
    links: {
      enable_mfa: { url: 'https://support.atlassian.com/atlassian-account/docs/manage-two-step-verification-for-your-atlassian-account/', kind: 'help_page' },
      security: { url: 'https://id.atlassian.com/manage-profile/security', kind: 'settings_page', source: 'https://support.atlassian.com/atlassian-account/docs/manage-two-step-verification-for-your-atlassian-account/' },
    },
  },
  'slack.com': { name: 'Slack', links: { enable_mfa: { url: 'https://slack.com/help/articles/204509068', kind: 'help_page' } } },
  'discord.com': { name: 'Discord', links: { enable_mfa: { url: 'https://support.discord.com/hc/en-us/articles/219576828', kind: 'help_page' } } },
  'reddit.com': {
    name: 'Reddit',
    links: {
      enable_mfa: { url: 'https://support.reddithelp.com/hc/en-us/articles/360043470031', kind: 'help_page' },
      security: { url: 'https://www.reddit.com/settings/account', kind: 'settings_page', source: 'https://support.reddithelp.com/hc/en-us/articles/360043470031' },
    },
  },
  'x.com': { name: 'X', links: { enable_mfa: { url: 'https://help.x.com/en/managing-your-account/two-factor-authentication', kind: 'help_page' } } },
  'instagram.com': { name: 'Instagram', links: { enable_mfa: { url: 'https://help.instagram.com/566810106808145', kind: 'help_page' } } },
  // Re-checked 2026-10-10: the older /account-access/enable-two-step-verification
  // path now 302s to this one.
  'dropbox.com': { name: 'Dropbox', links: { enable_mfa: { url: 'https://help.dropbox.com/account-access/enable-2-factor-authentication', kind: 'help_page' } } },
  'pinterest.com': { name: 'Pinterest', links: { enable_mfa: { url: 'https://help.pinterest.com/en/article/two-factor-authentication', kind: 'help_page' } } },
  'canva.com': { name: 'Canva', links: { enable_mfa: { url: 'https://www.canva.com/help/login-verification/', kind: 'help_page' } } },
  'netflix.com': {
    name: 'Netflix',
    links: {
      // Netflix has no public 2FA article; this is its official phishing and
      // account-safety page, which covers changing a compromised password.
      help: { url: 'https://help.netflix.com/en/node/65674', kind: 'help_page' },
      change_password: { url: 'https://help.netflix.com/en/node/65674', kind: 'help_page' },
    },
  },
};

// Domains that share another domain's account system.
const ALIASES = {
  'gmail.com': 'google.com', 'googlemail.com': 'google.com', 'youtube.com': 'google.com', 'accounts.google.com': 'google.com',
  'live.com': 'microsoft.com', 'outlook.com': 'microsoft.com', 'hotmail.com': 'microsoft.com', 'office.com': 'microsoft.com', 'xbox.com': 'microsoft.com', 'skype.com': 'microsoft.com',
  'icloud.com': 'apple.com', 'twitter.com': 'x.com', 'atlassian.net': 'atlassian.com', 'trello.com': 'atlassian.com', 'yahoo.co.in': 'yahoo.com', 'discordapp.com': 'discord.com',
};

export const CATEGORY_IMPACT = Object.freeze({
  identity_email: 1.3,
  financial: 1.3,
  cloud_storage: 1.2,
  developer: 1.15,
  work_productivity: 1.1,
  social: 1.1,
  commerce: 1.1,
  other: 1.0,
});

export const CATEGORY_LABELS = Object.freeze({
  identity_email: 'Email & identity',
  financial: 'Finance & payments',
  cloud_storage: 'Cloud storage',
  developer: 'Developer & infrastructure',
  work_productivity: 'Work & productivity',
  social: 'Social & messaging',
  commerce: 'Shopping & services',
  other: 'Other',
});

const CATEGORIES = {
  identity_email: ['google.com', 'microsoft.com', 'apple.com', 'yahoo.com', 'proton.me', 'protonmail.com', 'zoho.com', 'aol.com', 'fastmail.com', 'gmx.com'],
  financial: ['paypal.com', 'stripe.com', 'razorpay.com', 'paytm.com', 'phonepe.com', 'hdfcbank.com', 'icicibank.com', 'sbi.co.in', 'onlinesbi.sbi', 'axisbank.com', 'kotak.com', 'chase.com', 'wise.com', 'revolut.com', 'coinbase.com', 'binance.com', 'zerodha.com', 'groww.in', 'upstox.com', 'americanexpress.com', 'venmo.com', 'cred.club', 'policybazaar.com', 'paisabazaar.com', 'bankofamerica.com', 'wellsfargo.com', 'citi.com', 'hsbc.com', 'kraken.com'],
  cloud_storage: ['dropbox.com', 'box.com', 'mega.nz', 'pcloud.com', 'onedrive.com', 'wetransfer.com'],
  developer: ['github.com', 'gitlab.com', 'bitbucket.org', 'atlassian.com', 'npmjs.com', 'heroku.com', 'vercel.com', 'netlify.com', 'digitalocean.com', 'cloudflare.com', 'docker.com', 'pypi.org', 'stackoverflow.com', 'render.com', 'linode.com', 'mongodb.com', 'supabase.com', 'firebase.google.com', 'jetbrains.com'],
  work_productivity: ['slack.com', 'notion.so', 'notion.com', 'zoom.us', 'canva.com', 'adobe.com', 'figma.com', 'asana.com', 'monday.com', 'miro.com', 'docusign.com', 'clickup.com', 'airtable.com', 'calendly.com', 'grammarly.com', 'openai.com', 'anthropic.com'],
  social: ['facebook.com', 'instagram.com', 'x.com', 'linkedin.com', 'reddit.com', 'discord.com', 'snapchat.com', 'pinterest.com', 'tiktok.com', 'quora.com', 'tumblr.com', 'telegram.org', 'whatsapp.com', 'twitch.tv', 'medium.com', 'mastodon.social', 'threads.net'],
  commerce: ['amazon.com', 'amazon.in', 'flipkart.com', 'myntra.com', 'ebay.com', 'etsy.com', 'swiggy.com', 'zomato.com', 'uber.com', 'olacabs.com', 'airbnb.com', 'booking.com', 'makemytrip.com', 'goibibo.com', 'nykaa.com', 'ajio.com', 'meesho.com', 'bigbasket.com', 'irctc.co.in', 'shopify.com', 'aliexpress.com', 'walmart.com', 'bookmyshow.com'],
};

const DOMAIN_CATEGORY = new Map(Object.entries(CATEGORIES).flatMap(([cat, domains]) => domains.map((d) => [d, cat])));

export const canonicalServiceDomain = (domain) => (domain ? ALIASES[domain] || domain : null);

export function categoryFor(domain) {
  if (!domain) return 'other';
  return DOMAIN_CATEGORY.get(canonicalServiceDomain(domain)) || 'other';
}

export function officialServiceName(domain) {
  return OFFICIAL[canonicalServiceDomain(domain)]?.name || null;
}

/**
 * Official destination for an action on a service. Returns
 * { url, kind, source, note } or { url: null, kind: 'none', note }.
 */
export function officialLinkFor(domain, actionType) {
  const entry = OFFICIAL[canonicalServiceDomain(domain)];
  const direct = entry?.links[actionType];
  if (direct) return { url: direct.url, kind: direct.kind, source: direct.source || direct.url, verifiedOn: REGISTRY_VERIFIED_ON, note: direct.kind === 'help_page' ? 'Official help article. Follow its steps to reach the setting.' : null };
  const landing = entry?.links.security || entry?.links.help;
  if (landing) {
    return {
      url: landing.url,
      kind: landing.kind,
      source: landing.source || landing.url,
      verifiedOn: REGISTRY_VERIFIED_ON,
      note: 'This is the official security or help page for this service; you may need to navigate to the specific setting.',
    };
  }
  // No entry in the registry. The service's own canonical domain is still a
  // defensible destination: it comes from authenticated (DMARC-passing) message
  // evidence, not from a link inside an email, and sending the user to the site
  // they already have an account on is exactly the "navigate there yourself"
  // advice — with the typing done for them. It is deliberately NOT presented as
  // a verified deep link, and no path is ever appended.
  const canonical = canonicalServiceDomain(domain);
  if (canonical && /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(canonical)) {
    return {
      url: `https://${canonical}/`,
      kind: 'domain_root',
      source: null,
      verifiedOn: null,
      note: 'FootprintX has no verified deep link to this service’s security settings, so this opens the service’s own home page. Sign in there and look for Settings → Security or Password. Never follow a security link from an email.',
    };
  }
  return {
    url: null,
    kind: 'none',
    note: 'FootprintX does not have a verified official link for this service. Type the service’s address into your browser yourself (do not follow links in emails) and look for its security settings.',
  };
}

export const registeredOfficialDomains = () => Object.keys(OFFICIAL);
