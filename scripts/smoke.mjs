const origin = process.argv[2];
if (!origin || !/^https?:\/\//.test(origin)) throw new Error('Usage: node scripts/smoke.mjs https://YOUR_DOMAIN');
for (const endpoint of ['/api/health','/api/ready','/api/config','/']) {
  const response = await fetch(new URL(endpoint, origin), { signal: AbortSignal.timeout(15000), redirect: 'error' });
  if (!response.ok) throw new Error(`${endpoint}: HTTP ${response.status}`);
  if (endpoint === '/') {
    if (!(await response.text()).includes('id="root"')) throw new Error('Frontend HTML missing');
  } else {
    const body = await response.json();
    if (endpoint === '/api/ready' && body.ready !== true) throw new Error('Not ready');
    if (endpoint === '/api/config' && origin.startsWith('https:') && (body.environment !== 'production' || body.syntheticDataEnabled || body.billing.billingMode !== 'disabled')) throw new Error('Unsafe launch configuration');
  }
  console.log(`PASS ${endpoint}`);
}
console.log('Public smoke checks passed. Authenticated workflows and provider checks must also be verified.');
