// Detection-quality evaluation for the look-alike heuristics and the threat
// list matching rules. Reproducible: `npm run eval:detection -w shared`.
//
// Measures:
//   * false-positive rate of lookalike heuristics on a benign reference set
//   * true-positive rate on a crafted look-alike set
//   * matching semantics on fixed cases (exact / parent / sibling / substring)
//   * optional: share of a real phishing feed (path given as argv[2]) the
//     heuristics would catch on their own — an upper bound on what amber adds
//     when a site is NOT yet listed (the list itself is the primary control).
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeLookalike } from '../src/lookalike.js';
import { indicatorMatches } from '../src/domain.js';
import { validateIndicatorHost } from '../src/threat.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const read = (f) => fs.readFileSync(path.join(here, '../eval', f), 'utf8').split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
const benign = read('benign-domains.txt');
const lookalikes = read('lookalike-domains.txt');

const fp = benign.filter((d) => analyzeLookalike(d).suspicious);
const tp = lookalikes.filter((d) => analyzeLookalike(d).suspicious);
const fn = lookalikes.filter((d) => !analyzeLookalike(d).suspicious);

const cases = [
  ['evil.example', 'evil.example', true],
  ['a.evil.example', 'evil.example', true],
  ['evil.example', 'a.evil.example', false],
  ['notevil.example', 'evil.example', false],
  ['evil.example.com', 'evil.example', false],
  ['google.com', 'sites.google.com', false],
];
const matchingOk = cases.every(([h, i, want]) => indicatorMatches(h, i) === want);
const rejected = ['google.com', 'sites.google.com', 'github.io', 'weebly.com', 'localhost'].filter((h) => validateIndicatorHost(h).rejected).length;

const report = {
  benign: { total: benign.length, flagged: fp.length, falsePositiveRate: +(fp.length / benign.length).toFixed(4), flaggedDomains: fp },
  lookalikes: { total: lookalikes.length, detected: tp.length, recall: +(tp.length / lookalikes.length).toFixed(4), missed: fn },
  matchingSemantics: { cases: cases.length, allCorrect: matchingOk },
  protectedListingsRejected: `${rejected}/5`,
};

if (process.argv[2] && fs.existsSync(process.argv[2])) {
  const feed = fs.readFileSync(process.argv[2], 'utf8').split('\n').map((l) => l.trim()).filter(Boolean).slice(0, 100000);
  const caught = feed.filter((d) => analyzeLookalike(d).suspicious).length;
  report.realFeedSample = { file: path.basename(process.argv[2]), sampled: feed.length, heuristicOnlyDetections: caught, share: +(caught / feed.length).toFixed(4) };
}
console.log(JSON.stringify(report, null, 2));
if (report.benign.falsePositiveRate > 0.02 || !matchingOk) process.exitCode = 1;
