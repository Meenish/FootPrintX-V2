import ExcelJS from 'exceljs';
import { query } from '../db.js';
import { getEntitlement } from './billing.js';

export function safeCell(value) {
  if (value == null) return 'Unknown';
  if (value instanceof Date || typeof value === 'number' || typeof value === 'boolean') return value;
  const s = typeof value === 'object' ? JSON.stringify(value) : String(value);
  return (/^[\s]*[=+\-@]/.test(s) ? `'${s}` : s).slice(0, 32000);
}

export async function createReport(userId) {
  const ent = await getEntitlement(userId);
  const q = (sql) => query(sql, [userId]);
  const [accounts, findings, recommendations, history, events] = await Promise.all([
    q('SELECT service_name, service_domain, status, confidence, discovery_source, mfa_status, mfa_source, exposure_status, account_state, risk_score, risk_level, last_observed_at, is_synthetic FROM discovered_accounts WHERE user_id=$1 ORDER BY service_name'),
    q('SELECT service_name, service_domain, risk_level, risk_score, risk_upper, risk_factors, risk_model_version, risk_assessed_at FROM discovered_accounts WHERE user_id=$1 AND status=\'confirmed\' ORDER BY risk_score DESC NULLS LAST'),
    q('SELECT title, action_type, severity, status, reported_at, verified_at, created_at FROM recommendations WHERE user_id=$1 ORDER BY created_at DESC'),
    q('SELECT model_version, score, upper_bound, level, confidence, trigger, delta, change_reasons, created_at FROM dasi_snapshots WHERE user_id=$1 ORDER BY created_at DESC'),
    query('SELECT type, domain, status, reason_codes, occurred_at FROM extension_events WHERE user_id=$1 AND occurred_at > now() - make_interval(days => $2) ORDER BY occurred_at DESC', [userId, ent.features.advancedHistoryDays]),
  ]);
  const book = new ExcelJS.Workbook();
  book.creator = 'FootprintX';
  book.created = new Date();
  function sheet(name, keys, rows) {
    const s = book.addWorksheet(name, { views: [{ state: 'frozen', ySplit: 1 }] });
    s.columns = keys.map((key) => ({ header: key.replaceAll('_', ' '), key, width: /reason|factor|title|message/.test(key) ? 55 : 25 }));
    for (const row of rows) s.addRow(Object.fromEntries(keys.map((key) => [key, safeCell(row[key])])));
    s.autoFilter = { from: { row: 1, column: 1 }, to: { row: Math.max(1, s.rowCount), column: keys.length } };
    s.getRow(1).font = { bold: true, color: { argb: 'FFFFFFFF' } };
    s.getRow(1).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF173C38' } };
    s.eachRow((r, i) => { if (i > 1) r.eachCell((c) => { c.alignment = { vertical: 'top', wrapText: true }; if (c.value instanceof Date) c.numFmt = 'yyyy-mm-dd hh:mm'; }); });
    if (!rows.length) s.addRow({ [keys[0]]: 'No records available' });
  }
  sheet('Summary', ['item','value'], [
    { item: 'Generated at (UTC)', value: new Date() }, { item: 'Plan', value: ent.plan },
    { item: 'Accounts', value: accounts.length }, { item: 'DASI', value: history[0]?.score },
    { item: 'Scoring model', value: history[0]?.model_version },
    { item: 'Limitations', value: 'DASI is an internal evidence-based index. Unknown is not safe. Inventory is not exhaustive; account association does not prove current login.' },
    { item: 'Security activity', value: `Only opted-in warning events, limited to ${ent.features.advancedHistoryDays} days. No complete browsing history.` },
  ]);
  sheet('Accounts', ['service_name','service_domain','status','confidence','discovery_source','mfa_status','mfa_source','exposure_status','account_state','risk_score','risk_level','last_observed_at','is_synthetic'], accounts);
  sheet('Risk Findings', ['service_name','service_domain','risk_level','risk_score','risk_upper','risk_factors','risk_model_version','risk_assessed_at'], findings);
  sheet('Recommendations', ['title','action_type','severity','status','reported_at','verified_at','created_at'], recommendations);
  sheet('DASI History', ['model_version','score','upper_bound','level','confidence','trigger','delta','change_reasons','created_at'], history);
  sheet('Security Activity', ['type','domain','status','reason_codes','occurred_at'], events);
  return book.xlsx.writeBuffer();
}
