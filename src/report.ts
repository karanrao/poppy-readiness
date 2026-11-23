// Markdown reports. No Node imports: safe to use in a browser.

import { CHECKS, STAGES, type CheckEvent, type CompanyType, type DoneEvent } from './catalogue.js';

export const COMPANY_TYPE_LABEL: Record<CompanyType, string> = {
  'signed-out': 'Signed out only (no issuer)',
  issuer: 'Has an issuer',
  unknown: 'Unknown',
};

const cell = (s: string | undefined) => (s ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ');

/** A readiness report as Markdown: a summary, then a table per stage. */
export function markdownReport(events: CheckEvent[], d: DoneEvent, o: { checkedAt?: Date; by?: string } = {}): string {
  const when = (o.checkedAt ?? new Date()).toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' });
  const out = [
    `# Poppy readiness report: ${d.domain}`,
    `${d.passed} of ${d.passed + d.failed + d.warned} passed · ${d.failed} failed · ${d.warned} warning${d.warned === 1 ? '' : 's'} · ${d.skipped} skipped`,
    `${COMPANY_TYPE_LABEL[d.companyType]} · identifier ${d.identifier ?? 'none'} · Poppy ${d.version ?? '?'}`,
    `Checked ${when}${o.by ? ` by ${o.by}` : ''}`,
  ];
  for (const s of STAGES) {
    out.push('', `## ${s.title} (${s.section})`, '| Check | Result | Section | Detail |', '|---|---|---|---|');
    for (const c of CHECKS.filter((x) => x.stage === s.id)) {
      const e = events.find((x) => x.id === c.id);
      out.push(`| ${c.id} ${cell(c.title)} | ${e?.status ?? 'not run'} | ${c.section} | ${cell([e?.detail, e?.http].filter(Boolean).join(' '))} |`);
    }
  }
  return out.join('\n') + '\n';
}
