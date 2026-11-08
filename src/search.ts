// Search with operators, like KeePassXC:
//   word            anywhere in title, tags, note and plain fields (never in passwords)
//   "two words"     as a phrase
//   user: url: notes: tag: title:   only in that part
//   is:expired is:weak is:reused is:old is:breached is:pinned is:totp
//   -term           must NOT match (works with every form above)
import { searchText, type Item } from './model.ts';

export const FIELDS = ['user', 'url', 'notes', 'tag', 'title'] as const;
export type SearchField = typeof FIELDS[number];
export const STATES = ['expired', 'weak', 'reused', 'old', 'breached', 'pinned', 'totp'] as const;
export type State = typeof STATES[number];

export type Term =
  | { neg: boolean; text: string; field?: SearchField }
  | { neg: boolean; is: State };

/** "-user:\"john doe\" is:weak mail" → terms. Unknown prefixes stay plain text (e.g. "https://…"). */
export function parseQuery(query: string): Term[] {
  const terms: Term[] = [];
  const re = /(-?)(?:([a-z]+):)?(?:"([^"]*)"?|(\S+))/gi;
  for (const m of query.matchAll(re)) {
    const neg = m[1] === '-';
    const prefix = m[2]?.toLowerCase();
    const value = (m[3] ?? m[4] ?? '').toLowerCase();
    if (prefix === 'is' && (STATES as readonly string[]).includes(value)) { terms.push({ neg, is: value as State }); continue; }
    if (prefix && (FIELDS as readonly string[]).includes(prefix)) {
      if (value) terms.push({ neg, text: value, field: prefix as SearchField });
      continue;
    }
    // not an operator: the whole token is text (keeps "https://x" or "a:b" intact)
    const text = ((m[2] ? m[2] + ':' : '') + (m[3] ?? m[4] ?? '')).toLowerCase();
    // "user:" still being typed: no filter yet
    const half = /^([a-z]+):$/.exec(text);
    if (half && (half[1] === 'is' || (FIELDS as readonly string[]).includes(half[1]))) continue;
    if (text) terms.push({ neg, text });
  }
  return terms;
}

/** Health findings for is:weak/reused/old/breached (from the password health check). */
export type IssuesOf = (id: string) => string[];

const plain = (i: Item) => i.fields.filter(f => !f.protected && f.kind !== 'hidden' && f.kind !== 'totp');
const partText = (i: Item, field: SearchField): string => {
  switch (field) {
    case 'user': return plain(i).filter(f => f.key === 'username' || f.key === 'email' || /user|login|e-?mail/i.test(f.label ?? '')).map(f => f.value).join('\n');
    case 'url': return plain(i).filter(f => f.key === 'website' || f.kind === 'url').map(f => f.value).join('\n');
    case 'notes': return i.note ?? '';
    case 'tag': return (i.tags ?? []).join('\n');
    case 'title': return i.title;
  }
};
const today = () => new Date().toISOString().slice(0, 10);

function hit(i: Item, t: Term, issues: IssuesOf, all: () => string): boolean {
  if ('is' in t) {
    switch (t.is) {
      case 'expired': return !!i.expires && i.expires < today();
      case 'pinned': return !!i.pinned;
      case 'totp': return i.fields.some(f => f.kind === 'totp' || f.key === 'totp');
      default: return issues(i.id).includes(t.is);
    }
  }
  return (t.field ? partText(i, t.field).toLowerCase() : all()).includes(t.text);
}

export function matchesTerms(i: Item, terms: Term[], issues: IssuesOf = () => []): boolean {
  let text: string | null = null;
  const all = () => (text ??= searchText(i));
  return terms.every(t => hit(i, t, issues, all) !== t.neg);
}

/** true when the query needs the password health data */
export const needsHealth = (terms: Term[]) => terms.some(t => 'is' in t && ['weak', 'reused', 'old', 'breached'].includes(t.is));
