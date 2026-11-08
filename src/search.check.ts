// node src/search.check.ts — search operators
import { matchesTerms, needsHealth, parseQuery } from './search.ts';
import type { Item } from './model.ts';

const eq = (a: unknown, b: unknown, what: string) => {
  if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error(`${what}: ${JSON.stringify(a)} !== ${JSON.stringify(b)}`);
};

// parsing
eq(parseQuery('mail bank'), [{ neg: false, text: 'mail' }, { neg: false, text: 'bank' }], 'words');
eq(parseQuery('"two words"'), [{ neg: false, text: 'two words' }], 'phrase');
eq(parseQuery('-user:"John Doe"'), [{ neg: true, text: 'john doe', field: 'user' }], 'negated field phrase');
eq(parseQuery('is:weak -is:pinned'), [{ neg: false, is: 'weak' }, { neg: true, is: 'pinned' }], 'states');
eq(parseQuery('https://example.org'), [{ neg: false, text: 'https://example.org' }], 'url stays text');
eq(parseQuery('is:banana'), [{ neg: false, text: 'is:banana' }], 'unknown state is text');
eq(parseQuery('user:'), [], 'empty operator ignored');
eq(parseQuery('"open'), [{ neg: false, text: 'open' }], 'unclosed quote');
eq(needsHealth(parseQuery('is:reused')), true, 'health needed');
eq(needsHealth(parseQuery('is:expired mail')), false, 'no health needed');

// matching
const item: Item = {
  id: 'a', vault: 'v', type: 'login', title: 'Mail Account', subtitle: 'john@example.org', modified: '2026-01-01',
  tags: ['work', 'private mail'], note: 'Recovery codes in the safe', pinned: true, expires: '2020-01-01',
  fields: [
    { key: 'username', value: 'john@example.org' },
    { key: 'password', value: 'hunter2', kind: 'hidden', protected: true },
    { key: 'website', value: 'https://mail.example.org', kind: 'url' },
    { key: 'totp', value: 'otpauth://totp/x?secret=ABC', kind: 'totp', protected: true },
    { label: 'Backup mail', value: 'jd@other.net' },
  ],
};
const m = (q: string, issues: string[] = []) => matchesTerms(item, parseQuery(q), () => issues);
eq(m('mail account'), true, 'two words anywhere');
eq(m('"mail account"'), true, 'phrase');
eq(m('"account mail"'), false, 'phrase order matters');
eq(m('user:john'), true, 'user field');
eq(m('user:mail.example'), false, 'website is not user');
eq(m('url:mail.example'), true, 'url field');
eq(m('notes:safe'), true, 'notes');
eq(m('notes:john'), false, 'notes only');
eq(m('tag:"private mail"'), true, 'tag phrase');
eq(m('title:recovery'), false, 'title only');
eq(m('-tag:work'), false, 'negated tag');
eq(m('-tag:home mail'), true, 'negation plus word');
eq(m('is:expired'), true, 'expired');
eq(m('is:pinned is:totp'), true, 'pinned and totp');
eq(m('is:weak'), false, 'not weak without health data');
eq(m('is:weak', ['weak']), true, 'weak from health data');
eq(m('-is:reused', ['reused']), false, 'negated reused');
eq(m('hunter2'), false, 'passwords never match');
eq(m('secret=abc'), false, 'totp secret never matches');
eq(m(''), true, 'empty query');
eq([m('backup'), m('other.net'), m('EXAMPLE john')], [true, true, true], 'custom field label and value, any case and order');

console.log('search ok');
