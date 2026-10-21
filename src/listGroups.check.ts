// node src/listGroups.check.ts
import { groupItems, letterOf, sortItems, type GroupLabels } from './listGroups.ts';
import type { Item } from './model.ts';

const eq = (a: unknown, b: unknown, msg: string) => {
  if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error(`${msg}: ${JSON.stringify(a)} !== ${JSON.stringify(b)}`);
};
const item = (title: string, extra: Partial<Item> = {}): Item => ({
  id: title, vault: 'v', type: 'login', title, subtitle: '', fields: [], modified: '2026-01-01', ...extra,
});
const labels: GroupLabels = {
  other: 'Other', noFolder: 'No folder', noWebsite: 'No website', noTag: 'No tag',
  today: 'Today', yesterday: 'Yesterday', week: 'This week', month: 'This month', older: 'Older',
  type: t => t, folder: id => id, vault: id => id,
};

eq(letterOf('Ärzte'), 'A', 'umlaut');
eq(letterOf('1password'), '#', 'digit');
eq(sortItems([item('b'), item('A'), item('c')], 'title').map(i => i.title), ['A', 'b', 'c'], 'sort title');
eq(sortItems([item('item2'), item('item10')], 'title').map(i => i.title), ['item2', 'item10'], 'numeric sort');

const g = groupItems(sortItems([item('Zoom'), item('#hash'), item('apple'), item('Amazon')], 'title'), 'letter', labels);
eq(g.map(x => x.label), ['A', 'Z', '#'], 'letters, # last');
eq(g[0].items.map(i => i.title), ['Amazon', 'apple'], 'items in group');

const tags = groupItems([item('x', { tags: ['work', 'mail'] }), item('y')], 'tag', labels);
eq(tags.map(x => x.label), ['mail', 'work', 'No tag'], 'tags, untagged last');

const web = groupItems([item('a', { fields: [{ key: 'website', raw: 'URL', kind: 'url', value: 'https://www.github.com/login' }] }), item('b')], 'domain', labels);
eq(web.map(x => x.label), ['github.com', 'No website'], 'domains');

const now = new Date(2026, 9, 21, 12);
const dates = groupItems([item('t', { modifiedAt: '2026-10-21T08:00:00' }), item('o', { modifiedAt: '2025-01-01T00:00:00' })], 'date', labels, now);
eq(dates.map(x => x.label), ['Today', 'Older'], 'date buckets');
console.log('listGroups ok');
