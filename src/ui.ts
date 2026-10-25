// Small helpers and constants shared by the list, the detail pane and dialogs.
import { type ItemType, type Item } from './model';

export type Theme = 'dark' | 'light';

export const TYPE_ICON: Record<ItemType, string> = {
  login: 'person', card: 'credit_card', note: 'sticky_note_2', pin: 'pin', identity: 'badge', other: 'category',
};
export const today = () => new Date().toISOString().slice(0, 10);

export const isExpired = (i: Item) => !!i.expires && i.expires < today();
