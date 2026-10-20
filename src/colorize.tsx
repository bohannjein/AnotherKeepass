// digits and symbols get their own colour, like KeePassXC's "colorize passwords"
export const colorize = (s: string) => [...s].map((c, i) =>
  /\d/.test(c) ? <span key={i} className="pw-d">{c}</span>
  : /[^\p{L}\p{N}]/u.test(c) ? <span key={i} className="pw-s">{c}</span>
  : c);

