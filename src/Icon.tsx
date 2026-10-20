export const Icon = ({ n, fill }: { n: string; fill?: boolean }) =>
  <span className={'ms' + (fill ? ' fill' : '')} aria-hidden>{n}</span>;
