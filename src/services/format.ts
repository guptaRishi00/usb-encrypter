/** Small display helpers. Nothing here decides anything; Rust does that. */

const UNITS = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];

export function bytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return '—';
  if (n < 1024) return `${n} B`;
  let value = n;
  let unit = 0;
  while (value >= 1024 && unit < UNITS.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${UNITS[unit]}`;
}

export function count(n: number): string {
  return n.toLocaleString();
}

/**
 * `3 files`, but `1 file`. Only for the plain English plurals this app uses;
 * anything irregular takes an explicit `plural` argument.
 */
export function quantity(n: number, singular: string, plural = `${singular}s`): string {
  return `${count(n)} ${n === 1 ? singular : plural}`;
}

export function when(unixSeconds: number | null | undefined): string {
  if (!unixSeconds) return '—';
  const d = new Date(unixSeconds * 1000);
  const today = new Date();
  const sameDay =
    d.getFullYear() === today.getFullYear() &&
    d.getMonth() === today.getMonth() &&
    d.getDate() === today.getDate();
  return sameDay
    ? d.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' })
    : d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

/** Last path component, for either separator. */
export function basename(path: string): string {
  const parts = path.split(/[\\/]/).filter(Boolean);
  return parts[parts.length - 1] ?? path;
}

export function dirname(path: string): string {
  const idx = Math.max(path.lastIndexOf('\\'), path.lastIndexOf('/'));
  return idx > 0 ? path.slice(0, idx) : path;
}

/** Shorten a long path for display without losing which drive it is on. */
export function shortPath(path: string, max = 58): string {
  if (path.length <= max) return path;
  const name = basename(path);
  const head = path.slice(0, Math.max(0, max - name.length - 4));
  return `${head}…\\${name}`;
}

const TEXT_EXT = new Set([
  'txt', 'md', 'csv', 'json', 'xml', 'yml', 'yaml', 'log', 'ini', 'cfg', 'conf',
  'ts', 'tsx', 'js', 'jsx', 'rs', 'py', 'go', 'java', 'c', 'h', 'cpp', 'cs',
  'html', 'css', 'scss', 'sh', 'ps1', 'bat', 'sql', 'toml', 'env', 'gitignore',
]);

const IMAGE_MIME: Record<string, string> = {
  png: 'image/png',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  gif: 'image/gif',
  webp: 'image/webp',
  bmp: 'image/bmp',
  svg: 'image/svg+xml',
  avif: 'image/avif',
};

export function extension(name: string): string {
  const i = name.lastIndexOf('.');
  return i > 0 ? name.slice(i + 1).toLowerCase() : '';
}

export type PreviewKind = { kind: 'text' } | { kind: 'image'; mime: string } | { kind: 'none' };

/**
 * What the in-app viewer can show.
 *
 * Deliberately narrow. Anything else is exported rather than handed to a system
 * application, because handing a file to another program means writing the
 * plaintext to disk first.
 */
export function previewKind(name: string): PreviewKind {
  const ext = extension(name);
  if (IMAGE_MIME[ext]) return { kind: 'image', mime: IMAGE_MIME[ext] };
  if (TEXT_EXT.has(ext)) return { kind: 'text' };
  return { kind: 'none' };
}
