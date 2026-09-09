import type { ReactNode } from 'react';
import { AlertIcon, CheckIcon, InfoIcon } from './Icons';

type Tone = 'info' | 'warn' | 'danger' | 'ok' | 'accent';

const ICON = {
  info: InfoIcon,
  warn: AlertIcon,
  danger: AlertIcon,
  ok: CheckIcon,
  accent: InfoIcon,
} as const;

const CLASS = {
  info: '',
  warn: 'note-warn',
  danger: 'note-danger',
  ok: 'note-ok',
  accent: 'note-accent',
} as const;

const COLOR = {
  info: 'var(--text-faint)',
  warn: 'var(--warn)',
  danger: 'var(--danger)',
  ok: 'var(--ok)',
  accent: 'var(--accent)',
} as const;

export function Note({
  tone = 'info',
  title,
  children,
}: {
  tone?: Tone;
  title?: string;
  children?: ReactNode;
}) {
  const Icon = ICON[tone];
  return (
    <div className={`note ${CLASS[tone]}`} role={tone === 'danger' ? 'alert' : undefined}>
      <span style={{ color: COLOR[tone], display: 'flex' }}>
        <Icon size={16} />
      </span>
      <div>
        {title && <strong>{title}</strong>}
        {children}
      </div>
    </div>
  );
}
