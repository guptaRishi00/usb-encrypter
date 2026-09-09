import { useEffect, useId, useState } from 'react';

import { estimatePassword } from '../services/api';
import type { Strength } from '../types';

/**
 * A password input with a strength meter.
 *
 * The estimate is computed in Rust, not here: the same process that will derive
 * the key is the one that judges the password, and the web view never needs to
 * carry a scoring table. Nothing is enforced. A weak password produces a warning
 * and a red bar, and the Create button still works, because refusing pushes
 * people towards `Password1!` and nothing better.
 */
export function PasswordField({
  label,
  value,
  onChange,
  showStrength = false,
  autoFocus = false,
  placeholder,
  onEnter,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  showStrength?: boolean;
  autoFocus?: boolean;
  placeholder?: string;
  onEnter?: () => void;
}) {
  const id = useId();
  const [reveal, setReveal] = useState(false);
  const [strength, setStrength] = useState<Strength | null>(null);

  useEffect(() => {
    if (!showStrength) return;
    if (!value) {
      setStrength(null);
      return;
    }
    let cancelled = false;
    // A short debounce: scoring is cheap but this fires on every keystroke.
    const t = setTimeout(() => {
      estimatePassword(value)
        .then((s) => {
          if (!cancelled) setStrength(s);
        })
        .catch(() => {
          if (!cancelled) setStrength(null);
        });
    }, 140);
    return () => {
      cancelled = true;
      clearTimeout(t);
    };
  }, [value, showStrength]);

  return (
    <div className="stack-sm">
      <label className="field" htmlFor={id}>
        <span className="field-label">{label}</span>
        <div style={{ position: 'relative' }}>
          <input
            id={id}
            type={reveal ? 'text' : 'password'}
            value={value}
            autoFocus={autoFocus}
            placeholder={placeholder}
            spellCheck={false}
            autoComplete="off"
            onChange={(e) => onChange(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && onEnter) onEnter();
            }}
            style={{ paddingRight: 60 }}
          />
          <button
            type="button"
            className="btn btn-ghost"
            onClick={() => setReveal((r) => !r)}
            aria-pressed={reveal}
            style={{
              position: 'absolute',
              right: 4,
              top: 4,
              bottom: 4,
              padding: '0 10px',
              fontSize: 12,
              color: 'var(--text-muted)',
            }}
          >
            {reveal ? 'Hide' : 'Show'}
          </button>
        </div>
      </label>

      {showStrength && (
        <div className="strength" aria-live="polite">
          <div className="strength-bars">
            {[0, 1, 2, 3].map((i) => (
              <div
                key={i}
                className={`strength-bar ${
                  strength && i <= strength.score ? `on-${strength.score}` : ''
                }`}
              />
            ))}
          </div>
          <div className="strength-line">
            <span>Password strength</span>
            <span style={{ fontWeight: 560 }}>{strength ? strength.label : '—'}</span>
          </div>
          {strength && strength.notes.length > 0 && (
            <ul className="strength-notes">
              {strength.notes.map((n) => (
                <li key={n}>{n}</li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}
