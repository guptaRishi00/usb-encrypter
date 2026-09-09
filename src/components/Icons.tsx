/** Inline stroked icons. No icon library: eight glyphs is not worth a dependency. */

type P = { size?: number; className?: string };

const base = (size: number) => ({
  width: size,
  height: size,
  viewBox: '0 0 24 24',
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 1.7,
  strokeLinecap: 'round' as const,
  strokeLinejoin: 'round' as const,
  'aria-hidden': true,
});

export const HomeIcon = ({ size = 17, className }: P) => (
  <svg {...base(size)} className={className}>
    <path d="M3 10.5 12 3l9 7.5" />
    <path d="M5.5 9.5V20h13V9.5" />
  </svg>
);

export const VaultIcon = ({ size = 17, className }: P) => (
  <svg {...base(size)} className={className}>
    <rect x="3" y="4" width="18" height="16" rx="2.5" />
    <circle cx="12" cy="12" r="3.6" />
    <path d="M12 8.4V6.6M12 17.4v-1.8" />
  </svg>
);

export const PlusIcon = ({ size = 17, className }: P) => (
  <svg {...base(size)} className={className}>
    <path d="M12 5v14M5 12h14" />
  </svg>
);

export const KeyIcon = ({ size = 17, className }: P) => (
  <svg {...base(size)} className={className}>
    <circle cx="8" cy="14" r="4" />
    <path d="M11 11.5 20 3M17.5 5.5l2 2M15 8l2 2" />
  </svg>
);

export const GearIcon = ({ size = 17, className }: P) => (
  <svg {...base(size)} className={className}>
    <circle cx="12" cy="12" r="3" />
    <path d="M12 2.5v2.2M12 19.3v2.2M4.2 7.3l1.9 1.1M17.9 15.6l1.9 1.1M4.2 16.7l1.9-1.1M17.9 8.4l1.9-1.1" />
  </svg>
);

export const LockIcon = ({ size = 17, className }: P) => (
  <svg {...base(size)} className={className}>
    <rect x="4.5" y="10.5" width="15" height="10" rx="2.2" />
    <path d="M8 10.5V7.8a4 4 0 0 1 8 0v2.7" />
  </svg>
);

export const FolderIcon = ({ size = 18, className }: P) => (
  <svg {...base(size)} className={className}>
    <path d="M3 7.5A1.5 1.5 0 0 1 4.5 6h4.2l2 2.4h8.8A1.5 1.5 0 0 1 21 9.9v8.6a1.5 1.5 0 0 1-1.5 1.5h-15A1.5 1.5 0 0 1 3 18.5Z" />
  </svg>
);

export const FileIcon = ({ size = 18, className }: P) => (
  <svg {...base(size)} className={className}>
    <path d="M13.5 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8.5Z" />
    <path d="M13.5 3v5.5H19" />
  </svg>
);

export const DriveIcon = ({ size = 20, className }: P) => (
  <svg {...base(size)} className={className}>
    <rect x="2.5" y="9" width="19" height="10" rx="2" />
    <path d="M6.5 13.5h.01M10 13.5h.01" />
    <path d="M9 9V5.5A1.5 1.5 0 0 1 10.5 4h3A1.5 1.5 0 0 1 15 5.5V9" />
  </svg>
);

export const DiskIcon = ({ size = 20, className }: P) => (
  <svg {...base(size)} className={className}>
    <rect x="2.5" y="4.5" width="19" height="15" rx="2" />
    <path d="M2.5 14h19M6 17h.01M9 17h.01" />
  </svg>
);

export const AlertIcon = ({ size = 16, className }: P) => (
  <svg {...base(size)} className={className}>
    <path d="M12 4.5 21 20H3Z" />
    <path d="M12 10v4M12 17h.01" />
  </svg>
);

export const CheckIcon = ({ size = 16, className }: P) => (
  <svg {...base(size)} className={className}>
    <path d="M4.5 12.5 9.5 17.5 19.5 6.5" />
  </svg>
);

export const InfoIcon = ({ size = 16, className }: P) => (
  <svg {...base(size)} className={className}>
    <circle cx="12" cy="12" r="9" />
    <path d="M12 11v5.5M12 7.8h.01" />
  </svg>
);

export const ChevronIcon = ({ size = 14, className }: P) => (
  <svg {...base(size)} className={className}>
    <path d="M9 5.5 15.5 12 9 18.5" />
  </svg>
);

export const SpinnerIcon = ({ size = 16, className }: P) => (
  <svg {...base(size)} className={`spin ${className ?? ''}`}>
    <path d="M12 3a9 9 0 1 0 9 9" />
  </svg>
);

export const TrashIcon = ({ size = 16, className }: P) => (
  <svg {...base(size)} className={className}>
    <path d="M4.5 6.5h15M9.5 6.5V4.8a1.3 1.3 0 0 1 1.3-1.3h2.4a1.3 1.3 0 0 1 1.3 1.3v1.7" />
    <path d="M6.5 6.5 7.4 20a1.3 1.3 0 0 0 1.3 1.2h6.6a1.3 1.3 0 0 0 1.3-1.2l.9-13.5" />
  </svg>
);

export const CloseIcon = ({ size = 15, className }: P) => (
  <svg {...base(size)} className={className}>
    <path d="M6 6l12 12M18 6 6 18" />
  </svg>
);

/** The app mark: the padlock from the icon set, drawn at any size. */
export const BrandMark = ({ size = 28, className }: P) => (
  <svg width={size} height={size} viewBox="0 0 64 64" className={className} aria-hidden>
    <rect width="64" height="64" rx="15" fill="url(#vd-g)" />
    <rect x="18" y="30" width="28" height="21" rx="4.5" fill="#E8E7FF" />
    <path
      d="M23.5 30v-4a8.5 8.5 0 0 1 17 0v4"
      stroke="#E8E7FF"
      strokeWidth="4.6"
      fill="none"
      strokeLinecap="round"
    />
    <circle cx="32" cy="38" r="3.4" fill="#7C6AFF" />
    <rect x="30.3" y="38" width="3.4" height="7" rx="1.7" fill="#7C6AFF" />
    <defs>
      <linearGradient id="vd-g" x1="0" y1="0" x2="0" y2="64" gradientUnits="userSpaceOnUse">
        <stop stopColor="#18162E" />
        <stop offset="1" stopColor="#2E2854" />
      </linearGradient>
    </defs>
  </svg>
);
