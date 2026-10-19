import type { SVGProps } from "react";

export type IconName =
  | "search"
  | "package"
  | "workflow"
  | "settings"
  | "lock"
  | "play"
  | "sun"
  | "moon"
  | "server"
  | "check"
  | "spark"
  | "alert"
  | "x"
  | "rocket"
  | "orbit"
  | "laptop"
  | "layout"
  | "terminal";

export function Icon({ name, size = 16 }: { name: IconName; size?: number }) {
  const p: SVGProps<SVGSVGElement> = {
    width: size,
    height: size,
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 1.9,
    strokeLinecap: "round",
    strokeLinejoin: "round",
    "aria-hidden": true,
  };
  switch (name) {
    case "search":
      return (
        <svg {...p}>
          <circle cx="11" cy="11" r="8" />
          <path d="m21 21-4.3-4.3" />
        </svg>
      );
    case "package":
      return (
        <svg {...p}>
          <path d="M11 21.73a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73z" />
          <path d="M12 22V12" />
          <path d="m3.3 7 8.7 5 8.7-5" />
        </svg>
      );
    case "workflow":
      return (
        <svg {...p}>
          <rect width="8" height="8" x="3" y="3" rx="2" />
          <path d="M7 11v4a2 2 0 0 0 2 2h4" />
          <rect width="8" height="8" x="13" y="13" rx="2" />
        </svg>
      );
    case "settings":
      return (
        <svg {...p}>
          <path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z" />
          <circle cx="12" cy="12" r="3" />
        </svg>
      );
    case "lock":
      return (
        <svg {...p}>
          <rect width="18" height="11" x="3" y="11" rx="2" />
          <path d="M7 11V7a5 5 0 0 1 10 0v4" />
        </svg>
      );
    case "play":
      return (
        <svg {...p}>
          <polygon points="6 3 20 12 6 21 6 3" />
        </svg>
      );
    case "sun":
      return (
        <svg {...p}>
          <circle cx="12" cy="12" r="4" />
          <path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" />
        </svg>
      );
    case "moon":
      return (
        <svg {...p}>
          <path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9z" />
        </svg>
      );
    case "server":
      return (
        <svg {...p}>
          <rect width="20" height="8" x="2" y="2" rx="2" />
          <rect width="20" height="8" x="2" y="14" rx="2" />
          <path d="M6 6h.01M6 18h.01" />
        </svg>
      );
    case "check":
      return (
        <svg {...p}>
          <path d="M20 6 9 17l-5-5" />
        </svg>
      );
    case "spark":
      return (
        <svg {...p}>
          <path d="M12 3l1.6 5.2L19 10l-5.4 1.8L12 17l-1.6-5.2L5 10l5.4-1.8L12 3z" />
          <path d="M19 15l.6 1.8L21.5 17.5 19.6 18l-.6 1.8-.6-1.8-1.9-.7 1.9-.7L19 15z" />
        </svg>
      );
    case "alert":
      return (
        <svg {...p}>
          <path d="M12 9v4" />
          <path d="M12 17h.01" />
          <path d="M10.3 4.3 2.6 18a2 2 0 0 0 1.7 3h15.4a2 2 0 0 0 1.7-3L13.7 4.3a2 2 0 0 0-3.4 0z" />
        </svg>
      );
    case "x":
      return (
        <svg {...p}>
          <circle cx="12" cy="12" r="10" />
          <path d="m15 9-6 6M9 9l6 6" />
        </svg>
      );
    case "rocket":
      return (
        <svg {...p}>
          <path d="M4.5 16.5c-1.5 1.3-2 5-2 5s3.7-.5 5-2c.7-.8.7-2 0-2.8a2.1 2.1 0 0 0-3-.2z" />
          <path d="M12 15l-3-3a22 22 0 0 1 2-3.95A12.9 12.9 0 0 1 22 2c0 2.7-.7 7.2-4 11a22 22 0 0 1-4 3z" />
          <path d="M9 12H4s.5-1 1.5-2.5S8 7 8 7" />
          <path d="M12 15v5s1-.5 2.5-1.5S17 16 17 16" />
        </svg>
      );
    case "orbit":
      return (
        <svg {...p}>
          <circle cx="12" cy="12" r="3" />
          <path d="M12 3a9 9 0 1 0 9 9" />
          <path d="M19 3v4h-4" />
        </svg>
      );
    case "laptop":
      return (
        <svg {...p}>
          <path d="M4 6.5A2.5 2.5 0 0 1 6.5 4h11A2.5 2.5 0 0 1 20 6.5V15H4z" />
          <path d="M2 18h20" />
          <path d="M8 18a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2" />
        </svg>
      );
    case "layout":
      return (
        <svg {...p}>
          <rect width="18" height="18" x="3" y="3" rx="2" />
          <path d="M3 9h18M9 21V9" />
        </svg>
      );
    case "terminal":
      return (
        <svg {...p}>
          <rect width="18" height="14" x="3" y="5" rx="2" />
          <path d="m7 10 3 2.5L7 15" />
          <path d="M12 15h5" />
        </svg>
      );
  }
}
