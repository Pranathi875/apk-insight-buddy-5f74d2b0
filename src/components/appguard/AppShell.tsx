import { Link } from "@tanstack/react-router";
import type { ReactNode } from "react";
import { ShieldCheck } from "lucide-react";

const NAV = [
  { to: "/", label: "Analyze" },
  { to: "/library", label: "Library" },
  { to: "/compare", label: "Compare" },
  { to: "/methodology", label: "Methodology" },
] as const;

export function AppShell({ children }: { children: ReactNode }) {
  return (
    <div className="flex min-h-screen flex-col bg-background text-foreground">
      <header className="sticky top-0 z-40 border-b border-border/70 bg-background/85 backdrop-blur">
        <div className="mx-auto flex h-16 w-full max-w-7xl items-center gap-6 px-5">
          <Link to="/" className="flex items-center gap-2.5">
            <span className="flex size-8 items-center justify-center rounded-md bg-primary/15 text-primary">
              <ShieldCheck className="size-4.5" />
            </span>
            <span className="font-display text-base font-semibold tracking-tight">
              AppGuard
            </span>
            <span className="hidden rounded border border-border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-widest text-muted-foreground sm:inline">
              static analysis
            </span>
          </Link>

          <nav className="ml-auto flex items-center gap-1">
            {NAV.map((item) => (
              <Link
                key={item.to}
                to={item.to}
                className="rounded-md px-3 py-1.5 text-sm text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
                activeProps={{ className: "bg-accent text-foreground" }}
                activeOptions={{ exact: item.to === "/" }}
              >
                {item.label}
              </Link>
            ))}
          </nav>
        </div>
      </header>

      <main className="mx-auto w-full max-w-7xl flex-1 px-5 py-8">{children}</main>

      <footer className="border-t border-border/70 py-6">
        <div className="mx-auto flex w-full max-w-7xl flex-col gap-1 px-5 text-xs text-muted-foreground">
          <p>
            AppGuard performs static inspection only. Scores are analytical indicators derived from
            documented rules — not a security certification.
          </p>
          <p className="font-mono text-[11px]">APK bytes are parsed in your browser and never uploaded.</p>
        </div>
      </footer>
    </div>
  );
}