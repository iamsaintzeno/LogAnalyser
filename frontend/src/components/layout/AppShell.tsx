import type { ReactNode } from 'react';

interface AppShellProps {
  children: ReactNode;
}

export function AppShell({ children }: AppShellProps) {
  return (
    <div className="flex min-h-screen flex-col">
      <header className="border-b border-slate-200">
        <div className="mx-auto flex w-full max-w-7xl flex-wrap items-center justify-between gap-3 px-6 py-4">
          <div>
            <p className="text-lg font-semibold">LogGuard</p>
            <p className="text-sm text-slate-600">Your logs never leave this browser</p>
          </div>
          <span className="rounded-full bg-green-100 px-3 py-1 text-sm font-medium text-green-800">
            <span aria-hidden="true">● </span>Offline-safe
          </span>
        </div>
      </header>

      <main className="mx-auto w-full max-w-7xl flex-1 px-6 py-8">{children}</main>

      <footer className="border-t border-slate-200">
        <div className="mx-auto w-full max-w-7xl px-6 py-4 text-sm text-slate-600">
          0 bytes uploaded
        </div>
      </footer>
    </div>
  );
}
