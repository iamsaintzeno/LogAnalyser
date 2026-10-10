import { useEffect, useState } from 'react';
import { getNetworkStats, subscribeNetworkStats } from '../../../../src/lib/networkGuard.ts';

export function PrivacyBadge() {
  const [stats, setStats] = useState(getNetworkStats);
  const [online, setOnline] = useState(navigator.onLine);

  useEffect(() => {
    const updateStats = () => setStats(getNetworkStats());
    const updateOnline = () => setOnline(navigator.onLine);
    const unsubscribe = subscribeNetworkStats(updateStats);
    window.addEventListener('online', updateOnline);
    window.addEventListener('offline', updateOnline);
    return () => {
      unsubscribe();
      window.removeEventListener('online', updateOnline);
      window.removeEventListener('offline', updateOnline);
    };
  }, []);

  return (
    <div className="flex flex-wrap items-center gap-2 text-sm">
      {stats.blockedRequests === 0 ? (
        <span className="rounded-full bg-green-100 px-3 py-1 font-medium text-green-800">
          0 external requests - works offline
        </span>
      ) : (
        <span className="rounded-full bg-red-100 px-3 py-1 font-medium text-red-800" role="status">
          External request blocked: {stats.lastBlockedHost}
        </span>
      )}
      <span aria-label={online ? 'Browser is online' : 'Browser is offline'} className="text-slate-600">
        {online ? 'Online' : 'Offline'}
      </span>
    </div>
  );
}
