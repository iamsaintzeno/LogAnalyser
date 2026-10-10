export interface NetworkStats {
  blockedRequests: number;
  allowedRequests: number;
  lastBlockedHost: string | null;
}

interface GuardContext {
  location?: { origin: string };
  fetch?: typeof fetch;
  XMLHttpRequest?: typeof XMLHttpRequest;
  navigator?: { sendBeacon?: Navigator['sendBeacon'] };
  WebSocket?: typeof WebSocket;
  EventSource?: typeof EventSource;
  PerformanceObserver?: typeof PerformanceObserver;
  performance?: Performance;
  console?: Console;
}

const stats: NetworkStats = {
  blockedRequests: 0,
  allowedRequests: 0,
  lastBlockedHost: null,
};
const listeners = new Set<() => void>();
let installed = false;

function isAllowedUrl(input: string | URL, origin: string | undefined): boolean {
  try {
    const url = new URL(String(input), origin);
    if (url.protocol === 'blob:' || url.protocol === 'data:' || url.origin === origin) return true;
    if (origin && (url.protocol === 'ws:' || url.protocol === 'wss:')) {
      const pageOrigin = new URL(origin);
      const expectedProtocol = pageOrigin.protocol === 'https:' ? 'wss:' : 'ws:';
      return url.protocol === expectedProtocol && url.host === pageOrigin.host;
    }
    return false;
  } catch {
    return false;
  }
}

function record(context: GuardContext, input: string | URL): boolean {
  if (isAllowedUrl(input, context.location?.origin)) {
    stats.allowedRequests += 1;
    return true;
  }
  let host = String(input);
  try {
    host = new URL(String(input)).host || new URL(String(input)).protocol;
  } catch {
    // Keep the original input for malformed URLs.
  }
  stats.blockedRequests += 1;
  stats.lastBlockedHost = host;
  context.console?.warn(`Blocked non-local network request: ${host}`);
  for (const listener of listeners) listener();
  return false;
}

export function installNetworkGuard(): void {
  if (installed) return;
  installed = true;
  const context = globalThis as unknown as GuardContext;

  if (context.fetch) {
    const originalFetch = context.fetch.bind(globalThis);
    context.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
      const target = input instanceof Request ? input.url : input;
      if (!record(context, target)) return Promise.reject(new TypeError('External network requests are blocked'));
      return originalFetch(input, init);
    }) as typeof fetch;
  }

  if (context.XMLHttpRequest) {
    const originalOpen = context.XMLHttpRequest.prototype.open;
    context.XMLHttpRequest.prototype.open = function (
      this: XMLHttpRequest,
      method: string,
      url: string | URL,
      ...rest: [async?: boolean, username?: string | null, password?: string | null]
    ) {
      if (!record(context, url)) throw new DOMException('External network requests are blocked', 'SecurityError');
      return Reflect.apply(originalOpen, this, [method, url, ...rest]) as void;
    };
  }

  if (context.navigator?.sendBeacon) {
    const originalBeacon = context.navigator.sendBeacon.bind(context.navigator);
    context.navigator.sendBeacon = ((url: string | URL, data?: BodyInit | null) => (
      record(context, url) ? originalBeacon(url, data ?? null) : false
    )) as Navigator['sendBeacon'];
  }

  if (context.WebSocket) {
    const OriginalWebSocket = context.WebSocket;
    context.WebSocket = class extends OriginalWebSocket {
      constructor(url: string | URL, protocols?: string | string[]) {
        if (!record(context, url)) throw new DOMException('External network requests are blocked', 'SecurityError');
        super(url, protocols);
      }
    };
  }

  if (context.EventSource) {
    const OriginalEventSource = context.EventSource;
    context.EventSource = class extends OriginalEventSource {
      constructor(url: string | URL, init?: EventSourceInit) {
        if (!record(context, url)) throw new DOMException('External network requests are blocked', 'SecurityError');
        super(url, init);
      }
    };
  }

  if (context.PerformanceObserver && context.performance) {
    try {
      const observer = new context.PerformanceObserver((list) => {
        for (const entry of list.getEntries()) {
          if (entry.name && !isAllowedUrl(entry.name, context.location?.origin)) {
            record(context, entry.name);
          }
        }
      });
      observer.observe({ type: 'resource', buffered: true });
    } catch (error) {
      context.console?.warn('Could not monitor resource requests', error);
    }
  }
}

export function getNetworkStats(): Readonly<NetworkStats> {
  return { ...stats };
}

export function subscribeNetworkStats(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}
