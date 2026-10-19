type LimiterOptions = {
  perClientLimit: number;
  globalLimit: number;
  windowMs: number;
  perClientConcurrency: number;
  globalConcurrency: number;
  maxClients: number;
};
type Acquisition = { allowed: true; remaining: number; release: () => void } | { allowed: false; retryAfterSeconds: number };

export function createScanLimiter(options: LimiterOptions) {
  const clientRequests = new Map<string, number[]>();
  const activeByClient = new Map<string, number>();
  const globalRequests: number[] = [];
  let activeGlobal = 0;

  function trim(now: number) {
    const cutoff = now - options.windowMs;
    while (globalRequests.length && globalRequests[0] <= cutoff) globalRequests.shift();
    for (const [client, requests] of clientRequests) {
      while (requests.length && requests[0] <= cutoff) requests.shift();
      if (!requests.length && !activeByClient.has(client)) clientRequests.delete(client);
    }
  }

  return {
    acquire(client: string, now = Date.now()): Acquisition {
      trim(now);
      const requests = clientRequests.get(client) ?? [];
      const clientWait = requests.length >= options.perClientLimit ? Math.ceil((requests[0] + options.windowMs - now) / 1000) : 0;
      const globalWait = globalRequests.length >= options.globalLimit ? Math.ceil((globalRequests[0] + options.windowMs - now) / 1000) : 0;
      const concurrent = activeByClient.get(client) ?? 0;
      const concurrencyLimitReached = concurrent >= options.perClientConcurrency || activeGlobal >= options.globalConcurrency;
      if (clientWait > 0 || globalWait > 0 || concurrencyLimitReached || clientRequests.size >= options.maxClients && !clientRequests.has(client)) {
        return { allowed: false, retryAfterSeconds: Math.max(1, clientWait, globalWait, concurrencyLimitReached ? 2 : 0) };
      }

      requests.push(now);
      globalRequests.push(now);
      clientRequests.set(client, requests);
      activeByClient.set(client, concurrent + 1);
      activeGlobal += 1;
      let released = false;
      return {
        allowed: true,
        remaining: options.perClientLimit - requests.length,
        release() {
          if (released) return;
          released = true;
          const active = activeByClient.get(client) ?? 0;
          if (active <= 1) activeByClient.delete(client);
          else activeByClient.set(client, active - 1);
          activeGlobal = Math.max(0, activeGlobal - 1);
        },
      };
    },
  };
}