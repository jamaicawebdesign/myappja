import assert from "node:assert/strict";
import test from "node:test";
import { createScanLimiter } from "./scan-limiter";

const options = { perClientLimit: 2, globalLimit: 3, windowMs: 1000, perClientConcurrency: 1, globalConcurrency: 2, maxClients: 10 };

test("enforces a per-client sliding window and releases capacity after expiry", () => {
  const limiter = createScanLimiter(options);
  const first = limiter.acquire("client-a", 1000);
  assert.equal(first.allowed, true);
  if (!first.allowed) return;
  first.release();
  const second = limiter.acquire("client-a", 1100);
  assert.equal(second.allowed, true);
  if (!second.allowed) return;
  second.release();
  const blocked = limiter.acquire("client-a", 1200);
  assert.equal(blocked.allowed, false);
  if (!blocked.allowed) assert.equal(blocked.retryAfterSeconds, 1);
  const expired = limiter.acquire("client-a", 2101);
  assert.equal(expired.allowed, true);
});

test("enforces global and concurrent scan caps across clients", () => {
  const limiter = createScanLimiter(options);
  const first = limiter.acquire("client-a", 1000);
  assert.equal(first.allowed, true);
  const concurrent = limiter.acquire("client-a", 1000);
  assert.equal(concurrent.allowed, false);
  const secondClient = limiter.acquire("client-b", 1000);
  assert.equal(secondClient.allowed, true);
  assert.equal(limiter.acquire("client-c", 1000).allowed, false);
  if (first.allowed) first.release();
  assert.equal(limiter.acquire("client-c", 1000).allowed, true);
  if (secondClient.allowed) secondClient.release();
  const globalBlocked = limiter.acquire("client-d", 1000);
  assert.equal(globalBlocked.allowed, false);
});