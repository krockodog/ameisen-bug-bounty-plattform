// @ts-nocheck
// Particle Field generation engine.
// Off-main-thread form generation. The engine falls back to main-thread `generate`
// if the worker can't be constructed (see engine.ts).
import { generate } from './generators';

self.onmessage = (e) => {
  const { id, kind, seed, count } = e.data;
  const r = generate(kind, seed, count);
  self.postMessage({ id, ...r }, [r.tex.buffer, r.aL.buffer, r.aU.buffer, r.aO.buffer, r.aR.buffer]);
};
