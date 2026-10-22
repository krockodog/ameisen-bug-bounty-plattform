// Determinismus-Smoke-Test für das Partikelfeld "attractor".
// Lauf:  node tools/brain_determinism_test.mjs
// Verifiziert die verbatim generators.js (sobald eingesetzt):
//   aL.length === 250000*4, keine NaN in tex/aO nach normalize,
//   motion.tilt ≈ [-0.1425, 2.5467, -0.8594], motion.spin ≈ 0.0598.
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const genPath = path.resolve(here, "../antbb/web/static/brain/generators.js");

const EXPECT = {
  count: 250000,
  tilt: [-0.1425, 2.5467, -0.8594],
  spin: 0.0598,
  tol: 0.01,
};

function fail(msg) { console.error("FAIL:", msg); process.exit(1); }
function approx(a, b, tol) { return Math.abs(a - b) <= tol; }

const mod = await import(genPath);
if (mod.BRAIN_SOURCE_PENDING) {
  console.error("SKIP: generators.js ist noch ein Platzhalter.");
  console.error("Bitte verbatim Code aus t146u einsetzen, dann erneut laufen.");
  process.exit(2);
}
if (typeof mod.generate !== "function") fail("generate() nicht exportiert");

const out = mod.generate("attractor", 2033444172, 250000);
// Die genauen Feldnamen (aL/tex/aO/motion) kommen aus dem verbatim Code.
const aL = out.aL ?? out.positions ?? out.al;
if (!aL || aL.length !== EXPECT.count * 4) fail(`aL.length=${aL && aL.length}, erwartet ${EXPECT.count*4}`);

const hasNaN = (arr) => { for (let i=0;i<arr.length;i++) if (Number.isNaN(arr[i])) return true; return false; };
if (out.tex && hasNaN(out.tex)) fail("NaN in tex nach normalize");
if (out.aO && hasNaN(out.aO)) fail("NaN in aO nach normalize");

const m = out.motion || {};
if (!m.tilt || !approx(m.tilt[0], EXPECT.tilt[0], EXPECT.tol)
   || !approx(m.tilt[1], EXPECT.tilt[1], EXPECT.tol)
   || !approx(m.tilt[2], EXPECT.tilt[2], EXPECT.tol)) {
  fail(`motion.tilt=${JSON.stringify(m.tilt)}, erwartet ~${JSON.stringify(EXPECT.tilt)}`);
}
if (!approx(m.spin, EXPECT.spin, EXPECT.tol)) fail(`motion.spin=${m.spin}, erwartet ~${EXPECT.spin}`);

console.log("OK: count, NaN-frei, tilt≈", m.tilt, "spin≈", m.spin);
process.exit(0);
