// ── src/lib/particle-field/core.ts

// @ts-nocheck
// Particle Field generation engine.
// Do NOT hand-edit beyond the documented adaptations.
// Layout core. A form is a set of curves and surface grids baked into a float texture
// (TEX_W samples per row), plus free points. Each particle stores where it lives on that
// structure and how fast it travels along it; the shader moves it continuously.
//
// Per-particle attributes (vec4 each):
//   aL: row0, rows, closed, mode (0 curve, 1 grid, 2 free)
//   aU: u0, v0 | mix(free), du | drift speed(free), vAmp | drift amp(free)
//   aO: offset xyz (free: absolute position), mix offset
//   aR: size, phase, delay, fade-at-ends flag

export const TEX_W = 256;

const MAX_ROWS = 4000;

export function mulberry32(a) {
  return function () {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// ── Seeded 3D simplex noise ────────────────────────────────────────────────
const GRAD3 = new Float32Array([1,1,0, -1,1,0, 1,-1,0, -1,-1,0, 1,0,1, -1,0,1, 1,0,-1, -1,0,-1, 0,1,1, 0,-1,1, 0,1,-1, 0,-1,-1]);

const F3 = 1 / 3, G3 = 1 / 6;

export function makeNoise(rng) {
  const p = new Uint8Array(256);
  for (let i = 0; i < 256; i++) p[i] = i;
  for (let i = 255; i > 0; i--) { const j = Math.floor(rng() * (i + 1)); const t = p[i]; p[i] = p[j]; p[j] = t; }
  const perm = new Uint8Array(512), pm12 = new Uint8Array(512);
  for (let i = 0; i < 512; i++) { perm[i] = p[i & 255]; pm12[i] = perm[i] % 12; }

  function n3(x, y, z) {
    const s = (x + y + z) * F3;
    const i = Math.floor(x + s), j = Math.floor(y + s), k = Math.floor(z + s);
    const t = (i + j + k) * G3;
    const x0 = x - (i - t), y0 = y - (j - t), z0 = z - (k - t);
    let i1, j1, k1, i2, j2, k2;
    if (x0 >= y0) {
      if (y0 >= z0) { i1 = 1; j1 = 0; k1 = 0; i2 = 1; j2 = 1; k2 = 0; }
      else if (x0 >= z0) { i1 = 1; j1 = 0; k1 = 0; i2 = 1; j2 = 0; k2 = 1; }
      else { i1 = 0; j1 = 0; k1 = 1; i2 = 1; j2 = 0; k2 = 1; }
    } else {
      if (y0 < z0) { i1 = 0; j1 = 0; k1 = 1; i2 = 0; j2 = 1; k2 = 1; }
      else if (x0 < z0) { i1 = 0; j1 = 1; k1 = 0; i2 = 0; j2 = 1; k2 = 1; }
      else { i1 = 0; j1 = 1; k1 = 0; i2 = 1; j2 = 1; k2 = 0; }
    }
    const x1 = x0 - i1 + G3, y1 = y0 - j1 + G3, z1 = z0 - k1 + G3;
    const x2 = x0 - i2 + 2 * G3, y2 = y0 - j2 + 2 * G3, z2 = z0 - k2 + 2 * G3;
    const x3 = x0 - 1 + 3 * G3, y3 = y0 - 1 + 3 * G3, z3 = z0 - 1 + 3 * G3;
    const ii = i & 255, jj = j & 255, kk = k & 255;
    let n = 0, tt, g;
    tt = 0.6 - x0 * x0 - y0 * y0 - z0 * z0;
    if (tt > 0) { g = pm12[ii + perm[jj + perm[kk]]] * 3; tt *= tt; n += tt * tt * (GRAD3[g] * x0 + GRAD3[g + 1] * y0 + GRAD3[g + 2] * z0); }
    tt = 0.6 - x1 * x1 - y1 * y1 - z1 * z1;
    if (tt > 0) { g = pm12[ii + i1 + perm[jj + j1 + perm[kk + k1]]] * 3; tt *= tt; n += tt * tt * (GRAD3[g] * x1 + GRAD3[g + 1] * y1 + GRAD3[g + 2] * z1); }
    tt = 0.6 - x2 * x2 - y2 * y2 - z2 * z2;
    if (tt > 0) { g = pm12[ii + i2 + perm[jj + j2 + perm[kk + k2]]] * 3; tt *= tt; n += tt * tt * (GRAD3[g] * x2 + GRAD3[g + 1] * y2 + GRAD3[g + 2] * z2); }
    tt = 0.6 - x3 * x3 - y3 * y3 - z3 * z3;
    if (tt > 0) { g = pm12[ii + 1 + perm[jj + 1 + perm[kk + 1]]] * 3; tt *= tt; n += tt * tt * (GRAD3[g] * x3 + GRAD3[g + 1] * y3 + GRAD3[g + 2] * z3); }
    return 32 * n;
  }
  function fbm(x, y, z, oct = 3) {
    let a = 0.5, f = 1, s = 0;
    for (let o = 0; o < oct; o++) { s += a * n3(x * f, y * f, z * f); f *= 2.03; a *= 0.5; }
    return s;
  }
  const vec = [0, 0, 0];
  function field(x, y, z) {
    vec[0] = n3(x, y, z);
    vec[1] = n3(y + 31.4, z - 17.1, x + 9.2);
    vec[2] = n3(z + 71.3, x - 3.3, y + 47.7);
    return vec;
  }
  return { n3, fbm, field };
}

// ── Math helpers ───────────────────────────────────────────────────────────
export const TAU = Math.PI * 2;

export const clamp01 = (v) => (v < 0 ? 0 : v > 1 ? 1 : v);

export const lerp = (a, b, t) => a + (b - a) * t;

export const R = (rng, a, b) => a + (b - a) * rng();

export const int = (rng, a, b) => Math.floor(a + (b - a + 1) * rng());

export const sgn = (rng) => (rng() < 0.5 ? -1 : 1);

export const pick = (rng, arr) => arr[Math.floor(rng() * arr.length)];

export function gauss(rng) {
  let u = 0; while (u === 0) u = rng();
  return Math.sqrt(-2 * Math.log(u)) * Math.cos(TAU * rng());
}

export function unitVec(rng, out = [0, 0, 0]) {
  const z = rng() * 2 - 1, a = rng() * TAU, r = Math.sqrt(1 - z * z);
  out[0] = r * Math.cos(a); out[1] = z; out[2] = r * Math.sin(a);
  return out;
}

// Random rotation matrix (row-major 3x3)
export function randRot(rng) {
  const a = rng() * TAU, b = Math.acos(rng() * 2 - 1), c = rng() * TAU;
  const ca = Math.cos(a), sa = Math.sin(a), cb = Math.cos(b), sb = Math.sin(b), cc = Math.cos(c), sc = Math.sin(c);
  return [
    ca * cc - sa * cb * sc, -ca * sc - sa * cb * cc, sa * sb,
    sa * cc + ca * cb * sc, -sa * sc + ca * cb * cc, -ca * sb,
    sb * sc, sb * cc, cb,
  ];
}

export function applyRot(m, o) {
  const x = o[0], y = o[1], z = o[2];
  o[0] = m[0] * x + m[1] * y + m[2] * z;
  o[1] = m[3] * x + m[4] * y + m[5] * z;
  o[2] = m[6] * x + m[7] * y + m[8] * z;
  return o;
}

// ── Layout builder ─────────────────────────────────────────────────────────
// Resamples a row so its samples are evenly spaced along the curve: particles then spread
// evenly and travel at a steady speed however unevenly the source curve was parameterized.
function arcResample(row, closed) {
  const n = TEX_W, segs = closed ? n : n - 1;
  const cum = new Float32Array(segs + 1);
  for (let i = 0; i < segs; i++) {
    const a = i * 4, b = ((i + 1) % n) * 4;
    cum[i + 1] = cum[i] + Math.hypot(row[b] - row[a], row[b + 1] - row[a + 1], row[b + 2] - row[a + 2]);
  }
  const total = cum[segs];
  if (!(total > 1e-6)) return row;
  const out = new Float32Array(n * 4);
  let j = 0;
  for (let k = 0; k < n; k++) {
    const target = (k / (closed ? n : n - 1)) * total;
    while (j < segs - 1 && cum[j + 1] < target) j++;
    const f = cum[j + 1] > cum[j] ? (target - cum[j]) / (cum[j + 1] - cum[j]) : 0;
    const a = j * 4, b = ((j + 1) % n) * 4;
    for (let c = 0; c < 4; c++) out[k * 4 + c] = row[a + c] + (row[b + c] - row[a + c]) * f;
  }
  return out;
}

export function makeLayout(rng, nz) {
  const rows = [];
  const layers = [];
  const tmp = [0, 0, 0, 0.5];

  function rowLength(row, closed) {
    let len = 0;
    for (let i = 4; i < TEX_W * 4; i += 4) len += Math.hypot(row[i] - row[i - 4], row[i + 1] - row[i - 3], row[i + 2] - row[i - 2]);
    if (closed) len += Math.hypot(row[0] - row[TEX_W * 4 - 4], row[1] - row[TEX_W * 4 - 3], row[2] - row[TEX_W * 4 - 2]);
    return Math.max(len, 1e-3);
  }

  const L = {
    rng, nz, rows, layers,
    motion: { spin: 0.08, wobble: 0.03, pulse: 0, tilt: [0, 0, 0] },
    full: () => rows.length >= MAX_ROWS - 64,

    // fn(u, out) writes x,y,z and optional mix into out
    curve(fn, closed = false) {
      const row = new Float32Array(TEX_W * 4);
      const n = closed ? TEX_W : TEX_W - 1;
      for (let i = 0; i < TEX_W; i++) {
        tmp[3] = 0.5;
        fn(i / n, tmp);
        row[i * 4] = tmp[0]; row[i * 4 + 1] = tmp[1]; row[i * 4 + 2] = tmp[2]; row[i * 4 + 3] = tmp[3];
      }
      const even = arcResample(row, closed);
      rows.push(even);
      return { row: rows.length - 1, len: rowLength(even, closed), closed };
    },

    // pts: Float32Array(TEX_W*3), sampled at i/(TEX_W-1) (or i/TEX_W when closed)
    polyline(pts, closed = false, mixFn = null) {
      return L.curve((u, o) => {
        const i = closed ? Math.round(u * TEX_W) % TEX_W : Math.round(u * (TEX_W - 1));
        o[0] = pts[i * 3]; o[1] = pts[i * 3 + 1]; o[2] = pts[i * 3 + 2];
        o[3] = mixFn ? mixFn(u, i) : u;
      }, closed);
    },

    // Curve through a TEX_W polyline, with fn(x, y, z, out) mapping each sample to world space.
    mapped(poly, closed, fn) {
      return L.curve((u, o) => {
        const i = closed ? Math.round(u * TEX_W) % TEX_W : Math.round(u * (TEX_W - 1));
        fn(poly[i * 3], poly[i * 3 + 1], poly[i * 3 + 2], o);
      }, closed);
    },

    // fn(u, v, out) writes position/mix and may return a sampling density 0..1
    grid(fn, nRows, closed = false) {
      const row0 = rows.length;
      const n = closed ? TEX_W : TEX_W - 1;
      const dens = new Float32Array(nRows * TEX_W);
      let hasDens = false;
      for (let j = 0; j < nRows; j++) {
        const v = j / (nRows - 1);
        const row = new Float32Array(TEX_W * 4);
        for (let i = 0; i < TEX_W; i++) {
          tmp[3] = 0.5;
          const d = fn(i / n, v, tmp);
          row[i * 4] = tmp[0]; row[i * 4 + 1] = tmp[1]; row[i * 4 + 2] = tmp[2]; row[i * 4 + 3] = tmp[3];
          if (d !== undefined) { dens[j * TEX_W + i] = d; hasDens = true; } else dens[j * TEX_W + i] = 1;
        }
        rows.push(row);
      }
      if (hasDens) {
        let mx = 0;
        for (let k = 0; k < dens.length; k++) mx = Math.max(mx, dens[k]);
        if (mx > 0) for (let k = 0; k < dens.length; k++) dens[k] /= mx;
      }
      return { row0, rows: nRows, len: rowLength(rows[row0 + (nRows >> 1)], closed), closed, dens: hasDens ? dens : null };
    },

    addCurves(curves, o = {}) { if (curves.length) layers.push({ type: 0, curves, ...o }); },
    addGrid(g, o = {}) { layers.push({ type: 1, grids: Array.isArray(g) ? g : [g], ...o }); },
    addFree(gen, o = {}) { layers.push({ type: 2, gen, ...o }); },
  };
  return L;
}

// ── Particle distribution ──────────────────────────────────────────────────
export function fill(L, N, rng) {
  const H = Math.max(1, L.rows.length);
  const tex = new Float32Array(TEX_W * H * 4);
  L.rows.forEach((r, i) => tex.set(r, i * TEX_W * 4));
  const aL = new Float32Array(N * 4), aU = new Float32Array(N * 4), aO = new Float32Array(N * 4), aR = new Float32Array(N * 4);
  const ambient = new Uint8Array(N); // background layers that should not drive the framing
  const layers = L.layers;
  const total = layers.reduce((s, l) => s + (l.weight ?? 1), 0);
  const tmp = [0, 0, 0, 0.5];
  let idx = 0;

  layers.forEach((ly, li) => {
    const cnt = li === layers.length - 1 ? N - idx : Math.min(N - idx, Math.round((N * (ly.weight ?? 1)) / total));
    const speed = ly.speed ?? 0.2, speedVar = ly.speedVar ?? 0.35, thick = ly.thick ?? 0.01;
    const size = ly.size ?? 1, mixJit = ly.mixJit ?? 0.12, dir = ly.dir ?? 1;
    let cum = null, signs = null;
    if (ly.type === 0) {
      cum = new Float32Array(ly.curves.length);
      let s = 0;
      ly.curves.forEach((c, k) => { s += c.len; cum[k] = s; });
      if (ly.dirPerCurve) signs = ly.curves.map(() => (rng() < 0.5 ? -1 : 1));
    }
    for (let k = 0; k < cnt; k++, idx++) {
      const i = idx, i4 = i * 4;
      if (ly.ambient) ambient[i] = 1;
      const s = rng();
      aR[i4] = size * (0.45 + s * s * s * 1.0);
      aR[i4 + 1] = rng();
      aR[i4 + 2] = rng();
      const sp = speed * (1 + (rng() * 2 - 1) * speedVar) * (dir === 0 ? (rng() < 0.5 ? -1 : 1) : dir);
      const th = thick * Math.abs(gauss(rng)) ;
      const ox = gauss(rng), oy = gauss(rng), oz = gauss(rng);
      const ol = Math.hypot(ox, oy, oz) || 1;

      if (ly.type === 0) {
        const target = rng() * cum[cum.length - 1];
        let lo = 0, hi = cum.length - 1;
        while (lo < hi) { const m = (lo + hi) >> 1; if (cum[m] < target) lo = m + 1; else hi = m; }
        const c = ly.curves[lo];
        const u0 = ly.uDist ? ly.uDist(rng) : rng();
        const dsp = sp * (signs ? signs[lo] : 1);
        aL[i4] = c.row; aL[i4 + 1] = 1; aL[i4 + 2] = c.closed ? 1 : 0; aL[i4 + 3] = 0;
        aU[i4] = u0; aU[i4 + 1] = 0; aU[i4 + 2] = dsp / c.len; aU[i4 + 3] = 0;
        aO[i4] = (ox / ol) * th; aO[i4 + 1] = (oy / ol) * th; aO[i4 + 2] = (oz / ol) * th; aO[i4 + 3] = (rng() - 0.5) * mixJit;
        aR[i4 + 3] = !c.closed && ly.fade !== false && dsp !== 0 ? 1 : 0;
      } else if (ly.type === 1) {
        const g = ly.grids[Math.floor(rng() * ly.grids.length)];
        let u0, v0;
        if (ly.useDens && g.dens) {
          let best = -1;
          for (let t = 0; t < 48; t++) {
            const uu = rng(), vv = rng();
            const d = g.dens[Math.round(vv * (g.rows - 1)) * TEX_W + Math.min(TEX_W - 1, Math.round(uu * (TEX_W - 1)))];
            if (d > best) { best = d; u0 = uu; v0 = vv; }
            if (rng() < d) { u0 = uu; v0 = vv; break; }
          }
        } else {
          u0 = ly.uDist ? ly.uDist(rng) : rng();
          v0 = ly.vDist ? ly.vDist(rng) : rng();
        }
        const du = (ly.duFn ? ly.duFn(u0, v0, sp) : sp) / g.len;
        aL[i4] = g.row0; aL[i4 + 1] = g.rows; aL[i4 + 2] = g.closed ? 1 : 0; aL[i4 + 3] = 1;
        aU[i4] = u0; aU[i4 + 1] = v0; aU[i4 + 2] = du; aU[i4 + 3] = (ly.vAmp ?? 0) * rng();
        aO[i4] = (ox / ol) * th; aO[i4 + 1] = (oy / ol) * th; aO[i4 + 2] = (oz / ol) * th; aO[i4 + 3] = (rng() - 0.5) * mixJit;
        aR[i4 + 3] = !g.closed && ly.fade !== false && du !== 0 ? 1 : 0;
      } else {
        tmp[3] = 0.5;
        ly.gen(rng, tmp);
        aL[i4 + 3] = 2;
        aU[i4] = 0; aU[i4 + 1] = clamp01(tmp[3] + (rng() - 0.5) * mixJit);
        aU[i4 + 2] = (ly.driftSpeed ?? 0.3) * (0.5 + rng());
        aU[i4 + 3] = (ly.driftAmp ?? 0.02) * (0.3 + rng());
        aO[i4] = tmp[0]; aO[i4 + 1] = tmp[1]; aO[i4 + 2] = tmp[2]; aO[i4 + 3] = 0;
        aR[i4 + 3] = 0;
      }
    }
  });
  return { tex, H, aL, aU, aO, aR, ambient };
}

// ── Evaluation (mirrors the vertex shader) ─────────────────────────────────
function rowS(tex, row, u, closed, out, add) {
  let i0, i1, f;
  if (closed) {
    const x = (u - Math.floor(u)) * TEX_W;
    i0 = Math.min(TEX_W - 1, Math.floor(x)); f = x - i0; i1 = (i0 + 1) % TEX_W;
  } else {
    const x = Math.min(Math.max(u, 0), 1) * (TEX_W - 1);
    i0 = Math.floor(x); f = x - i0; i1 = Math.min(i0 + 1, TEX_W - 1);
  }
  const a0 = (row * TEX_W + i0) * 4, a1 = (row * TEX_W + i1) * 4;
  for (let c = 0; c < 4; c++) {
    const v = tex[a0 + c] + (tex[a1 + c] - tex[a0 + c]) * f;
    if (add) out[c] += v * add; else out[c] = v;
  }
}

// out: [x, y, z, mix, alpha]
export function evalParticle(F, i, t, out) {
  const { tex, aL, aU, aO, aR } = F;
  const i4 = i * 4;
  const mode = aL[i4 + 3];
  if (mode > 1.5) {
    const tt = t * aU[i4 + 2], ph = aR[i4 + 1] * TAU, a = aU[i4 + 3];
    out[0] = aO[i4] + Math.sin(tt + ph) * a;
    out[1] = aO[i4 + 1] + Math.sin(tt * 0.83 + ph * 1.7 + 1.3) * a;
    out[2] = aO[i4 + 2] + Math.sin(tt * 0.71 + ph * 2.3 + 2.1) * a;
    out[3] = aU[i4 + 1];
    out[4] = 1;
    return out;
  }
  let u = aU[i4] + aU[i4 + 2] * t;
  u -= Math.floor(u);
  const ss = (e0, e1, x) => { const k = clamp01((x - e0) / (e1 - e0)); return k * k * (3 - 2 * k); };
  out[4] = aR[i4 + 3] > 0.5 ? ss(0, 0.07, u) * (1 - ss(0.9, 1, u)) : 1;
  const closed = aL[i4 + 2] > 0.5;
  if (mode < 0.5) {
    rowS(tex, aL[i4], u, closed, out, 0);
  } else {
    const rowsN = aL[i4 + 1];
    const v = clamp01(aU[i4 + 1] + aU[i4 + 3] * Math.sin(t * 0.5 + aR[i4 + 1] * TAU));
    const y = v * (rowsN - 1), j0 = Math.floor(y), g = y - j0, j1 = Math.min(j0 + 1, rowsN - 1);
    rowS(tex, aL[i4] + j0, u, closed, out, 0);
    for (let c = 0; c < 4; c++) out[c] *= 1 - g;
    rowS(tex, aL[i4] + j1, u, closed, out, g);
  }
  out[0] += aO[i4]; out[1] += aO[i4 + 1]; out[2] += aO[i4 + 2]; out[3] += aO[i4 + 3];
  return out;
}

// ── Post: global deformation + normalization ───────────────────────────────
function forEachPoint(F, cb) {
  const { tex, H, aL, aO } = F;
  for (let i = 0; i < TEX_W * H * 4; i += 4) cb(tex, i);
  const N = aL.length / 4;
  for (let i = 0; i < N; i++) if (aL[i * 4 + 3] > 1.5) cb(aO, i * 4);
}

export function deform(F, rng) {
  const k = R(rng, 0.4, 1.2) * sgn(rng), pinch = rng() < 0.35;
  forEachPoint(F, (a, i) => {
    const x = a[i], y = a[i + 1], z = a[i + 2];
    if (pinch) {
      const f = 1 - 0.3 * Math.exp(-y * y * 3) * Math.abs(k);
      a[i] = x * f; a[i + 2] = z * f;
    } else {
      const an = y * k, c = Math.cos(an), s = Math.sin(an);
      a[i] = x * c - z * s; a[i + 2] = x * s + z * c;
    }
  });
}

// Re-assigns the color blend by a spatial rule so the same structure can read very differently.
export function remix(F, mode, freq) {
  const f = (x, y, z, m) => {
    const r = Math.hypot(x, y, z);
    if (mode === 1) return 1 - m;
    if (mode === 2) return clamp01(r / 1.35);
    if (mode === 3) return clamp01(0.5 + y * 0.42);
    if (mode === 4) return 0.5 + 0.5 * Math.sin(r * freq);
    return m;
  };
  const { tex, H, aL, aU, aO } = F;
  for (let i = 0; i < TEX_W * H * 4; i += 4) tex[i + 3] = f(tex[i], tex[i + 1], tex[i + 2], tex[i + 3]);
  const N = aL.length / 4;
  for (let i = 0; i < N; i++) {
    const i4 = i * 4;
    if (aL[i4 + 3] > 1.5) aU[i4 + 1] = f(aO[i4], aO[i4 + 1], aO[i4 + 2], aU[i4 + 1]);
    else if (mode === 1) aO[i4 + 3] = -aO[i4 + 3];
  }
}

export function normalize(F, target = 1.25) {
  const N = F.aL.length / 4;
  const step = Math.max(1, Math.floor(N / 5000));
  const o = [0, 0, 0, 0, 0];
  const xs = [], ys = [], zs = [];
  for (let i = 0; i < N; i += step) {
    if (F.ambient && F.ambient[i]) continue;
    evalParticle(F, i, 0, o);
    if (Number.isFinite(o[0] + o[1] + o[2])) { xs.push(o[0]); ys.push(o[1]); zs.push(o[2]); }
  }
  const med = (arr) => { const s = [...arr].sort((a, b) => a - b); return (s[Math.floor(s.length * 0.02)] + s[Math.floor(s.length * 0.98)]) / 2; };
  const cx = med(xs), cy = med(ys), cz = med(zs);
  const rad = xs.map((x, k) => Math.hypot(x - cx, ys[k] - cy, zs[k] - cz)).sort((a, b) => a - b);
  const r97 = rad[Math.floor(rad.length * 0.97)] || 1;
  const s = target / r97;
  // Coverage of the silhouette: concentrated forms stack more additive light, so dim them.
  const B = 48, occ = new Uint8Array(B * B);
  for (let k = 0; k < xs.length; k++) {
    const bx = Math.floor(((xs[k] - cx) * s / 1.6 + 1) * 0.5 * B), by = Math.floor(((ys[k] - cy) * s / 1.6 + 1) * 0.5 * B);
    if (bx >= 0 && by >= 0 && bx < B && by < B) occ[by * B + bx] = 1;
  }
  let filled = 0;
  for (let k = 0; k < occ.length; k++) filled += occ[k];
  F.gain = Math.min(1.15, Math.max(0.78, Math.pow(filled / occ.length / 0.3, 0.35)));
  const { tex, H, aL, aU, aO } = F;
  for (let i = 0; i < TEX_W * H * 4; i += 4) {
    tex[i] = (tex[i] - cx) * s; tex[i + 1] = (tex[i + 1] - cy) * s; tex[i + 2] = (tex[i + 2] - cz) * s;
  }
  for (let i = 0; i < N; i++) {
    const i4 = i * 4;
    if (aL[i4 + 3] > 1.5) {
      aO[i4] = (aO[i4] - cx) * s; aO[i4 + 1] = (aO[i4 + 1] - cy) * s; aO[i4 + 2] = (aO[i4 + 2] - cz) * s;
      aU[i4 + 3] *= s;
    } else {
      aO[i4] *= s; aO[i4 + 1] *= s; aO[i4 + 2] *= s;
    }
  }
  // sanitize (attractors can occasionally spit NaN)
  for (let i = 0; i < tex.length; i++) if (!Number.isFinite(tex[i])) tex[i] = 0;
  for (let i = 0; i < aO.length; i++) if (!Number.isFinite(aO[i])) aO[i] = 0;
}

// ── src/lib/particle-field/forms-a.ts

// ── Strange attractors ─────────────────────────────────────────────────────
const SYSTEMS = {
  lorenz: { name: 'Лоренца', dt: 0.004, sub: 2, p0: [0.1, 0, 0], f: (x, y, z, o) => { o[0] = 10 * (y - x); o[1] = x * (28 - z) - y; o[2] = x * y - (8 / 3) * z; } },
  aizawa: { name: 'Айзавы', dt: 0.008, sub: 2, p0: [0.1, 0, 0], f: (x, y, z, o) => { o[0] = (z - 0.7) * x - 3.5 * y; o[1] = 3.5 * x + (z - 0.7) * y; o[2] = 0.6 + 0.95 * z - (z * z * z) / 3 - (x * x + y * y) * (1 + 0.25 * z) + 0.1 * z * x * x * x; } },
  thomas: { name: 'Томаса', dt: 0.05, sub: 2, p0: [0.1, 0, 0], f: (x, y, z, o) => { const b = 0.208186; o[0] = Math.sin(y) - b * x; o[1] = Math.sin(z) - b * y; o[2] = Math.sin(x) - b * z; } },
  halvorsen: { name: 'Хальворсена', dt: 0.004, sub: 2, p0: [-1.48, -1.51, 2.04], f: (x, y, z, o) => { const a = 1.89; o[0] = -a * x - 4 * y - 4 * z - y * y; o[1] = -a * y - 4 * z - 4 * x - z * z; o[2] = -a * z - 4 * x - 4 * y - x * x; } },
  dadras: { name: 'Дадраса', dt: 0.004, sub: 2, p0: [1.1, 2.1, -2], f: (x, y, z, o) => { o[0] = y - 3 * x + 2.7 * y * z; o[1] = 1.7 * y - x * z + z; o[2] = 2 * x * y - 9 * z; } },
  rossler: { name: 'Рёсслера', dt: 0.03, sub: 2, p0: [0.1, 0, 0], f: (x, y, z, o) => { o[0] = -y - z; o[1] = x + 0.2 * y; o[2] = 0.2 + z * (x - 5.7); } },
  fourwing: { name: 'Четырёхкрылый', dt: 0.03, sub: 2, p0: [1.3, -0.18, 0.01], f: (x, y, z, o) => { o[0] = 0.2 * x + y * z; o[1] = 0.01 * x - 0.4 * y - x * z; o[2] = -z - x * y; } },
  chen: { name: 'Чена', dt: 0.002, sub: 2, p0: [-0.1, 0.5, -0.6], f: (x, y, z, o) => { o[0] = 5 * x - y * z; o[1] = -10 * y + x * z; o[2] = -0.38 * z + (x * y) / 3; } },
  sprott: { name: 'Спротта', dt: 0.02, sub: 2, p0: [0.63, 0.47, -0.54], f: (x, y, z, o) => { o[0] = y + 2.07 * x * y + x * z; o[1] = 1 - 1.79 * x * x + y * z; o[2] = x - x * x - y * y; } },
};

export function attractor(L) {
  const { rng } = L;
  const key = pick(rng, Object.keys(SYSTEMS));
  const sys = SYSTEMS[key];
  const chunks = int(rng, 90, 200), half = TEX_W >> 1;
  const total = chunks * half + TEX_W;
  const pts = new Float32Array(total * 3), spd = new Float32Array(total);
  let x = sys.p0[0] + gauss(rng) * 0.01, y = sys.p0[1] + gauss(rng) * 0.01, z = sys.p0[2] + gauss(rng) * 0.01;
  const k1 = [0, 0, 0], k2 = [0, 0, 0], k3 = [0, 0, 0], k4 = [0, 0, 0];
  const h = sys.dt;
  const rk4 = () => {
    sys.f(x, y, z, k1);
    sys.f(x + k1[0] * h / 2, y + k1[1] * h / 2, z + k1[2] * h / 2, k2);
    sys.f(x + k2[0] * h / 2, y + k2[1] * h / 2, z + k2[2] * h / 2, k3);
    sys.f(x + k3[0] * h, y + k3[1] * h, z + k3[2] * h, k4);
    x += (h / 6) * (k1[0] + 2 * k2[0] + 2 * k3[0] + k4[0]);
    y += (h / 6) * (k1[1] + 2 * k2[1] + 2 * k3[1] + k4[1]);
    z += (h / 6) * (k1[2] + 2 * k2[2] + 2 * k3[2] + k4[2]);
    if (!Number.isFinite(x + y + z) || Math.abs(x) + Math.abs(y) + Math.abs(z) > 1e4) { x = sys.p0[0]; y = sys.p0[1]; z = sys.p0[2]; }
  };
  for (let i = 0; i < 3000; i++) rk4();
  let mx = 0, my = 0, mz = 0;
  for (let i = 0; i < total; i++) {
    for (let s = 0; s < sys.sub; s++) rk4();
    pts[i * 3] = x; pts[i * 3 + 1] = y; pts[i * 3 + 2] = z;
    spd[i] = Math.hypot(k1[0], k1[1], k1[2]);
    mx += x; my += y; mz += z;
  }
  mx /= total; my /= total; mz /= total;
  const rad = [];
  for (let i = 0; i < total; i += 7) rad.push(Math.hypot(pts[i * 3] - mx, pts[i * 3 + 1] - my, pts[i * 3 + 2] - mz));
  rad.sort((a, b) => a - b);
  const sc = 1.2 / (rad[Math.floor(rad.length * 0.97)] || 1);
  const sSorted = Array.from(spd).sort((a, b) => a - b), sLo = sSorted[Math.floor(total * 0.05)], sHi = sSorted[Math.floor(total * 0.95)];
  for (let i = 0; i < total; i++) {
    pts[i * 3] = (pts[i * 3] - mx) * sc; pts[i * 3 + 1] = (pts[i * 3 + 1] - my) * sc; pts[i * 3 + 2] = (pts[i * 3 + 2] - mz) * sc;
    spd[i] = clamp01((spd[i] - sLo) / (sHi - sLo + 1e-6));
  }
  const curves = [];
  for (let c = 0; c < chunks; c++) {
    const start = c * half;
    curves.push(L.curve((u, o) => {
      const i = start + Math.round(u * (TEX_W - 1));
      o[0] = pts[i * 3]; o[1] = pts[i * 3 + 1]; o[2] = pts[i * 3 + 2]; o[3] = spd[i];
    }));
  }
  L.addCurves(curves, { weight: 0.8, speed: R(rng, 0.2, 0.4), thick: R(rng, 0.003, 0.01), mixJit: 0.1 });
  L.addFree((r, o) => {
    const i = Math.floor(r() * total), s = 0.02 + Math.abs(gauss(r)) * 0.04;
    o[0] = pts[i * 3] + gauss(r) * s; o[1] = pts[i * 3 + 1] + gauss(r) * s; o[2] = pts[i * 3 + 2] + gauss(r) * s; o[3] = spd[i];
  }, { weight: 0.18, driftAmp: 0.02, size: 0.8 });
  L.motion = { spin: R(rng, 0.05, 0.14), wobble: R(rng, 0.005, 0.02), tilt: [R(rng, -1, 1), R(rng, 0, TAU), R(rng, -1, 1)], label: `Аттрактор ${sys.name}` };
}

// ── src/lib/particle-field/forms-c.ts

// ── Accents: optional extra layers that make a form feel like a scene ──────
export function addAccent(L) {
  const { rng } = L;
  const kind = int(rng, 0, 3);
  if (kind === 0) {
    const n = int(rng, 2, 5), rings = [];
    for (let k = 0; k < n; k++) {
      const m = randRot(rng), rr = R(rng, 1.5, 2.1);
      rings.push(L.curve((u, o) => { const a = u * TAU; o[0] = Math.cos(a) * rr; o[1] = 0; o[2] = Math.sin(a) * rr; applyRot(m, o); o[3] = 1; }, true));
    }
    L.addCurves(rings, { weight: 0.06, speed: 0.35, thick: 0.004, dirPerCurve: true });
  } else if (kind === 1) {
    L.addFree((r, o) => {
      const v = unitVec(r), g = R(r, 1.6, 2.6);
      o[0] = v[0] * g; o[1] = v[1] * g; o[2] = v[2] * g; o[3] = r();
    }, { weight: 0.05, driftAmp: 0.12, driftSpeed: 0.2, size: 0.8 });
  } else if (kind === 2) {
    const sats = [];
    const ns = int(rng, 3, 8);
    for (let k = 0; k < ns; k++) { const v = unitVec(rng), g = R(rng, 1.5, 2); sats.push([v[0] * g, v[1] * g, v[2] * g, R(rng, 0.03, 0.08)]); }
    L.addFree((r, o) => {
      const s = sats[Math.floor(r() * sats.length)], v = unitVec(r), g = Math.abs(gauss(r)) * s[3];
      o[0] = s[0] + v[0] * g; o[1] = s[1] + v[1] * g; o[2] = s[2] + v[2] * g; o[3] = 1;
    }, { weight: 0.04, driftAmp: 0.02, size: 1.1 });
  } else {
    // a ring disc; density depends only on radius so its flow never smears the pattern
    const disc = L.grid((u, v, o) => {
      const a = u * TAU, rr = lerp(1.5, 2.2, v);
      o[0] = Math.cos(a) * rr; o[1] = 0; o[2] = Math.sin(a) * rr; o[3] = v;
      return 0.2 + 0.8 * Math.pow(Math.sin(v * Math.PI * 4), 8);
    }, 32, true);
    L.addGrid(disc, { weight: 0.07, useDens: true, speed: 0.3, thick: 0.005 });
  }
}

// ── src/lib/particle-field/generators.ts

// ARCHETYPES narrowed to the current archetype (entry verbatim).
export const ARCHETYPES = {
  attractor: { fn: attractor, label: 'Attractor', noDeform: true },
};

export function generate(kind, seed, N) {
  const rng = mulberry32(seed);
  const nz = makeNoise(mulberry32(seed * 7 + 13));
  const L = makeLayout(rng, nz);
  const arch = ARCHETYPES[kind];
  arch.fn(L);
  if (!arch.noAccent && rng() < 0.35) addAccent(L);
  const F = fill(L, N, rng);
  if (!arch.noDeform && rng() < 0.28) deform(F, rng);
  normalize(F);
  // Occasional alternative color layouts keep repeat visits of an archetype from looking identical.
  const roll = rng();
  const mode = roll < 0.7 ? 0 : roll < 0.8 ? 1 : roll < 0.87 ? 2 : roll < 0.94 ? 3 : 4;
  if (mode) remix(F, mode, R(rng, 4, 12));
  const grain = R(rng, 0.85, 1.2);
  for (let i = 0; i < F.aR.length; i += 4) F.aR[i] *= grain;
  return { ...F, motion: { label: arch.label, gain: F.gain, ...L.motion } };
}
