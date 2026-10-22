import * as THREE from "three";
import { OrbitControls } from "three/examples/jsm/controls/OrbitControls.js";
import { EffectComposer } from "three/examples/jsm/postprocessing/EffectComposer.js";
import { RenderPass } from "three/examples/jsm/postprocessing/RenderPass.js";
import { UnrealBloomPass } from "three/examples/jsm/postprocessing/UnrealBloomPass.js";
import { ShaderPass } from "three/examples/jsm/postprocessing/ShaderPass.js";
import { OutputPass } from "three/examples/jsm/postprocessing/OutputPass.js";
import { generate, evalParticle, TEX_W } from "./generators";
import type { ParticleFieldSettings } from "@/data/particle-field-presets";

/**
 * The Particle Field render engine — a thin studio wrapper around the
 * generation engine (see `core.ts` / `forms-*.ts` / `generators.ts`).
 *
 * A form is a set of curves + surface grids baked into a float texture; each
 * particle stores where it lives on that structure and how fast it travels along
 * it, and the shader moves it continuously — so the cloud *flows* rather than
 * jitters. `generate(kind, seed, N)` (off-main-thread when a Worker is available)
 * produces the buffers; `showForm` morphs from the current form into the new one.
 *
 * Adapted for our stack: three@0.158 (GLSL1 — the reference's `texelFetch` is
 * replaced with a `texture2D` fetch on a Nearest-filtered float texture, so no
 * three bump is needed); dark-only (no theme invert); colours come from the
 * viewer's pickers rather than a per-form palette.
 */

const DPR_CAP = 2;
const MORPH_TIME = 2.6;

const NOISE_GLSL = /* glsl */ `
vec3 mod289(vec3 x){return x - floor(x*(1.0/289.0))*289.0;}
vec4 mod289(vec4 x){return x - floor(x*(1.0/289.0))*289.0;}
vec4 permute(vec4 x){return mod289(((x*34.0)+10.0)*x);}
vec4 taylorInvSqrt(vec4 r){return 1.79284291400159 - 0.85373472095314*r;}
float snoise(vec3 v){
  const vec2 C = vec2(1.0/6.0, 1.0/3.0);
  const vec4 D = vec4(0.0, 0.5, 1.0, 2.0);
  vec3 i = floor(v + dot(v, C.yyy));
  vec3 x0 = v - i + dot(i, C.xxx);
  vec3 g = step(x0.yzx, x0.xyz);
  vec3 l = 1.0 - g;
  vec3 i1 = min(g.xyz, l.zxy);
  vec3 i2 = max(g.xyz, l.zxy);
  vec3 x1 = x0 - i1 + C.xxx;
  vec3 x2 = x0 - i2 + C.yyy;
  vec3 x3 = x0 - D.yyy;
  i = mod289(i);
  vec4 p = permute(permute(permute(i.z + vec4(0.0, i1.z, i2.z, 1.0)) + i.y + vec4(0.0, i1.y, i2.y, 1.0)) + i.x + vec4(0.0, i1.x, i2.x, 1.0));
  float n_ = 0.142857142857;
  vec3 ns = n_ * D.wyz - D.xzx;
  vec4 j = p - 49.0 * floor(p * ns.z * ns.z);
  vec4 x_ = floor(j * ns.z);
  vec4 y_ = floor(j - 7.0 * x_);
  vec4 x = x_ * ns.x + ns.yyyy;
  vec4 y = y_ * ns.x + ns.yyyy;
  vec4 h = 1.0 - abs(x) - abs(y);
  vec4 b0 = vec4(x.xy, y.xy);
  vec4 b1 = vec4(x.zw, y.zw);
  vec4 s0 = floor(b0)*2.0 + 1.0;
  vec4 s1 = floor(b1)*2.0 + 1.0;
  vec4 sh = -step(h, vec4(0.0));
  vec4 a0 = b0.xzyw + s0.xzyw*sh.xxyy;
  vec4 a1 = b1.xzyw + s1.xzyw*sh.zzww;
  vec3 p0 = vec3(a0.xy, h.x);
  vec3 p1 = vec3(a0.zw, h.y);
  vec3 p2 = vec3(a1.xy, h.z);
  vec3 p3 = vec3(a1.zw, h.w);
  vec4 norm = taylorInvSqrt(vec4(dot(p0,p0), dot(p1,p1), dot(p2,p2), dot(p3,p3)));
  p0 *= norm.x; p1 *= norm.y; p2 *= norm.z; p3 *= norm.w;
  vec4 m = max(0.6 - vec4(dot(x0,x0), dot(x1,x1), dot(x2,x2), dot(x3,x3)), 0.0);
  m = m * m;
  return 42.0 * dot(m*m, vec4(dot(p0,x0), dot(p1,x1), dot(p2,x2), dot(p3,x3)));
}
vec3 snoiseVec(vec3 p){
  return vec3(snoise(p), snoise(p.yzx + vec3(31.4, -17.1, 9.2)), snoise(p.zxy + vec3(71.3, -3.3, 47.7)));
}`;

interface GenData {
  tex: Float32Array;
  H: number;
  aL: Float32Array;
  aU: Float32Array;
  aO: Float32Array;
  aR: Float32Array;
  motion: {
    label: string;
    gain: number;
    spin: number;
    wobble: number;
    pulse: number;
    tilt: [number, number, number];
  };
}

/** Camera distance at rest, and the dolly limits the zoom buttons clamp to. */
const HOME_DISTANCE = 4.8;
const MIN_DISTANCE = 1.8;
const MAX_DISTANCE = 12;
/** Zoom-button dolly rate (1/s) — eases like a critically-damped spring. */
const ZOOM_EASE = 9;

export class ParticleStudio {
  private renderer: THREE.WebGLRenderer;
  private scene: THREE.Scene;
  private camera: THREE.PerspectiveCamera;
  private controls: OrbitControls;
  private composer: EffectComposer;
  private bloom: UnrealBloomPass;
  private finish: ShaderPass;
  private material: THREE.ShaderMaterial;
  private dustMaterial: THREE.ShaderMaterial;
  private geometry: THREE.BufferGeometry;
  private points: THREE.Points;
  private tiltGroup: THREE.Group;
  private spinGroup: THREE.Group;
  private layoutTex: THREE.DataTexture | null = null;

  private settings: ParticleFieldSettings;
  private N = 0;
  private buf: {
    prev: Float32Array;
    prevX: Float32Array;
    aL: Float32Array;
    aU: Float32Array;
    aO: Float32Array;
    aR: Float32Array;
  } | null = null;
  private curForm: GenData | null = null;

  private worker: Worker | null = null;
  private reqId = 0;
  private latestShown = 0;
  private pending = new Map<number, (d: GenData) => void>();

  private time = 0;
  private morphT = 1;
  private morphRunning = false;
  private spin = 0.08;
  private gain = 1;
  private motionFrom = { wobble: 0.04, pulse: 0, gain: 1 };
  private motionTo = { wobble: 0.04, pulse: 0, gain: 1 };
  private qFrom = new THREE.Quaternion();
  private qTo = new THREE.Quaternion();
  private dpr = 1;
  private width = 1;
  private height = 1;
  /** Live state parked while an offline export owns the renderer. */
  private exportSaved: {
    width: number;
    height: number;
    dpr: number;
    time: number;
    morphT: number;
    morphRunning: boolean;
    gain: number;
    spinY: number;
    tilt: THREE.Quaternion;
    camPos: THREE.Vector3;
    camQuat: THREE.Quaternion;
    target: THREE.Vector3;
    uMorph: number;
    uWobble: number;
    uPulse: number;
    uStorm: number;
  } | null = null;

  /** The current form's display label + human name (for the preview caption). */
  label = "";

  constructor(canvas: HTMLCanvasElement, settings: ParticleFieldSettings) {
    this.settings = settings;

    this.renderer = new THREE.WebGLRenderer({
      canvas,
      antialias: false,
      powerPreference: "high-performance",
    });
    this.renderer.setClearColor(0x000000, 1);

    this.scene = new THREE.Scene();
    this.camera = new THREE.PerspectiveCamera(40, 1, 0.05, 100);
    this.camera.position.set(0, 0, HOME_DISTANCE);

    // Drag orbits; the wheel is left to the page (it must scroll down to the
    // footer), so zoom is the stage's +/- buttons → `zoomBy` (2026-10-08).
    this.controls = new OrbitControls(this.camera, canvas);
    this.controls.enableDamping = true;
    this.controls.dampingFactor = 0.06;
    this.controls.enablePan = false;
    this.controls.enableZoom = false;
    this.controls.minDistance = MIN_DISTANCE;
    this.controls.maxDistance = MAX_DISTANCE;
    this.controls.rotateSpeed = 0.7;

    this.tiltGroup = new THREE.Group();
    this.spinGroup = new THREE.Group();
    this.tiltGroup.add(this.spinGroup);
    this.scene.add(this.tiltGroup);

    this.material = new THREE.ShaderMaterial({
      uniforms: {
        uTime: { value: 0 },
        uSize: { value: settings.size },
        uScale: { value: 1 },
        uMorph: { value: 1 },
        uStorm: { value: 1 },
        uColorA: { value: new THREE.Color(settings.colorA) },
        uColorB: { value: new THREE.Color(settings.colorB) },
        uOpacity: { value: settings.opacity },
        uWobble: { value: 0.04 },
        uPulse: { value: 0 },
        uTexW: { value: TEX_W },
        uTexH: { value: 1 },
        uLayout: { value: null },
      },
      vertexShader: /* glsl */ `
        uniform float uTime, uSize, uScale, uMorph, uStorm, uWobble, uPulse, uTexW, uTexH;
        uniform sampler2D uLayout;
        attribute vec2 aPrevX;
        attribute vec4 aL;
        attribute vec4 aU;
        attribute vec4 aO;
        attribute vec4 aR;
        varying float vMix;
        varying float vAlpha;
        ${NOISE_GLSL}

        // Nearest-filtered fetch of texel (x, row) — the three@0.158 GLSL1 stand-in
        // for the reference's texelFetch (needs no WebGL2 shader version bump).
        vec4 tf(float x, float row) { return texture2D(uLayout, vec2((x + 0.5) / uTexW, (row + 0.5) / uTexH)); }
        vec4 rowS(float row, float u, float closed) {
          if (closed > 0.5) {
            float x = fract(u) * uTexW;
            float i0 = min(floor(x), uTexW - 1.0);
            float i1 = mod(i0 + 1.0, uTexW);
            return mix(tf(i0, row), tf(i1, row), x - i0);
          }
          float x = clamp(u, 0.0, 1.0) * (uTexW - 1.0);
          float i0 = floor(x);
          return mix(tf(i0, row), tf(min(i0 + 1.0, uTexW - 1.0), row), x - i0);
        }
        vec4 evalForm(out float alpha) {
          float mode = aL.w;
          if (mode > 1.5) {
            alpha = 1.0;
            float t = uTime * aU.z, ph = aR.y * 6.2831853;
            vec3 d = vec3(sin(t + ph), sin(t * 0.83 + ph * 1.7 + 1.3), sin(t * 0.71 + ph * 2.3 + 2.1)) * aU.w;
            return vec4(aO.xyz + d, aU.y);
          }
          float u = fract(aU.x + aU.z * uTime);
          alpha = aR.w > 0.5 ? smoothstep(0.0, 0.07, u) * (1.0 - smoothstep(0.9, 1.0, u)) : 1.0;
          vec4 s;
          if (mode < 0.5) {
            s = rowS(aL.x, u, aL.z);
          } else {
            float v = clamp(aU.y + aU.w * sin(uTime * 0.5 + aR.y * 6.2831853), 0.0, 1.0);
            float y = v * (aL.y - 1.0);
            float j0 = floor(y);
            float j1 = min(j0 + 1.0, aL.y - 1.0);
            s = mix(rowS(aL.x + j0, u, aL.z), rowS(aL.x + j1, u, aL.z), y - j0);
          }
          return vec4(s.xyz + aO.xyz, s.w + aO.w);
        }

        void main() {
          float m = clamp((uMorph - aR.z * 0.45) / 0.55, 0.0, 1.0);
          m = m * m * (3.0 - 2.0 * m);
          float a1;
          vec4 f = evalForm(a1);
          vec3 p = mix(position, f.xyz, m);
          float storm = sin(m * 3.14159265) * uStorm;

          vec3 n = snoiseVec(p * 0.8 + vec3(0.0, uTime * 0.07, uTime * 0.04));
          p += n * (uWobble + storm * 0.45);
          p *= 1.0 + uPulse * 0.035 * sin(length(p) * 5.0 - uTime * 1.4);

          vec4 mv = modelViewMatrix * vec4(p, 1.0);
          gl_Position = projectionMatrix * mv;

          float px = uSize * aR.x * uScale / -mv.z;
          float fade = 1.0;
          if (px < 2.0) { fade = px * px * 0.25; px = 2.0; }
          gl_PointSize = px;

          vMix = mix(aPrevX.y, f.w, m);
          vAlpha = fade * mix(aPrevX.x, a1, m) * (1.0 + storm * 0.3);
        }
      `,
      fragmentShader: /* glsl */ `
        uniform vec3 uColorA, uColorB;
        uniform float uOpacity;
        varying float vMix;
        varying float vAlpha;
        void main() {
          vec2 c = gl_PointCoord - 0.5;
          float d = length(c);
          if (d > 0.5) discard;
          float a = smoothstep(0.5, 0.0, d);
          a = a * a * (0.6 + 0.4 * a);
          vec3 col = mix(uColorA, uColorB, smoothstep(0.0, 1.0, vMix));
          gl_FragColor = vec4(col, a * vAlpha * uOpacity);
        }
      `,
      transparent: true,
      depthWrite: false,
      depthTest: false,
      blending: THREE.AdditiveBlending,
    });

    this.geometry = new THREE.BufferGeometry();
    this.points = new THREE.Points(this.geometry, this.material);
    this.points.frustumCulled = false;
    this.points.visible = false;
    this.spinGroup.add(this.points);

    // Ambient dust around the specimen.
    this.dustMaterial = new THREE.ShaderMaterial({
      uniforms: {
        uTime: { value: 0 },
        uScale: { value: 1 },
        uColor: { value: new THREE.Color("#9a9ab8") },
        uOpacity: { value: 0.7 },
      },
      vertexShader: /* glsl */ `
        uniform float uTime, uScale;
        attribute float aSeed;
        varying float vA;
        void main() {
          vec3 p = position;
          float t = uTime * 0.03;
          p.x += sin(t + aSeed * 12.0) * 0.3;
          p.y += cos(t * 0.8 + aSeed * 7.0) * 0.3;
          vec4 mv = modelViewMatrix * vec4(p, 1.0);
          gl_Position = projectionMatrix * mv;
          float px = (0.6 + aSeed * 1.4) * uScale / -mv.z;
          vA = clamp(px * px * 0.25, 0.0, 1.0) * (0.35 + 0.5 * aSeed);
          gl_PointSize = max(px, 2.0);
        }
      `,
      fragmentShader: /* glsl */ `
        uniform vec3 uColor;
        uniform float uOpacity;
        varying float vA;
        void main() {
          float d = length(gl_PointCoord - 0.5);
          if (d > 0.5) discard;
          float a = smoothstep(0.5, 0.0, d);
          gl_FragColor = vec4(uColor, a * vA * uOpacity);
        }
      `,
      transparent: true,
      depthWrite: false,
      depthTest: false,
      blending: THREE.AdditiveBlending,
    });
    {
      const DUST = 2600;
      let a = 4242;
      const rng = () => {
        a |= 0;
        a = (a + 0x6d2b79f5) | 0;
        let t = Math.imul(a ^ (a >>> 15), 1 | a);
        t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
      };
      const p = new Float32Array(DUST * 3);
      const s = new Float32Array(DUST);
      for (let i = 0; i < DUST; i++) {
        const z = rng() * 2 - 1;
        const ang = rng() * Math.PI * 2;
        const r = 3 + Math.pow(rng(), 0.6) * 9;
        const q = Math.sqrt(1 - z * z);
        p[i * 3] = Math.cos(ang) * q * r;
        p[i * 3 + 1] = z * r;
        p[i * 3 + 2] = Math.sin(ang) * q * r;
        s[i] = rng();
      }
      const g = new THREE.BufferGeometry();
      g.setAttribute("position", new THREE.BufferAttribute(p, 3));
      g.setAttribute("aSeed", new THREE.BufferAttribute(s, 1));
      const dust = new THREE.Points(g, this.dustMaterial);
      dust.frustumCulled = false;
      this.scene.add(dust);
    }

    this.composer = new EffectComposer(this.renderer);
    this.composer.addPass(new RenderPass(this.scene, this.camera));
    this.bloom = new UnrealBloomPass(
      new THREE.Vector2(1, 1),
      settings.bloomStrength,
      settings.bloomRadius,
      settings.bloomThreshold,
    );
    this.composer.addPass(this.bloom);
    // Soft exposure curve keeps dense regions colourful + adds faint film grain.
    this.finish = new ShaderPass({
      uniforms: {
        tDiffuse: { value: null },
        uExposure: { value: 1.35 },
      },
      vertexShader: `varying vec2 vUv; void main(){ vUv = uv; gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0); }`,
      fragmentShader: /* glsl */ `
        uniform sampler2D tDiffuse;
        uniform float uExposure;
        varying vec2 vUv;
        float hash(vec2 p){ return fract(sin(dot(p, vec2(12.9898, 78.233))) * 43758.5453); }
        void main() {
          vec3 c = texture2D(tDiffuse, vUv).rgb;
          c = 1.0 - exp(-c * uExposure);
          c += (hash(gl_FragCoord.xy) - 0.5) / 255.0;
          gl_FragColor = vec4(c, 1.0);
        }
      `,
    });
    this.composer.addPass(this.finish);
    this.composer.addPass(new OutputPass());

    // Off-main-thread generation, with a main-thread fallback.
    try {
      this.worker = new Worker(new URL("./worker.ts", import.meta.url), {
        type: "module",
      });
      this.worker.onmessage = (e: MessageEvent) => {
        const job = this.pending.get(e.data.id);
        if (job) {
          this.pending.delete(e.data.id);
          job(e.data as GenData);
        }
      };
      this.worker.onerror = (err) => {
        err.preventDefault?.();
        this.worker?.terminate();
        this.worker = null;
      };
    } catch {
      this.worker = null;
    }

    this.allocate(settings.count);
  }

  private allocate(count: number): void {
    this.N = count;
    this.buf = {
      prev: new Float32Array(count * 3),
      prevX: new Float32Array(count * 2),
      aL: new Float32Array(count * 4),
      aU: new Float32Array(count * 4),
      aO: new Float32Array(count * 4),
      aR: new Float32Array(count * 4),
    };
    this.curForm = null;
    this.geometry.dispose();
    const attrs: [string, keyof NonNullable<typeof this.buf>, number][] = [
      ["position", "prev", 3],
      ["aPrevX", "prevX", 2],
      ["aL", "aL", 4],
      ["aU", "aU", 4],
      ["aO", "aO", 4],
      ["aR", "aR", 4],
    ];
    for (const [name, key, size] of attrs) {
      this.geometry.deleteAttribute(name);
      this.geometry.setAttribute(
        name,
        new THREE.BufferAttribute(this.buf[key], size),
      );
    }
    this.geometry.setDrawRange(0, count);
    this.points.visible = false;
  }

  private setLayoutTexture(tex: Float32Array, H: number): void {
    const t = new THREE.DataTexture(
      tex as unknown as BufferSource,
      TEX_W,
      H,
      THREE.RGBAFormat,
      THREE.FloatType,
    );
    t.minFilter = THREE.NearestFilter;
    t.magFilter = THREE.NearestFilter;
    t.generateMipmaps = false;
    t.needsUpdate = true;
    this.layoutTex?.dispose();
    this.layoutTex = t;
    this.material.uniforms.uLayout.value = t;
    this.material.uniforms.uTexH.value = H;
  }

  private ev = [0, 0, 0, 0, 0];
  private smooth01(x: number): number {
    const k = Math.min(1, Math.max(0, x));
    return k * k * (3 - 2 * k);
  }

  // Freeze what's on screen (per-particle morph progress included) into "prev".
  private snapshotCurrent(): void {
    if (!this.curForm || !this.buf) return;
    const { prev, prevX, aR } = this.buf;
    const mt = this.morphT;
    for (let i = 0; i < this.N; i++) {
      evalParticle(this.curForm, i, this.time, this.ev);
      const m = mt >= 1 ? 1 : this.smooth01((mt - aR[i * 4 + 2] * 0.45) / 0.55);
      const i3 = i * 3, i2 = i * 2;
      prev[i3] += (this.ev[0] - prev[i3]) * m;
      prev[i3 + 1] += (this.ev[1] - prev[i3 + 1]) * m;
      prev[i3 + 2] += (this.ev[2] - prev[i3 + 2]) * m;
      prevX[i2] += (this.ev[4] - prevX[i2]) * m;
      prevX[i2 + 1] += (this.ev[3] - prevX[i2 + 1]) * m;
    }
  }

  // Start the new form from a shrunken copy (implode) or a wide cloud (gather).
  private scatterPrev(scale: number): void {
    if (!this.curForm || !this.buf) return;
    let a = 0x1234 ^ (this.reqId * 2654435761);
    const rng = () => {
      a |= 0;
      a = (a + 0x6d2b79f5) | 0;
      let t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
    const { prev, prevX } = this.buf;
    for (let i = 0; i < this.N; i++) {
      evalParticle(this.curForm, i, this.time, this.ev);
      const i3 = i * 3;
      if (scale < 1) {
        prev[i3] = this.ev[0] * scale;
        prev[i3 + 1] = this.ev[1] * scale;
        prev[i3 + 2] = this.ev[2] * scale;
      } else {
        const z = rng() * 2 - 1, ang = rng() * Math.PI * 2, r = scale * (0.6 + rng());
        const q = Math.sqrt(1 - z * z);
        prev[i3] = Math.cos(ang) * q * r;
        prev[i3 + 1] = z * r;
        prev[i3 + 2] = Math.sin(ang) * q * r;
      }
      prevX[i * 2] = 0;
      prevX[i * 2 + 1] = this.ev[3];
    }
  }

  /** Generate + present a form. `mode`: 'morph' | 'implode' | 'gather'. */
  async showForm(
    kind: string,
    seed: number,
    mode: "morph" | "implode" | "gather" = "morph",
  ): Promise<void> {
    if (!this.buf) return;
    const id = ++this.reqId;
    const data = await new Promise<GenData>((resolve) => {
      if (this.worker) {
        this.pending.set(id, resolve);
        this.worker.postMessage({ id, kind, seed, count: this.N });
      } else {
        setTimeout(() => resolve(generate(kind, seed, this.N) as unknown as GenData), 0);
      }
    });
    if (id < this.latestShown) return; // a newer request already landed
    this.latestShown = id;
    if (data.aL.length !== this.N * 4) return; // count changed mid-flight

    if (mode === "morph" && this.curForm) this.snapshotCurrent();
    this.buf.aL.set(data.aL);
    this.buf.aU.set(data.aU);
    this.buf.aO.set(data.aO);
    this.buf.aR.set(data.aR);
    this.curForm = {
      ...data,
      aL: this.buf.aL,
      aU: this.buf.aU,
      aO: this.buf.aO,
      aR: this.buf.aR,
    };
    this.setLayoutTexture(data.tex, data.H);
    if (mode === "implode" || (!this.points.visible && mode === "morph"))
      this.scatterPrev(0.15);
    if (mode === "gather") this.scatterPrev(4);
    for (const name of ["position", "aPrevX", "aL", "aU", "aO", "aR"])
      this.geometry.getAttribute(name).needsUpdate = true;

    this.qFrom.copy(this.tiltGroup.quaternion);
    const tl = data.motion.tilt || [0, 0, 0];
    this.qTo.setFromEuler(new THREE.Euler(tl[0], tl[1], tl[2]));
    this.motionFrom.wobble = this.material.uniforms.uWobble.value;
    this.motionFrom.pulse = this.material.uniforms.uPulse.value;
    this.motionFrom.gain = this.gain;
    this.motionTo.wobble = data.motion.wobble;
    this.motionTo.pulse = data.motion.pulse || 0;
    this.motionTo.gain = data.motion.gain || 1;
    this.spin = data.motion.spin;
    this.label = data.motion.label;
    this.morphT = 0;
    this.morphRunning = true;
    this.points.visible = true;
    this.material.uniforms.uStorm.value = mode === "morph" ? 1 : 0.5;
  }

  // ── Live setters ────────────────────────────────────────────────────
  setCount(count: number): void {
    if (count === this.N) return;
    this.allocate(count);
  }
  setSize(size: number): void {
    this.settings.size = size;
    this.material.uniforms.uSize.value = size;
  }
  setColors(colorA: string, colorB: string): void {
    this.material.uniforms.uColorA.value.set(colorA);
    this.material.uniforms.uColorB.value.set(colorB);
  }
  setBloom(strength: number, radius: number, threshold: number): void {
    this.bloom.strength = strength;
    this.bloom.radius = radius;
    this.bloom.threshold = threshold;
  }
  setOpacity(opacity: number): void {
    this.settings.opacity = opacity;
  }
  setSpeed(speed: number): void {
    this.settings.speed = speed;
  }
  setAutorotate(on: boolean): void {
    this.settings.autorotate = on;
  }

  resetView(): void {
    this.camera.position.set(0, 0, HOME_DISTANCE);
    this.distance = HOME_DISTANCE;
    this.distanceGoal = HOME_DISTANCE;
    this.controls.target.set(0, 0, 0);
    this.controls.update();
  }

  /** Camera distance now, and where the zoom buttons asked it to go — the
   *  render loop eases one into the other (a damped dolly). */
  private distance = HOME_DISTANCE;
  private distanceGoal = HOME_DISTANCE;

  /** Dolly by `factor` (< 1 = closer), clamped to the orbit's limits. */
  zoomBy(factor: number): void {
    this.distanceGoal = THREE.MathUtils.clamp(
      this.distanceGoal * factor,
      MIN_DISTANCE,
      MAX_DISTANCE,
    );
  }

  /** Whether the zoom goal can still move closer / further. */
  zoomRange(): { canIn: boolean; canOut: boolean } {
    return {
      canIn: this.distanceGoal > MIN_DISTANCE + 0.001,
      canOut: this.distanceGoal < MAX_DISTANCE - 0.001,
    };
  }

  /** Ease the camera's distance toward the zoom goal along its current
   *  orbit direction (before `controls.update`, which keeps the radius).
   *  `snap` lands it at once (an export must not dolly mid-render). */
  private stepZoom(dt: number, snap = false): void {
    const gap = this.distanceGoal - this.distance;
    if (gap === 0) return;
    this.distance =
      snap || Math.abs(gap) < 0.0001
        ? this.distanceGoal
        : this.distance + gap * (1 - Math.exp(-dt * ZOOM_EASE));
    const t = this.controls.target;
    this.camera.position.sub(t).setLength(this.distance).add(t);
  }

  resize(width: number, height: number, dpr: number): void {
    if (this.exportSaved) {
      // An export owns the renderer — apply the new live size on `endExport`.
      this.exportSaved.width = width;
      this.exportSaved.height = height;
      this.exportSaved.dpr = dpr;
      return;
    }
    this.applySize(width, height, dpr);
  }

  private applySize(width: number, height: number, dpr: number): void {
    this.dpr = dpr;
    this.width = width;
    this.height = height;
    this.renderer.setPixelRatio(dpr);
    this.renderer.setSize(width, height, false);
    this.composer.setPixelRatio(dpr);
    this.composer.setSize(width, height);
    this.bloom.resolution.set(width, height);
    this.camera.aspect = width / height;
    this.camera.updateProjectionMatrix();
    const scale = dpr * height * 0.0045;
    this.material.uniforms.uScale.value = scale;
    this.dustMaterial.uniforms.uScale.value = scale;
  }

  /** Advance the live loop by `dt` seconds and draw (no-op while exporting). */
  renderFrame(dt: number): void {
    if (this.exportSaved) return;
    this.step(dt);
  }

  private step(dt: number): void {
    const speed = this.settings.speed;
    this.time += dt * speed;
    const u = this.material.uniforms;

    if (this.morphRunning) {
      this.morphT = Math.min(1, this.morphT + dt / MORPH_TIME);
      const e =
        this.morphT < 0.5
          ? 4 * this.morphT ** 3
          : 1 - Math.pow(-2 * this.morphT + 2, 3) / 2;
      u.uMorph.value = this.morphT;
      this.tiltGroup.quaternion.slerpQuaternions(this.qFrom, this.qTo, e);
      u.uWobble.value =
        this.motionFrom.wobble + (this.motionTo.wobble - this.motionFrom.wobble) * e;
      u.uPulse.value =
        this.motionFrom.pulse + (this.motionTo.pulse - this.motionFrom.pulse) * e;
      this.gain = this.motionFrom.gain + (this.motionTo.gain - this.motionFrom.gain) * e;
      if (this.morphT >= 1) this.morphRunning = false;
    }

    this.spinGroup.rotation.y += this.spin * dt * speed;
    this.controls.autoRotate = this.settings.autorotate;
    this.controls.autoRotateSpeed = 0.35 * Math.max(speed, 0.001);
    this.stepZoom(dt);
    this.controls.update();

    u.uTime.value = this.time;
    u.uSize.value = this.settings.size;
    // Keep overall luminance stable regardless of particle count.
    u.uOpacity.value =
      this.gain *
      this.settings.opacity *
      Math.min(2.2, Math.max(0.3, Math.sqrt(160000 / Math.max(1, this.N)))) *
      0.8;
    this.dustMaterial.uniforms.uTime.value = this.time;

    this.composer.render(dt);
  }

  // ── Offline export (video frames / hi-res PNG) ───────────────────────

  /** The live preview's aspect (width / height). */
  get aspect(): number {
    return this.width / Math.max(1, this.height);
  }

  /**
   * Hand the renderer to an offline export at `width×height` (pixel ratio 1).
   * The live loop pauses and its full state (time, morph, spin, tilt, camera)
   * is parked; frames then advance deterministically via {@link exportFrame}.
   * `uScale` follows the frame height, so particles keep their proportions.
   */
  beginExport(width: number, height: number): void {
    if (this.exportSaved) this.endExport();
    this.stepZoom(0, true);
    const u = this.material.uniforms;
    this.exportSaved = {
      width: this.width,
      height: this.height,
      dpr: this.dpr,
      time: this.time,
      morphT: this.morphT,
      morphRunning: this.morphRunning,
      gain: this.gain,
      spinY: this.spinGroup.rotation.y,
      tilt: this.tiltGroup.quaternion.clone(),
      camPos: this.camera.position.clone(),
      camQuat: this.camera.quaternion.clone(),
      target: this.controls.target.clone(),
      uMorph: u.uMorph.value,
      uWobble: u.uWobble.value,
      uPulse: u.uPulse.value,
      uStorm: u.uStorm.value,
    };
    this.applySize(width, height, 1);
  }

  /**
   * Advance the export timeline by `dt` seconds (0 for the first frame), render
   * at the export size and copy the frame into `out` — in the same task, so the
   * drawing buffer is still intact (no `preserveDrawingBuffer` needed).
   */
  exportFrame(out: CanvasRenderingContext2D, dt: number): void {
    if (!this.exportSaved) throw new Error("No export in progress.");
    this.step(dt);
    out.drawImage(this.renderer.domElement, 0, 0, out.canvas.width, out.canvas.height);
  }

  /** Restore the live state + size parked by {@link beginExport}. */
  endExport(): void {
    const s = this.exportSaved;
    if (!s) return;
    this.exportSaved = null;
    const u = this.material.uniforms;
    this.time = s.time;
    this.morphT = s.morphT;
    this.morphRunning = s.morphRunning;
    this.gain = s.gain;
    this.spinGroup.rotation.y = s.spinY;
    this.tiltGroup.quaternion.copy(s.tilt);
    this.camera.position.copy(s.camPos);
    this.camera.quaternion.copy(s.camQuat);
    this.controls.target.copy(s.target);
    u.uMorph.value = s.uMorph;
    u.uWobble.value = s.uWobble;
    u.uPulse.value = s.uPulse;
    u.uStorm.value = s.uStorm;
    this.applySize(s.width, s.height, s.dpr);
    this.step(0);
  }

  /** The canvas the renderer draws into (for video capture). */
  get canvas(): HTMLCanvasElement {
    return this.renderer.domElement;
  }

  dispose(): void {
    this.exportSaved = null;
    this.worker?.terminate();
    this.worker = null;
    this.pending.clear();
    this.controls.dispose();
    this.geometry.dispose();
    this.material.dispose();
    this.dustMaterial.dispose();
    this.layoutTex?.dispose();
    this.composer.dispose();
    this.renderer.dispose();
  }
}
