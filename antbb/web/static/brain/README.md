# /static/brain — „Neuronales Gehirn der Königin" (GPU-Partikelfeld)

Clientseitige Three.js-r158-Ansicht. Reiner Browser-Code, keine Serverlogik, keine Secrets.

## WICHTIG: 4 Dateien müssen 1:1 (verbatim) aus t146u eingesetzt werden
Der vom Nutzer gelieferte verbatim Three.js-Code (generators.js / worker.ts / engine.ts +
Host-Mount) lag in der Eltern-/Hauptchat-Nachricht t146u. Dieser Executor-Subagent konnte
den Haupt-Chat NICHT per ReadTranscript lesen (Regel: „none from the main chat"), und die
Code-Blöcke waren aus dem Launch-Prompt entfernt („[…54834 characters omitted…]").
Deshalb sind folgende vier Dateien aktuell PLATZHALTER und müssen mit dem exakten Code
befüllt werden (jede Konstante, RNG-Aufrufreihenfolge, alle Shader unverändert):

- `generators.js`  ← aus `generators.js` (TS→ES-JS: `import type`/`@`-Alias entfernen, Logik/Konstanten/RNG exakt)
- `worker.js`      ← aus `worker.ts`      (echtes ES-Module-Worker, importiert `./generators.js`)
- `engine.js`      ← aus `engine.ts`      (Main-Thread-Fallback behalten; `import type ParticleFieldSettings` entfällt)
- `mount.js`       ← aus dem Host-Mount-Snippet (container = full-screen, ResizeObserver,
                     IntersectionObserver-Pause, prefers-reduced-motion → setSpeed(min(speed,0.12)))

## Three-Einbindung (bereits vendored, r158, offline-fähig)
`/static/vendor/three/three.module.js` (r158) + `/static/vendor/three/jsm/...`
Importmap (in brain.html gesetzt):
    "three"          -> /static/vendor/three/three.module.js
    "three/addons/"  -> /static/vendor/three/jsm/
Die jsm-Dateien importieren `from 'three'` und relative Pfade; beides wird über die
vendorte Verzeichnisstruktur aufgelöst. Kein CDN nötig.

## Exakte Eingaben (ParticleFieldSettings)
form:     { kind: "attractor", seed: 2033444172 }
settings: { count: 250000, size: 1.95, speed: 0.45, opacity: 0.7,
            bloomStrength: 1.5, bloomRadius: 0.08, bloomThreshold: 0.21,
            colorA: "#25b8ff", colorB: "#b04dff", autorotate: true }

## Determinismus-Prüfung (nach Einsetzen der echten generators.js)
    node tools/brain_determinism_test.mjs
Erwartet: aL.length === 250000*4, keine NaN in tex/aO nach normalize,
motion.tilt ≈ [-0.1425, 2.5467, -0.8594], motion.spin ≈ 0.0598.
