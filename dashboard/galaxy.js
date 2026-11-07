// Marty GALAXY view — a 3D visualization of status.json's projects, in the spirit of
// brain-jarvis V7's knowledge-galaxy viewer, but built for Marty's own status data
// (projects/right-now) instead of a vault-notes graph. Three.js only; no webcam/hand
// tracking, no vault walking — just: central pulsing "now" node, orbiting project
// spheres sized by percent and colored by status, click a node to open its existing
// drilldown panel (reuses app.js's renderDrilldown, not duplicated here).

// Vendored locally (dashboard/vendor/three/) rather than loaded from a CDN - this
// dashboard is explicitly local-network-only by design, and a CDN dependency broke
// silently for Lukas (2026-09-19), most likely blocked by an ad-blocker/security tool.
import * as THREE from "/vendor/three/three.module.js";
import { OrbitControls } from "/vendor/three/OrbitControls.js";

const STATUS_COLOR = {
  green: 0x0ca30c,
  yellow: 0xfab219,
  red: 0xd03b3b,
};
const DEFAULT_COLOR = 0x898781;
const SUN_COLOR = 0x3987e5;

let scene, camera, renderer, controls, raycaster, mouse;
let sunMesh, sunGlow;
let clock;
let container, tooltipEl;
let onNodeClick = null;               // set by init(); called with the project object

// name -> { mesh, orbitLine, orbitRadius, orbitSpeed, orbitPhase, project }
const nodes = new Map();

function statusColor(status) {
  return STATUS_COLOR[(status || "").toLowerCase()] ?? DEFAULT_COLOR;
}

function makeOrbitRing(radius) {
  const points = [];
  const SEGMENTS = 96;
  for (let i = 0; i <= SEGMENTS; i++) {
    const a = (i / SEGMENTS) * Math.PI * 2;
    points.push(new THREE.Vector3(Math.cos(a) * radius, 0, Math.sin(a) * radius));
  }
  const geo = new THREE.BufferGeometry().setFromPoints(points);
  const mat = new THREE.LineBasicMaterial({ color: 0x2c2c2a, transparent: true, opacity: 0.6 });
  return new THREE.Line(geo, mat);
}

function nodeRadius(percent) {
  const pct = Math.max(0, Math.min(100, Number(percent) || 0));
  return 0.35 + (pct / 100) * 0.55;      // 0.35 .. 0.9
}

// A billboarded text label (canvas texture on a Sprite) - always faces the camera,
// no extra library needed beyond the Three.js already vendored locally.
function makeLabelSprite(text, colorCss) {
  const canvas = document.createElement("canvas");
  const ctx = canvas.getContext("2d");
  const fontPx = 42;
  ctx.font = `600 ${fontPx}px system-ui, -apple-system, sans-serif`;
  const textWidth = ctx.measureText(text).width;
  canvas.width = Math.ceil(textWidth) + 32;
  canvas.height = fontPx + 24;
  ctx.font = `600 ${fontPx}px system-ui, -apple-system, sans-serif`;
  ctx.textBaseline = "middle";
  ctx.fillStyle = "rgba(13, 13, 13, 0.55)";
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = colorCss || "#ffffff";
  ctx.fillText(text, 16, canvas.height / 2);

  const texture = new THREE.CanvasTexture(canvas);
  texture.minFilter = THREE.LinearFilter;
  const material = new THREE.SpriteMaterial({ map: texture, transparent: true, depthWrite: false });
  const sprite = new THREE.Sprite(material);
  const aspect = canvas.width / canvas.height;
  const height = 0.5;
  sprite.scale.set(height * aspect, height, 1);
  return sprite;
}

function hexToCss(hex) {
  return "#" + hex.toString(16).padStart(6, "0");
}

function showError(canvasContainer, message) {
  canvasContainer.innerHTML =
    `<div class="galaxy-error">Galaxy view failed to load: ${message}</div>`;
}

export function initGalaxy(canvasContainer, opts = {}) {
  container = canvasContainer;
  onNodeClick = opts.onNodeClick || null;

  if (!window.WebGLRenderingContext) {
    showError(container, "this browser has no WebGL support.");
    return;
  }

  try {
    initScene();
  } catch (err) {
    showError(container, (err && err.message) || String(err));
    console.error("[galaxy] init failed:", err);
  }
}

function initScene() {
  scene = new THREE.Scene();
  scene.background = new THREE.Color(0x0d0d0d);
  scene.fog = new THREE.FogExp2(0x0d0d0d, 0.02);

  const w = container.clientWidth || 800;
  const h = container.clientHeight || 500;
  camera = new THREE.PerspectiveCamera(55, w / h, 0.1, 500);
  camera.position.set(0, 9, 15);

  renderer = new THREE.WebGLRenderer({ antialias: true });
  renderer.setSize(w, h);
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
  container.appendChild(renderer.domElement);

  controls = new OrbitControls(camera, renderer.domElement);
  controls.enableDamping = true;
  controls.dampingFactor = 0.08;
  controls.minDistance = 4;
  controls.maxDistance = 60;

  scene.add(new THREE.AmbientLight(0xffffff, 0.35));
  const pointLight = new THREE.PointLight(0xffffff, 2.2, 100);
  pointLight.position.set(0, 6, 0);
  scene.add(pointLight);

  // starfield backdrop
  const starGeo = new THREE.BufferGeometry();
  const starCount = 800;
  const starPos = new Float32Array(starCount * 3);
  for (let i = 0; i < starCount; i++) {
    const r = 40 + Math.random() * 160;
    const theta = Math.random() * Math.PI * 2;
    const phi = Math.acos(2 * Math.random() - 1);
    starPos[i * 3] = r * Math.sin(phi) * Math.cos(theta);
    starPos[i * 3 + 1] = r * Math.sin(phi) * Math.sin(theta);
    starPos[i * 3 + 2] = r * Math.cos(phi);
  }
  starGeo.setAttribute("position", new THREE.BufferAttribute(starPos, 3));
  const starMat = new THREE.PointsMaterial({ color: 0x898781, size: 0.06, transparent: true, opacity: 0.5 });
  scene.add(new THREE.Points(starGeo, starMat));

  // central "right now" sun
  sunMesh = new THREE.Mesh(
    new THREE.SphereGeometry(0.6, 32, 32),
    new THREE.MeshStandardMaterial({ color: SUN_COLOR, emissive: SUN_COLOR, emissiveIntensity: 0.9 })
  );
  scene.add(sunMesh);
  sunGlow = new THREE.PointLight(SUN_COLOR, 1.5, 12);
  sunMesh.add(sunGlow);
  const sunLabel = makeLabelSprite("RIGHT NOW", hexToCss(SUN_COLOR));
  sunLabel.position.set(0, 1.1, 0);
  sunMesh.add(sunLabel);

  raycaster = new THREE.Raycaster();
  mouse = new THREE.Vector2();
  clock = new THREE.Clock();

  tooltipEl = document.createElement("div");
  tooltipEl.className = "galaxy-tooltip hidden";
  container.appendChild(tooltipEl);

  renderer.domElement.addEventListener("mousemove", onMouseMove);
  renderer.domElement.addEventListener("click", onClick);
  window.addEventListener("resize", onResize);

  animate();
}

function onResize() {
  if (!container || !renderer || !camera) return;
  // container may still be display:none (tab not open, or WebGL init failed
  // silently) - skip a zero-size resize rather than dividing by zero.
  const w = container.clientWidth;
  const h = container.clientHeight;
  if (!w || !h) return;
  camera.aspect = w / h;
  camera.updateProjectionMatrix();
  renderer.setSize(w, h);
}

// Call this when the Galaxy tab becomes visible - it was likely display:none
// at initGalaxy() time (tabs start hidden), so the very first real size read
// has to happen after the container is actually shown, not at init.
export function resizeGalaxy() {
  onResize();
}

function pickAt(clientX, clientY) {
  const rect = renderer.domElement.getBoundingClientRect();
  mouse.x = ((clientX - rect.left) / rect.width) * 2 - 1;
  mouse.y = -((clientY - rect.top) / rect.height) * 2 + 1;
  raycaster.setFromCamera(mouse, camera);
  const meshes = [...nodes.values()].map((n) => n.mesh);
  meshes.push(sunMesh);
  const hits = raycaster.intersectObjects(meshes);
  if (!hits.length) return null;
  if (hits[0].object === sunMesh) return { isSun: true };
  for (const [name, n] of nodes) {
    if (n.mesh === hits[0].object) return { isSun: false, name, node: n };
  }
  return null;
}

function placeTooltip(text, clientX, clientY) {
  tooltipEl.textContent = text;
  const rect = container.getBoundingClientRect();
  tooltipEl.style.left = (clientX - rect.left + 14) + "px";
  tooltipEl.style.top = (clientY - rect.top + 6) + "px";
  tooltipEl.classList.remove("hidden");
}

function onMouseMove(e) {
  const hit = pickAt(e.clientX, e.clientY);
  if (!hit) {
    tooltipEl.classList.add("hidden");
    renderer.domElement.style.cursor = "grab";
    return;
  }
  renderer.domElement.style.cursor = "pointer";
  if (hit.isSun) {
    placeTooltip(sunMesh.userData.tooltip || "Right now", e.clientX, e.clientY);
  } else {
    const p = hit.node.project;
    placeTooltip(`${p.name} — ${p.percent ?? 0}%`, e.clientX, e.clientY);
  }
}

function onClick(e) {
  const hit = pickAt(e.clientX, e.clientY);
  if (hit && !hit.isSun && onNodeClick) onNodeClick(hit.node.project);
}

// Rebuilds the node pool to match `projects` (add/update/remove), keyed by name.
export function updateGalaxy(projects, rightNowText) {
  if (!scene) return;
  sunMesh.userData.tooltip = rightNowText || "";

  const seen = new Set();
  const list = projects || [];
  list.forEach((p, idx) => {
    seen.add(p.name);
    const orbitRadius = 2.6 + idx * 1.15;
    let n = nodes.get(p.name);
    const color = statusColor(p.status);
    const r = nodeRadius(p.percent);

    if (!n) {
      const mesh = new THREE.Mesh(
        new THREE.SphereGeometry(r, 24, 24),
        new THREE.MeshStandardMaterial({ color, emissive: color, emissiveIntensity: 0.25, roughness: 0.5 })
      );
      const label = makeLabelSprite(p.name || "(unnamed)", hexToCss(color));
      label.position.set(0, r + 0.35, 0);
      mesh.add(label);
      const orbitLine = makeOrbitRing(orbitRadius);
      scene.add(mesh);
      scene.add(orbitLine);
      n = {
        mesh, orbitLine, orbitRadius, label,
        orbitSpeed: 0.12 / Math.sqrt(orbitRadius),   // farther orbits move slower
        orbitPhase: Math.random() * Math.PI * 2,
        bobPhase: Math.random() * Math.PI * 2,
        project: p,
      };
      nodes.set(p.name, n);
    } else {
      n.project = p;
      n.mesh.geometry.dispose();
      n.mesh.geometry = new THREE.SphereGeometry(r, 24, 24);
      n.mesh.material.color.setHex(color);
      n.mesh.material.emissive.setHex(color);
      n.label.position.y = r + 0.35;
      if (Math.abs(n.orbitRadius - orbitRadius) > 0.001) {
        scene.remove(n.orbitLine);
        n.orbitLine.geometry.dispose();
        n.orbitLine = makeOrbitRing(orbitRadius);
        scene.add(n.orbitLine);
        n.orbitRadius = orbitRadius;
        n.orbitSpeed = 0.12 / Math.sqrt(orbitRadius);
      }
    }
  });

  // remove nodes for projects no longer present
  for (const [name, n] of [...nodes]) {
    if (!seen.has(name)) {
      scene.remove(n.mesh);
      scene.remove(n.orbitLine);
      n.mesh.geometry.dispose();
      n.mesh.material.dispose();
      n.label.material.map.dispose();
      n.label.material.dispose();
      n.orbitLine.geometry.dispose();
      n.orbitLine.material.dispose();
      nodes.delete(name);
    }
  }
}

function animate() {
  requestAnimationFrame(animate);
  const t = clock.getElapsedTime();

  const pulse = 1 + Math.sin(t * 1.6) * 0.08;
  sunMesh.scale.setScalar(pulse);

  for (const n of nodes.values()) {
    const a = n.orbitPhase + t * n.orbitSpeed;
    const bob = Math.sin(t * 0.8 + n.bobPhase) * 0.25;   // gentle organic drift, not a flat rail
    n.mesh.position.set(Math.cos(a) * n.orbitRadius, bob, Math.sin(a) * n.orbitRadius);
    n.mesh.rotation.y += 0.01;
  }

  controls.update();
  renderer.render(scene, camera);
}
