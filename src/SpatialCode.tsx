import { useEffect, useRef, useState, type CSSProperties } from 'react';
import * as THREE from 'three';
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls.js';
import { FontLoader } from 'three/examples/jsm/loaders/FontLoader.js';
import type { Font } from 'three/examples/jsm/loaders/FontLoader.js';
import { TextGeometry } from 'three/examples/jsm/geometries/TextGeometry.js';
import { tokenizeLine } from './tokens';
import ExpressionOverlay from './ExpressionOverlay';
import type { ExpressionProjector, ExpressionStyle, ScreenRect } from './expression-layout';
import type { ExpressionEvent } from './execution-types';
import { fitPerspectiveDistance, flightDuration, flightPose, smoothPanStep, type CameraPose, type CameraVector } from './camera-motion';
import './spatial.css';

type SyntaxPalette = {
  plain: string;
  keyword: string;
  string: string;
  number: string;
  comment: string;
  preprocessor: string;
  type: string;
  function: string;
  variable: string;
  systemFunction?: string;
  declaration?: string;
};

type SpatialCodeProps = {
  source: string;
  palette: SyntaxPalette;
  theme?: 'dark' | 'light';
  activeLine?: number;
  isPlaying?: boolean;
  executionKey?: number | string;
  followExecution?: boolean;
  depth?: number;
  light?: number;
  wireframe?: boolean;
  highlightBrightness?: number;
  expression?: ExpressionEvent | null;
  expressionStyle?: ExpressionStyle;
  stepDurationMs?: number;
  resetKey?: number;
};

type SceneHandle = {
  group: THREE.Group;
  operandGuides: THREE.Group;
  keyLight: THREE.DirectionalLight;
  reset: () => void;
  invalidate: () => void;
  syncExecution: () => void;
  setHighlightBrightness: (value: number) => void;
  updateExpression: (event: ExpressionEvent | null) => void;
};

function textWidth(text: string, font: Font, size: number) {
  return Array.from(text).reduce((width, char) => {
    const glyph = font.data.glyphs[char] || font.data.glyphs['?'];
    return width + (glyph?.ha || font.data.resolution * 0.6) * size / font.data.resolution;
  }, 0);
}

function paletteColor(value: string) {
  const cssColor = value.match(/^rgb\(\s*([\d.]+)%\s+([\d.]+)%\s+([\d.]+)%(?:\s*\/\s*([\d.]+))?\s*\)$/);
  if (!cssColor) return { color: new THREE.Color(value), opacity: 1 };
  return {
    color: new THREE.Color().setRGB(Number(cssColor[1]) / 100, Number(cssColor[2]) / 100, Number(cssColor[3]) / 100, THREE.SRGBColorSpace),
    opacity: cssColor[4] ? Number(cssColor[4]) : 1,
  };
}

export default function SpatialCode({
  source, palette, theme = 'dark', activeLine = 0, isPlaying = false,
  executionKey = activeLine, followExecution = true, depth = 0.56, light = 3.4,
  wireframe = false, highlightBrightness = 1, resetKey = 0, expression, expressionStyle = 'float', stepDurationMs = 1250,
}: SpatialCodeProps) {
  const viewportRef = useRef<HTMLDivElement>(null);
  const sceneRef = useRef<SceneHandle | null>(null);
  const projectorRef = useRef<ExpressionProjector | null>(null);
  const [ready, setReady] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [cameraMode, setCameraMode] = useState<'follow' | 'manual' | 'free' | 'overview'>('overview');
  const executionRef = useRef({ activeLine, isPlaying, executionKey, followExecution });
  executionRef.current = { activeLine, isPlaying, executionKey, followExecution };
  const settingsRef = useRef({ depth, light, wireframe, highlightBrightness });
  const previousResetKey = useRef(resetKey);
  const expressionContext = useRef<{ source: string; active: boolean; blockedId: string | null }>({ source, active: activeLine > 0, blockedId: null });
  if (expressionContext.current.source !== source || (expressionContext.current.active && activeLine <= 0)) {
    expressionContext.current = { source, active: activeLine > 0, blockedId: expression?.id ?? null };
  }
  expressionContext.current.active = activeLine > 0;
  if (!expression || (expressionContext.current.blockedId && expression.id !== expressionContext.current.blockedId)) {
    expressionContext.current.blockedId = null;
  }
  const visibleExpression = expression && activeLine > 0 && expression.line === activeLine && expression.id !== expressionContext.current.blockedId ? expression : null;
  const visibleExpressionRef = useRef(visibleExpression);
  visibleExpressionRef.current = visibleExpression;
  const guideSignature = JSON.stringify([visibleExpression?.line, visibleExpression?.operandRanges]);
  settingsRef.current = { depth, light, wireframe, highlightBrightness };
  const paletteSignature = Object.values(palette).join('|');

  useEffect(() => {
    const host = viewportRef.current;
    if (!host) return;

    let disposed = false;
    let frame = 0;
    let renderDirty = true;
    let renderer: THREE.WebGLRenderer | undefined;
    let controls: OrbitControls | undefined;
    let resizeObserver: ResizeObserver | undefined;
    let cleanupCamera: (() => void) | undefined;
    const geometries = new Set<THREE.BufferGeometry>();
    const materials = new Set<THREE.Material>();
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(37, 1, 0.1, 500);
    const lightTheme = theme === 'light';
    scene.background = new THREE.Color(lightTheme ? '#e6e7eb' : '#08090d');
    setReady(false);
    setError(null);

    const rememberMaterial = <T extends THREE.Material,>(material: T): T => {
      materials.add(material);
      return material;
    };
    const rememberGeometry = <T extends THREE.BufferGeometry,>(geometry: T): T => {
      geometries.add(geometry);
      return geometry;
    };

    const contextLost = (event: Event) => {
      event.preventDefault();
      setError('3D-сцена приостановлена. Переключите вид, чтобы открыть её снова.');
      cancelAnimationFrame(frame);
    };

    try {
      renderer = new THREE.WebGLRenderer({ antialias: true, alpha: false, powerPreference: 'high-performance' });
      renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
      renderer.outputColorSpace = THREE.SRGBColorSpace;
      renderer.toneMapping = THREE.NoToneMapping;
      renderer.shadowMap.enabled = true;
      renderer.shadowMap.type = THREE.VSMShadowMap;
      renderer.shadowMap.autoUpdate = false;
      renderer.shadowMap.needsUpdate = true;
      renderer.domElement.setAttribute('aria-label', 'Трёхмерный код. Стрелки — перемещение, мышь — вращение, прокрутка — масштаб.');
      renderer.domElement.setAttribute('aria-keyshortcuts', 'ArrowUp ArrowDown ArrowLeft ArrowRight');
      renderer.domElement.tabIndex = 0;
      renderer.domElement.addEventListener('webglcontextlost', contextLost);
      host.appendChild(renderer.domElement);

      controls = new OrbitControls(camera, renderer.domElement);
      controls.enableDamping = true;
      controls.dampingFactor = 0.065;
      controls.enablePan = true;
      controls.minPolarAngle = Math.PI * 0.13;
      controls.maxPolarAngle = Math.PI * 0.87;
      controls.maxAzimuthAngle = Math.PI * 0.45;
      controls.minAzimuthAngle = -Math.PI * 0.45;
      controls.rotateSpeed = 0.55;
      controls.zoomSpeed = 0.65;
      controls.addEventListener('change', () => { renderDirty = true; });

      const ambient = new THREE.HemisphereLight(lightTheme ? '#ffffff' : '#becde4', lightTheme ? '#6c687c' : '#191a2b', 1.4);
      scene.add(ambient);
      scene.add(new THREE.AmbientLight('#c3c9df', lightTheme ? 0.75 : 0.8));
      const keyLight = new THREE.DirectionalLight('#fff3e7', settingsRef.current.light);
      keyLight.position.set(-10, 12, 28);
      keyLight.castShadow = true;
      keyLight.shadow.mapSize.set(2048, 2048);
      keyLight.shadow.radius = 4;
      keyLight.shadow.blurSamples = 8;
      keyLight.shadow.normalBias = 0.02;
      keyLight.shadow.bias = -0.0002;
      scene.add(keyLight);
      const edgeLight = new THREE.DirectionalLight('#8299d9', 2.1);
      edgeLight.position.set(25, -5, 8);
      scene.add(edgeLight);

      const fontLoader = new FontLoader();
      fontLoader.load(`${import.meta.env.BASE_URL}fonts/code.typeface.json`, (font) => {
        if (disposed || !renderer || !controls) return;
        try {
          const size = 0.65;
          const lineHeight = 1.18;
          const sourceLines = source.split('\n');
          const lines = sourceLines.map((line) => line.replace(/\t/g, '    '));
          const contentWidth = Math.max(14, ...lines.map((line) => textWidth(line, font, size)));
          const contentHeight = Math.max(7, lines.length * lineHeight);
          const left = -contentWidth / 2;
          const top = contentHeight / 2 - lineHeight;
          const codeGroup = new THREE.Group();
          codeGroup.scale.z = settingsRef.current.depth;
          scene.add(codeGroup);

          const tokenMaterials = new Map<string, [THREE.MeshBasicMaterial, THREE.MeshStandardMaterial]>();
          for (const [type, value] of Object.entries(palette)) {
            const { color, opacity } = paletteColor(value);
            // Unlit front faces + no tone mapping preserve the theme's exact RGB colors.
            const face = rememberMaterial(new THREE.MeshBasicMaterial({
              color, opacity, transparent: opacity < 1, fog: false, wireframe: settingsRef.current.wireframe,
            }));
            const side = rememberMaterial(new THREE.MeshStandardMaterial({
              color: color.clone().multiplyScalar(lightTheme ? 0.65 : 0.42),
              roughness: 0.36, metalness: 0.25, wireframe: settingsRef.current.wireframe,
            }));
            tokenMaterials.set(type, [face, side]);
          }

          const numberMaterial = rememberMaterial(new THREE.MeshBasicMaterial({
            color: lightTheme ? '#7b7b87' : '#555866', transparent: true, opacity: 0.62,
          }));

          lines.forEach((line, index) => {
            const y = top - index * lineHeight;
            const number = `${index + 1}`.padStart(String(lines.length).length, ' ');
            const numberGeometry = rememberGeometry(new TextGeometry(number, {
              font, size: size * 0.75, depth: 0.002, curveSegments: 3,
              bevelEnabled: false,
            }));
            const numberMesh = new THREE.Mesh(numberGeometry, numberMaterial);
            numberMesh.position.set(left - 2.3, y + 0.025, 0);
            scene.add(numberMesh);

            let x = left;
            for (const token of tokenizeLine(line)) {
              if (token.text.trim().length) {
                const geometry = rememberGeometry(new TextGeometry(token.text, {
                  font, size, depth: 1, curveSegments: 5,
                  bevelEnabled: true, bevelThickness: 0.015, bevelSize: 0.007, bevelSegments: 2,
                }));
                const material = tokenMaterials.get(token.type) || tokenMaterials.get('plain')!;
                const mesh = new THREE.Mesh(geometry, material);
                mesh.position.set(x, y, 0);
                mesh.castShadow = true;
                codeGroup.add(mesh);
              }
              x += textWidth(token.text, font, size);
            }
          });

          // A continuous matte surface catches the actual glyph shadows.
          const backdropGeometry = rememberGeometry(new THREE.PlaneGeometry(contentWidth + 50, contentHeight + 40));
          const backdropMaterial = rememberMaterial(new THREE.MeshStandardMaterial({
            color: lightTheme ? '#d6d7de' : '#11131c', roughness: 0.9, metalness: 0.05,
          }));
          const backdrop = new THREE.Mesh(backdropGeometry, backdropMaterial);
          backdrop.position.z = -0.3;
          backdrop.receiveShadow = true;
          scene.add(backdrop);

          const shadowExtent = Math.max(contentWidth, contentHeight) * 0.75 + 5;
          Object.assign(keyLight.shadow.camera, {
            left: -shadowExtent, right: shadowExtent,
            top: shadowExtent, bottom: -shadowExtent, near: 0.1, far: 120,
          });
          keyLight.shadow.camera.updateProjectionMatrix();

          const marker = new THREE.Mesh(
            rememberGeometry(new THREE.PlaneGeometry(contentWidth + 3.6, lineHeight * .92)),
            rememberMaterial(new THREE.MeshBasicMaterial({ color: lightTheme ? '#287d8a' : '#acdedb', transparent: true, opacity: lightTheme ? .07 : .045, depthWrite: false })),
          );
          marker.position.set(-.5, 0, -.26);
          marker.visible = false;
          scene.add(marker);

          const canvas = renderer.domElement;
          let projectionRevision = 0;
          let cachedRevision = -1;
          let projectedGlyphs: ScreenRect[] = [];
          const screenPoint = (x: number, y: number, z = settingsRef.current.depth + .03) => {
            const point = new THREE.Vector3(x, y, z).project(camera);
            return { x: (point.x + 1) * host.clientWidth / 2, y: (1 - point.y) * host.clientHeight / 2 };
          };
          const sourceX = (line: number, column: number) => left + textWidth(sourceLines[line - 1].slice(0, column).replace(/\t/g, '    '), font, size);
          const sourceRect = (line: number, start: number, end: number): ScreenRect => {
            const y = top - (line - 1) * lineHeight;
            const startX = sourceX(line, start);
            const endX = Math.max(startX + .15, sourceX(line, end));
            const points = [0, settingsRef.current.depth + .03].flatMap((z) => [
              screenPoint(startX, y - .18, z), screenPoint(endX, y - .18, z),
              screenPoint(startX, y + size * 1.08, z), screenPoint(endX, y + size * 1.08, z),
            ]);
            return { left: Math.min(...points.map((point) => point.x)), right: Math.max(...points.map((point) => point.x)),
              top: Math.min(...points.map((point) => point.y)), bottom: Math.max(...points.map((point) => point.y)) };
          };
          const lineRect = (line: number) => {
            const raw = sourceLines[line - 1];
            return sourceRect(line, Math.max(0, raw.search(/\S/)), raw.trimEnd().length);
          };
          projectorRef.current = (range, fallbackLine) => {
            if (fallbackLine < 1 || fallbackLine > lines.length) return null;
            const exact = Boolean(range && Number.isInteger(range.start.line) && Number.isInteger(range.end.line)
              && range.start.line >= 1 && range.end.line <= lines.length && range.end.line >= range.start.line
              && Number.isInteger(range.start.column) && Number.isInteger(range.end.column)
              && range.start.column >= 1 && range.start.column <= sourceLines[range.start.line - 1].length + 1
              && range.end.column >= 1 && range.end.column <= sourceLines[range.end.line - 1].length + 1
              && (range.end.line > range.start.line || range.end.column > range.start.column));
            const line = exact ? range!.start.line : fallbackLine;
            const lastLine = exact ? range!.end.line : line;
            const segments: ScreenRect[] = [];
            for (let index = line; index <= lastLine; index++) {
              segments.push(exact ? sourceRect(index, index === line ? range!.start.column - 1 : 0,
                index === lastLine ? range!.end.column - 1 : sourceLines[index - 1].length) : lineRect(index));
            }
            const bounds = {
              left: Math.min(...segments.map((rect) => rect.left)), right: Math.max(...segments.map((rect) => rect.right)),
              top: Math.min(...segments.map((rect) => rect.top)), bottom: Math.max(...segments.map((rect) => rect.bottom)),
            };
            const anchorX = exact ? (sourceX(line, range!.start.column - 1) + sourceX(line, line === lastLine ? range!.end.column - 1 : sourceLines[line - 1].length)) / 2
              : (sourceX(line, 0) + sourceX(line, sourceLines[line - 1].length)) / 2;
            const anchorY = top - (line - 1) * lineHeight + .22;
            const worldAnchor = new THREE.Vector3(anchorX, anchorY, settingsRef.current.depth + .03);
            const inFront = worldAnchor.clone().applyMatrix4(camera.matrixWorldInverse).z < -.1;
            const clip = worldAnchor.project(camera);
            const origin = screenPoint(anchorX, anchorY);
            const axisX = screenPoint(anchorX + 1, anchorY);
            const axisY = screenPoint(anchorX, anchorY - 1);
            const lengthX = Math.hypot(axisX.x - origin.x, axisX.y - origin.y) || 1;
            const lengthY = Math.hypot(axisY.x - origin.x, axisY.y - origin.y) || 1;
            if (cachedRevision !== projectionRevision) {
              projectedGlyphs = sourceLines.flatMap((raw, index) => raw.trim() ? [lineRect(index + 1)] : [])
                .filter((rect) => rect.right >= 0 && rect.left <= host.clientWidth && rect.bottom >= 0 && rect.top <= host.clientHeight);
              cachedRevision = projectionRevision;
            }
            return {
              visible: inFront && clip.z >= -1 && clip.z <= 1 && clip.x >= -1 && clip.x <= 1 && clip.y >= -1 && clip.y <= 1,
              exact, revision: projectionRevision, width: host.clientWidth, height: host.clientHeight,
              bounds, lineBounds: lineRect(line), lineHeight: lengthY * lineHeight,
              tangent: [(axisX.x - origin.x) / lengthX, (axisX.y - origin.y) / lengthX, (axisY.x - origin.x) / lengthY, (axisY.y - origin.y) / lengthY],
              glyphs: projectedGlyphs,
            };
          };
          const operandGuides = new THREE.Group();
          operandGuides.position.z = settingsRef.current.depth + .03;
          scene.add(operandGuides);
          const guideGeometry = rememberGeometry(new THREE.PlaneGeometry(1, 1));
          const guideMaterial = rememberMaterial(new THREE.MeshBasicMaterial({
            color: paletteColor(palette.number).color, transparent: true, opacity: .68, depthWrite: false,
          }));
          const updateExpression = (event: ExpressionEvent | null) => {
            operandGuides.clear();
            for (const range of event?.operandRanges ?? []) {
              // Only backend-provided, single-line ranges identify the actual operands.
              if (range.start.line !== event!.line || range.end.line !== event!.line) continue;
              const rawLine = sourceLines[event!.line - 1];
              const start = range.start.column - 1;
              const end = range.end.column - 1;
              if (rawLine === undefined || !Number.isInteger(start) || !Number.isInteger(end) || start < 0 || end <= start || end > rawLine.length) continue;
              const prefix = rawLine.slice(0, start).replace(/\t/g, '    ');
              const operand = rawLine.slice(start, end).replace(/\t/g, '    ');
              const width = textWidth(operand, font, size);
              const guide = new THREE.Mesh(guideGeometry, guideMaterial);
              guide.scale.set(width, .035, 1);
              guide.position.set(left + textWidth(prefix, font, size) + width / 2, top - (event!.line - 1) * lineHeight - .12, 0);
              operandGuides.add(guide);
            }
            canvas.dataset.operandGuideCount = String(operandGuides.children.length);
            renderDirty = true;
          };
          updateExpression(visibleExpressionRef.current);
          const setHighlightBrightness = (value: number) => {
            const brightness = Number.isFinite(value) ? Math.max(0, Math.min(2, value)) : 1;
            marker.material.opacity = (lightTheme ? .07 : .045) * brightness;
            canvas.dataset.highlightOpacity = String(marker.material.opacity);
            renderDirty = true;
          };
          setHighlightBrightness(settingsRef.current.highlightBrightness);
          const motionPreference = window.matchMedia('(prefers-reduced-motion: reduce)');
          let reducedMotion = motionPreference.matches;
          let baseDistance = 1;
          let initialized = false;
          let eventIndex = 0;
          let orbitHeld = false;
          let manualOverride = false;
          let resumeTimer: ReturnType<typeof setTimeout> | undefined;
          let previousExecution: typeof executionRef.current | undefined;
          let flight: { from: CameraPose; to: CameraPose; started: number; duration: number } | undefined;
          const pressedArrows = new Map<string, boolean>();
          const tapArrows = new Map<string, { until: number; fast: boolean }>();
          let panVelocity: CameraVector = [0, 0, 0];
          let panTime = performance.now();
          const arrowKeys = new Set(['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight']);
          const fitDistance = () => fitPerspectiveDistance(contentWidth + 7, contentHeight + 4.8, camera.aspect, camera.fov) * 1.06;
          const currentPose = (): CameraPose => ({ position: camera.position.toArray() as CameraVector, target: controls!.target.toArray() as CameraVector });
          const poseAtTarget = (target: THREE.Vector3, distance: number, angle: number): CameraPose => ({
            target: target.toArray() as CameraVector,
            position: target.clone().add(new THREE.Vector3(angle, .09, 1).normalize().multiplyScalar(distance)).toArray() as CameraVector,
          });
          const overviewPose = () => poseAtTarget(new THREE.Vector3(-.8, -.25, 0), fitDistance(), -.22);
          const executionPose = (): CameraPose => {
            const execution = executionRef.current;
            if (execution.activeLine < 1 || execution.activeLine > lines.length) return overviewPose();
            const index = execution.activeLine - 1;
            const neighborhood = lines.slice(Math.max(0, index - 3), Math.min(lines.length, index + 4));
            const focusWidth = Math.max(12, ...neighborhood.map((line) => textWidth(line, font, size)));
            const focusHeight = Math.min(contentHeight, lineHeight * 8);
            const distance = fitPerspectiveDistance(focusWidth + 5.2, focusHeight + 2.6, camera.aspect, camera.fov) * 1.07;
            const angle = -.18 + Math.sin(eventIndex * .72) * (execution.isPlaying ? .15 : .095);
            return poseAtTarget(new THREE.Vector3(left + focusWidth / 2, top - index * lineHeight + .25, .12), distance, angle);
          };
          const applyPose = (pose: CameraPose) => {
            camera.position.fromArray(pose.position);
            controls!.target.fromArray(pose.target);
            controls!.update();
            renderDirty = true;
          };
          const updateMode = (mode: typeof cameraMode) => {
            canvas.dataset.followState = mode;
            setCameraMode(mode);
          };
          const followMode = () => executionRef.current.activeLine > 0 ? 'follow' as const : 'overview' as const;
          const flyTo = (destination: CameraPose) => {
            panVelocity = [0, 0, 0];
            tapArrows.clear();
            panTime = performance.now();
            if (reducedMotion) {
              flight = undefined;
              canvas.dataset.cameraMotion = 'still';
              applyPose(destination);
              return;
            }
            const from = currentPose();
            flight = { from, to: destination, started: performance.now(), duration: flightDuration(from, destination) };
            canvas.dataset.cameraMotion = 'flying';
            renderDirty = true;
          };
          const clearResume = () => {
            clearTimeout(resumeTimer);
            resumeTimer = undefined;
            delete canvas.dataset.resumeAt;
          };
          const holding = () => orbitHeld || pressedArrows.size > 0;
          const suspendFollow = () => {
            clearResume();
            flight = undefined;
            canvas.dataset.cameraMotion = 'still';
            manualOverride = true;
            canvas.dataset.interacting = String(holding());
            updateMode(executionRef.current.followExecution ? 'manual' : 'free');
          };
          const scheduleResume = () => {
            clearResume();
            canvas.dataset.interacting = String(holding());
            if (holding() || !executionRef.current.followExecution) return;
            canvas.dataset.resumeAt = String(performance.now() + 2000);
            resumeTimer = setTimeout(() => {
              if (disposed || holding() || !executionRef.current.followExecution) return;
              manualOverride = false;
              clearResume();
              canvas.dataset.resumedAt = String(performance.now());
              updateMode(followMode());
              flyTo(executionPose());
            }, 2000);
          };
          const orbitStart = () => {
            orbitHeld = true;
            canvas.focus({ preventScroll: true });
            suspendFollow();
          };
          const orbitEnd = () => {
            orbitHeld = false;
            scheduleResume();
          };
          const advanceArrowMotion = (now: number) => {
            if (now <= panTime) return;
            // Split at short-tap deadlines so a tap between frames still has the same
            // smooth response. Keyboard repeat never adds displacement or momentum.
            const boundaries = [...tapArrows.values()].map((tap) => tap.until)
              .filter((until) => until > panTime && until < now).sort((a, b) => a - b);
            boundaries.push(now);
            for (const end of boundaries) {
              const middle = (panTime + end) / 2;
              const keys = new Map(pressedArrows);
              for (const [key, tap] of tapArrows) if (tap.until > middle && !keys.has(key)) keys.set(key, tap.fast);
              const direction = new THREE.Vector3();
              for (const key of keys.keys()) {
                if (key === 'ArrowLeft') direction.x -= 1;
                if (key === 'ArrowRight') direction.x += 1;
                if (key === 'ArrowUp') direction.y += 1;
                if (key === 'ArrowDown') direction.y -= 1;
              }
              const speed = camera.position.distanceTo(controls!.target) * .30 * ([...keys.values()].some(Boolean) ? 2.5 : 1);
              const desired = direction.normalize().multiplyScalar(speed).toArray() as CameraVector;
              const motion = smoothPanStep(panVelocity, desired, (end - panTime) / 1000, reducedMotion ? .075 : .16);
              panVelocity = motion.velocity;
              if (!keys.size && Math.hypot(...panVelocity) < .0001) panVelocity = [0, 0, 0];
              const movement = new THREE.Vector3().fromArray(motion.displacement);
              if (movement.lengthSq() > 1e-14) {
                camera.position.add(movement);
                controls!.target.add(movement);
                renderDirty = true;
              }
              panTime = end;
            }
            for (const [key, tap] of tapArrows) if (tap.until <= now) tapArrows.delete(key);
          };
          const keyDown = (event: KeyboardEvent) => {
            if (!arrowKeys.has(event.key) || event.altKey || event.ctrlKey || event.metaKey) return;
            event.preventDefault();
            if (pressedArrows.has(event.key)) {
              pressedArrows.set(event.key, event.shiftKey);
              return;
            }
            const now = performance.now();
            advanceArrowMotion(now);
            tapArrows.set(event.key, { until: now + 80, fast: event.shiftKey });
            pressedArrows.set(event.key, event.shiftKey);
            suspendFollow();
            canvas.dataset.cameraMotion = 'panning';
          };
          const keyUp = (event: KeyboardEvent) => {
            if (!pressedArrows.has(event.key)) return;
            advanceArrowMotion(performance.now());
            pressedArrows.delete(event.key);
            scheduleResume();
          };
          const releaseKeys = () => {
            if (!pressedArrows.size) return;
            advanceArrowMotion(performance.now());
            pressedArrows.clear();
            tapArrows.clear();
            scheduleResume();
          };
          const releaseAll = () => {
            orbitHeld = false;
            pressedArrows.clear();
            tapArrows.clear();
            panVelocity = [0, 0, 0];
            panTime = performance.now();
            if (manualOverride) scheduleResume();
          };
          const syncExecution = () => {
            const next = executionRef.current;
            marker.visible = next.activeLine > 0 && next.activeLine <= lines.length;
            marker.position.y = top - (next.activeLine - 1) * lineHeight + .24;
            canvas.dataset.activeLine = String(next.activeLine);
            renderDirty = true;
            const eventChanged = !previousExecution || next.activeLine !== previousExecution.activeLine || next.executionKey !== previousExecution.executionKey;
            const followChanged = next.followExecution !== previousExecution?.followExecution;
            const playbackChanged = next.isPlaying !== previousExecution?.isPlaying;
            if (eventChanged) eventIndex += 1;
            previousExecution = { ...next };
            if (!next.followExecution) {
              clearResume();
              flight = undefined;
              updateMode('free');
              return;
            }
            if (followChanged) manualOverride = false;
            if (manualOverride || holding()) return;
            if (eventChanged || followChanged || playbackChanged) {
              clearResume();
              updateMode(followMode());
              flyTo(executionPose());
            }
          };
          const reset = () => {
            clearResume();
            manualOverride = false;
            if (holding()) return;
            updateMode(executionRef.current.followExecution ? followMode() : 'free');
            flyTo(executionRef.current.followExecution ? executionPose() : overviewPose());
          };
          const resize = () => {
            if (!renderer || !controls) return;
            const width = Math.max(1, host.clientWidth);
            const height = Math.max(1, host.clientHeight);
            camera.aspect = width / height;
            camera.far = Math.max(500, contentHeight * 5);
            camera.updateProjectionMatrix();
            renderer.setSize(width, height, false);
            const nextDistance = fitDistance();
            if (initialized) {
              if (executionRef.current.followExecution && !manualOverride && !holding()) flyTo(executionPose());
              else camera.position.sub(controls.target).multiplyScalar(nextDistance / baseDistance).add(controls.target);
            }
            baseDistance = nextDistance;
            controls.minDistance = 3;
            controls.maxDistance = baseDistance * 2.6;
            renderDirty = true;
          };
          const motionPreferenceChanged = (event: MediaQueryListEvent) => {
            reducedMotion = event.matches;
            if (reducedMotion && flight) {
              applyPose(flight.to);
              flight = undefined;
            }
          };
          controls.addEventListener('start', orbitStart);
          controls.addEventListener('end', orbitEnd);
          canvas.addEventListener('keydown', keyDown);
          canvas.addEventListener('blur', releaseKeys);
          window.addEventListener('keyup', keyUp);
          window.addEventListener('blur', releaseAll);
          motionPreference.addEventListener('change', motionPreferenceChanged);
          cleanupCamera = () => {
            clearResume();
            controls?.removeEventListener('start', orbitStart);
            controls?.removeEventListener('end', orbitEnd);
            canvas.removeEventListener('keydown', keyDown);
            canvas.removeEventListener('blur', releaseKeys);
            window.removeEventListener('keyup', keyUp);
            window.removeEventListener('blur', releaseAll);
            motionPreference.removeEventListener('change', motionPreferenceChanged);
          };
          resize();
          applyPose(overviewPose());
          initialized = true;
          resizeObserver = new ResizeObserver(resize);
          resizeObserver.observe(host);
          sceneRef.current = {
            group: codeGroup, operandGuides, keyLight, reset, syncExecution, setHighlightBrightness, updateExpression,
            invalidate: () => {
              renderDirty = true;
              if (renderer) renderer.shadowMap.needsUpdate = true;
            },
          };
          syncExecution();

          const animate = (now: number) => {
            if (disposed || !renderer || !controls) return;
            advanceArrowMotion(now);
            if (flight) {
              applyPose(flightPose(flight.from, flight.to, now - flight.started, flight.duration));
              if (now - flight.started >= flight.duration) flight = undefined;
            }
            controls.update();
            canvas.dataset.cameraTarget = controls.target.toArray().map((value) => value.toFixed(4)).join(',');
            canvas.dataset.cameraPosition = camera.position.toArray().map((value) => value.toFixed(4)).join(',');
            canvas.dataset.panVelocity = panVelocity.map((value) => value.toFixed(6)).join(',');
            canvas.dataset.cameraMotion = flight ? 'flying' : pressedArrows.size || tapArrows.size || Math.hypot(...panVelocity) > .0001 ? 'panning' : 'still';
            if (renderDirty) {
              projectionRevision += 1;
              renderer.render(scene, camera);
              renderDirty = false;
            }
            frame = requestAnimationFrame(animate);
          };
          frame = requestAnimationFrame(animate);
          setReady(true);
        } catch {
          setError('Не удалось открыть 3D. Ниже показан исходный код.');
        }
      }, undefined, () => {
        if (!disposed) setError('Не удалось загрузить шрифт для 3D. Ниже показан исходный код.');
      });
    } catch {
      setError('3D недоступен в этом браузере. Ниже показан исходный код.');
    }

    return () => {
      disposed = true;
      cancelAnimationFrame(frame);
      cleanupCamera?.();
      resizeObserver?.disconnect();
      controls?.dispose();
      sceneRef.current = null;
      projectorRef.current = null;
      for (const geometry of geometries) geometry.dispose();
      for (const material of materials) material.dispose();
      scene.clear();
      if (renderer) {
        renderer.domElement.removeEventListener('webglcontextlost', contextLost);
        renderer.dispose();
        renderer.domElement.remove();
      }
    };
    // Palette entries are represented by their stable value signature.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [source, paletteSignature, theme]);

  useEffect(() => {
    const scene = sceneRef.current;
    if (!scene) return;
    scene.group.scale.z = depth;
    scene.operandGuides.position.z = depth + .03;
    scene.keyLight.intensity = light;
    scene.group.traverse((object) => {
      if (!(object instanceof THREE.Mesh)) return;
      const materials = Array.isArray(object.material) ? object.material : [object.material];
      for (const material of materials) {
        if (material instanceof THREE.MeshBasicMaterial || material instanceof THREE.MeshStandardMaterial) {
          material.wireframe = wireframe;
        }
      }
    });
    scene.invalidate();
  }, [depth, light, wireframe, ready]);

  useEffect(() => {
    sceneRef.current?.setHighlightBrightness(highlightBrightness);
  }, [highlightBrightness, ready]);

  useEffect(() => {
    sceneRef.current?.updateExpression(visibleExpressionRef.current);
  }, [guideSignature, ready]);

  useEffect(() => {
    sceneRef.current?.syncExecution();
  }, [activeLine, isPlaying, executionKey, followExecution, ready]);

  useEffect(() => {
    if (!ready || previousResetKey.current === resetKey) return;
    previousResetKey.current = resetKey;
    sceneRef.current?.reset();
  }, [resetKey, ready]);

  return (
    <div className={`spatial-code ${theme === 'light' ? 'spatial-code--light' : ''}`} data-ready={ready && !error}
      style={{ '--expression-number': palette.number, '--expression-result': palette.variable } as CSSProperties}>
      <div className="spatial-code__viewport" ref={viewportRef} aria-hidden={Boolean(error)} />
      <div className="spatial-code__vignette" aria-hidden="true" />
      {ready && !error && <ExpressionOverlay event={visibleExpression} isPlaying={isPlaying} stepDurationMs={stepDurationMs} style={expressionStyle} projectorRef={projectorRef} />}
      {!ready && !error && <div className="spatial-code__loading" role="status">Загружаем 3D<span>· · ·</span></div>}
      {error && (
        <div className="spatial-code__fallback">
          <p role="status">{error}</p>
          <pre>{source}</pre>
        </div>
      )}
      {ready && !error && cameraMode !== 'overview' && (
        <div className="spatial-code__camera-status">
          <span role="status" aria-live={isPlaying ? 'off' : 'polite'}>{cameraMode === 'manual' ? 'Ручная · возврат через 2 с' : cameraMode === 'follow' ? `Слежение · строка ${activeLine}` : 'Свободная камера'}</span>
        </div>
      )}
    </div>
  );
}
