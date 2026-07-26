import React, { useEffect, useRef, useState, useMemo } from 'react';
import * as THREE from 'three';
import { EffectComposer } from 'three/examples/jsm/postprocessing/EffectComposer.js';
import { RenderPass } from 'three/examples/jsm/postprocessing/RenderPass.js';
import { UnrealBloomPass } from 'three/examples/jsm/postprocessing/UnrealBloomPass.js';
import { OutputPass } from 'three/examples/jsm/postprocessing/OutputPass.js';
import type { Alert, PipelineStage, Severity } from '@/types';
import { STAGE_LABELS } from '@/types';
import { Sparkles, Activity, ShieldAlert, Cpu, CheckCircle } from 'lucide-react';

interface Pipeline3DHeroProps {
  alerts: Alert[];
  connected: boolean;
  onOpenCommand?: () => void;
}

interface StageInfo {
  id: PipelineStage;
  label: string;
  sublabel: string;
  icon: React.ElementType;
  color: string;
  hexColor: number;
}

const STAGES: StageInfo[] = [
  { id: 'ingested', label: 'INGEST', sublabel: 'Telemetry stream', icon: Activity, color: '#2563EB', hexColor: 0x2563EB },
  { id: 'classified', label: 'CLASSIFY', sublabel: 'Threat triage', icon: ShieldAlert, color: '#D97706', hexColor: 0xD97706 },
  { id: 'enriched', label: 'ENRICH', sublabel: 'Context injection', icon: Sparkles, color: '#EA580C', hexColor: 0xEA580C },
  { id: 'reasoned', label: 'REASON', sublabel: 'AI synthesis', icon: Cpu, color: '#DC2626', hexColor: 0xDC2626 },
  { id: 'done', label: 'DONE', sublabel: 'Action dispatched', icon: CheckCircle, color: '#16A34A', hexColor: 0x16A34A },
];

const SEVERITY_HEX: Record<Severity, number> = {
  critical: 0xDC2626,
  high: 0xEA580C,
  medium: 0xD97706,
  low: 0x2563EB,
  info: 0x3B82F6,
};

interface Particle3D {
  mesh: THREE.Mesh;
  light: THREE.PointLight;
  curve: THREE.CatmullRomCurve3;
  t: number;
  speed: number;
  severity: Severity;
}

export function Pipeline3DHero({ alerts, connected, onOpenCommand }: Pipeline3DHeroProps) {
  const mountRef = useRef<HTMLDivElement | null>(null);
  const [nodeScreenPos, setNodeScreenPos] = useState<{ id: PipelineStage; x: number; y: number; count: number }[]>([]);
  const [activeStage, setActiveStage] = useState<PipelineStage>('reasoned');
  const [webglError, setWebglError] = useState<string | null>(null);
  const scrollRef = useRef<number>(0);

  // Compute stage alert metrics
  const stageCounts = useMemo(() => {
    const counts: Record<PipelineStage, number> = {
      ingested: 0,
      classified: 0,
      enriched: 0,
      reasoned: 0,
      done: 0,
      failed: 0,
    };
    alerts.forEach((a) => {
      const st = (a.status || a.stage || 'done') as PipelineStage;
      if (counts[st] !== undefined) counts[st]++;
    });
    return counts;
  }, [alerts]);

  // Track scroll position for scene interaction
  useEffect(() => {
    const handleScroll = () => {
      const scrollY = window.scrollY;
      const heroHeight = mountRef.current?.clientHeight || 600;
      scrollRef.current = Math.min(1, Math.max(0, scrollY / heroHeight));
    };
    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  useEffect(() => {
    const container = mountRef.current;
    if (!container) return;

    let animationFrameId: number;
    let renderer: THREE.WebGLRenderer;
    let scene: THREE.Scene;
    let camera: THREE.PerspectiveCamera;
    let composer: EffectComposer;

    try {
      // 1. Scene setup
      scene = new THREE.Scene();
      scene.background = new THREE.Color(0x0b0e11);
      scene.fog = new THREE.FogExp2(0x0b0e11, 0.022);

      const width = container.clientWidth;
      const height = container.clientHeight;

      // 2. Camera setup
      camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 100);
      camera.position.set(0, 2.5, 13.5);

      // 3. WebGL Renderer
      renderer = new THREE.WebGLRenderer({
        antialias: true,
        powerPreference: 'high-performance',
        alpha: false,
        stencil: false,
      });
      renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
      renderer.setSize(width, height);
      renderer.toneMapping = THREE.ACESFilmicToneMapping;
      renderer.toneMappingExposure = 1.1;
      renderer.shadowMap.enabled = true;
      renderer.shadowMap.type = THREE.PCFSoftShadowMap;

      container.appendChild(renderer.domElement);

      // 4. Lighting - Key light, rim light, ambient
      const keyLight = new THREE.DirectionalLight(0xf8fafc, 3.2);
      keyLight.position.set(-8, 10, 8);
      keyLight.castShadow = true;
      keyLight.shadow.mapSize.width = 1024;
      keyLight.shadow.mapSize.height = 1024;
      keyLight.shadow.bias = -0.0001;
      scene.add(keyLight);

      const rimLight = new THREE.DirectionalLight(0x93c5fd, 1.8);
      rimLight.position.set(2, 5, -10);
      scene.add(rimLight);

      const fillLight = new THREE.DirectionalLight(0x1e293b, 1.0);
      fillLight.position.set(8, -4, 4);
      scene.add(fillLight);

      const ambientLight = new THREE.AmbientLight(0x0f172a, 0.8);
      scene.add(ambientLight);

      // Studio procedural reflection map generator
      const pmremGenerator = new THREE.PMREMGenerator(renderer);
      pmremGenerator.compileEquirectangularShader();
      const envScene = new THREE.Scene();
      envScene.background = new THREE.Color(0x1e293b);
      const envLight1 = new THREE.DirectionalLight(0xffffff, 4);
      envLight1.position.set(1, 1, 1);
      envScene.add(envLight1);
      const envLight2 = new THREE.DirectionalLight(0x38bdf8, 3);
      envLight2.position.set(-1, -1, -1);
      envScene.add(envLight2);
      const envTexture = pmremGenerator.fromScene(envScene).texture;
      scene.environment = envTexture;

      // 5. Physically-Based Glass Material
      const createGlassMaterial = () =>
        new THREE.MeshPhysicalMaterial({
          color: 0xf8fafc,
          transmission: 0.94,
          opacity: 1.0,
          transparent: true,
          roughness: 0.05,
          metalness: 0.05,
          ior: 1.52, // Glass refractive index
          thickness: 1.2,
          clearcoat: 1.0,
          clearcoatRoughness: 0.04,
          reflectivity: 0.9,
          specularColor: new THREE.Color(0xe2e8f0),
          flatShading: true, // Faceted crystalline look
          side: THREE.DoubleSide,
        });

      // 6. Build the 5 Crystalline Nodes
      const nodeGroup = new THREE.Group();
      scene.add(nodeGroup);

      const nodeGeometries = [
        new THREE.IcosahedronGeometry(1.0, 0), // Ingested
        new THREE.OctahedronGeometry(1.15, 0), // Classified
        new THREE.DodecahedronGeometry(1.05, 0), // Enriched
        new THREE.OctahedronGeometry(1.25, 0), // Reasoned
        new THREE.IcosahedronGeometry(1.0, 1), // Done
      ];

      const nodeMeshes: THREE.Mesh[] = [];
      const innerCoreMeshes: THREE.Mesh[] = [];
      const nodePointLights: THREE.PointLight[] = [];
      const baseNodePositions: THREE.Vector3[] = [];

      STAGES.forEach((stage, i) => {
        const xPos = (i - 2) * 2.8; // Center at 0
        const yPos = Math.sin(i * 0.8) * 0.25;
        const zPos = Math.cos(i * 0.8) * 0.3;
        const pos = new THREE.Vector3(xPos, yPos, zPos);
        baseNodePositions.push(pos);

        // Glass Outer Polyhedron
        const glassMat = createGlassMaterial();
        const glassMesh = new THREE.Mesh(nodeGeometries[i], glassMat);
        glassMesh.position.copy(pos);
        glassMesh.castShadow = true;
        glassMesh.receiveShadow = true;
        nodeGroup.add(glassMesh);
        nodeMeshes.push(glassMesh);

        // Inner Glowing Core (Emissive)
        const coreGeo = new THREE.IcosahedronGeometry(0.38, 0);
        const coreMat = new THREE.MeshStandardMaterial({
          color: stage.hexColor,
          emissive: stage.hexColor,
          emissiveIntensity: i === 3 ? 3.5 : 2.2, // Active stage pulses brighter
          roughness: 0.2,
          metalness: 0.1,
          flatShading: true,
        });
        const coreMesh = new THREE.Mesh(coreGeo, coreMat);
        glassMesh.add(coreMesh); // Parented to glass mesh
        innerCoreMeshes.push(coreMesh);

        // Inner Point Light illuminating glass from within
        const pLight = new THREE.PointLight(stage.hexColor, i === 3 ? 4.0 : 2.0, 5);
        glassMesh.add(pLight);
        nodePointLights.push(pLight);
      });

      // 7. Glass Conduits Linking Nodes
      const mainCurvePoints: THREE.Vector3[] = baseNodePositions.map((p) => p.clone());
      const mainSpline = new THREE.CatmullRomCurve3(mainCurvePoints);

      const conduitGeo = new THREE.TubeGeometry(mainSpline, 64, 0.1, 12, false);
      const conduitGlassMat = createGlassMaterial();
      conduitGlassMat.thickness = 0.6;
      conduitGlassMat.roughness = 0.08;
      const conduitMesh = new THREE.Mesh(conduitGeo, conduitGlassMat);
      conduitMesh.castShadow = true;
      nodeGroup.add(conduitMesh);

      // Bypass / Skip conduit (Classified -> Reasoned)
      const skipCurvePoints = [
        baseNodePositions[1].clone(),
        new THREE.Vector3(
          (baseNodePositions[1].x + baseNodePositions[3].x) / 2,
          -1.2,
          -0.8,
        ),
        baseNodePositions[3].clone(),
      ];
      const skipSpline = new THREE.CatmullRomCurve3(skipCurvePoints);
      const skipConduitGeo = new THREE.TubeGeometry(skipSpline, 36, 0.06, 8, false);
      const skipConduitMesh = new THREE.Mesh(skipConduitGeo, conduitGlassMat);
      nodeGroup.add(skipConduitMesh);

      // 8. Glowing Alert Particles traveling through conduits
      const particleGroup = new THREE.Group();
      scene.add(particleGroup);

      const particles3D: Particle3D[] = [];
      const particleGeo = new THREE.SphereGeometry(0.1, 16, 16);

      const spawnParticle = (curve: THREE.CatmullRomCurve3, severity: Severity) => {
        const colorHex = SEVERITY_HEX[severity] || 0x2563eb;
        const pMat = new THREE.MeshStandardMaterial({
          color: colorHex,
          emissive: colorHex,
          emissiveIntensity: 4.0,
          roughness: 0.1,
        });
        const pMesh = new THREE.Mesh(particleGeo, pMat);
        const pLight = new THREE.PointLight(colorHex, 2.5, 3);
        pMesh.add(pLight);

        particleGroup.add(pMesh);

        particles3D.push({
          mesh: pMesh,
          light: pLight,
          curve,
          t: 0,
          speed: 0.15 + Math.random() * 0.1,
          severity,
        });
      };

      // Initial particles
      spawnParticle(mainSpline, 'critical');
      spawnParticle(mainSpline, 'high');
      spawnParticle(skipSpline, 'low');

      let lastParticleSpawn = 0;

      // 9. Fading Perspective Grid Floor
      const gridHelper = new THREE.GridHelper(40, 40, 0x334155, 0x1e293b);
      gridHelper.position.y = -3.2;
      const gridMat = gridHelper.material as THREE.LineBasicMaterial;
      gridMat.transparent = true;
      gridMat.opacity = 0.25;
      scene.add(gridHelper);

      // Shadow receiver plane below object
      const shadowPlaneGeo = new THREE.PlaneGeometry(50, 50);
      const shadowPlaneMat = new THREE.ShadowMaterial({ opacity: 0.4 });
      const shadowPlane = new THREE.Mesh(shadowPlaneGeo, shadowPlaneMat);
      shadowPlane.rotation.x = -Math.PI / 2;
      shadowPlane.position.y = -3.19;
      shadowPlane.receiveShadow = true;
      scene.add(shadowPlane);

      // 10. Background Bokeh / Dust Motes
      const motesCount = 180;
      const motesGeo = new THREE.BufferGeometry();
      const motesPos = new Float32Array(motesCount * 3);
      for (let i = 0; i < motesCount * 3; i += 3) {
        motesPos[i] = (Math.random() - 0.5) * 35;
        motesPos[i + 1] = (Math.random() - 0.5) * 20;
        motesPos[i + 2] = (Math.random() - 0.5) * 20 - 5;
      }
      motesGeo.setAttribute('position', new THREE.BufferAttribute(motesPos, 3));
      const motesMat = new THREE.PointsMaterial({
        color: 0x94a3b8,
        size: 0.08,
        transparent: true,
        opacity: 0.35,
        blending: THREE.AdditiveBlending,
      });
      const motesMesh = new THREE.Points(motesGeo, motesMat);
      scene.add(motesMesh);

      // 11. Selective Bloom Post-Processing
      composer = new EffectComposer(renderer);
      const renderPass = new RenderPass(scene, camera);
      composer.addPass(renderPass);

      const bloomPass = new UnrealBloomPass(
        new THREE.Vector2(width, height),
        0.8, // Strength
        0.4, // Radius
        0.65 // Threshold (Bloom on emissive cores/particles only!)
      );
      composer.addPass(bloomPass);

      const outputPass = new OutputPass();
      composer.addPass(outputPass);

      // 12. Animation & Render Loop
      const clock = new THREE.Clock();

      const renderLoop = () => {
        animationFrameId = requestAnimationFrame(renderLoop);

        const elapsedTime = clock.getElapsedTime();
        const delta = clock.getDelta();
        const scrollFactor = scrollRef.current;

        // Autonomous camera orbit (imperceptibly slow: ~50s full revolution)
        const baseRadius = 13.5 + scrollFactor * 4.0; // Camera pulls back on scroll
        const orbitAngle = elapsedTime * 0.08;
        const camX = Math.sin(orbitAngle) * baseRadius * 0.35;
        const camY = 2.2 + Math.sin(elapsedTime * 0.12) * 0.4 + scrollFactor * 1.5;
        const camZ = Math.cos(orbitAngle * 0.5) * baseRadius;

        camera.position.set(camX, camY, camZ);
        camera.lookAt(0, 0, 0);

        // Nodes continuous motion & expansion on scroll
        const nodeSpacing = 2.8 + scrollFactor * 1.2; // Nodes separate on scroll
        nodeMeshes.forEach((mesh, i) => {
          const targetX = (i - 2) * nodeSpacing;
          mesh.position.x = THREE.MathUtils.lerp(mesh.position.x, targetX, 0.1);

          // Subtle crystalline float & rotation
          mesh.rotation.x = Math.sin(elapsedTime * 0.3 + i) * 0.15;
          mesh.rotation.y = elapsedTime * (0.15 + i * 0.03);
          mesh.rotation.z = Math.cos(elapsedTime * 0.2 + i) * 0.1;

          // Pulse active node core light
          if (i === 3) { // Reasoned stage active
            const pulse = 1.0 + Math.sin(elapsedTime * 4.0) * 0.35;
            (innerCoreMeshes[i].material as THREE.MeshStandardMaterial).emissiveIntensity = 3.2 * pulse;
            nodePointLights[i].intensity = 4.0 * pulse;
          }
        });

        // Dynamic dust motes float
        const posAttr = motesGeo.attributes.position as THREE.BufferAttribute;
        for (let i = 0; i < motesCount; i++) {
          let y = posAttr.getY(i);
          y += Math.sin(elapsedTime + i) * 0.002;
          if (y > 10) y = -10;
          posAttr.setY(i, y);
        }
        posAttr.needsUpdate = true;

        // Particle travel along conduits
        if (elapsedTime - lastParticleSpawn > 1.8) {
          lastParticleSpawn = elapsedTime;
          const sevPool: Severity[] = ['critical', 'high', 'medium', 'low'];
          const randomSev = sevPool[Math.floor(Math.random() * sevPool.length)];
          const splineChoice = Math.random() > 0.3 ? mainSpline : skipSpline;
          spawnParticle(splineChoice, randomSev);
        }

        for (let i = particles3D.length - 1; i >= 0; i--) {
          const p = particles3D[i];
          p.t += delta * p.speed;
          if (p.t >= 1) {
            particleGroup.remove(p.mesh);
            p.mesh.geometry.dispose();
            (p.mesh.material as THREE.Material).dispose();
            particles3D.splice(i, 1);
          } else {
            const pt = p.curve.getPoint(p.t);
            p.mesh.position.copy(pt);
          }
        }

        // Project 3D node positions to HTML overlay screen space
        const screenPositions = nodeMeshes.map((mesh, i) => {
          const worldPos = new THREE.Vector3();
          mesh.getWorldPosition(worldPos);
          worldPos.y -= 1.4; // Label offset below glass node

          const proj = worldPos.clone().project(camera);
          const px = (proj.x * 0.5 + 0.5) * width;
          const py = (-proj.y * 0.5 + 0.5) * height;

          return {
            id: STAGES[i].id,
            x: px,
            y: py,
            count: stageCounts[STAGES[i].id] || 0,
          };
        });
        setNodeScreenPos(screenPositions);

        // Render scene with bloom composer
        composer.render();
      };

      renderLoop();

      // Handle Resize
      const handleResize = () => {
        if (!container) return;
        const w = container.clientWidth;
        const h = container.clientHeight;
        camera.aspect = w / h;
        camera.updateProjectionMatrix();
        renderer.setSize(w, h);
        composer.setSize(w, h);
      };

      window.addEventListener('resize', handleResize);

      return () => {
        window.removeEventListener('resize', handleResize);
        cancelAnimationFrame(animationFrameId);
        renderer.dispose();
        pmremGenerator.dispose();
        if (container.contains(renderer.domElement)) {
          container.removeChild(renderer.domElement);
        }
      };
    } catch (err: any) {
      console.error('WebGL initialization error:', err);
      setWebglError(err?.message || 'WebGL context failure');
    }
  }, [stageCounts]);

  return (
    <div className="relative w-full h-[520px] md:h-[620px] bg-void rounded-lg overflow-hidden border border-edge/60 shadow-2xl">
      {/* 3D Canvas Container */}
      <div ref={mountRef} className="absolute inset-0 w-full h-full cursor-default" />

      {/* Radial Void Vignette Overlay */}
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,transparent_40%,rgba(11,14,17,0.7)_85%,#0B0E11_100%)] pointer-events-none" />

      {/* WebGL Fallback Notification if GPU is disabled */}
      {webglError && (
        <div className="absolute inset-0 flex items-center justify-center bg-void/90 p-6 text-center">
          <div className="max-w-md bg-raised p-6 rounded border border-sev-critical/40">
            <ShieldAlert className="mx-auto text-sev-critical mb-3" size={32} />
            <h3 className="font-mono text-sm uppercase tracking-wider text-ink font-semibold">
              3D WebGL Acceleration Unavailable
            </h3>
            <p className="text-xs text-dim mt-2">
              Falling back to standard view. Enable WebGL in your browser to experience the photorealistic crystalline pipeline render.
            </p>
          </div>
        </div>
      )}

      {/* Interactive HTML 3D Floating Node Labels */}
      {!webglError && (
        <div className="absolute inset-0 pointer-events-none overflow-hidden">
          {nodeScreenPos.map((pos) => {
            const stage = STAGES.find((s) => s.id === pos.id)!;
            const Icon = stage.icon;
            const isActive = activeStage === pos.id;

            return (
              <div
                key={pos.id}
                style={{
                  left: `${pos.x}px`,
                  top: `${pos.y}px`,
                  transform: 'translate(-50%, -50%)',
                }}
                className={`absolute transition-transform duration-200 pointer-events-auto cursor-pointer ${
                  isActive ? 'z-20 scale-105' : 'z-10 hover:scale-105'
                }`}
                onClick={() => setActiveStage(pos.id)}
              >
                <div
                  className={`flex flex-col items-center p-2 rounded-md border backdrop-blur-md transition-all duration-300 ${
                    isActive
                      ? 'bg-surface/90 border-ink/40 shadow-[0_0_20px_rgba(37,99,235,0.25)]'
                      : 'bg-void/70 border-edge/60 hover:border-edge-bright hover:bg-surface/80'
                  }`}
                >
                  <div className="flex items-center gap-1.5">
                    <span
                      className="w-2 h-2 rounded-full animate-pulse"
                      style={{ backgroundColor: stage.color }}
                    />
                    <Icon size={12} className="text-ink/80" />
                    <span className="font-mono text-[11px] font-semibold tracking-wider text-ink">
                      {stage.label}
                    </span>
                  </div>

                  <div className="flex items-center justify-between w-full gap-3 mt-1 pt-1 border-t border-edge/40">
                    <span className="font-mono text-[9px] text-dim">{stage.sublabel}</span>
                    <span
                      className="font-mono text-[10px] font-bold px-1.5 py-0.2 rounded"
                      style={{
                        backgroundColor: `${stage.color}1A`,
                        color: stage.color,
                      }}
                    >
                      {pos.count}
                    </span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Hero Header HUD Overlay */}
      <div className="absolute top-4 left-6 pointer-events-none max-w-lg">
        <div className="flex items-center gap-2 mb-1.5">
          <span className="font-mono text-xs font-semibold tracking-[0.2em] text-ink uppercase">
            Crystalline Pipeline Topology
          </span>
          <span className="font-mono text-[9px] text-sev-info bg-sev-info/10 border border-sev-info/30 px-2 py-0.5 rounded-full flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-sev-info animate-ping" /> Real-Time Telemetry
          </span>
        </div>
        <p className="text-xs text-dim leading-relaxed">
          Five linked polyhedral glass nodes floating center-frame. Severity alerts pulse inside each node in real time as data passes through conduits.
        </p>
      </div>

      {/* Command Engine Button HUD */}
      {onOpenCommand && (
        <div className="absolute top-4 right-6">
          <button
            onClick={onOpenCommand}
            className="font-mono text-xs text-ink bg-surface/80 hover:bg-raised border border-edge hover:border-edge-bright px-3 py-1.5 rounded-md transition-all flex items-center gap-2 shadow-lg backdrop-blur-md cursor-pointer"
          >
            <Sparkles size={13} className="text-sev-high" />
            <span>⌘K Command Engine</span>
          </button>
        </div>
      )}

      {/* Severity Color Signal Legend */}
      <div className="absolute bottom-4 right-6 pointer-events-auto flex items-center gap-3 bg-void/80 border border-edge/60 backdrop-blur-md px-3 py-1.5 rounded-md font-mono text-[10px] uppercase text-dim">
        <span className="text-[9px] tracking-wider text-ink/70">Severity Signal:</span>
        <span className="flex items-center gap-1">
          <span className="w-2 h-2 rounded-full bg-sev-critical shadow-[0_0_6px_#DC2626]" /> critical
        </span>
        <span className="flex items-center gap-1">
          <span className="w-2 h-2 rounded-full bg-sev-high shadow-[0_0_6px_#EA580C]" /> high
        </span>
        <span className="flex items-center gap-1">
          <span className="w-2 h-2 rounded-full bg-sev-medium shadow-[0_0_6px_#D97706]" /> medium
        </span>
        <span className="flex items-center gap-1">
          <span className="w-2 h-2 rounded-full bg-sev-low shadow-[0_0_6px_#2563EB]" /> low
        </span>
      </div>
    </div>
  );
}
