import React, { useRef, useMemo, useState } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import { Environment, Sparkles, Stars } from '@react-three/drei';
import * as THREE from 'three';
import { motion } from 'framer-motion';
import { Sparkles as SparklesIcon, ShieldAlert } from 'lucide-react';
import type { Alert } from '@/types';

interface Realistic3DHeroProps {
  alerts: Alert[];
  connected: boolean;
  onOpenCommand?: () => void;
}

// React Error Boundary for 3D Canvas
class R3FErrorBoundary extends React.Component<
  { children: React.ReactNode; fallback: React.ReactNode },
  { hasError: boolean }
> {
  constructor(props: any) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError() {
    return { hasError: true };
  }

  componentDidCatch(error: any) {
    console.warn('R3F 3D Error caught safely:', error);
  }

  render() {
    if (this.state.hasError) {
      return this.props.fallback;
    }
    return this.props.children;
  }
}

// 3D Continents Dot-Density Grid
function ContinentDotGrid() {
  const points = useMemo(() => {
    const coords: number[] = [];
    const radius = 2.43;
    const addContinent = (minLat: number, maxLat: number, minLon: number, maxLon: number, density: number) => {
      for (let i = 0; i < density; i++) {
        const lat = THREE.MathUtils.degToRad(minLat + Math.random() * (maxLat - minLat));
        const lon = THREE.MathUtils.degToRad(minLon + Math.random() * (maxLon - minLon));
        coords.push(
          radius * Math.cos(lat) * Math.cos(lon),
          radius * Math.sin(lat),
          radius * Math.cos(lat) * Math.sin(lon)
        );
      }
    };
    // North America
    addContinent(15, 65, -130, -60, 160);
    // South America
    addContinent(-50, 10, -80, -35, 100);
    // Europe
    addContinent(35, 65, -10, 40, 130);
    // Africa
    addContinent(-35, 35, -15, 50, 150);
    // Asia
    addContinent(10, 70, 60, 140, 220);
    // Australia
    addContinent(-40, -10, 110, 155, 80);

    return new Float32Array(coords);
  }, []);

  return (
    <points>
      <bufferGeometry>
        <bufferAttribute attach="attributes-position" args={[points, 3]} />
      </bufferGeometry>
      <pointsMaterial size={0.044} color="#60a5fa" transparent opacity={0.9} sizeAttenuation />
    </points>
  );
}

// 3D Global Attack Vector Arcs (3D Great-Circle Flight Lines over Globe)
function GlobalAttackArcs() {
  const { arcs, targetRings } = useMemo(() => {
    const coords: number[] = [];
    const targets: THREE.Vector3[] = [];
    const arcCount = 8;
    for (let i = 0; i < arcCount; i++) {
      const lat1 = (Math.random() - 0.5) * Math.PI;
      const lon1 = Math.random() * Math.PI * 2;
      const lat2 = (Math.random() - 0.5) * Math.PI;
      const lon2 = Math.random() * Math.PI * 2;

      const r = 2.45;
      const p1 = new THREE.Vector3(r * Math.cos(lat1) * Math.cos(lon1), r * Math.sin(lat1), r * Math.cos(lat1) * Math.sin(lon1));
      const p2 = new THREE.Vector3(r * Math.cos(lat2) * Math.cos(lon2), r * Math.sin(lat2), r * Math.cos(lat2) * Math.sin(lon2));

      targets.push(p2);

      const mid = new THREE.Vector3().addVectors(p1, p2).multiplyScalar(0.7);
      mid.normalize().multiplyScalar(r * 1.55);

      const curve = new THREE.QuadraticBezierCurve3(p1, mid, p2);
      const points = curve.getPoints(36);

      for (let j = 0; j < points.length - 1; j++) {
        coords.push(points[j].x, points[j].y, points[j].z);
        coords.push(points[j + 1].x, points[j + 1].y, points[j + 1].z);
      }
    }
    return { arcs: new Float32Array(coords), targetRings: targets };
  }, []);

  return (
    <group>
      <lineSegments>
        <bufferGeometry>
          <bufferAttribute attach="attributes-position" args={[arcs, 3]} />
        </bufferGeometry>
        <lineBasicMaterial color="#ef4444" transparent opacity={0.65} linewidth={1.5} />
      </lineSegments>

      {targetRings.map((target, idx) => (
        <mesh key={idx} position={target}>
          <sphereGeometry args={[0.065, 12, 12]} />
          <meshBasicMaterial color="#f59e0b" transparent opacity={0.9} />
        </mesh>
      ))}
    </group>
  );
}

// Interactive Photorealistic 3D Globe with Atmosphere & Orbit Rings
function PhotorealisticGlobe() {
  const globeGroupRef = useRef<THREE.Group>(null);
  const wireframeRef = useRef<THREE.Mesh>(null);
  const atmosphereRef = useRef<THREE.Mesh>(null);
  const ring1Ref = useRef<THREE.Group>(null);
  const ring2Ref = useRef<THREE.Group>(null);
  const ring3Ref = useRef<THREE.Group>(null);
  const coreLightRef = useRef<THREE.PointLight>(null);

  useFrame((state, delta) => {
    const d = Math.min(delta, 0.033);
    const time = state.clock.getElapsedTime();

    // 1. Globe Rotation
    if (globeGroupRef.current) {
      globeGroupRef.current.rotation.y += d * 0.22;
    }

    if (wireframeRef.current) {
      wireframeRef.current.rotation.y += d * 0.08;
    }

    if (atmosphereRef.current) {
      atmosphereRef.current.rotation.y -= d * 0.05;
    }

    // 2. Orbital Rings Rotation
    if (ring1Ref.current) {
      ring1Ref.current.rotation.y += d * 0.42;
    }
    if (ring2Ref.current) {
      ring2Ref.current.rotation.y -= d * 0.34;
    }
    if (ring3Ref.current) {
      ring3Ref.current.rotation.y += d * 0.24;
    }

    // 3. Core Breathing Pulse
    if (coreLightRef.current) {
      coreLightRef.current.intensity = 24 + Math.sin(time * 3) * 6;
    }
  });

  return (
    <group>
      {/* Globe & Atmosphere Container */}
      <group ref={globeGroupRef}>
        {/* Core Flame Light */}
        <pointLight ref={coreLightRef} position={[0, 0, 0]} intensity={26} distance={15} color="#ef4444" />
        <pointLight position={[0, 3, 0]} intensity={14} distance={12} color="#3b82f6" />

        {/* 1. Inner Dark Metallic Globe */}
        <mesh castShadow receiveShadow>
          <sphereGeometry args={[2.4, 64, 64]} />
          <meshStandardMaterial
            color="#080e18"
            roughness={0.1}
            metalness={0.94}
            emissive="#0b1329"
            emissiveIntensity={0.65}
          />
        </mesh>

        {/* 2. Continents Dot Density Grid */}
        <ContinentDotGrid />

        {/* 3. Latitude/Longitude Cyber Wireframe Grid */}
        <mesh ref={wireframeRef}>
          <sphereGeometry args={[2.42, 36, 36]} />
          <meshStandardMaterial
            color="#1e293b"
            emissive="#3b82f6"
            emissiveIntensity={1.3}
            wireframe
            transparent
            opacity={0.7}
          />
        </mesh>

        {/* 4. Atmospheric Blue Fresnel Light Shield */}
        <mesh ref={atmosphereRef}>
          <sphereGeometry args={[2.51, 64, 64]} />
          <meshPhysicalMaterial
            color="#60a5fa"
            transmission={0.88}
            opacity={0.42}
            transparent
            roughness={0.05}
            metalness={0.1}
            ior={1.15}
            thickness={1.2}
          />
        </mesh>

        {/* 3D Global Attack Vector Arcs */}
        <GlobalAttackArcs />

        {/* Orbital Ring 1: Primary Geosynchronous Ring (Crimson Flare) */}
        <group rotation={[Math.PI / 4, 0, 0]}>
          <group ref={ring1Ref}>
            <mesh>
              <torusGeometry args={[3.5, 0.038, 16, 100]} />
              <meshStandardMaterial
                color="#ef4444"
                emissive="#ef4444"
                emissiveIntensity={3.5}
                metalness={0.9}
                roughness={0.1}
              />
            </mesh>
          </group>
        </group>

        {/* Orbital Ring 2: Polar Telemetry Ring (Cyan / Deep Blue) */}
        <group rotation={[-Math.PI / 5, 0, 0]}>
          <group ref={ring2Ref}>
            <mesh>
              <torusGeometry args={[4.3, 0.03, 16, 100]} />
              <meshStandardMaterial
                color="#3b82f6"
                emissive="#3b82f6"
                emissiveIntensity={3.0}
                metalness={0.9}
                roughness={0.1}
              />
            </mesh>
          </group>
        </group>

        {/* Orbital Ring 3: Outer Defense Ring (Gold / Amber) */}
        <group rotation={[Math.PI / 8, Math.PI / 6, 0]}>
          <group ref={ring3Ref}>
            <mesh>
              <torusGeometry args={[5.2, 0.024, 16, 100]} />
              <meshStandardMaterial
                color="#f59e0b"
                emissive="#f59e0b"
                emissiveIntensity={2.6}
                metalness={0.9}
                roughness={0.05}
              />
            </mesh>
          </group>
        </group>
      </group>
    </group>
  );
}

export function Realistic3DHero({ alerts, connected, onOpenCommand }: Realistic3DHeroProps) {
  const [isReady, setIsReady] = useState(false);

  const fallbackUI = (
    <div className="absolute inset-0 flex items-center justify-center bg-slate-950/90 p-6 text-center">
      <div className="max-w-md bg-slate-900 p-6 rounded-xl border border-red-500/40 shadow-2xl">
        <ShieldAlert className="mx-auto text-red-500 mb-3" size={32} />
        <h3 className="font-mono text-sm uppercase tracking-wider text-white font-semibold">
          3D WebGL Globe Engine
        </h3>
        <p className="text-xs text-slate-400 mt-2">
          Photorealistic 3D cyber telemetry active.
        </p>
      </div>
    </div>
  );

  return (
    <div className="absolute inset-0 w-full h-full bg-black">
      {/* Radial aura glow behind canvas */}
      <div className="absolute inset-0 bg-gradient-to-b from-red-600/10 via-transparent to-black pointer-events-none" />

      <R3FErrorBoundary fallback={fallbackUI}>
        <motion.div
          initial={{ opacity: 0, scale: 0.96 }}
          animate={{ opacity: isReady ? 1 : 0, scale: isReady ? 1 : 0.96 }}
          transition={{ duration: 1.5, ease: [0.16, 1, 0.3, 1] }}
          className="absolute inset-0 w-full h-full"
        >
          <Canvas
            camera={{ position: [0, 0, 11], fov: 45 }}
            gl={{ antialias: true, alpha: true, powerPreference: 'high-performance' }}
            onCreated={({ gl }) => {
              gl.setClearColor(0x000000, 1);
              requestAnimationFrame(() => setIsReady(true));
            }}
          >
            {/* Atmospheric Fog */}
            <fog attach="fog" args={['#000000', 6, 23]} />

            {/* Lighting Rig */}
            <ambientLight intensity={0.65} />
            <directionalLight position={[12, 12, 8]} intensity={3.2} color="#ffffff" castShadow />
            <pointLight position={[-10, 6, 6]} intensity={14} color="#3b82f6" distance={25} />
            <pointLight position={[10, -6, -4]} intensity={10} color="#f59e0b" distance={20} />

            {/* Environment Reflections */}
            <Environment preset="night" />

            {/* Master Globe & Orbit Scene */}
            <PhotorealisticGlobe />

            {/* Cyber Embers & Cosmic Starfield */}
            <Sparkles count={250} scale={16} size={2.6} speed={0.8} color="#ef4444" opacity={0.6} />
            <Sparkles count={180} scale={18} size={2.0} speed={0.5} color="#3b82f6" opacity={0.5} />
            <Stars radius={60} depth={50} count={4000} factor={3} saturation={0} fade speed={1.2} />
          </Canvas>
        </motion.div>
      </R3FErrorBoundary>
    </div>
  );
}
