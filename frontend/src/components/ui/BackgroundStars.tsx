import React, { useRef } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import { Stars, Sparkles } from '@react-three/drei';
import { motion } from 'framer-motion';
import * as THREE from 'three';

function RotatingStars() {
  const groupRef = useRef<THREE.Group>(null);
  
  useFrame((state, delta) => {
    if (groupRef.current) {
      groupRef.current.rotation.y -= delta * 0.05; // Slow rotation
      groupRef.current.rotation.x -= delta * 0.02;
    }
  });

  return (
    <group ref={groupRef}>
      <Stars radius={100} depth={50} count={5000} factor={4} saturation={0.8} fade speed={1} />
      <Sparkles count={400} scale={100} size={4} speed={0.2} opacity={0.5} color="#06b6d4" />
      <Sparkles count={300} scale={100} size={3} speed={0.3} opacity={0.4} color="#8b5cf6" />
      <Sparkles count={300} scale={100} size={3} speed={0.4} opacity={0.3} color="#10b981" />
    </group>
  );
}

export function BackgroundStars() {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 0.85 }}
      transition={{ duration: 1.2, ease: 'easeOut' }}
      className="fixed inset-0 pointer-events-none mix-blend-screen"
      style={{ zIndex: 0 }}
    >
      <Canvas camera={{ position: [0, 0, 1] }}>
        <RotatingStars />
      </Canvas>
    </motion.div>
  );
}
