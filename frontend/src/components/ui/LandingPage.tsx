import React, { useRef } from 'react';
import { motion, useScroll, useSpring, useTransform } from 'framer-motion';
import { Realistic3DHero } from '@/components/pipeline/Realistic3DHero';
import type { Alert } from '@/types';
import {
  ChevronRight,
  ChevronDown,
  ShieldCheck,
  Cpu,
  Terminal,
  Zap,
  ShieldAlert,
  Search,
  Target,
  Radio,
  CheckCircle2,
  ArrowRight,
} from 'lucide-react';

interface LandingPageProps {
  onEnter: () => void;
  alerts: Alert[];
  connected: boolean;
}

export function LandingPage({ onEnter, alerts, connected }: LandingPageProps) {
  const containerRef = useRef<HTMLDivElement>(null);

  // Scroll Progress Tracking for Left Laser Indicator Bar
  const { scrollYProgress } = useScroll({ container: containerRef });
  const scrollScaleY = useSpring(scrollYProgress, { stiffness: 200, damping: 25 });

  // Scroll-Linked Parallax Transforms for Smooth Realistic Page Flow
  const heroOpacity = useTransform(scrollYProgress, [0, 0.2], [1, 0]);
  const heroScale = useTransform(scrollYProgress, [0, 0.2], [1, 0.92]);
  const heroY = useTransform(scrollYProgress, [0, 0.2], [0, -65]);
  const bg3DOpacity = useTransform(scrollYProgress, [0, 0.7, 1], [1, 0.85, 0.65]);

  const scrollToFeatures = () => {
    const el = document.getElementById('pipeline-section');
    if (el) el.scrollIntoView({ behavior: 'smooth' });
  };

  return (
    <motion.div
      ref={containerRef}
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0, filter: 'blur(20px)' }}
      transition={{ duration: 0.8, ease: [0.16, 1, 0.3, 1] }}
      className="fixed inset-0 z-40 overflow-y-auto scroll-smooth bg-black text-slate-100 font-sans select-none scrollbar-thin scrollbar-thumb-slate-800"
    >
      {/* Left Laser Scroll Progress Bar */}
      <div className="fixed top-0 left-3 bottom-0 w-1 z-50 pointer-events-none hidden md:block">
        <div className="w-full h-full bg-slate-900/60 rounded-full overflow-hidden relative">
          <motion.div
            style={{ scaleY: scrollScaleY }}
            className="w-full bg-gradient-to-b from-red-600 via-red-500 to-amber-500 origin-top h-full shadow-[0_0_10px_#ef4444]"
          />
        </div>
      </div>

      {/* Right Laser Scroll Progress Bar */}
      <div className="fixed top-0 right-3 bottom-0 w-1 z-50 pointer-events-none hidden md:block">
        <div className="w-full h-full bg-slate-900/60 rounded-full overflow-hidden relative">
          <motion.div
            style={{ scaleY: scrollScaleY }}
            className="w-full bg-gradient-to-b from-red-600 via-red-500 to-amber-500 origin-top h-full shadow-[0_0_10px_#ef4444]"
          />
        </div>
      </div>

      {/* 3D Photorealistic Background (Fixed Position with Framer Motion Fade-In & Scroll Depth) */}
      <motion.div
        style={{ opacity: bg3DOpacity }}
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 1.4, ease: [0.16, 1, 0.3, 1] }}
        className="fixed inset-0 pointer-events-none z-0"
      >
        <Realistic3DHero alerts={alerts} connected={connected} onOpenCommand={() => {}} />
      </motion.div>

      {/* Floating Tactical Navigation HUD Cards */}
      <header className="fixed top-6 inset-x-6 sm:inset-x-12 z-50 flex items-center justify-between pointer-events-none">
        {/* Floating Brand Pill */}
        <div className="pointer-events-auto tactical-hud-pill flex items-center gap-3 px-4 py-2.5 rounded-xl shadow-2xl backdrop-blur-xl">
          <img src="/logo.png" alt="Flare Logo" className="h-7 w-auto object-contain filter drop-shadow-[0_0_8px_rgba(239,68,68,0.8)]" />
          <span className="font-orbitron text-sm font-extrabold tracking-[0.2em] text-white">FLARE</span>
          <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-red-500/10 border border-red-500/30 text-red-400 font-semibold uppercase">
            Defense OS v2.4
          </span>
        </div>

        {/* Floating Action Area */}
        <div className="pointer-events-auto flex items-center gap-3">
          <div className="hidden sm:flex items-center gap-2 px-4 py-2 rounded-xl tactical-hud-pill font-mono text-xs shadow-2xl backdrop-blur-xl">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span className="text-emerald-400 font-bold text-[11px]">FastAPI + LangGraph</span>
          </div>
          <button
            onClick={onEnter}
            className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-red-600 to-orange-500 hover:from-red-500 hover:to-orange-400 border border-white/20 text-white font-mono text-xs font-bold transition-all shadow-[0_0_25px_rgba(239,68,68,0.45)] flex items-center gap-2 cursor-pointer"
          >
            <span>Launch Dashboard</span>
            <ChevronRight size={15} />
          </button>
        </div>
      </header>

      {/* HERO SECTION */}
      <section className="relative z-10 min-h-screen flex flex-col items-center justify-between px-6 lg:px-12 pt-32 pb-8 w-full max-w-[1800px] mx-auto">
        {/* Central High-Precision Tactical Hero Card (with Scroll-Driven Parallax Exit) */}
        <motion.div
          style={{ opacity: heroOpacity, scale: heroScale, y: heroY }}
          initial={{ y: 25, opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.15, duration: 0.85, ease: [0.16, 1, 0.3, 1] }}
          className="relative z-10 flex flex-col items-center text-center max-w-xl sm:max-w-[640px] w-full px-7 sm:px-10 py-8 sm:py-10 pointer-events-auto tactical-glass-card rounded-2xl mx-auto my-auto group overflow-hidden shadow-2xl"
        >
          {/* Tactical Corner Brackets */}
          <div className="absolute top-3 left-3.5 text-slate-500 font-mono text-xs pointer-events-none font-bold">┌</div>
          <div className="absolute top-3 right-3.5 text-slate-500 font-mono text-xs pointer-events-none font-bold">┐</div>
          <div className="absolute bottom-3 left-3.5 text-slate-500 font-mono text-xs pointer-events-none font-bold">└</div>
          <div className="absolute bottom-3 right-3.5 text-slate-500 font-mono text-xs pointer-events-none font-bold">┘</div>

          {/* Animated Holographic Laser Scan Line */}
          <div className="absolute inset-x-0 h-1 bg-gradient-to-r from-transparent via-red-500/40 to-transparent pointer-events-none animate-scanline" />

          {/* Status Tag Pill */}
          <motion.div
            initial={{ opacity: 0, y: -8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
            className="flex items-center gap-2.5 px-4 py-1.5 rounded-full bg-slate-950/40 backdrop-blur-md border border-slate-700/50 text-red-400 font-mono text-xs uppercase tracking-wider mb-5 shadow-sm"
          >
            <span className="w-2 h-2 rounded-full bg-emerald-400" />
            <span className="font-bold text-slate-200">Incident Triage Engine</span>
            <span className="text-slate-600">·</span>
            <span className="text-slate-400 font-medium">FastAPI + LangGraph</span>
          </motion.div>

          {/* Central Logo Emblem */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.25, duration: 0.7 }}
            className="relative group mb-5 sm:mb-6 cursor-pointer"
          >
            <div className="relative w-24 h-24 sm:w-28 sm:h-28 rounded-2xl bg-slate-950/40 backdrop-blur-md border border-slate-700/50 flex items-center justify-center p-3.5 shadow-xl transition-transform duration-500 group-hover:scale-105">
              <img
                src="/logo.png"
                alt="Flare Logo"
                className="w-full h-full object-contain filter drop-shadow-[0_0_15px_rgba(239,68,68,0.85)]"
              />
            </div>
          </motion.div>

          {/* Brand Title (Orbitron Font) */}
          <motion.h1
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.35 }}
            className="font-orbitron text-3xl sm:text-4xl lg:text-5xl font-black tracking-wider text-white mb-3"
          >
            FLARE <span className="font-light text-red-500">Command OS</span>
          </motion.h1>

          {/* Subtitle */}
          <motion.p
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4 }}
            className="font-sans text-slate-300 text-xs sm:text-base mb-6 leading-relaxed max-w-lg font-normal"
          >
            AI-powered incident triage agent. Replays intrusion flows, evaluates indicators via AbuseIPDB & VirusTotal, and grounds mitigations in MITRE ATT&CK.
          </motion.p>

          {/* Live Telemetry Ticker Log */}
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.45 }}
            className="w-full bg-slate-950/40 backdrop-blur-md border border-slate-800/80 rounded-xl p-3.5 sm:p-4 mb-6 font-mono text-xs text-left overflow-hidden flex items-center gap-2.5"
          >
            <Terminal size={14} className="text-red-500 shrink-0" />
            <span className="text-slate-500 font-bold shrink-0">LOG &gt;</span>
            <span className="text-emerald-400 truncate font-medium">
              [21:37:18 UTC] SURICATA_EVE: Packet 0x9f4a &rarr; Groq Triage (82ms) &rarr; AbuseIPDB score 92
            </span>
          </motion.div>

          {/* Action Button */}
          <motion.button
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.5 }}
            whileHover={{ scale: 1.03 }}
            whileTap={{ scale: 0.97 }}
            onClick={onEnter}
            className="group relative px-8 sm:px-9 py-3.5 sm:py-4 bg-gradient-to-r from-red-600 via-red-500 to-orange-500 hover:from-red-500 hover:to-orange-400 rounded-xl flex items-center gap-3 transition-all shadow-[0_0_35px_rgba(239,68,68,0.5)] text-white font-mono text-xs sm:text-sm uppercase tracking-wider font-bold cursor-pointer"
          >
            <span>Launch Dashboard</span>
            <ChevronRight size={18} className="group-hover:translate-x-1 transition-transform text-white" />
          </motion.button>
        </motion.div>

        {/* Scroll Prompt */}
        <div className="pt-4 pb-2 z-20 flex justify-center pointer-events-auto">
          <motion.div
            animate={{ y: [0, 6, 0] }}
            transition={{ duration: 2.2, repeat: Infinity, ease: 'easeInOut' }}
            onClick={scrollToFeatures}
            className="flex flex-col items-center gap-1 font-mono text-[11px] text-slate-400 hover:text-red-400 cursor-pointer transition-colors"
          >
            <span>Explore Pipeline Architecture</span>
            <ChevronDown size={18} className="text-red-500" />
          </motion.div>
        </div>
      </section>

      {/* SECTION 2: 5-STAGE AUTONOMOUS TRIAGE PIPELINE */}
      <section id="pipeline-section" className="relative z-10 pt-36 pb-28 px-6 lg:px-12 w-full max-w-[1800px] mx-auto space-y-12 sm:space-y-16">
        <motion.div
          initial={{ opacity: 0, y: 40, scale: 0.95 }}
          whileInView={{ opacity: 1, y: 0, scale: 1 }}
          viewport={{ once: true, amount: 0.3 }}
          transition={{ duration: 0.8, ease: [0.16, 1, 0.3, 1] }}
          className="text-center space-y-4"
        >
          <span className="font-orbitron text-xs font-bold uppercase tracking-[0.25em] text-red-400 bg-red-500/10 px-4 py-1.5 rounded-full border border-red-500/30 inline-block shadow-[0_0_15px_rgba(239,68,68,0.2)]">
            Autonomous Pipeline Matrix
          </span>
          <h2 className="font-syne text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
            5-Stage AI Triage Engine
          </h2>
          <p className="font-sans text-slate-400 text-sm sm:text-base max-w-2xl mx-auto">
            Network telemetry events undergo multi-stage zero-shot classification, threat intel lookup, vector retrieval, and automated action plan synthesis.
          </p>
        </motion.div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-5 lg:gap-6">
          {[
            {
              step: '01',
              title: 'Ingest & Decode',
              desc: 'Streaming Suricata EVE JSON & CICIDS2017 flow packets into bounded queue workers.',
              icon: <Radio className="text-blue-400" size={20} />,
              tech: 'FastAPI + Workers',
            },
            {
              step: '02',
              title: 'Groq Classification',
              desc: 'Sub-second Llama-3.1-8B zero-shot severity scoring (<85ms p50 latency).',
              icon: <Zap className="text-amber-400" size={20} />,
              tech: 'Groq Llama-3.1',
            },
            {
              step: '03',
              title: 'Threat Intel Query',
              desc: 'Parallel lookup across AbuseIPDB score calculation and VirusTotal 70+ AV engine reputation lookup.',
              icon: <Search className="text-emerald-400" size={20} />,
              tech: 'AbuseIPDB + VT',
            },
            {
              step: '04',
              title: 'MITRE ATT&CK RAG',
              desc: 'ChromaDB vector embedding search retrieving exact adversary techniques, tactics, and mitigations.',
              icon: <Target className="text-purple-400" size={20} />,
              tech: 'ChromaDB RAG',
            },
            {
              step: '05',
              title: 'Gemini Deep Reason',
              desc: 'Gemini Flash multi-step reasoning, rationale synthesis, and action plan generation by urgency.',
              icon: <Cpu className="text-red-400" size={20} />,
              tech: 'Gemini Flash',
            },
          ].map((card, idx) => (
            <motion.div
              key={card.step}
              initial={{ opacity: 0, y: 45, scale: 0.93 }}
              whileInView={{ opacity: 1, y: 0, scale: 1 }}
              viewport={{ once: true, amount: 0.2 }}
              transition={{ duration: 0.65, delay: idx * 0.12, ease: [0.16, 1, 0.3, 1] }}
              whileHover={{ y: -8, scale: 1.025, transition: { duration: 0.25 } }}
              className="p-6 sm:p-7 rounded-2xl tactical-glass-card shadow-xl flex flex-col justify-between h-full transition-all group cursor-pointer border border-slate-800/80 hover:border-red-500/50 hover:shadow-[0_0_30px_rgba(239,68,68,0.2)] bg-slate-900/60 backdrop-blur-md"
            >
              <div>
                <div className="flex items-center justify-between mb-4">
                  <span className="font-orbitron text-xs font-black text-slate-500 group-hover:text-red-400 transition-colors">{card.step}</span>
                  <div className="p-2 rounded-xl bg-slate-950/60 border border-slate-800 group-hover:border-slate-700 transition-colors">
                    {card.icon}
                  </div>
                </div>
                <h3 className="font-syne text-lg font-bold text-white mb-2 group-hover:text-red-400 transition-colors">{card.title}</h3>
                <p className="font-sans text-xs text-slate-400 leading-relaxed">{card.desc}</p>
              </div>
              <div className="mt-6 pt-3 border-t border-slate-800 flex items-center justify-between font-mono text-[11px] text-slate-400">
                <span>{card.tech}</span>
                <CheckCircle2 size={13} className="text-emerald-400" />
              </div>
            </motion.div>
          ))}
        </div>
      </section>

      {/* SECTION 3: THREAT INTEL ESCALATION RULES */}
      <section className="relative z-10 pt-36 pb-28 px-6 lg:px-12 w-full max-w-[1800px] mx-auto border-t border-slate-800/80">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-10 lg:gap-16 items-stretch">
          {/* Left Column Slide-In */}
          <motion.div
            initial={{ opacity: 0, x: -45 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true, amount: 0.25 }}
            transition={{ duration: 0.75, ease: [0.16, 1, 0.3, 1] }}
            className="space-y-6 flex flex-col justify-between"
          >
            <div className="space-y-4">
              <span className="font-orbitron text-xs font-bold uppercase tracking-[0.25em] text-amber-400 bg-amber-500/10 px-3.5 py-1.5 rounded-full border border-amber-500/30 inline-block shadow-[0_0_15px_rgba(245,158,11,0.2)]">
                Intelligence Escalation
              </span>
              <h2 className="font-syne text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
                Deterministic Threat Intel Escalation Rules
              </h2>
              <p className="font-sans text-slate-300 text-base leading-relaxed">
                When threat intelligence engines detect malicious indicators (AbuseIPDB score ≥ 80 or VirusTotal hits ≥ 5), Flare automatically overrides model-predicted severity to <strong>HIGH / CRITICAL</strong>.
              </p>
            </div>

            <div className="space-y-4 font-mono text-xs">
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.5, delay: 0.2 }}
                className="p-4 bg-slate-900/90 border border-red-500/40 rounded-xl flex items-center justify-between shadow-md hover:border-red-500/70 transition-all"
              >
                <div className="flex items-center gap-3">
                  <ShieldAlert className="text-red-500 animate-pulse" size={22} />
                  <div>
                    <span className="text-white font-bold text-sm block">AbuseIPDB Malicious Score 92/100</span>
                    <span className="text-slate-400 text-xs">IP: 45.13.2.99 · Hostinger International</span>
                  </div>
                </div>
                <span className="text-red-400 font-bold uppercase text-xs bg-red-500/20 px-2.5 py-1 rounded shrink-0">OVERRIDDEN &rarr; HIGH</span>
              </motion.div>

              <motion.div
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.5, delay: 0.35 }}
                className="p-4 bg-slate-900/90 border border-emerald-500/40 rounded-xl flex items-center justify-between shadow-md hover:border-emerald-500/70 transition-all"
              >
                <div className="flex items-center gap-3">
                  <ShieldCheck className="text-emerald-400" size={22} />
                  <div>
                    <span className="text-white font-bold text-sm block">VirusTotal 18 / 70 Engine Detections</span>
                    <span className="text-slate-400 text-xs">IOC Type: IPv4 Address Reputation</span>
                  </div>
                </div>
                <span className="text-emerald-400 font-bold uppercase text-xs bg-emerald-500/20 px-2.5 py-1 rounded shrink-0">CONFIRMED MALICIOUS</span>
              </motion.div>
            </div>
          </motion.div>

          {/* Right Column Slide-In: Grounded RAG Excerpt */}
          <motion.div
            initial={{ opacity: 0, x: 45, scale: 0.95 }}
            whileInView={{ opacity: 1, x: 0, scale: 1 }}
            viewport={{ once: true, amount: 0.25 }}
            transition={{ duration: 0.75, delay: 0.15, ease: [0.16, 1, 0.3, 1] }}
            className="p-7 tactical-glass-card rounded-2xl font-mono text-xs space-y-4 border border-slate-800/80 bg-slate-900/60 backdrop-blur-md shadow-2xl hover:border-purple-500/40 transition-all flex flex-col justify-start"
          >
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <span className="text-slate-200 font-bold text-sm flex items-center gap-2 font-syne">
                <Target size={18} className="text-purple-400" /> Grounded MITRE ATT&CK RAG Excerpt
              </span>
              <span className="text-purple-400 text-xs bg-purple-500/10 px-2.5 py-1 rounded border border-purple-500/30 shadow-[0_0_12px_rgba(168,85,247,0.2)] font-bold">
                Vector Match (0.942)
              </span>
            </div>

            {/* RAG Vector Query Telemetry Strip */}
            <div className="grid grid-cols-3 gap-2 text-[10px] bg-slate-950 p-2.5 rounded-lg border border-slate-800 text-slate-400">
              <div>
                <span className="text-slate-500 block uppercase font-bold text-[9px]">Vector Store</span>
                <span className="text-purple-300 font-bold">Chroma DB (v14.1)</span>
              </div>
              <div>
                <span className="text-slate-500 block uppercase font-bold text-[9px]">Retrieval Time</span>
                <span className="text-emerald-400 font-bold">42ms</span>
              </div>
              <div>
                <span className="text-slate-500 block uppercase font-bold text-[9px]">Distance Metric</span>
                <span className="text-slate-200 font-bold">Cosine 0.058</span>
              </div>
            </div>

            {/* Grounded Technique Excerpt Card */}
            <div className="bg-slate-950 p-4 sm:p-5 rounded-xl border border-purple-500/30 space-y-3 text-slate-300 text-xs shadow-inner">
              <div className="flex justify-between text-slate-400 flex-wrap gap-2 text-xs border-b border-slate-800/80 pb-2">
                <span>Technique: <strong className="text-white font-orbitron">T1059.001 (PowerShell)</strong></span>
                <span>Tactic: <strong className="text-purple-400 font-syne font-bold">Execution</strong></span>
              </div>
              <p className="text-slate-300 italic font-sans leading-relaxed text-xs sm:text-sm">
                &quot;Adversaries may abuse PowerShell commands to execute malicious scripts, download secondary payloads, and bypass traditional endpoint execution policies.&quot;
              </p>
              <div className="pt-2 border-t border-slate-800/80 flex justify-between text-xs text-slate-400 flex-wrap gap-2">
                <span>Ref: Enterprise ATT&CK v14.1</span>
                <span className="text-emerald-400 font-bold">Mitigation: M1047 Audit Policy</span>
              </div>
            </div>

            {/* Actionable Playbook Grounding Footer */}
            <div className="p-3 bg-purple-500/10 border border-purple-500/30 rounded-xl text-purple-300 font-mono text-[11px] flex items-center justify-between gap-2">
              <span className="font-bold text-slate-200">Recommended Policy:</span>
              <span className="text-purple-400 font-semibold truncate">PowerShell Constrained Language Mode (CLM)</span>
            </div>
          </motion.div>
        </div>
      </section>

      {/* SECTION 4: BENCHMARK TIER COMPARISON */}
      <section className="relative z-10 pt-36 pb-28 px-6 lg:px-12 w-full max-w-[1800px] mx-auto border-t border-slate-800/80">
        <motion.div
          initial={{ opacity: 0, y: 40, scale: 0.95 }}
          whileInView={{ opacity: 1, y: 0, scale: 1 }}
          viewport={{ once: true, amount: 0.3 }}
          transition={{ duration: 0.75, ease: [0.16, 1, 0.3, 1] }}
          className="text-center space-y-4 mb-12 sm:mb-16"
        >
          <span className="font-orbitron text-xs font-bold uppercase tracking-[0.25em] text-blue-400 bg-blue-500/10 px-4 py-1.5 rounded-full border border-blue-500/30 inline-block shadow-[0_0_15px_rgba(59,130,246,0.2)]">
            Provider Benchmark Suite
          </span>
          <h2 className="font-syne text-3xl sm:text-5xl font-extrabold text-white tracking-tight">
            Fast Tier vs Quality Tier Model Routing
          </h2>
          <p className="font-sans text-slate-400 text-sm sm:text-base max-w-2xl mx-auto">
            Dual-model routing sends sub-second triage to Groq, reserving Gemini quality reasoning for complex multi-stage attack vectors.
          </p>
        </motion.div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 lg:gap-12">
          {/* Fast Tier Card Slide-In Left */}
          <motion.div
            initial={{ opacity: 0, x: -40, scale: 0.95 }}
            whileInView={{ opacity: 1, x: 0, scale: 1 }}
            viewport={{ once: true, amount: 0.25 }}
            transition={{ duration: 0.7, ease: [0.16, 1, 0.3, 1] }}
            whileHover={{ y: -6, scale: 1.015 }}
            className="p-7 tactical-glass-card rounded-2xl font-mono text-xs space-y-5 cursor-pointer border border-slate-800/80 hover:border-amber-500/50 transition-all bg-slate-900/60 backdrop-blur-md shadow-2xl"
          >
            <div className="flex items-center justify-between border-b border-slate-800 pb-3 flex-wrap gap-2">
              <span className="text-white font-bold text-base flex items-center gap-2 font-syne">
                <Zap size={20} className="text-amber-400" /> Fast Tier (Groq Llama-3.1-8B)
              </span>
              <span className="text-amber-400 text-xs bg-amber-500/10 px-2.5 py-1 rounded border border-amber-500/30 font-bold">
                Sub-Second Triage
              </span>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-slate-300">
              {[
                { label: 'p50 Latency', val: '84ms', color: 'text-emerald-400' },
                { label: 'Cost / 1k', val: '$0.42', color: 'text-white' },
                { label: 'Precision', val: '91.1%', color: 'text-white' },
                { label: 'Recall', val: '87.6%', color: 'text-white' },
              ].map((stat, i) => (
                <motion.div
                  key={stat.label}
                  initial={{ opacity: 0, scale: 0.88 }}
                  whileInView={{ opacity: 1, scale: 1 }}
                  viewport={{ once: true }}
                  transition={{ duration: 0.4, delay: 0.2 + i * 0.08 }}
                  className="bg-slate-950 p-4 rounded-xl border border-slate-800 hover:border-slate-700 transition-colors"
                >
                  <span className="text-xs text-slate-400 block mb-1">{stat.label}</span>
                  <span className={`text-2xl font-orbitron font-bold ${stat.color}`}>{stat.val}</span>
                </motion.div>
              ))}
            </div>
          </motion.div>

          {/* Quality Tier Card Slide-In Right */}
          <motion.div
            initial={{ opacity: 0, x: 40, scale: 0.95 }}
            whileInView={{ opacity: 1, x: 0, scale: 1 }}
            viewport={{ once: true, amount: 0.25 }}
            transition={{ duration: 0.7, delay: 0.12, ease: [0.16, 1, 0.3, 1] }}
            whileHover={{ y: -6, scale: 1.015 }}
            className="p-7 tactical-glass-card rounded-2xl font-mono text-xs space-y-5 cursor-pointer border border-slate-800/80 hover:border-blue-500/50 transition-all bg-slate-900/60 backdrop-blur-md shadow-2xl"
          >
            <div className="flex items-center justify-between border-b border-slate-800 pb-3 flex-wrap gap-2">
              <span className="text-white font-bold text-base flex items-center gap-2 font-syne">
                <Cpu size={20} className="text-blue-400" /> Quality Tier (Gemini Flash)
              </span>
              <span className="text-blue-400 text-xs bg-blue-500/10 px-2.5 py-1 rounded border border-blue-500/30 font-bold">
                Deep Triage Reasoning
              </span>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-slate-300">
              {[
                { label: 'p50 Latency', val: '920ms', color: 'text-amber-400' },
                { label: 'Cost / 1k', val: '$4.80', color: 'text-white' },
                { label: 'Precision', val: '96.2%', color: 'text-emerald-400' },
                { label: 'Recall', val: '94.1%', color: 'text-emerald-400' },
              ].map((stat, i) => (
                <motion.div
                  key={stat.label}
                  initial={{ opacity: 0, scale: 0.88 }}
                  whileInView={{ opacity: 1, scale: 1 }}
                  viewport={{ once: true }}
                  transition={{ duration: 0.4, delay: 0.3 + i * 0.08 }}
                  className="bg-slate-950 p-4 rounded-xl border border-slate-800 hover:border-slate-700 transition-colors"
                >
                  <span className="text-xs text-slate-400 block mb-1">{stat.label}</span>
                  <span className={`text-2xl font-orbitron font-bold ${stat.color}`}>{stat.val}</span>
                </motion.div>
              ))}
            </div>
          </motion.div>
        </div>
      </section>

      {/* SECTION 5: FINAL LAUNCH CTA & FOOTER */}
      <section className="relative z-10 pt-36 pb-28 px-6 lg:px-12 w-full max-w-[1400px] mx-auto text-center">
        <motion.div
          initial={{ opacity: 0, y: 50, scale: 0.92 }}
          whileInView={{ opacity: 1, y: 0, scale: 1 }}
          viewport={{ once: true, amount: 0.3 }}
          transition={{ duration: 0.85, ease: [0.16, 1, 0.3, 1] }}
          className="p-8 sm:p-14 rounded-3xl tactical-glass-card space-y-6 border border-slate-800/80 bg-slate-900/60 backdrop-blur-md shadow-2xl hover:border-red-500/40 transition-all"
        >
          <motion.div
            animate={{ scale: [1, 1.08, 1] }}
            transition={{ duration: 3, repeat: Infinity, ease: 'easeInOut' }}
            className="w-16 h-16 rounded-2xl bg-red-950/60 border border-red-500/40 mx-auto flex items-center justify-center p-3 shadow-[0_0_25px_rgba(239,68,68,0.35)]"
          >
            <img src="/logo.png" alt="Flare Logo" className="w-full h-full object-contain filter drop-shadow-[0_0_12px_rgba(239,68,68,0.9)]" />
          </motion.div>

          <h2 className="font-syne text-3xl sm:text-5xl font-black text-white tracking-tight">
            Launch Flare Command OS
          </h2>
          <p className="font-sans text-slate-400 text-sm sm:text-base max-w-md mx-auto">
            Access live security telemetry dashboard, inspect LangGraph traces, and prompt the Mercury AI Command Engine.
          </p>

          <motion.button
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.96 }}
            onClick={onEnter}
            className="group relative px-10 py-4 bg-gradient-to-r from-red-600 via-red-500 to-orange-500 hover:from-red-500 hover:to-orange-400 rounded-xl inline-flex items-center gap-3 transition-all shadow-[0_0_35px_rgba(239,68,68,0.45)] hover:shadow-[0_0_45px_rgba(239,68,68,0.65)] text-white font-mono text-sm uppercase tracking-wider font-bold cursor-pointer"
          >
            <span>Open Triage Dashboard</span>
            <ArrowRight size={18} className="group-hover:translate-x-1.5 transition-transform text-white" />
          </motion.button>
        </motion.div>

        <footer className="mt-16 sm:mt-20 pt-8 border-t border-slate-800/80 font-mono text-xs text-slate-500 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span>FastAPI + LangGraph + SQLite + ChromaDB Active</span>
          </div>
          <span>Flare AI Security Incident Triage Agent</span>
        </footer>
      </section>

      {/* 3D Infinite Perspective Cyber Laser Grid Floor */}
      <div className="fixed bottom-0 inset-x-0 h-48 pointer-events-none z-0 opacity-20 overflow-hidden">
        <div className="w-full h-full bg-[linear-gradient(to_right,#ef444420_1px,transparent_1px),linear-gradient(to_bottom,#ef444420_1px,transparent_1px)] bg-[size:3rem_3rem] [transform:perspective(500px)_rotateX(60deg)] animate-grid-flow origin-bottom" />
      </div>
    </motion.div>
  );
}
