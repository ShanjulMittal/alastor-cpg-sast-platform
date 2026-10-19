"use client";

import React, { useState, useEffect, useRef } from "react";
import { useAuditStore } from "@/store/useAuditStore";
import { AppThemeId, BackdropIntensity } from "@/types/cpg";
import {
  Sun,
  Moon,
  Palette,
  Sparkles,
  Check,
  Flame,
  Eye,
  ShieldAlert,
} from "lucide-react";

export interface AlastorThemeSpec {
  id: AppThemeId;
  name: string;
  subtitle: string;
  mode: "light" | "dark";
  badge: string;
  swatches: [string, string, string, string];
}

export const ALASTOR_THEMES: AlastorThemeSpec[] = [
  // LIGHT THEMES
  {
    id: "olympian-light",
    name: "Olympian Daylight",
    subtitle: "Crisp Alabaster White, Cool Marble Slate & Royal Crimson-Gold",
    mode: "light",
    badge: "LIGHT • CRISP",
    swatches: ["#f3f6fb", "#ffffff", "#0f172a", "#e11d48"],
  },
  {
    id: "athena-parchment",
    name: "Athena Parchment",
    subtitle: "Eye-Friendly Warm Ivory, Classical Gold & Espresso Ink",
    mode: "light",
    badge: "LIGHT • WARM",
    swatches: ["#f6f0e4", "#fefbf5", "#1c1510", "#b45309"],
  },
  {
    id: "hyperborean-light",
    name: "Hyperborean Frost",
    subtitle: "Glacier Ice Azure, Pure White & Deep Sapphire Ink",
    mode: "light",
    badge: "LIGHT • COOL",
    swatches: ["#ebf4fc", "#fafdff", "#09192e", "#0284c7"],
  },
  // DARK & MYTHIC THEMES
  {
    id: "alastor-infernal",
    name: "Alastor Infernal",
    subtitle: "Mythological Demon Obsidian, Molten Gold & Crimson Ember",
    mode: "dark",
    badge: "MYTHIC DEFAULT",
    swatches: ["#0b0609", "#170b10", "#e11d48", "#f59e0b"],
  },
  {
    id: "hecate-arcane",
    name: "Hecate Arcane",
    subtitle: "Astral Amethyst Void, Deep Indigo & Eldritch Magenta",
    mode: "dark",
    badge: "DARK • VIOLET",
    swatches: ["#090514", "#180b28", "#a855f7", "#ec4899"],
  },
  {
    id: "stygian-abyss",
    name: "Stygian Abyss",
    subtitle: "Classic Deep Zinc Obsidian, Cobalt & Electric Stygian Cyan",
    mode: "dark",
    badge: "DARK • CYBER",
    swatches: ["#09090b", "#18181b", "#06b6d4", "#3b82f6"],
  },
];

export function isLightAppTheme(themeId: AppThemeId): boolean {
  return (
    themeId === "olympian-light" ||
    themeId === "athena-parchment" ||
    themeId === "hyperborean-light"
  );
}

/**
 * Vector SVG Mythological Horned Demon / Daimon Emblem for ALASTOR.
 * Combines swept demon wings, curved obsidian/gold horns, glowing crimson eyes of Nemesis,
 * and an arcane hexagonal CPG sigil.
 */
export function AlastorDemonCrestSvg({
  className = "w-7 h-7",
}: {
  className?: string;
}) {
  return (
    <svg
      viewBox="0 0 120 120"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
    >
      <defs>
        <linearGradient id="alastorHornGrad" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#fde68a" />
          <stop offset="45%" stopColor="#f59e0b" />
          <stop offset="100%" stopColor="#be123c" />
        </linearGradient>
        <linearGradient id="alastorWingGrad" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#f43f5e" />
          <stop offset="55%" stopColor="#9f1239" />
          <stop offset="100%" stopColor="#4c0519" />
        </linearGradient>
        <linearGradient id="alastorArmorGrad" x1="50%" y1="0%" x2="50%" y2="100%">
          <stop offset="0%" stopColor="#3f3f46" />
          <stop offset="50%" stopColor="#18181b" />
          <stop offset="100%" stopColor="#09090b" />
        </linearGradient>
      </defs>

      {/* Outer Arcane Hexagram Ring */}
      <circle
        cx="60"
        cy="62"
        r="52"
        stroke="url(#alastorHornGrad)"
        strokeWidth="1.5"
        strokeDasharray="4 3"
        opacity="0.55"
      />

      {/* Swept Mythological Demon Wings (Left & Right) */}
      <path
        d="M52 68 L10 26 C14 44 21 56 32 66 L12 48 C18 63 28 73 42 78 L18 68 C26 81 38 88 52 90 Z"
        fill="url(#alastorWingGrad)"
        stroke="#f59e0b"
        strokeWidth="1.4"
        strokeLinejoin="round"
      />
      <path
        d="M68 68 L110 26 C106 44 99 56 88 66 L108 48 C102 63 92 73 78 78 L102 68 C94 81 82 88 68 90 Z"
        fill="url(#alastorWingGrad)"
        stroke="#f59e0b"
        strokeWidth="1.4"
        strokeLinejoin="round"
      />

      {/* Great Curved Infernal Horns */}
      <path
        d="M46 46 C26 38 18 20 34 8 C29 21 35 32 52 38 Z"
        fill="url(#alastorHornGrad)"
        stroke="#fef08a"
        strokeWidth="1.3"
      />
      <path
        d="M74 46 C94 38 102 20 86 8 C91 21 85 32 68 38 Z"
        fill="url(#alastorHornGrad)"
        stroke="#fef08a"
        strokeWidth="1.3"
      />

      {/* Inner Crown Spikes */}
      <path
        d="M48 39 L43 22 L54 35 L60 18 L66 35 L77 22 L72 39 Z"
        fill="url(#alastorHornGrad)"
      />

      {/* Armored Daimon Visage / Skull Mask */}
      <path
        d="M42 40 L60 32 L78 40 L82 60 L72 82 L60 95 L48 82 L38 60 Z"
        fill="url(#alastorArmorGrad)"
        stroke="url(#alastorHornGrad)"
        strokeWidth="2.2"
        strokeLinejoin="round"
      />

      {/* Piercing Glowing Crimson-Amber Demon Eyes */}
      <polygon
        points="44,54 56,59 47,62"
        fill="#fef08a"
        stroke="#ef4444"
        strokeWidth="1.5"
      />
      <polygon
        points="76,54 64,59 73,62"
        fill="#fef08a"
        stroke="#ef4444"
        strokeWidth="1.5"
      />

      {/* Fanged Jaw & Chin Crest */}
      <path
        d="M48 72 L53 79 L56 73 L60 78 L64 73 L67 79 L72 72"
        stroke="#f59e0b"
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
      />

      {/* Glowing Chest Hexagram CPG Core Sigil */}
      <polygon
        points="60,84 71,102 49,102"
        stroke="#f43f5e"
        strokeWidth="1.6"
        fill="rgba(225,29,72,0.28)"
      />
      <polygon
        points="60,106 71,88 49,88"
        stroke="#f59e0b"
        strokeWidth="1.6"
        fill="rgba(245,158,11,0.2)"
      />
      <circle cx="60" cy="95" r="3.2" fill="#fef08a" />
    </svg>
  );
}

/**
 * Interactive Top-Bar Brand Emblem & Lore Popover for ALASTOR.
 */
export function AlastorBrandHeader() {
  const [showCrestModal, setShowCrestModal] = useState(false);
  const [imgError, setImgError] = useState(false);

  return (
    <div className="relative flex items-center gap-2.5">
      <button
        type="button"
        onClick={() => setShowCrestModal((v) => !v)}
        title="ALASTOR — Mythological Spirit of Retribution & Deterministic CPG Security Engine (Click to view Demon Crest)"
        className="group relative w-9 h-9 rounded-xl bg-gradient-to-br from-rose-950 via-zinc-950 to-amber-950 p-0.5 border border-amber-500/60 shadow-lg shadow-rose-600/25 hover:border-amber-400 hover:scale-105 transition-all flex items-center justify-center overflow-hidden"
      >
        {!imgError ? (
          <img
            src="/alastor-demon-logo.png"
            alt="Alastor Demon Crest"
            onError={() => setImgError(true)}
            className="w-full h-full object-cover rounded-[10px]"
          />
        ) : (
          <AlastorDemonCrestSvg className="w-7 h-7" />
        )}
        <span className="absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 rounded-full bg-rose-500 border border-amber-300 animate-pulse" />
      </button>

      <div
        className="hidden sm:block cursor-pointer"
        onClick={() => setShowCrestModal((v) => !v)}
      >
        <h1 className="text-sm font-black tracking-wider text-zinc-100 flex items-center gap-1.5">
          <span className="bg-gradient-to-r from-amber-400 via-rose-500 to-amber-300 bg-clip-text text-transparent drop-shadow-sm">
            ALASTOR
          </span>
          <span className="text-[9px] font-mono font-bold px-1.5 py-0.2 rounded bg-rose-950/90 text-amber-300 border border-rose-700/80 tracking-widest">
            DAIMON CPG
          </span>
        </h1>
        <p className="text-[10px] text-zinc-400 font-medium tracking-tight">
          Nemesis of Code Flaws • SAST • SCA • IaC
        </p>
      </div>

      {/* Mythological Crest & Lore Showcase Popover */}
      {showCrestModal && (
        <div className="absolute left-0 top-12 w-80 rounded-2xl bg-zinc-950 border border-amber-600/60 shadow-2xl p-4 z-50 text-left space-y-3">
          <div className="flex items-center justify-between border-b border-zinc-800 pb-2">
            <div className="flex items-center gap-1.5">
              <Flame className="w-4 h-4 text-rose-500" />
              <span className="text-xs font-black tracking-wider uppercase text-zinc-100">
                ALASTOR • Ἀλάστωρ
              </span>
            </div>
            <button
              type="button"
              onClick={() => setShowCrestModal(false)}
              className="text-[10px] font-mono text-zinc-400 hover:text-zinc-100 px-1.5 py-0.5 rounded bg-zinc-900 border border-zinc-800"
            >
              ESC
            </button>
          </div>

          <div className="relative rounded-xl overflow-hidden border border-amber-500/40 bg-black aspect-square max-h-52 mx-auto flex items-center justify-center shadow-inner">
            <img
              src="/alastor-demon-logo.png"
              alt="Alastor Mythological Demon Crest"
              className="w-full h-full object-contain"
            />
          </div>

          <div className="space-y-1.5 text-[11px] text-zinc-300 leading-relaxed">
            <p>
              In ancient Greek mythology, <b className="text-amber-400">Alastor</b>{" "}
              (<i>&ldquo;The Unforgetting Avenger&rdquo;</i>) is the relentless{" "}
              <b className="text-rose-400">Daimon of Retribution</b> who tracks down
              hidden corruptions and unseen sins so that no flaw escapes judgment.
            </p>
            <p className="text-[10px] text-zinc-400 font-mono border-t border-zinc-800 pt-1.5">
              Deterministic Code Property Graph (AST + CFG + DFG) • Unified SAST, SCA &amp; IaC
            </p>
          </div>
        </div>
      )}
    </div>
  );
}

/**
 * Full-Viewport Atmospheric Mythological Demon & Arcane Sigil Background.
 * Adapts smoothly to both Light Themes and Dark/Mythic Themes.
 */
export function AlastorMythicBackground() {
  const appTheme = useAuditStore((s) => s.appTheme);
  const backdropIntensity = useAuditStore((s) => s.backdropIntensity);
  const isLight = isLightAppTheme(appTheme);

  if (backdropIntensity === "MINIMAL") {
    return null;
  }

  const imageOpacity =
    backdropIntensity === "VIVID"
      ? isLight
        ? "opacity-[0.09]"
        : "opacity-[0.24]"
      : isLight
      ? "opacity-[0.045]"
      : "opacity-[0.12]";

  const sigilOpacity =
    backdropIntensity === "VIVID"
      ? isLight
        ? "opacity-[0.22]"
        : "opacity-[0.30]"
      : isLight
      ? "opacity-[0.11]"
      : "opacity-[0.15]";

  return (
    <div
      aria-hidden="true"
      className="pointer-events-none fixed inset-0 z-0 overflow-hidden select-none"
    >
      {/* Layer 1: Mythological Sanctuary & Demon Guardian Artwork */}
      <div
        className={`absolute inset-0 bg-cover bg-center bg-no-repeat transition-opacity duration-500 ${imageOpacity} ${
          isLight ? "mix-blend-multiply filter contrast-125" : "mix-blend-screen"
        }`}
        style={{
          backgroundImage: `url('/alastor-mythic-bg.png')`,
        }}
      />

      {/* Layer 2: Ambient Mythological Radial Glows */}
      <div
        className="absolute inset-0"
        style={{
          background: `
            radial-gradient(circle at 50% 42%, var(--alastor-glow-primary), transparent 62%),
            radial-gradient(circle at 18% 82%, var(--alastor-glow-secondary), transparent 50%),
            radial-gradient(circle at 85% 18%, var(--alastor-glow-secondary), transparent 48%)
          `,
        }}
      />

      {/* Layer 3: Rotating Arcane Greek & Demon CPG Sigil Watermark */}
      <div
        className={`absolute inset-0 flex items-center justify-center transition-opacity duration-500 ${sigilOpacity}`}
      >
        <div className="relative w-[640px] h-[640px] flex items-center justify-center">
          {/* Outer Rotating Sacred Geometry Ring */}
          <svg
            viewBox="0 0 500 500"
            className="absolute inset-0 w-full h-full animate-alastor-sigil"
          >
            <circle
              cx="250"
              cy="250"
              r="232"
              fill="none"
              stroke="var(--alastor-sigil-stroke)"
              strokeWidth="1.5"
              strokeDasharray="8 6"
            />
            <circle
              cx="250"
              cy="250"
              r="212"
              fill="none"
              stroke="var(--alastor-sigil-stroke)"
              strokeWidth="1"
            />
            {/* Hexagram of Retribution */}
            <polygon
              points="250,38 433,356 67,356"
              fill="none"
              stroke="var(--alastor-sigil-stroke)"
              strokeWidth="1.3"
            />
            <polygon
              points="250,462 433,144 67,144"
              fill="none"
              stroke="var(--alastor-sigil-stroke)"
              strokeWidth="1.3"
            />
          </svg>

          {/* Counter-Rotating Inner Arcane CPG Ring */}
          <svg
            viewBox="0 0 500 500"
            className="absolute inset-0 w-full h-full animate-alastor-sigil-reverse"
          >
            <circle
              cx="250"
              cy="250"
              r="156"
              fill="none"
              stroke="var(--alastor-sigil-stroke)"
              strokeWidth="1.5"
              strokeDasharray="4 8"
            />
            <rect
              x="140"
              y="140"
              width="220"
              height="220"
              fill="none"
              stroke="var(--alastor-sigil-stroke)"
              strokeWidth="1"
              transform="rotate(45 250 250)"
            />
          </svg>

          {/* Center Horned Demon Crest Watermark */}
          <div className="w-52 h-52 flex items-center justify-center opacity-70">
            <AlastorDemonCrestSvg className="w-44 h-44" />
          </div>
        </div>
      </div>
    </div>
  );
}

/**
 * Top-Bar Theme & Appearance Switcher:
 * - 1-Click Light / Dark Mode Quick Toggle
 * - 6 Curated Themes (3 Light Themes + 3 Mythic/Dark Themes)
 * - Mythic Demon Backdrop Intensity Selector (Vivid / Subtle / Minimal)
 */
export function AlastorThemeSwitcher() {
  const appTheme = useAuditStore((s) => s.appTheme);
  const setAppTheme = useAuditStore((s) => s.setAppTheme);
  const backdropIntensity = useAuditStore((s) => s.backdropIntensity);
  const setBackdropIntensity = useAuditStore((s) => s.setBackdropIntensity);

  const [open, setOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement | null>(null);

  const currentSpec =
    ALASTOR_THEMES.find((t) => t.id === appTheme) || ALASTOR_THEMES[3];
  const isLight = isLightAppTheme(appTheme);

  // Sync theme attributes to <html> and restore from localStorage on mount
  useEffect(() => {
    try {
      const savedTheme = localStorage.getItem("alastor_app_theme_v3") as AppThemeId | null;
      const savedBackdrop = localStorage.getItem(
        "alastor_backdrop_intensity"
      ) as BackdropIntensity | null;
      if (savedTheme && ALASTOR_THEMES.some((t) => t.id === savedTheme)) {
        setAppTheme(savedTheme);
      }
      if (
        savedBackdrop &&
        ["VIVID", "SUBTLE", "MINIMAL"].includes(savedBackdrop)
      ) {
        setBackdropIntensity(savedBackdrop);
      }
    } catch {}
  }, [setAppTheme, setBackdropIntensity]);

  useEffect(() => {
    if (typeof document !== "undefined") {
      const htmlEl = document.documentElement;
      htmlEl.setAttribute("data-theme", appTheme);
      htmlEl.setAttribute("data-theme-mode", isLight ? "light" : "dark");
      if (isLight) {
        htmlEl.classList.remove("dark");
        htmlEl.classList.add("light");
      } else {
        htmlEl.classList.remove("light");
        htmlEl.classList.add("dark");
      }
    }
  }, [appTheme, isLight]);

  // Close popover on outside click
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    if (open) {
      document.addEventListener("mousedown", handleClickOutside);
    }
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [open]);

  const toggleQuickLightDark = () => {
    if (isLight) {
      setAppTheme("alastor-infernal");
    } else {
      setAppTheme("olympian-light");
    }
  };

  const lightThemes = ALASTOR_THEMES.filter((t) => t.mode === "light");
  const darkThemes = ALASTOR_THEMES.filter((t) => t.mode === "dark");

  return (
    <div ref={menuRef} className="relative flex items-center gap-1 shrink-0">
      {/* 1-Click Quick Light / Dark Mode Toggle */}
      <button
        type="button"
        onClick={toggleQuickLightDark}
        title={
          isLight
            ? "Currently in Light Mode — Click to switch to Alastor Infernal Dark"
            : "Currently in Dark Mode — Click to switch to Olympian Daylight (Light Mode)"
        }
        className={`px-2 py-1 rounded-md border text-xs font-medium flex items-center gap-1 transition-all ${
          isLight
            ? "bg-amber-950/80 border-amber-700 text-amber-300 hover:bg-amber-900/60"
            : "bg-zinc-900 border-zinc-700 text-amber-300 hover:bg-zinc-800"
        }`}
      >
        {isLight ? (
          <>
            <Sun className="w-3.5 h-3.5 text-amber-500" />
            <span className="hidden 2xl:inline text-[11px] font-semibold">
              Light
            </span>
          </>
        ) : (
          <>
            <Moon className="w-3.5 h-3.5 text-rose-400" />
            <span className="hidden 2xl:inline text-[11px] font-semibold">
              Dark
            </span>
          </>
        )}
      </button>

      {/* Full Theme Palette Picker Button */}
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        title="Choose Color Theme (Light Themes, Warm Parchment, Alastor Infernal Demon, Arcane Violet, Cyber Abyss)"
        className={`px-2 py-1 rounded-md border text-xs font-medium flex items-center gap-1.5 transition-all ${
          open
            ? "bg-rose-950/90 border-rose-600 text-amber-300"
            : "bg-zinc-900 hover:bg-zinc-800 border-zinc-700 text-zinc-200"
        }`}
      >
        <Palette className="w-3.5 h-3.5 text-rose-400" />
        <span className="hidden xl:inline text-[11px] truncate max-w-[92px]">
          {currentSpec.name.split(" ")[0]}
        </span>
        <span className="flex items-center -space-x-1">
          {currentSpec.swatches.slice(0, 3).map((hex, idx) => (
            <span
              key={idx}
              className="w-2.5 h-2.5 rounded-full border border-zinc-600"
              style={{ backgroundColor: hex }}
            />
          ))}
        </span>
      </button>

      {/* Theme & Mythic Backdrop Dropdown Modal */}
      {open && (
        <div className="absolute right-0 top-10 w-80 rounded-2xl bg-zinc-950 border border-zinc-700 shadow-2xl p-3 z-50 space-y-3 text-left">
          <div className="flex items-center justify-between border-b border-zinc-800 pb-2">
            <span className="text-xs font-bold uppercase tracking-wider text-zinc-100 flex items-center gap-1.5">
              <Palette className="w-3.5 h-3.5 text-rose-400" />
              Alastor Themes &amp; Light Mode
            </span>
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-zinc-900 border border-zinc-800 text-zinc-400">
              6 Palettes
            </span>
          </div>

          {/* Section 1: Light Themes */}
          <div className="space-y-1.5">
            <div className="text-[10px] font-mono font-bold uppercase tracking-wider text-amber-400 flex items-center gap-1">
              <Sun className="w-3 h-3" />
              Light &amp; Daylight Themes
            </div>
            <div className="space-y-1">
              {lightThemes.map((t) => {
                const active = appTheme === t.id;
                return (
                  <button
                    key={t.id}
                    type="button"
                    onClick={() => setAppTheme(t.id)}
                    className={`w-full p-2 rounded-xl border text-left transition-all flex items-center justify-between gap-2 ${
                      active
                        ? "bg-amber-950/40 border-amber-500 shadow-sm"
                        : "bg-zinc-900/70 border-zinc-800 hover:border-zinc-700"
                    }`}
                  >
                    <div className="min-w-0">
                      <div className="flex items-center gap-1.5">
                        <span className="text-xs font-bold text-zinc-100">
                          {t.name}
                        </span>
                        <span className="text-[9px] font-mono px-1.5 py-0.1 rounded bg-amber-950 text-amber-300 border border-amber-700/70">
                          {t.badge}
                        </span>
                      </div>
                      <p className="text-[10px] text-zinc-400 truncate mt-0.5">
                        {t.subtitle}
                      </p>
                    </div>
                    <div className="flex items-center gap-1 shrink-0">
                      <div className="flex items-center -space-x-1">
                        {t.swatches.map((hex, i) => (
                          <span
                            key={i}
                            className="w-3.5 h-3.5 rounded-full border border-zinc-500 shadow-sm"
                            style={{ backgroundColor: hex }}
                          />
                        ))}
                      </div>
                      {active && <Check className="w-3.5 h-3.5 text-emerald-400 ml-1" />}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Section 2: Mythic Demon & Dark Themes */}
          <div className="space-y-1.5 pt-1 border-t border-zinc-800">
            <div className="text-[10px] font-mono font-bold uppercase tracking-wider text-rose-400 flex items-center gap-1">
              <Flame className="w-3 h-3" />
              Mythic Demon &amp; Dark Themes
            </div>
            <div className="space-y-1">
              {darkThemes.map((t) => {
                const active = appTheme === t.id;
                return (
                  <button
                    key={t.id}
                    type="button"
                    onClick={() => setAppTheme(t.id)}
                    className={`w-full p-2 rounded-xl border text-left transition-all flex items-center justify-between gap-2 ${
                      active
                        ? "bg-rose-950/40 border-rose-500 shadow-sm"
                        : "bg-zinc-900/70 border-zinc-800 hover:border-zinc-700"
                    }`}
                  >
                    <div className="min-w-0">
                      <div className="flex items-center gap-1.5">
                        <span className="text-xs font-bold text-zinc-100">
                          {t.name}
                        </span>
                        <span className="text-[9px] font-mono px-1.5 py-0.1 rounded bg-rose-950 text-rose-300 border border-rose-700/70">
                          {t.badge}
                        </span>
                      </div>
                      <p className="text-[10px] text-zinc-400 truncate mt-0.5">
                        {t.subtitle}
                      </p>
                    </div>
                    <div className="flex items-center gap-1 shrink-0">
                      <div className="flex items-center -space-x-1">
                        {t.swatches.map((hex, i) => (
                          <span
                            key={i}
                            className="w-3.5 h-3.5 rounded-full border border-zinc-600 shadow-sm"
                            style={{ backgroundColor: hex }}
                          />
                        ))}
                      </div>
                      {active && <Check className="w-3.5 h-3.5 text-emerald-400 ml-1" />}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Section 3: Mythological Demon Background Intensity */}
          <div className="pt-2 border-t border-zinc-800 space-y-1.5">
            <div className="flex items-center justify-between text-[10px] font-mono text-zinc-400">
              <span className="flex items-center gap-1 font-bold uppercase text-zinc-300">
                <Eye className="w-3 h-3 text-amber-400" />
                Mythic Demon Background
              </span>
              <span>{backdropIntensity}</span>
            </div>
            <div className="grid grid-cols-3 gap-1 bg-zinc-900 p-1 rounded-lg border border-zinc-800">
              {(["VIVID", "SUBTLE", "MINIMAL"] as BackdropIntensity[]).map(
                (lvl) => (
                  <button
                    key={lvl}
                    type="button"
                    onClick={() => setBackdropIntensity(lvl)}
                    className={`py-1 rounded text-[10px] font-mono font-bold transition-colors ${
                      backdropIntensity === lvl
                        ? "bg-rose-950 text-amber-300 border border-rose-700/80"
                        : "text-zinc-400 hover:text-zinc-200"
                    }`}
                  >
                    {lvl === "VIVID"
                      ? "Vivid Art"
                      : lvl === "SUBTLE"
                      ? "Subtle"
                      : "Off"}
                  </button>
                )
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
