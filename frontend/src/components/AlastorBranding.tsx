"use client";

import React, { useState, useEffect, useRef } from "react";
import { useAuditStore } from "@/store/useAuditStore";
import { AppThemeId, BackdropIntensity } from "@/types/cpg";
import {
  Sun,
  Palette,
  Check,
  Flame,
  Eye,
} from "lucide-react";

export interface AlastorThemeSpec {
  id: AppThemeId;
  name: string;
  subtitle: string;
  mode: "light";
  badge: string;
  swatches: [string, string, string, string];
}

export const ALASTOR_THEMES: AlastorThemeSpec[] = [
  {
    id: "olympian-light",
    name: "Olympian Daylight",
    subtitle: "Crisp High-Contrast Slate, Pure White & Royal Crimson-Gold",
    mode: "light",
    badge: "DEFAULT • CRISP",
    swatches: ["#f8fafc", "#ffffff", "#0f172a", "#be123c"],
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
];

export function isLightAppTheme(_themeId?: AppThemeId | string): boolean {
  return true;
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
        className="group relative w-9 h-9 rounded-xl bg-white p-0.5 border border-amber-500/70 shadow-sm hover:border-rose-500 hover:scale-105 transition-all flex items-center justify-center overflow-hidden"
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
        <span className="absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 rounded-full bg-rose-600 border border-white" />
      </button>

      <div
        className="hidden sm:block cursor-pointer"
        onClick={() => setShowCrestModal((v) => !v)}
      >
        <h1 className="text-sm font-black tracking-wider text-slate-900 flex items-center gap-1.5">
          <span className="bg-gradient-to-r from-rose-700 via-amber-700 to-rose-800 bg-clip-text text-transparent">
            ALASTOR
          </span>
          <span className="text-[9px] font-mono font-bold px-1.5 py-0.2 rounded bg-rose-50 text-rose-800 border border-rose-200 tracking-widest">
            DAIMON CPG
          </span>
        </h1>
        <p className="text-[10px] text-slate-600 font-medium tracking-tight">
          Nemesis of Code Flaws • SAST • SCA • IaC
        </p>
      </div>

      {/* Mythological Crest & Lore Showcase Popover */}
      {showCrestModal && (
        <div className="absolute left-0 top-12 w-80 rounded-2xl bg-white border border-slate-300 shadow-2xl p-4 z-50 text-left space-y-3">
          <div className="flex items-center justify-between border-b border-slate-200 pb-2">
            <div className="flex items-center gap-1.5">
              <Flame className="w-4 h-4 text-rose-600" />
              <span className="text-xs font-black tracking-wider uppercase text-slate-900">
                ALASTOR • Ἀλάστωρ
              </span>
            </div>
            <button
              type="button"
              onClick={() => setShowCrestModal(false)}
              className="text-[10px] font-mono text-slate-600 hover:text-slate-900 px-1.5 py-0.5 rounded bg-slate-100 border border-slate-300"
            >
              ESC
            </button>
          </div>

          <div className="relative rounded-xl overflow-hidden border border-slate-200 bg-slate-50 aspect-square max-h-52 mx-auto flex items-center justify-center shadow-inner">
            <img
              src="/alastor-demon-logo.png"
              alt="Alastor Mythological Demon Crest"
              className="w-full h-full object-contain"
            />
          </div>

          <div className="space-y-1.5 text-[11px] text-slate-700 leading-relaxed">
            <p>
              In ancient Greek mythology, <b className="text-amber-700">Alastor</b>{" "}
              (<i>&ldquo;The Unforgetting Avenger&rdquo;</i>) is the relentless{" "}
              <b className="text-rose-700">Daimon of Retribution</b> who tracks down
              hidden corruptions and unseen sins so that no flaw escapes judgment.
            </p>
            <p className="text-[10px] text-slate-500 font-mono border-t border-slate-200 pt-1.5">
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
 * Strictly calibrated for High-Contrast Daylight Themes.
 */
export function AlastorMythicBackground() {
  const backdropIntensity = useAuditStore((s) => s.backdropIntensity);
  const showPortalGate = useAuditStore((s) => s.showPortalGate);

  if (backdropIntensity === "MINIMAL") {
    return null;
  }

  const isVividOrGate = backdropIntensity === "VIVID" || showPortalGate;

  const imageOpacity =
    backdropIntensity === "VIVID"
      ? "opacity-[0.06]"
      : showPortalGate
      ? "opacity-[0.035]"
      : "opacity-[0.012]";

  const sigilOpacity =
    backdropIntensity === "VIVID"
      ? "opacity-[0.14]"
      : showPortalGate
      ? "opacity-[0.08]"
      : "opacity-[0.025]";

  const outerSpinClass = isVividOrGate ? "animate-alastor-sigil" : "";
  const innerSpinClass = isVividOrGate ? "animate-alastor-sigil-reverse" : "";

  return (
    <div
      aria-hidden="true"
      className="pointer-events-none fixed inset-0 z-0 overflow-hidden select-none"
    >
      {/* Layer 1: Mythological Sanctuary & Demon Guardian Artwork */}
      <div
        className={`absolute inset-0 bg-cover bg-center bg-no-repeat transition-opacity duration-500 ${imageOpacity} mix-blend-multiply filter contrast-125`}
        style={{
          backgroundImage: `url('/alastor-mythic-bg.png')`,
        }}
      />

      {/* Layer 2: Ambient Daylight Radial Accents */}
      <div
        className={`absolute inset-0 transition-opacity duration-500 ${
          isVividOrGate ? "opacity-80" : "opacity-30"
        }`}
        style={{
          background: `
            radial-gradient(circle at 50% 42%, var(--alastor-glow-primary), transparent 62%),
            radial-gradient(circle at 18% 82%, var(--alastor-glow-secondary), transparent 50%),
            radial-gradient(circle at 85% 18%, var(--alastor-glow-secondary), transparent 48%)
          `,
        }}
      />

      {/* Layer 3: Arcane Greek & Demon CPG Sigil Watermark */}
      <div
        className={`absolute inset-0 flex items-center justify-center transition-opacity duration-500 ${sigilOpacity}`}
      >
        <div className="relative w-[640px] h-[640px] flex items-center justify-center">
          {/* Outer Sacred Geometry Ring */}
          <svg
            viewBox="0 0 500 500"
            className={`absolute inset-0 w-full h-full ${outerSpinClass}`}
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

          {/* Inner Arcane CPG Ring */}
          <svg
            viewBox="0 0 500 500"
            className={`absolute inset-0 w-full h-full ${innerSpinClass}`}
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
 * Top-Bar Daylight Theme & Appearance Switcher:
 * - 3 Curated High-Contrast Daylight Palettes (Olympian, Athena Parchment, Hyperborean Frost)
 * - Mythic Watermark Intensity Selector (Vivid / Subtle / Off)
 */
export function AlastorThemeSwitcher() {
  const appTheme = useAuditStore((s) => s.appTheme);
  const setAppTheme = useAuditStore((s) => s.setAppTheme);
  const backdropIntensity = useAuditStore((s) => s.backdropIntensity);
  const setBackdropIntensity = useAuditStore((s) => s.setBackdropIntensity);

  const [open, setOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement | null>(null);

  const currentSpec =
    ALASTOR_THEMES.find((t) => t.id === appTheme) || ALASTOR_THEMES[0];

  // Sync light-only theme attributes to <html> and restore from v4 localStorage on mount
  useEffect(() => {
    try {
      const savedTheme = localStorage.getItem("alastor_app_theme_v4") as AppThemeId | null;
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
      const validId = ALASTOR_THEMES.some((t) => t.id === appTheme)
        ? appTheme
        : "olympian-light";
      htmlEl.setAttribute("data-theme", validId);
      htmlEl.setAttribute("data-theme-mode", "light");
      htmlEl.classList.remove("dark");
      htmlEl.classList.add("light");
    }
  }, [appTheme]);

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

  const cycleDaylightPalette = () => {
    const idx = ALASTOR_THEMES.findIndex((t) => t.id === appTheme);
    const nextSpec = ALASTOR_THEMES[(idx + 1) % ALASTOR_THEMES.length];
    setAppTheme(nextSpec.id);
  };

  return (
    <div ref={menuRef} className="relative flex items-center gap-1 shrink-0">
      {/* 1-Click Daylight Palette Cycle Button */}
      <button
        type="button"
        onClick={cycleDaylightPalette}
        title="High-Contrast Daylight Mode — Click to cycle between Olympian Daylight, Athena Parchment, and Hyperborean Frost"
        className="h-7 px-2 rounded-md bg-[var(--surface-elevated)] hover:bg-[var(--surface-void)] border border-[var(--border-hairline)] text-[11px] font-medium text-[var(--ink-primary)] flex items-center gap-1 transition-all"
      >
        <Sun className="w-3.5 h-3.5 text-[var(--sig-gold)]" />
        <span className="hidden 2xl:inline text-[11px] font-semibold">
          Daylight
        </span>
      </button>

      {/* Full Daylight Theme Palette Picker Button */}
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        title="Choose High-Contrast Daylight Palette (Olympian Daylight, Athena Parchment, Hyperborean Frost)"
        className={`h-7 px-2 rounded-md border text-[11px] font-medium flex items-center gap-1.5 transition-all ${
          open
            ? "bg-[var(--surface-elevated)] border-[var(--sig-gold)] text-[var(--ink-primary)]"
            : "bg-[var(--surface-elevated)] hover:bg-[var(--surface-void)] border-[var(--border-hairline)] text-[var(--ink-primary)]"
        }`}
      >
        <Palette className="w-3.5 h-3.5 text-[var(--sig-gold)]" />
        <span className="hidden xl:inline text-[11px] truncate max-w-[84px]">
          {currentSpec.name.split(" ")[0]}
        </span>
        <span className="flex items-center -space-x-1">
          {currentSpec.swatches.slice(0, 3).map((hex, idx) => (
            <span
              key={idx}
              className="w-2.5 h-2.5 rounded-full border border-[var(--border-hairline)]"
              style={{ backgroundColor: hex }}
            />
          ))}
        </span>
      </button>

      {/* Daylight Theme & Watermark Dropdown Modal */}
      {open && (
        <div className="absolute right-0 top-9 w-80 rounded-xl bg-[var(--surface-panel)] border border-[var(--border-hairline)] shadow-xl p-3 z-[150] space-y-3 text-left text-[var(--ink-primary)]">
          <div className="flex items-center justify-between border-b border-[var(--border-hairline)] pb-2">
            <span className="text-xs font-bold uppercase tracking-wider text-[var(--ink-primary)] flex items-center gap-1.5">
              <Palette className="w-3.5 h-3.5 text-[var(--sig-gold)]" />
              Daylight Palettes
            </span>
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[var(--surface-elevated)] border border-[var(--border-hairline)] text-[var(--ink-muted)]">
              3 Light Themes
            </span>
          </div>

          <div className="space-y-1.5">
            <div className="text-[10px] font-mono font-bold uppercase tracking-wider text-[var(--sig-gold)] flex items-center gap-1">
              <Sun className="w-3 h-3" />
              High-Contrast Daylight Themes
            </div>
            <div className="space-y-1">
              {ALASTOR_THEMES.map((t) => {
                const active = appTheme === t.id;
                return (
                  <button
                    key={t.id}
                    type="button"
                    onClick={() => setAppTheme(t.id)}
                    className={`w-full p-2 rounded-lg border text-left transition-all flex items-center justify-between gap-2 ${
                      active
                        ? "bg-[var(--surface-elevated)] border-[var(--sig-gold)] shadow-sm"
                        : "bg-[var(--surface-panel)] border-[var(--border-hairline)] hover:border-[var(--sig-gold)]/50"
                    }`}
                  >
                    <div className="min-w-0">
                      <div className="flex items-center gap-1.5">
                        <span className="text-xs font-bold text-[var(--ink-primary)]">
                          {t.name}
                        </span>
                        <span className="text-[9px] font-mono px-1.5 py-0.1 rounded bg-[var(--surface-void)] text-[var(--sig-gold)] border border-[var(--border-hairline)]">
                          {t.badge}
                        </span>
                      </div>
                      <p className="text-[10px] text-[var(--ink-muted)] truncate mt-0.5">
                        {t.subtitle}
                      </p>
                    </div>
                    <div className="flex items-center gap-1 shrink-0">
                      <div className="flex items-center -space-x-1">
                        {t.swatches.map((hex, i) => (
                          <span
                            key={i}
                            className="w-3.5 h-3.5 rounded-full border border-[var(--border-hairline)] shadow-sm"
                            style={{ backgroundColor: hex }}
                          />
                        ))}
                      </div>
                      {active && <Check className="w-3.5 h-3.5 text-[var(--sig-emerald)] ml-1" />}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          <div className="pt-2 border-t border-[var(--border-hairline)] space-y-1.5">
            <div className="flex items-center justify-between text-[10px] font-mono text-[var(--ink-muted)]">
              <span className="flex items-center gap-1 font-bold uppercase text-[var(--ink-primary)]">
                <Eye className="w-3 h-3 text-[var(--sig-gold)]" />
                Watermark Intensity
              </span>
              <span>{backdropIntensity}</span>
            </div>
            <div className="grid grid-cols-3 gap-1 bg-[var(--surface-void)] p-1 rounded-lg border border-[var(--border-hairline)]">
              {(["VIVID", "SUBTLE", "MINIMAL"] as BackdropIntensity[]).map(
                (lvl) => (
                  <button
                    key={lvl}
                    type="button"
                    onClick={() => setBackdropIntensity(lvl)}
                    className={`py-1 rounded text-[10px] font-mono font-bold transition-colors ${
                      backdropIntensity === lvl
                        ? "bg-[var(--surface-panel)] text-[var(--sig-gold)] border border-[var(--sig-gold)]"
                        : "text-[var(--ink-muted)] hover:text-[var(--ink-primary)]"
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
