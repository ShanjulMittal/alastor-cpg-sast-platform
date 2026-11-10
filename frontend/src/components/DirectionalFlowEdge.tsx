"use client";

import React, { memo, useEffect } from "react";
import {
  BaseEdge,
  EdgeLabelRenderer,
  EdgeProps,
  Position,
  getBezierPath,
  getSmoothStepPath,
  getStraightPath,
} from "reactflow";

export type EdgeBadgeTone =
  | "CRIMSON"
  | "AMBER"
  | "EMERALD"
  | "CYAN"
  | "SKY"
  | "VIOLET"
  | "SLATE";

export type EdgeBlastState = "NONE" | "UPSTREAM" | "DOWNSTREAM" | "DIMMED";

export interface DirectionalFlowEdgeData {
  edgeType?: string;
  flowLabel?: string;
  stepIndex?: number;
  varName?: string | null;
  pathShape?: "bezier" | "smoothstep" | "straight";
  isSpider?: boolean;
  isSevered?: boolean;
  isDenseGraph?: boolean;
  isAnimatedPulse?: boolean;
  isHovered?: boolean;
  alwaysShowFullPill?: boolean;
  blastState?: EdgeBlastState;
  strokeColor?: string;
  badgeTone?: EdgeBadgeTone;
}

const CIRCLED_NUMERALS = [
  "①",
  "②",
  "③",
  "④",
  "⑤",
  "⑥",
  "⑦",
  "⑧",
  "⑨",
  "⑩",
  "⑪",
  "⑫",
];

export function formatCircledStep(step?: number): string {
  if (!step || step < 1) return "";
  if (step <= CIRCLED_NUMERALS.length) {
    return CIRCLED_NUMERALS[step - 1];
  }
  return `(${step})`;
}

export function resolveDirectionalEdgeMeta(
  edgeTypeRaw?: string,
  opts?: {
    isSevered?: boolean;
    varName?: string | null;
    flowLabel?: string;
    stepIndex?: number;
    isSpider?: boolean;
    isSinkTarget?: boolean;
  }
): {
  strokeColor: string;
  badgeTone: EdgeBadgeTone;
  isAnimatedPulse: boolean;
  flowLabel: string;
  dashPattern?: string;
} {
  const edgeType = (edgeTypeRaw || "FLOW").toUpperCase();
  const varClean = (opts?.varName || "").trim();
  const stepPrefix = opts?.stepIndex ? `${formatCircledStep(opts.stepIndex)} ` : "";

  if (opts?.isSevered) {
    return {
      strokeColor: "#047857",
      badgeTone: "EMERALD",
      isAnimatedPulse: false,
      flowLabel: "SANITIZED ✓",
      dashPattern: "6 4",
    };
  }

  const rawExisting = (opts?.flowLabel || "").trim();
  const withPrefix = (fallbackPhrase: string): string => {
    if (rawExisting) {
      if (
        opts?.stepIndex &&
        !CIRCLED_NUMERALS.some((c) => rawExisting.startsWith(c)) &&
        !rawExisting.startsWith("(")
      ) {
        return `${stepPrefix}${rawExisting}`;
      }
      return rawExisting;
    }
    return `${stepPrefix}${fallbackPhrase}`;
  };

  switch (edgeType) {
    case "DFG_FLOWS_TO": {
      const phrase = opts?.isSinkTarget
        ? varClean
          ? `EXEC SINK (${varClean}) ▶`
          : "EXEC SINK ▶"
        : varClean
        ? `TAINT (${varClean}) ▶`
        : "TAINT ▶";
      return {
        strokeColor: "#be123c",
        badgeTone: "CRIMSON",
        isAnimatedPulse: true,
        flowLabel: withPrefix(phrase),
      };
    }
    case "UNGUARDED":
      return {
        strokeColor: "#be123c",
        badgeTone: "CRIMSON",
        isAnimatedPulse: true,
        flowLabel: withPrefix(varClean ? `UNGUARDED (${varClean}) ▶` : "UNGUARDED ▶"),
      };
    case "SANITIZED":
      return {
        strokeColor: "#047857",
        badgeTone: "EMERALD",
        isAnimatedPulse: false,
        flowLabel: withPrefix("SANITIZED ✓"),
      };
    case "IMPORTS":
      return {
        strokeColor: "#6d28d9",
        badgeTone: "VIOLET",
        isAnimatedPulse: true,
        flowLabel: withPrefix(varClean ? `IMPORTS (${varClean}) ▶` : "IMPORTS ▶"),
      };
    case "CALLS":
      return {
        strokeColor: "#b45309",
        badgeTone: "AMBER",
        isAnimatedPulse: true,
        flowLabel: withPrefix(varClean ? `CALLS (${varClean}) ▶` : "CALLS ▶"),
      };
    case "CFG_TRUE":
      return {
        strokeColor: "#047857",
        badgeTone: "EMERALD",
        isAnimatedPulse: false,
        flowLabel: withPrefix("TRUE ▶"),
      };
    case "CFG_FALSE":
      return {
        strokeColor: "#c2410c",
        badgeTone: "AMBER",
        isAnimatedPulse: false,
        flowLabel: withPrefix("FALSE ▶"),
      };
    case "CFG_LOOP_BACK":
      return {
        strokeColor: "#7e22ce",
        badgeTone: "VIOLET",
        isAnimatedPulse: true,
        flowLabel: withPrefix("LOOP ↺"),
      };
    case "CFG_BREAK":
      return {
        strokeColor: "#b45309",
        badgeTone: "AMBER",
        isAnimatedPulse: false,
        flowLabel: withPrefix("BREAK ▶"),
      };
    case "CFG_NEXT":
    case "TRUST_CROSSING":
      return {
        strokeColor: "#0e7490",
        badgeTone: "CYAN",
        isAnimatedPulse: edgeType === "TRUST_CROSSING",
        flowLabel: withPrefix(varClean ? `${varClean.toUpperCase()} ▶` : "NEXT ▶"),
      };
    case "CONTAINS":
      return {
        strokeColor: opts?.isSpider ? "#0284c7" : "#047857",
        badgeTone: opts?.isSpider ? "SKY" : "EMERALD",
        isAnimatedPulse: false,
        flowLabel: withPrefix("CONTAINS ▶"),
      };
    case "DECLARES":
    case "DEFINES":
      return {
        strokeColor: "#b45309",
        badgeTone: "AMBER",
        isAnimatedPulse: false,
        flowLabel: withPrefix(`${edgeType} ▶`),
        dashPattern: "4 3",
      };
    case "CONFIGURES":
      return {
        strokeColor: "#0369a1",
        badgeTone: "SKY",
        isAnimatedPulse: true,
        flowLabel: withPrefix("CONFIGURES ▶"),
      };
    case "AST_CHILD":
    default:
      return {
        strokeColor: "#475569",
        badgeTone: "SLATE",
        isAnimatedPulse: false,
        flowLabel: withPrefix(`${edgeType} ▶`),
        dashPattern: "3 3",
      };
  }
}

const TONE_PILL_CLASSES: Record<EdgeBadgeTone, string> = {
  CRIMSON: "bg-rose-50 text-rose-900 border-rose-400 shadow-rose-900/10",
  AMBER: "bg-amber-50 text-amber-900 border-amber-400 shadow-amber-900/10",
  EMERALD: "bg-emerald-50 text-emerald-900 border-emerald-400 shadow-emerald-900/10",
  CYAN: "bg-cyan-50 text-cyan-900 border-cyan-400 shadow-cyan-900/10",
  SKY: "bg-sky-50 text-sky-900 border-sky-400 shadow-sky-900/10",
  VIOLET: "bg-violet-50 text-violet-900 border-violet-400 shadow-violet-900/10",
  SLATE: "bg-slate-50 text-slate-800 border-slate-300 shadow-slate-900/5",
};

function getTargetDockAngleDeg(
  targetPosition: Position,
  pathShape: "bezier" | "smoothstep" | "straight",
  sourceX: number,
  sourceY: number,
  targetX: number,
  targetY: number
): number {
  if (pathShape === "straight") {
    return (Math.atan2(targetY - sourceY, targetX - sourceX) * 180) / Math.PI;
  }
  switch (targetPosition) {
    case Position.Left:
      return 0;
    case Position.Right:
      return 180;
    case Position.Top:
      return 90;
    case Position.Bottom:
      return -90;
    default:
      return (Math.atan2(targetY - sourceY, targetX - sourceX) * 180) / Math.PI;
  }
}

function sampleCubicBezierPointAndAngle(
  edgePath: string,
  t: number
): { x: number; y: number; angleDeg: number } | null {
  const m = edgePath.match(
    /^M\s*([-\d.]+)[,\s]+([-\d.]+)\s*C\s*([-\d.]+)[,\s]+([-\d.]+)[,\s]+([-\d.]+)[,\s]+([-\d.]+)[,\s]+([-\d.]+)[,\s]+([-\d.]+)/i
  );
  if (!m) return null;
  const p0x = parseFloat(m[1]);
  const p0y = parseFloat(m[2]);
  const p1x = parseFloat(m[3]);
  const p1y = parseFloat(m[4]);
  const p2x = parseFloat(m[5]);
  const p2y = parseFloat(m[6]);
  const p3x = parseFloat(m[7]);
  const p3y = parseFloat(m[8]);

  const u = 1 - t;
  const x =
    u * u * u * p0x +
    3 * u * u * t * p1x +
    3 * u * t * t * p2x +
    t * t * t * p3x;
  const y =
    u * u * u * p0y +
    3 * u * u * t * p1y +
    3 * u * t * t * p2y +
    t * t * t * p3y;

  const dx =
    3 * u * u * (p1x - p0x) +
    6 * u * t * (p2x - p1x) +
    3 * t * t * (p3x - p2x);
  const dy =
    3 * u * u * (p1y - p0y) +
    6 * u * t * (p2y - p1y) +
    3 * t * t * (p3y - p2y);

  return {
    x,
    y,
    angleDeg: (Math.atan2(dy, dx) * 180) / Math.PI,
  };
}

let edgeKeyframesInjected = false;
function ensureEdgeKeyframes(): void {
  if (edgeKeyframesInjected || typeof document === "undefined") return;
  if (document.getElementById("alastor-edge-flow-keyframes")) {
    edgeKeyframesInjected = true;
    return;
  }
  const styleEl = document.createElement("style");
  styleEl.id = "alastor-edge-flow-keyframes";
  styleEl.textContent = `
    @keyframes alastorEdgeFlowForward {
      from { stroke-dashoffset: 28; }
      to { stroke-dashoffset: 0; }
    }
  `;
  document.head.appendChild(styleEl);
  edgeKeyframesInjected = true;
}

export const DirectionalFlowEdge = memo((props: EdgeProps<DirectionalFlowEdgeData>) => {
  useEffect(() => {
    ensureEdgeKeyframes();
  }, []);

  const {
    id,
    sourceX,
    sourceY,
    targetX,
    targetY,
    sourcePosition = Position.Right,
    targetPosition = Position.Left,
    markerEnd,
    style,
    data,
    label,
  } = props;

  const pathShape = data?.pathShape || "smoothstep";
  let edgePath = "";
  let labelX = (sourceX + targetX) / 2;
  let labelY = (sourceY + targetY) / 2;

  if (pathShape === "straight") {
    [edgePath, labelX, labelY] = getStraightPath({
      sourceX,
      sourceY,
      targetX,
      targetY,
    });
  } else if (pathShape === "bezier") {
    [edgePath, labelX, labelY] = getBezierPath({
      sourceX,
      sourceY,
      sourcePosition,
      targetX,
      targetY,
      targetPosition,
      curvature: 0.25,
    });
  } else {
    [edgePath, labelX, labelY] = getSmoothStepPath({
      sourceX,
      sourceY,
      sourcePosition,
      targetX,
      targetY,
      targetPosition,
      borderRadius: 12,
    });
  }

  const resolved = resolveDirectionalEdgeMeta(data?.edgeType, {
    isSevered: data?.isSevered,
    varName: data?.varName,
    flowLabel: data?.flowLabel || (typeof label === "string" ? label : undefined),
    stepIndex: data?.stepIndex,
    isSpider: data?.isSpider,
  });

  const blastState: EdgeBlastState = data?.blastState || "NONE";
  const isHovered = Boolean(data?.isHovered);

  let strokeColor = data?.strokeColor || resolved.strokeColor;
  let badgeTone: EdgeBadgeTone = data?.badgeTone || resolved.badgeTone;
  let shouldAnimate =
    data?.isAnimatedPulse !== undefined ? data.isAnimatedPulse : resolved.isAnimatedPulse;
  let strokeWidth = typeof style?.strokeWidth === "number" ? style.strokeWidth : 2.1;
  let edgeOpacity = typeof style?.opacity === "number" ? style.opacity : 1;

  if (blastState === "DIMMED") {
    edgeOpacity = 0.25;
    shouldAnimate = false;
  } else if (blastState === "UPSTREAM") {
    strokeColor = "#0369a1";
    badgeTone = "SKY";
    shouldAnimate = true;
    strokeWidth = 2.8;
  } else if (blastState === "DOWNSTREAM") {
    strokeColor = "#be123c";
    badgeTone = "CRIMSON";
    shouldAnimate = true;
    strokeWidth = 2.8;
  } else if (isHovered) {
    strokeWidth = Math.max(strokeWidth + 0.7, 2.8);
  }

  const displayLabel = resolved.flowLabel;
  const edgeTypeUpper = (data?.edgeType || "").toUpperCase();
  const isRoutineStructural =
    edgeTypeUpper === "CONTAINS" ||
    edgeTypeUpper === "AST_CHILD" ||
    edgeTypeUpper === "DECLARES" ||
    edgeTypeUpper === "DEFINES";
  const isPriorityEdge =
    edgeTypeUpper === "DFG_FLOWS_TO" ||
    edgeTypeUpper === "IMPORTS" ||
    edgeTypeUpper === "CALLS" ||
    edgeTypeUpper === "UNGUARDED" ||
    edgeTypeUpper === "SANITIZED" ||
    edgeTypeUpper === "TRUST_CROSSING" ||
    isHovered ||
    Boolean(data?.alwaysShowFullPill) ||
    blastState === "UPSTREAM" ||
    blastState === "DOWNSTREAM";

  const showCompactChevronOnly =
    Boolean(data?.isDenseGraph) && isRoutineStructural && !isPriorityEdge;

  const dx = targetX - sourceX;
  const dy = targetY - sourceY;
  const chordLen = Math.hypot(dx, dy);
  const overallAngleDeg = (Math.atan2(dy, dx) * 180) / Math.PI;
  const dockAngleDeg = getTargetDockAngleDeg(
    targetPosition,
    pathShape,
    sourceX,
    sourceY,
    targetX,
    targetY
  );

  // Mid-segment inline SVG directional chevron (~72% from source toward target)
  let inlineChevron: { x: number; y: number; angleDeg: number } | null = null;
  if (chordLen > 75) {
    if (pathShape === "straight") {
      inlineChevron = {
        x: sourceX + dx * 0.74,
        y: sourceY + dy * 0.74,
        angleDeg: overallAngleDeg,
      };
    } else if (pathShape === "bezier") {
      inlineChevron = sampleCubicBezierPointAndAngle(edgePath, 0.74);
    }
  }

  const pillToneClass = TONE_PILL_CLASSES[badgeTone] || TONE_PILL_CLASSES.SLATE;

  return (
    <>
      {/* Subtle white halo behind edge so crossing paths remain razor-sharp on #f8fafc */}
      <path
        d={edgePath}
        fill="none"
        stroke="#ffffff"
        strokeWidth={strokeWidth + 2.5}
        strokeOpacity={blastState === "DIMMED" ? 0.2 : 0.85}
        pointerEvents="none"
      />

      {/* Primary edge path + native markerEnd */}
      <BaseEdge
        id={id}
        path={edgePath}
        markerEnd={markerEnd}
        style={{
          ...style,
          stroke: strokeColor,
          strokeWidth,
          opacity: shouldAnimate ? edgeOpacity * 0.42 : edgeOpacity,
          strokeDasharray: shouldAnimate ? undefined : resolved.dashPattern,
        }}
      />

      {/* Animated strictly forward-flowing directional dash overlay (source -> target) */}
      {shouldAnimate && (
        <path
          d={edgePath}
          fill="none"
          stroke={strokeColor}
          strokeWidth={strokeWidth + 0.35}
          strokeDasharray="9 5"
          strokeLinecap="round"
          pointerEvents="none"
          style={{
            opacity: edgeOpacity,
            animation: "alastorEdgeFlowForward 0.9s linear infinite",
          }}
        />
      )}

      {/* Explicit mid-path inline SVG chevron on straight/bezier arcs */}
      {inlineChevron && (
        <g
          transform={`translate(${inlineChevron.x}, ${inlineChevron.y}) rotate(${inlineChevron.angleDeg})`}
          style={{ opacity: edgeOpacity }}
          pointerEvents="none"
        >
          <polygon
            points="5.5,0 -4.5,-4.3 -2.2,0 -4.5,4.3"
            fill={strokeColor}
            stroke="#ffffff"
            strokeWidth="1.15"
            strokeLinejoin="round"
          />
        </g>
      )}

      {/* Explicit perimeter-docked directional arrowhead at target handle */}
      <g
        transform={`translate(${targetX}, ${targetY}) rotate(${dockAngleDeg})`}
        style={{ opacity: edgeOpacity }}
        pointerEvents="none"
      >
        <polygon
          points="0,0 -11.5,-5.5 -8.8,0 -11.5,5.5"
          fill={strokeColor}
          stroke="#ffffff"
          strokeWidth="1.35"
          strokeLinejoin="round"
        />
      </g>

      {/* Mid-edge directional pill badge */}
      <EdgeLabelRenderer>
        <div
          style={{
            position: "absolute",
            transform: `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)`,
            opacity: edgeOpacity,
            pointerEvents: "all",
            zIndex: isPriorityEdge ? 20 : 10,
          }}
          className="nodrag nopan select-none"
          title={displayLabel}
        >
          {showCompactChevronOnly ? (
            <div
              className={`w-5 h-5 rounded-full border-[1.5px] bg-white shadow-sm flex items-center justify-center transition-transform hover:scale-125 ${pillToneClass}`}
            >
              <svg
                width="9"
                height="9"
                viewBox="-5 -5 10 10"
                style={{ transform: `rotate(${overallAngleDeg}deg)` }}
              >
                <polygon points="4.2,0 -3.4,-3.4 -1.6,0 -3.4,3.4" fill={strokeColor} />
              </svg>
            </div>
          ) : (
            <div
              className={`px-2 py-0.5 rounded-full border-[1.5px] shadow-sm font-mono text-[9.5px] font-extrabold tracking-tight whitespace-nowrap flex items-center gap-1 transition-transform ${
                isHovered ? "scale-105 ring-2 ring-slate-900/10" : ""
              } ${pillToneClass}`}
            >
              {blastState === "UPSTREAM" && (
                <span className="text-sky-800 font-black">⬆</span>
              )}
              {blastState === "DOWNSTREAM" && (
                <span className="text-rose-800 font-black">⬇</span>
              )}
              <span>{displayLabel}</span>
            </div>
          )}
        </div>
      </EdgeLabelRenderer>
    </>
  );
});

DirectionalFlowEdge.displayName = "DirectionalFlowEdge";
