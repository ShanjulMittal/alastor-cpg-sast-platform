"use client";

import React, { useRef, useState, useCallback } from "react";

export interface ResizableSplitPaneProps {
  mode?: "fixed-left" | "ratio";
  left: React.ReactNode;
  right: React.ReactNode;
  // Fixed-left mode props
  widthPx?: number;
  leftPx?: number;
  initialLeftPx?: number;
  minLeftPx?: number;
  maxLeftPx?: number;
  defaultLeftPx?: number;
  collapsed?: boolean;
  onChangeLeftPx?: (px: number) => void;
  // Ratio mode props
  ratio?: number;
  defaultRatio?: number;
  minRatio?: number;
  maxRatio?: number;
  onChangeRatio?: (ratio: number) => void;
  // Shared callback & styling
  onChange?: (value: number) => void;
  ariaLabel?: string;
  className?: string;
  leftClassName?: string;
  rightClassName?: string;
}

export const ResizableSplitPane: React.FC<ResizableSplitPaneProps> = ({
  mode,
  left,
  right,
  widthPx,
  leftPx,
  initialLeftPx,
  minLeftPx = 240,
  maxLeftPx = 480,
  defaultLeftPx = 310,
  collapsed = false,
  onChangeLeftPx,
  ratio,
  defaultRatio = 0.52,
  minRatio = 0.25,
  maxRatio = 0.75,
  onChangeRatio,
  onChange,
  ariaLabel = "Resize workspace panes",
  className = "",
  leftClassName = "",
  rightClassName = "",
}) => {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [isDragging, setIsDragging] = useState(false);

  const effectiveMode: "fixed-left" | "ratio" =
    mode ?? (ratio !== undefined || onChangeRatio !== undefined ? "ratio" : "fixed-left");

  const resolvedLeftPx = Math.max(
    minLeftPx,
    Math.min(maxLeftPx, Math.round(widthPx ?? leftPx ?? initialLeftPx ?? defaultLeftPx))
  );

  const resolvedRatio = Math.max(
    minRatio,
    Math.min(maxRatio, Number((ratio ?? defaultRatio).toFixed(3)))
  );

  const emitLeftPx = useCallback(
    (px: number) => {
      const clamped = Math.max(minLeftPx, Math.min(maxLeftPx, Math.round(px)));
      onChangeLeftPx?.(clamped);
      onChange?.(clamped);
    },
    [minLeftPx, maxLeftPx, onChangeLeftPx, onChange]
  );

  const emitRatio = useCallback(
    (r: number) => {
      const clamped = Math.max(minRatio, Math.min(maxRatio, Number(r.toFixed(3))));
      onChangeRatio?.(clamped);
      onChange?.(clamped);
    },
    [minRatio, maxRatio, onChangeRatio, onChange]
  );

  const handlePointerDown = (e: React.PointerEvent<HTMLDivElement>) => {
    e.preventDefault();
    try {
      e.currentTarget.setPointerCapture(e.pointerId);
    } catch {}
    setIsDragging(true);
  };

  const handlePointerMove = (e: React.PointerEvent<HTMLDivElement>) => {
    if (!isDragging || !containerRef.current) return;
    const rect = containerRef.current.getBoundingClientRect();
    if (rect.width <= 0) return;

    const offsetX = e.clientX - rect.left;
    if (effectiveMode === "fixed-left") {
      emitLeftPx(offsetX);
    } else {
      emitRatio(offsetX / rect.width);
    }
  };

  const handlePointerUpOrCancel = (e: React.PointerEvent<HTMLDivElement>) => {
    if (!isDragging) return;
    setIsDragging(false);
    try {
      e.currentTarget.releasePointerCapture(e.pointerId);
    } catch {}
  };

  const handleDoubleClick = () => {
    if (effectiveMode === "fixed-left") {
      emitLeftPx(defaultLeftPx);
    } else {
      emitRatio(defaultRatio);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLDivElement>) => {
    if (e.key === "ArrowLeft" || e.key === "ArrowRight") {
      e.preventDefault();
      const dir = e.key === "ArrowRight" ? 1 : -1;
      const stepScale = e.shiftKey ? 3 : 1;
      if (effectiveMode === "fixed-left") {
        emitLeftPx(resolvedLeftPx + dir * 16 * stepScale);
      } else {
        emitRatio(resolvedRatio + dir * 0.03 * stepScale);
      }
    } else if (e.key === "Enter" || e.key === "Home") {
      e.preventDefault();
      handleDoubleClick();
    }
  };

  if (effectiveMode === "fixed-left" && collapsed) {
    return (
      <div
        ref={containerRef}
        className={`flex flex-1 min-w-0 min-h-0 overflow-hidden ${className}`}
      >
        <div className={`flex-1 min-w-0 min-h-0 flex flex-col overflow-hidden ${rightClassName}`}>
          {right}
        </div>
      </div>
    );
  }

  const leftStyle: React.CSSProperties =
    effectiveMode === "fixed-left"
      ? { width: `${resolvedLeftPx}px`, flexShrink: 0 }
      : { width: `${(resolvedRatio * 100).toFixed(2)}%`, flexShrink: 0 };

  return (
    <div
      ref={containerRef}
      className={`flex flex-1 min-w-0 min-h-0 overflow-hidden ${
        isDragging ? "select-none cursor-col-resize" : ""
      } ${className}`}
    >
      {/* Left Pane */}
      <div
        style={leftStyle}
        className={`min-w-0 min-h-0 flex flex-col overflow-hidden ${leftClassName}`}
      >
        {left}
      </div>

      {/* Zero-Dependency Pointer-Capture Resize Handle */}
      <div
        role="separator"
        aria-orientation="vertical"
        aria-label={ariaLabel}
        aria-valuenow={
          effectiveMode === "fixed-left"
            ? resolvedLeftPx
            : Math.round(resolvedRatio * 100)
        }
        aria-valuemin={effectiveMode === "fixed-left" ? minLeftPx : Math.round(minRatio * 100)}
        aria-valuemax={effectiveMode === "fixed-left" ? maxLeftPx : Math.round(maxRatio * 100)}
        tabIndex={0}
        title="Drag to resize • Double-click to reset default split • ArrowLeft/ArrowRight to nudge"
        onPointerDown={handlePointerDown}
        onPointerMove={handlePointerMove}
        onPointerUp={handlePointerUpOrCancel}
        onPointerCancel={handlePointerUpOrCancel}
        onDoubleClick={handleDoubleClick}
        onKeyDown={handleKeyDown}
        className="group relative w-1.5 -mx-[2px] z-30 flex items-center justify-center cursor-col-resize shrink-0 focus:outline-none"
      >
        <div
          className={`h-full transition-all duration-150 ${
            isDragging
              ? "w-[3px] bg-[var(--sig-gold)] shadow-[0_0_8px_var(--sig-gold)]"
              : "w-px bg-[var(--border-hairline)] group-hover:w-[3px] group-hover:bg-[var(--sig-gold)] group-focus-visible:w-[3px] group-focus-visible:bg-[var(--sig-gold)]"
          }`}
        />
      </div>

      {/* Right Pane */}
      <div
        className={`flex-1 min-w-0 min-h-0 flex flex-col overflow-hidden ${rightClassName}`}
      >
        {right}
      </div>
    </div>
  );
};

export default ResizableSplitPane;
