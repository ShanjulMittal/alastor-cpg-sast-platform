"use client";

import { useEffect } from "react";
import { useAuditStore } from "@/store/useAuditStore";

const SEVERITY_RANK: Record<string, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  INFO: 0,
};

function isEditableElement(el: EventTarget | Element | null): boolean {
  if (!el || !(el instanceof HTMLElement)) return false;
  const tag = el.tagName.toUpperCase();
  if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") {
    return true;
  }
  if (el.isContentEditable || el.getAttribute("contenteditable") === "true") {
    return true;
  }
  if (el.closest(".monaco-editor") || el.closest("[contenteditable='true']")) {
    return true;
  }
  return false;
}

export function useKeyboardNavigation(): void {
  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.metaKey || event.ctrlKey || event.altKey) {
        return;
      }

      if (
        isEditableElement(event.target) ||
        isEditableElement(document.activeElement)
      ) {
        return;
      }

      const state = useAuditStore.getState();

      if (
        state.showPortalGate ||
        state.isSettingsModalOpen ||
        state.isIntegrationModalOpen ||
        state.isQuickCommandOpen ||
        state.isTargetPickerOpen ||
        state.isTrackChangesPanelOpen
      ) {
        return;
      }

      if (state.workspaceViewMode !== "REMEDIATION_IDE") {
        return;
      }

      const key = event.key;

      if (key === "j" || key === "k") {
        const pool = state.findings.filter((f) => {
          if (
            state.activeEngineFilter !== "ALL" &&
            (f.scan_engine || "SAST") !== state.activeEngineFilter
          ) {
            return false;
          }
          if (state.filterSecretsOnly) {
            const isSec =
              f.is_secret_finding ||
              Boolean(f.secret_key_name) ||
              (f.rule_id || "").toUpperCase().includes("SECRET") ||
              f.cwe_id === "CWE-798";
            if (!isSec) return false;
          }
          return true;
        });

        const list = (pool.length > 0 ? pool : state.findings)
          .slice()
          .sort(
            (a, b) =>
              (SEVERITY_RANK[b.severity] || 0) -
              (SEVERITY_RANK[a.severity] || 0)
          );

        if (list.length === 0) return;

        event.preventDefault();
        if (state.activeSidebarTab !== "FLAWS") {
          state.setActiveSidebarTab("FLAWS");
        }

        const currentId = state.selectedFinding?.id;
        const curIdx = currentId
          ? list.findIndex((f) => f.id === currentId)
          : -1;

        if (key === "j") {
          const nextIdx =
            curIdx === -1 ? 0 : Math.min(list.length - 1, curIdx + 1);
          state.selectFinding(list[nextIdx]);
        } else {
          const prevIdx = curIdx <= 0 ? 0 : curIdx - 1;
          state.selectFinding(list[prevIdx]);
        }
        return;
      }

      if (key === "[") {
        if (state.selectedFinding) {
          event.preventDefault();
          state.stepFindingPath(-1);
        }
        return;
      }

      if (key === "]") {
        if (state.selectedFinding) {
          event.preventDefault();
          state.stepFindingPath(1);
        }
        return;
      }

      if (key === "d" || key === "D") {
        if (state.selectedFinding) {
          event.preventDefault();
          state.setDiffEditorOpen(!state.isDiffEditorOpen);
        }
        return;
      }

      if (key === "1") {
        event.preventDefault();
        state.setIdeLayoutMode("CODE_FOCUS");
        return;
      }

      if (key === "2") {
        event.preventDefault();
        state.setIdeLayoutMode("SPLIT_BOTH");
        return;
      }

      if (key === "3") {
        event.preventDefault();
        state.setIdeLayoutMode("GRAPH_FOCUS");
        return;
      }

      if (key === "b" || key === "B") {
        event.preventDefault();
        state.setSidebarCollapsed(!state.isSidebarCollapsed);
        return;
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);
}
