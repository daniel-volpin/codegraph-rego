import { useCallback, useEffect, useMemo, useState } from "react";
import type { ViolationRow } from "../policyUtils";

export interface UseSelectionStateReturn {
  selectedFindingId: string | null;
  setSelectedFindingId: (id: string | null) => void;
  selectedFinding: ViolationRow | null;
  expandedFindingByGroup: Record<string, string | null>;
  toggleFindingExpanded: (groupId: string, findingId: string) => void;
}

export function useSelectionState(filteredFindings: ViolationRow[]): UseSelectionStateReturn {
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [expandedFindingByGroup, setExpandedFindingByGroup] = useState<Record<string, string | null>>({});

  const toggleFindingExpanded = useCallback((groupId: string, findingId: string) => {
    setExpandedFindingByGroup((prev) => ({
      ...prev,
      [groupId]: prev[groupId] === findingId ? null : findingId,
    }));
  }, []);

  useEffect(() => {
    if (filteredFindings.length === 0) {
      setSelectedFindingId(null);
      return;
    }
    if (!selectedFindingId || !filteredFindings.some((f) => f.id === selectedFindingId)) {
      setSelectedFindingId(filteredFindings[0].id);
    }
  }, [filteredFindings, selectedFindingId]);

  const selectedFinding = useMemo(
    () => filteredFindings.find((f) => f.id === selectedFindingId) ?? null,
    [filteredFindings, selectedFindingId],
  );

  return { selectedFindingId, setSelectedFindingId, selectedFinding, expandedFindingByGroup, toggleFindingExpanded };
}
