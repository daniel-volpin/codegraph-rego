import {
  createExpandedRowModel,
  createSortedRowModel,
  columnVisibilityFeature,
  rowExpandingFeature,
  rowSortingFeature,
  tableFeatures,
} from "@tanstack/react-table";

export const policyTableFeatures = tableFeatures({
  columnVisibilityFeature,
  rowSortingFeature,
  sortedRowModel: createSortedRowModel(),
  rowExpandingFeature,
  expandedRowModel: createExpandedRowModel(),
});

export type PolicyTableFeatures = typeof policyTableFeatures;
