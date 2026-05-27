// Shared permission helpers. The console previously inlined a private
// `hasPermission` in App.tsx; this module re-exports the same algorithm
// so individual page components can gate buttons (stage / approve /
// execute) on the SERVER-DECLARED permission level rather than on a UI
// role string.
//
// IMPORTANT: this helper is a defence-in-DEPTH check — the API always
// re-authorises every mutating request via the same permission model.
// Disabling a button in the console is purely UX so operators don't
// take an action that will be rejected.

import type { MeResponse, PermissionLevel } from "./api";

export type { PermissionLevel } from "./api";

export interface PermissionRequirement {
  resource: string;
  level: PermissionLevel;
}

const LEVEL_RANK: Record<PermissionLevel, number> = {
  none: 0,
  view: 1,
  edit: 2,
  manage: 3,
};

export function hasPermission(
  me: MeResponse | null,
  req: PermissionRequirement | null | undefined,
): boolean {
  if (!req) return true;
  if (!me) return false;
  const have = (me.permissions?.[req.resource] ?? "none") as PermissionLevel;
  const haveRank = LEVEL_RANK[have] ?? 0;
  return haveRank >= LEVEL_RANK[req.level];
}

/**
 * Returns the user's level for a resource, defaulting to "none".
 * Useful when callers need to branch on the exact level rather than a
 * yes/no answer.
 */
export function permissionLevel(
  me: MeResponse | null,
  resource: string,
): PermissionLevel {
  if (!me) return "none";
  const have = me.permissions?.[resource];
  return ((have as PermissionLevel) ?? "none") as PermissionLevel;
}
