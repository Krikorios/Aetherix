import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { StagedActionBadge } from "../components/protection/StagedActionBadge";
import { hasPermission, permissionLevel } from "../permissions";
import type { MeResponse } from "../api";

describe("StagedActionBadge", () => {
  it("renders STAGED for queued actions", () => {
    render(<StagedActionBadge status="queued" />);
    expect(screen.getByText("STAGED")).toBeInTheDocument();
    expect(screen.getByTestId("staged-action-badge-staged")).toBeInTheDocument();
  });

  it("renders AWAITING APPROVAL distinctly", () => {
    render(<StagedActionBadge status="awaiting_approval" />);
    expect(screen.getByText("AWAITING APPROVAL")).toBeInTheDocument();
    expect(screen.getByTestId("staged-action-badge-awaiting")).toBeInTheDocument();
  });

  it("renders EXECUTED when the agent confirms enforcement", () => {
    render(<StagedActionBadge status="executed" />);
    expect(screen.getByText("EXECUTED")).toBeInTheDocument();
    expect(screen.getByTestId("staged-action-badge-executed")).toBeInTheDocument();
  });

  it("upgrades an 'approved' badge to EXECUTED via confirmedExecuted prop", () => {
    render(<StagedActionBadge status="approved" confirmedExecuted />);
    expect(screen.getByText("EXECUTED")).toBeInTheDocument();
  });

  it("renders FAILED with destructive treatment", () => {
    render(<StagedActionBadge status="failed" />);
    expect(screen.getByText("FAILED")).toBeInTheDocument();
    expect(screen.getByTestId("staged-action-badge-failed")).toBeInTheDocument();
  });

  it("renders DENIED as a distinct terminal state", () => {
    render(<StagedActionBadge status="denied" />);
    expect(screen.getByText("DENIED")).toBeInTheDocument();
    expect(screen.getByTestId("staged-action-badge-denied")).toBeInTheDocument();
  });
});

describe("permissions helpers", () => {
  const me: MeResponse = {
    account: { id: "u1", email: "u@a.test", full_name: "U", status: "active" },
    roles: [],
    permissions: { policies: "edit", incidents: "view", companies: "manage" },
    audience: "platform",
    licensed_modules: [],
  } as unknown as MeResponse;

  it("returns true when the user meets the required level", () => {
    expect(hasPermission(me, { resource: "policies", level: "edit" })).toBe(true);
    expect(hasPermission(me, { resource: "policies", level: "view" })).toBe(true);
    expect(hasPermission(me, { resource: "companies", level: "manage" })).toBe(true);
  });

  it("returns false when the user lacks the required level", () => {
    expect(hasPermission(me, { resource: "policies", level: "manage" })).toBe(false);
    expect(hasPermission(me, { resource: "billing", level: "view" })).toBe(false);
  });

  it("permits null requirement and rejects null user", () => {
    expect(hasPermission(me, null)).toBe(true);
    expect(hasPermission(null, { resource: "policies", level: "view" })).toBe(false);
  });

  it("permissionLevel reports the exact level", () => {
    expect(permissionLevel(me, "policies")).toBe("edit");
    expect(permissionLevel(me, "companies")).toBe("manage");
    expect(permissionLevel(me, "unknown")).toBe("none");
    expect(permissionLevel(null, "policies")).toBe("none");
  });
});
