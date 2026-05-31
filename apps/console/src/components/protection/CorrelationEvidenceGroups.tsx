import React from "react";
import { FileText, Fingerprint, Expand, ShieldCheck, GitMerge } from "lucide-react";
import type { CorrelationResponse, CorrelationLink } from "../../api";
import { timeAgo } from "../../utils";

interface Props {
  data: CorrelationResponse | null | undefined;
  /** Maximum number of items rendered per group. Defaults to 5. */
  perGroupLimit?: number;
}

interface Group {
  key: string;
  title: string;
  icon: React.ReactNode;
  links: CorrelationLink[];
  renderLine: (link: CorrelationLink) => React.ReactNode;
}

function shortPath(p: string | undefined | null): string {
  if (!p) return "unknown path";
  return p.replace(/\\/g, "/").split("/").slice(-2).join("/") || p;
}

function shortHash(h: string | undefined | null): string {
  if (!h) return "—";
  return h.length > 16 ? `${h.slice(0, 8)}…${h.slice(-8)}` : h;
}

/**
 * CorrelationEvidenceGroups
 *
 * Renders the supporting correlation signals grouped by `correlation_type`
 * (file_path_match, sha256_match, process_path_match, plus a DLP grouping
 * derived from `related_kind === 'dlp_event'`).
 *
 * This is the same grouped layout proven on AlertsPage, extracted so it can
 * be reused inside DetailPanel-style protection workspaces (AntimalwareBehavior,
 * QuarantinePage, etc.) without re-implementing the grouping logic per page.
 */
export function CorrelationEvidenceGroups({ data, perGroupLimit = 5 }: Props) {
  if (!data || data.correlations.length === 0) return null;

  const dlp = data.correlations.filter((c) => c.related_kind === "dlp_event");
  const file = data.correlations.filter(
    (c) => c.correlation_type === "file_path_match" && c.related_kind !== "dlp_event",
  );
  const sha = data.correlations.filter(
    (c) => c.correlation_type === "sha256_match" && c.related_kind !== "dlp_event",
  );
  const proc = data.correlations.filter((c) => c.correlation_type === "process_path_match");
  const other = data.correlations.filter(
    (c) =>
      c.related_kind !== "dlp_event" &&
      !["file_path_match", "sha256_match", "process_path_match"].includes(c.correlation_type),
  );

  const groups: Group[] = [
    {
      key: "file",
      title: "File Path Matches",
      icon: <FileText size={13} />,
      links: file,
      renderLine: (link: CorrelationLink) => (
        <>
          <code className="corrEvidenceCode">{shortPath(link.evidence.file_path as string | undefined)}</code>
          {link.evidence.event_type ? (
            <span className="corrEvidenceMeta">{String(link.evidence.event_type)}</span>
          ) : null}
        </>
      ),
    },
    {
      key: "sha",
      title: "SHA-256 Hash Matches",
      icon: <Fingerprint size={13} />,
      links: sha,
      renderLine: (link: CorrelationLink) => (
        <code className="corrEvidenceCode corrEvidenceHash" title={String(link.evidence.sha256_hash ?? "")}>
          {shortHash(link.evidence.sha256_hash as string | undefined)}
        </code>
      ),
    },
    {
      key: "proc",
      title: "Process Path Matches",
      icon: <Expand size={13} />,
      links: proc,
      renderLine: (link: CorrelationLink) => (
        <code className="corrEvidenceCode">
          {shortPath(link.evidence.process_path as string | undefined)}
        </code>
      ),
    },
    {
      key: "dlp",
      title: "DLP Detection Matches",
      icon: <ShieldCheck size={13} />,
      links: dlp,
      renderLine: (link: CorrelationLink) => (
        <>
          <code className="corrEvidenceCode corrEvidenceHash" title={String(link.evidence.sha256_hash ?? "")}>
            {shortHash(link.evidence.sha256_hash as string | undefined)}
          </code>
          <span className="corrEvidenceMeta">
            {link.evidence.source ? String(link.evidence.source) : ""}
            {link.evidence.risk_band ? ` · ${String(link.evidence.risk_band)} risk` : ""}
            {link.evidence.action ? ` · ${String(link.evidence.action)}` : ""}
          </span>
        </>
      ),
    },
    {
      key: "other",
      title: "Other Correlated Events",
      icon: <GitMerge size={13} />,
      links: other,
      renderLine: (link: CorrelationLink) => (
        <span className="corrEvidenceMeta">
          {link.correlation_type.replace(/_/g, " ")} · {link.related_kind.replace(/_/g, " ")}
        </span>
      ),
    },
  ].filter((g) => g.links.length > 0);

  if (groups.length === 0) return null;

  return (
    <div className="corrEvidenceGroups">
      {groups.map((group) => (
        <section key={group.key} className="corrEvidenceGroup">
          <header className="corrEvidenceGroupHead">
            {group.icon}
            <span>{group.title}</span>
            <span className="corrEvidenceGroupCount">{group.links.length}</span>
          </header>
          <ul className="corrEvidenceList">
            {group.links.slice(0, perGroupLimit).map((link) => (
              <li key={link.id}>
                <div className="corrEvidenceLine">{group.renderLine(link)}</div>
                <div className="corrEvidenceAside">
                  <span
                    className="corrEvidenceScore"
                    title={`Confidence score ${(link.score * 100).toFixed(0)}%`}
                  >
                    {Math.round(link.score * 100)}
                  </span>
                  <span className="corrEvidenceTime">{timeAgo(link.created_at)}</span>
                </div>
              </li>
            ))}
            {group.links.length > perGroupLimit ? (
              <li className="corrEvidenceMore">
                +{group.links.length - perGroupLimit} more
              </li>
            ) : null}
          </ul>
        </section>
      ))}
    </div>
  );
}
