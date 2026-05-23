import { GitBranch, Network, TerminalSquare, UserRound } from "lucide-react";
import { EmptyState } from "../components";
import type { BehaviorDetection, ProcessNode } from "./antimalwareTypes";

type ProcessContextPanelProps = {
  detection: BehaviorDetection | null;
};

function ProcessTree({ node, depth = 0 }: { node: ProcessNode; depth?: number }) {
  return (
    <li>
      <div className="processNode" style={{ paddingLeft: depth * 14 }}>
        <span>{node.name}</span>
        <code>pid {node.pid}</code>
      </div>
      {node.children?.length ? (
        <ul>
          {node.children.map((child) => (
            <ProcessTree key={`${child.name}-${child.pid}`} node={child} depth={depth + 1} />
          ))}
        </ul>
      ) : null}
    </li>
  );
}

export function ProcessContextPanel({ detection }: ProcessContextPanelProps) {
  if (!detection) {
    return (
      <section className="panel behaviorPanel behaviorContextPanel">
        <div className="panelHeader">
          <div>
            <h2>Suspicious Process Context</h2>
            <span>Select a detection to review process evidence.</span>
          </div>
          <GitBranch size={18} aria-hidden="true" />
        </div>
        <EmptyState>No detection selected.</EmptyState>
      </section>
    );
  }

  const context = detection.context;

  return (
    <section className="panel behaviorPanel behaviorContextPanel">
      <div className="panelHeader">
        <div>
          <h2>Suspicious Process Context</h2>
          <span>{detection.summary}</span>
        </div>
        <GitBranch size={18} aria-hidden="true" />
      </div>

      <article className="contextBlock">
        <h3>Process Tree</h3>
        <ul className="processTree">
          <ProcessTree node={context.process_tree} />
        </ul>
      </article>

      <article className="contextBlock">
        <h3><TerminalSquare size={15} aria-hidden="true" /> Command Line</h3>
        <code className="commandLine">{context.command_line}</code>
      </article>

      <article className="contextBlock">
        <h3>File Reputation</h3>
        <div className="hashList">
          {context.file_hashes.map((hash) => (
            <div key={`${hash.algorithm}-${hash.value}`}>
              <span>{hash.algorithm}</span>
              <code>{hash.value}</code>
              <em className={`rep-${hash.reputation}`}>{hash.reputation}</em>
            </div>
          ))}
        </div>
      </article>

      <article className="contextBlock">
        <h3><Network size={15} aria-hidden="true" /> Network Connections</h3>
        {context.network_connections.length ? (
          <div className="networkList">
            {context.network_connections.map((connection) => (
              <span key={`${connection.destination}-${connection.port}`}>
                {connection.destination}:{connection.port} · {connection.protocol} · {connection.reputation}
              </span>
            ))}
          </div>
        ) : <p className="muted">No outbound connections observed.</p>}
      </article>

      <article className="contextBlock contextUserBlock">
        <h3><UserRound size={15} aria-hidden="true" /> User / Session</h3>
        <span>{context.user}</span>
        <code>{context.session}</code>
      </article>

      <article className="contextBlock">
        <h3>MITRE ATT&CK</h3>
        <div className="mitreList">
          {context.mitre_techniques.map((technique) => (
            <span key={technique.id}>{technique.id} · {technique.name}</span>
          ))}
        </div>
      </article>
    </section>
  );
}