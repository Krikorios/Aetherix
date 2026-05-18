export function timeAgo(value: string): string {
  const elapsed = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 1000));
  if (elapsed < 60) return "just now";
  const mins = Math.floor(elapsed / 60);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

export function formatDate(value: string): string {
  return new Date(value).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}
