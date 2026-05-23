// Maps a hostname to a canonical Aetherix policy `genai_destinations` slug.
// Must stay in sync with agent/src/policy/mod.rs DEFAULT_GENAI_DESTINATIONS.

const DESTINATION_MAP = [
  { match: /(^|\.)claude\.ai$/i, slug: "claude" },
  { match: /(^|\.)chatgpt\.com$/i, slug: "chatgpt" },
  { match: /(^|\.)chat\.openai\.com$/i, slug: "chatgpt" },
  { match: /(^|\.)gemini\.google\.com$/i, slug: "gemini" },
  { match: /(^|\.)copilot\.microsoft\.com$/i, slug: "copilot" },
];

export function resolveDestinationSlug(hostname) {
  if (!hostname) return null;
  for (const { match, slug } of DESTINATION_MAP) {
    if (match.test(hostname)) return slug;
  }
  return null;
}

export function isKnownGenaiHost(hostname) {
  return resolveDestinationSlug(hostname) !== null;
}
