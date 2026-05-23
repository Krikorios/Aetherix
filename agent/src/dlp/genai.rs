use url::Url;

pub fn destination_allowed(destination: &str, allowed: &[String]) -> bool {
    if allowed.is_empty() {
        return false;
    }

    let host = normalize_host(destination);
    allowed.iter().any(|entry| matches_destination(&host, entry))
}

pub fn normalize_host(input: &str) -> String {
    if input.contains("://") {
        if let Ok(url) = Url::parse(input) {
            if let Some(host) = url.host_str() {
                return host.to_lowercase();
            }
        }
    }
    input
        .trim()
        .trim_start_matches("www.")
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or_default()
        .to_lowercase()
}

fn matches_destination(host: &str, allowed_entry: &str) -> bool {
    let allowed = allowed_entry.to_lowercase();
    match allowed.as_str() {
        "copilot" => host.ends_with("copilot.microsoft.com") || host.ends_with("githubcopilot.com") || host == "github.com",
        "claude" => host.ends_with("claude.ai"),
        "gemini" => host.ends_with("gemini.google.com"),
        "chatgpt" => host.ends_with("chatgpt.com") || host.ends_with("chat.openai.com"),
        custom => host == custom || host.ends_with(&format!(".{custom}")),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn recognizes_known_genai_destinations() {
        let allowed = vec!["chatgpt".to_string(), "claude".to_string()];
        assert!(super::destination_allowed("https://chatgpt.com", &allowed));
        assert!(super::destination_allowed("claude.ai", &allowed));
        assert!(!super::destination_allowed("example.org", &allowed));
    }
}
