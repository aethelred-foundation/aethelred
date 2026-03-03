//! CLI utilities

use colored::*;

/// Format a duration in a human-readable way
pub fn format_duration(millis: f64) -> String {
    if millis < 1.0 {
        format!("{:.2} μs", millis * 1000.0)
    } else if millis < 1000.0 {
        format!("{:.2} ms", millis)
    } else {
        format!("{:.2} s", millis / 1000.0)
    }
}

/// Format bytes in a human-readable way
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if bytes >= TB {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Format a number with commas
pub fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.insert(0, ',');
        }
        result.insert(0, c);
    }
    result
}

/// Truncate a string with ellipsis
pub fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

/// Format a hash for display
pub fn format_hash(hash: &str) -> String {
    if hash.len() > 12 {
        format!("{}...{}", &hash[..6], &hash[hash.len() - 6..])
    } else {
        hash.to_string()
    }
}

/// Get status color
pub fn status_color(status: &str) -> ColoredString {
    match status.to_lowercase().as_str() {
        "active" | "completed" | "success" | "online" => status.green(),
        "pending" | "running" | "processing" => status.yellow(),
        "failed" | "error" | "offline" => status.red(),
        "inactive" | "stopped" => status.dimmed(),
        _ => status.normal(),
    }
}
