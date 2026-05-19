use std::cmp::Ordering;

use crate::ansi;

pub fn bar_line(label: &str, value: usize, max: usize, width: usize, color: bool) -> String {
    let bar = bar(value, max, width, color);
    format!("{label:<18} [{bar}] {value}")
}

pub fn bar(value: usize, max: usize, width: usize, color: bool) -> String {
    let width = width.max(1);
    let max = max.max(1);
    let filled = ((value.min(max) as f64 / max as f64) * width as f64).round() as usize;
    let mut out = String::new();
    for index in 0..width {
        if index < filled {
            out.push_str(&paint(color, ansi::GREEN, "#"));
        } else {
            out.push_str(&paint(color, ansi::GRAY, "."));
        }
    }
    out
}

pub fn sparkline(values: &[u128], width: usize, color: bool) -> String {
    if values.is_empty() {
        return paint(color, ansi::GRAY, "no data");
    }

    let max = values.iter().copied().max().unwrap_or(1).max(1);
    let buckets = width.max(values.len()).min(64);
    let chars = [' ', '.', ':', '-', '=', '+', '*', '#', '%', '@'];
    let mut out = String::new();

    for value in values.iter().copied().take(buckets) {
        let ratio = value as f64 / max as f64;
        let idx = (ratio.clamp(0.0, 1.0) * (chars.len() - 1) as f64).round() as usize;
        out.push(chars[idx]);
    }
    out
}

pub fn sorted_desc_counts(mut items: Vec<(String, usize)>) -> Vec<(String, usize)> {
    items.sort_by(|a, b| match b.1.cmp(&a.1) {
        Ordering::Equal => a.0.cmp(&b.0),
        other => other,
    });
    items
}

fn paint(color: bool, color_code: &str, text: impl AsRef<str>) -> String {
    if color {
        ansi::paint(color_code, text)
    } else {
        text.as_ref().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_bars_and_sparkline() {
        assert!(bar(5, 10, 10, false).contains("#####"));
        assert_eq!(sparkline(&[1, 2, 3], 3, false).len(), 3);
    }
}
