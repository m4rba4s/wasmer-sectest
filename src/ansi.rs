pub const RESET: &str = "\x1b[0m";
pub const BOLD: &str = "\x1b[1m";
pub const DIM: &str = "\x1b[2m";
pub const GREEN: &str = "\x1b[38;5;82m";
pub const RED: &str = "\x1b[38;5;203m";
pub const YELLOW: &str = "\x1b[38;5;220m";
pub const CYAN: &str = "\x1b[38;5;51m";
pub const BLUE: &str = "\x1b[38;5;75m";
pub const MAGENTA: &str = "\x1b[38;5;171m";
pub const ORANGE: &str = "\x1b[38;5;214m";
pub const GRAY: &str = "\x1b[38;5;244m";
pub const WHITE: &str = "\x1b[38;5;255m";

pub fn paint(color: &str, text: impl AsRef<str>) -> String {
    format!("{color}{}{RESET}", text.as_ref())
}

pub fn bold(text: impl AsRef<str>) -> String {
    format!("{BOLD}{}{RESET}", text.as_ref())
}

pub fn faint(text: impl AsRef<str>) -> String {
    format!("{DIM}{}{RESET}", text.as_ref())
}

pub fn badge(color: &str, text: impl AsRef<str>) -> String {
    format!("{BOLD}{color}[ {} ]{RESET}", text.as_ref())
}

pub fn status(value: bool) -> String {
    if value {
        badge(GREEN, "PASS")
    } else {
        badge(RED, "FAIL")
    }
}
