//! Minimal stderr logger. Under systemd, stderr goes to the journal, which adds the timestamp.
//! Debug lines are written only when `WSL_TPM_AGENT_DEBUG` is set (any value).

use std::fmt;
use std::io::Write as _;
use std::sync::OnceLock;

/// Environment variable that enables debug lines.
pub const DEBUG_ENV: &str = "WSL_TPM_AGENT_DEBUG";

static DEBUG: OnceLock<bool> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Debug,
    Info,
    Warn,
    Error,
}

fn debug_enabled() -> bool {
    *DEBUG.get_or_init(|| std::env::var_os(DEBUG_ENV).is_some())
}

/// `wsl-tpm-agent: <level>: <message>`, one line: line breaks in the message are escaped so a
/// single event never spans several journal entries.
pub fn format_line(level: Level, args: fmt::Arguments) -> String {
    let level = match level {
        Level::Debug => "debug",
        Level::Info => "info",
        Level::Warn => "warning",
        Level::Error => "error",
    };
    let message = args.to_string().replace('\n', "\\n").replace('\r', "\\r");
    format!("wsl-tpm-agent: {level}: {message}\n")
}

/// Writes one line to stderr; debug lines only when [`DEBUG_ENV`] is set.
pub fn write(level: Level, args: fmt::Arguments) {
    if level == Level::Debug && !debug_enabled() {
        return;
    }
    let line = format_line(level, args);
    _ = std::io::stderr().lock().write_all(line.as_bytes());
}

#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => { $crate::log::write($crate::log::Level::Debug, format_args!($($arg)*)) };
}

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => { $crate::log::write($crate::log::Level::Info, format_args!($($arg)*)) };
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => { $crate::log::write($crate::log::Level::Warn, format_args!($($arg)*)) };
}

#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => { $crate::log::write($crate::log::Level::Error, format_args!($($arg)*)) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_level_and_message() {
        assert_eq!(
            format_line(Level::Info, format_args!("signed key={}", "gfh-a")),
            "wsl-tpm-agent: info: signed key=gfh-a\n"
        );
        assert_eq!(
            format_line(Level::Error, format_args!("x")),
            "wsl-tpm-agent: error: x\n"
        );
    }

    #[test]
    fn keeps_one_event_on_one_line() {
        assert_eq!(
            format_line(Level::Warn, format_args!("a\nb\r")),
            "wsl-tpm-agent: warning: a\\nb\\r\n"
        );
    }
}
