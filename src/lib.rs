#![forbid(unsafe_code)]

/// Human-readable product name.
pub const PRODUCT_NAME: &str = "SciCapsule";

/// Canonical extension reserved for SciCapsule artifacts.
pub const FORMAT_EXTENSION: &str = "scicap";

/// Product version compiled into the binary.
pub const fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Stable bootstrap help text.
///
/// Operational commands are intentionally not advertised until their backing
/// SciRust capsule primitives exist and are wired into this product repository.
pub fn help_text() -> String {
    format!(
        "{PRODUCT_NAME} {}\n\
Portable, reproducible SciRust execution capsules.\n\n\
USAGE:\n    scicapsule [--help] [--version]\n\n\
OPTIONS:\n    -h, --help       Print help\n\
    -V, --version    Print version\n",
        version()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_extension_is_scicap() {
        assert_eq!(FORMAT_EXTENSION, "scicap");
    }

    #[test]
    fn help_mentions_product_and_extension_purpose() {
        let help = help_text();
        assert!(help.contains(PRODUCT_NAME));
        assert!(help.contains("Portable"));
        assert!(help.contains("--version"));
    }
}
