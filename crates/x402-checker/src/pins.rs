//! The upstream commits the checks were written against, stamped in every report.
//!
//! They live in source rather than being read from `spec/` at compile time so that the published crate builds
//! outside the workspace; a test keeps them equal to `spec/UPSTREAM_COMMIT` and `spec/external/EIP3009_COMMIT` when
//! those files are present.

/// Commit of the x402 repository the copies under `spec/` come from.
pub const SPEC_COMMIT: &str = "59f1347a1a0828af6c9eb9c01298338d3eff3053";

/// Commit of the `ethereum/ERCs` repository the EIP-3009 copy under `spec/external/` comes from.
pub const EIP3009_COMMIT: &str = "7c9338feb41279b037700259c631ff6f51b0df3d";

#[cfg(test)]
mod tests {
    use super::*;

    fn pinned(path: &str) -> Option<String> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        std::fs::read_to_string(root.join(path))
            .ok()
            .map(|s| s.trim().to_owned())
    }

    #[test]
    fn the_source_pins_match_the_spec_directory_when_it_is_there() {
        if let Some(commit) = pinned("spec/UPSTREAM_COMMIT") {
            assert_eq!(commit, SPEC_COMMIT, "update crates/x402-checker/src/pins.rs");
        }
        if let Some(commit) = pinned("spec/external/EIP3009_COMMIT") {
            assert_eq!(commit, EIP3009_COMMIT, "update crates/x402-checker/src/pins.rs");
        }
    }
}
