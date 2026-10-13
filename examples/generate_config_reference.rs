//! Refresh the commented application overrides and configuration table.
#[path = "support/config_reference.rs"]
mod reference;
fn main() -> anyhow::Result<()> {
    let check = std::env::args()
        .skip(1)
        .any(|argument| argument == "--check");
    reference::synchronize(check)
}
