//! Web UI entry point
//!
//! Initializes logging and mounts the Leptos application.

use web_ui::App;

fn main() {
    // Initialize tracing for WASM
    tracing_subscriber::fmt()
        .with_writer(tracing_web::MakeWebConsoleWriter::new())
        .with_ansi(false)
        .without_time()
        .init();

    tracing::info!("Starting Argus WebUI");

    // Mount the app
    leptos::mount::mount_to_body(App);
}
