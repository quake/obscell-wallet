// Allow some dead code for now - these are planned features
#![allow(dead_code)]

use color_eyre::Result;

mod action;
mod app;
mod cli;
mod components;
mod config;
mod domain;
mod errors;
mod infra;
mod logging;
mod tui;

#[tokio::main]
async fn main() -> Result<()> {
    errors::install_hooks()?;
    logging::init()?;

    let args = cli::Args::parse_args();
    let mut app = app::App::new(&args)?;

    app.run().await?;

    Ok(())
}
