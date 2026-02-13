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

    let args = cli::Args::parse_args();

    // Set directory overrides from CLI args (must be done before any config access)
    if let Some(ref data_dir) = args.data_dir {
        config::set_data_dir(std::path::PathBuf::from(data_dir));
    }
    if let Some(ref config_dir) = args.config_dir {
        config::set_config_dir(std::path::PathBuf::from(config_dir));
    }

    logging::init()?;

    let mut app = app::App::new(&args)?;

    app.run().await?;

    Ok(())
}
