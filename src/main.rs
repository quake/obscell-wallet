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

    if let Some(ref data_dir) = args.data_dir {
        // SAFETY: This is called at program startup before any other threads exist
        unsafe {
            std::env::set_var("OBSCELL_WALLET_DATA", data_dir);
        }
    }

    logging::init()?;

    let mut app = app::App::new(&args)?;

    app.run().await?;

    Ok(())
}
