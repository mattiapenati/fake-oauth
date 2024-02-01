use color_eyre::eyre::Result;

use self::{config::Config, state::AppState};

mod config;
mod state;

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    let config = Config::load()?;
    let state = AppState::new(&config).await?;

    Ok(())
}
