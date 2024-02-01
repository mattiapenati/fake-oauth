use color_eyre::eyre::Result;
use config::Config;
use sqlx::{sqlite::SqliteConnectOptions, ConnectOptions};

mod config;

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    let config = Config::load()?;
    let sqlite = SqliteConnectOptions::new()
        .filename(&config.database)
        .create_if_missing(true)
        .connect()
        .await?;

    Ok(())
}
