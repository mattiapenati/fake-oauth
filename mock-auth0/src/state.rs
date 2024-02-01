use color_eyre::eyre::Result;
use sqlx::{sqlite::SqliteConnectOptions, SqlitePool};

use crate::config::Config;

/// Application state
#[derive(Debug)]
pub struct AppState {
    pub sqlite: SqlitePool,
}

impl AppState {
    /// Create a new instance of application
    pub async fn new(config: &Config) -> Result<Self> {
        let sqlite = SqlitePool::connect_with(
            SqliteConnectOptions::new()
                .filename(&config.database)
                .create_if_missing(true),
        )
        .await?;
        sqlx::migrate!().run(&sqlite).await?;

        Ok(Self { sqlite })
    }
}
