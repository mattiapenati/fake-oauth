use std::path::PathBuf;

use color_eyre::Result;
use figment::{
    providers::{Env, Serialized},
    Figment,
};
use serde::Deserialize;

/// Application configuration
#[derive(Debug, Deserialize)]
pub struct Config {
    /// Database location
    pub database: PathBuf,
}

impl Config {
    /// Load the configuration from the environment variables
    pub fn load() -> Result<Self> {
        let config = Figment::new()
            .merge(Env::prefixed("MOCK_AUTH0_"))
            .join(Serialized::default("database", "/data/data.db"))
            .extract()?;
        Ok(config)
    }
}
