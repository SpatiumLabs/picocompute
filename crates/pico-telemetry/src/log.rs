//! Logging layer via tracing-subscriber.

use crate::settings::LogSettings;
use tracing_subscriber::EnvFilter;

pub(crate) fn create_filter(settings: &LogSettings) -> EnvFilter {
    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&settings.filter))
}
