use std::env;

#[derive(Debug, Clone)]
pub(crate) struct Config {
    pub api_url: String,
    pub token: String,
}

impl Config {
    pub(crate) fn from_env() -> Self {
        let api_url =
            env::var("PICO_API_URL").unwrap_or_else(|_| "http://localhost:8080".to_string());
        let token = env::var("PICO_API_TOKEN").unwrap_or_default();
        Self { api_url, token }
    }

    pub(crate) fn apply_overrides(&mut self, api_url: Option<String>, token: Option<String>) {
        if let Some(url) = api_url {
            self.api_url = url;
        }
        if let Some(t) = token {
            self.token = t;
        }
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.token.is_empty() {
            return Err("PICO_API_TOKEN must be set via env or --token flag".to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_env_loads_without_panicking() {
        let cfg = Config::from_env();
        // URL should be set (either from env or default)
        assert!(!cfg.api_url.is_empty());
    }

    #[test]
    fn validate_rejects_empty_token() {
        let cfg = Config {
            api_url: "http://example.com".into(),
            token: String::new(),
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_accepts_non_empty_token() {
        let cfg = Config {
            api_url: "http://example.com".into(),
            token: "secret".into(),
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn apply_overrides_replaces_values() {
        let mut cfg = Config {
            api_url: "http://original.com".into(),
            token: "old".into(),
        };
        cfg.apply_overrides(Some("http://override.com".into()), Some("new-token".into()));
        assert_eq!(cfg.api_url, "http://override.com");
        assert_eq!(cfg.token, "new-token");
    }

    #[test]
    fn apply_overrides_skips_none() {
        let mut cfg = Config {
            api_url: "http://original.com".into(),
            token: "old".into(),
        };
        cfg.apply_overrides(None, None);
        assert_eq!(cfg.api_url, "http://original.com");
        assert_eq!(cfg.token, "old");
    }
}
