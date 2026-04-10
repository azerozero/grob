//! W-1 : test unitaire du chainage wizard setup -> auto_flow.
//!
//! Verifie qu'un cold install (`grob setup --yes`) ecrit bien le provider
//! Anthropic en OAuth et que le chainage vers `auto_flow::detect_credentials`
//! reconnait le token manquant — sans quoi `grob exec -- claude` tombait en 502.

#[cfg(test)]
mod tests {
    use grob::auth::auto_flow::{detect_credentials, CredentialStatus};
    use grob::auth::TokenStore;
    use grob::cli::AppConfig;
    use grob::commands::setup::{run_setup_wizard, SetupFlags};
    use grob::storage::GrobStore;
    use std::sync::Arc;
    use tempfile::tempdir;

    /// W-1 : apres `grob setup --yes`, le fichier config.toml contient bien le
    /// provider Anthropic en OAuth et auto_flow::detect_credentials retourne
    /// `MissingOAuth` — prouve que le chainage wizard -> auto_flow est cable.
    #[tokio::test]
    async fn test_w1_cold_install_chains_to_auto_flow() {
        let dir = tempdir().expect("tempdir");
        let config_path = dir.path().join("config.toml");

        // Isole le home pour que GrobStore::default_path pointe dans le tempdir.
        std::env::set_var("GROB_HOME", dir.path());

        let flags = SetupFlags {
            yes: true,
            dry_run: false,
        };
        let ok = run_setup_wizard(&config_path, &flags)
            .await
            .expect("wizard --yes should succeed");
        assert!(ok, "wizard --yes should return true");
        assert!(config_path.exists(), "config.toml should be written");

        let config = AppConfig::from_file(&config_path).expect("config parseable");
        let has_anthropic_oauth = config
            .providers
            .iter()
            .any(|p| p.name == "anthropic" && p.oauth_provider.as_deref() == Some("anthropic-max"));
        assert!(
            has_anthropic_oauth,
            "wizard --yes should configure anthropic OAuth"
        );

        // Chainage : un token store vide sur le meme home voit bien un
        // MissingOAuth quand on passe par auto_flow::detect_credentials.
        let store = Arc::new(GrobStore::open(&GrobStore::default_path()).expect("grob store open"));
        let token_store = TokenStore::with_store(store).expect("token store");
        let statuses = detect_credentials(&config.providers, &token_store);
        let missing_oauth = statuses
            .iter()
            .any(|s| matches!(s, CredentialStatus::MissingOAuth { .. }));
        assert!(
            missing_oauth,
            "auto_flow::detect_credentials should flag anthropic OAuth as missing \
             (proves the wizard -> auto_flow pipeline is wired)"
        );

        std::env::remove_var("GROB_HOME");
    }
}
