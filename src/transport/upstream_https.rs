//! Upstream HTTPS transport.
//!
//! Connects to a remote MCP server over TLS using rustls with the ring
//! cryptography provider (no OpenSSL dependency — NFR-S1).  Loads the
//! platform's native certificate store so that corporate CAs are trusted
//! without extra configuration (Decision 9).
//!
//! When an [`UpstreamAuth`] credential is supplied it is injected as a
//! `Bearer` `Authorization` header at the HTTP level.  The raw token value is
//! never written to logs, error messages, or tracing spans (NFR-S2).

use anyhow::Context as _;
use rmcp::{RoleClient, service::{RunningService, serve_client_with_ct}};
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use secrecy::ExposeSecret as _;
use tokio_util::sync::CancellationToken;

use crate::config::UpstreamAuth;

/// Upstream HTTPS transport.
///
/// Opens an HTTPS connection to the configured URL, completes the MCP client
/// handshake, and returns the running service handle.
pub(crate) struct UpstreamHttpsTransport;

impl UpstreamHttpsTransport {
    /// Connect to a remote MCP server at `url` and complete the MCP client
    /// handshake.
    ///
    /// Returns the running client service and a display name suitable for use
    /// in audit log entries.  The display name is the URL's hostname, falling
    /// back to the full URL string if parsing fails.
    ///
    /// # Errors
    ///
    /// Returns an error if TLS configuration fails, if the HTTP client cannot
    /// be built, or if the MCP handshake is rejected by the remote server.
    pub(crate) async fn connect(
        url: &str,
        auth: Option<UpstreamAuth>,
        token: CancellationToken,
    ) -> anyhow::Result<(RunningService<RoleClient, ()>, String)> {
        let display_name = derive_display_name(url);

        let tls_config = build_tls_config()?;
        let http_client = reqwest::ClientBuilder::new()
            .tls_backend_preconfigured(tls_config)
            .build()
            .context("failed to build HTTP client")?;

        // Only call expose_secret() here at the injection point (NFR-S2).
        // Never log the token or include it in error messages.
        let auth_header = auth.map(|a| format!("Bearer {}", a.bearer_token.expose_secret()));

        let transport_config = StreamableHttpClientTransportConfig::with_uri(url).auth_header(
            auth_header.unwrap_or_default(),
        );

        let transport =
            StreamableHttpClientTransport::with_client(http_client, transport_config);

        let service: RunningService<RoleClient, ()> =
            serve_client_with_ct((), transport, token)
                .await
                .context("upstream MCP handshake failed")?;

        Ok((service, display_name))
    }
}

/// Build a `rustls::ClientConfig` loaded with the platform's native root
/// certificate store.
///
/// Individual certificate load failures are logged at `DEBUG` level (they
/// are common in environments with mixed CA stores and are non-actionable
/// unless *all* certificates fail to load).  The process aborts only when
/// no certificates at all could be loaded.
fn build_tls_config() -> anyhow::Result<rustls::ClientConfig> {
    let mut root_store = rustls::RootCertStore::empty();
    let certs = rustls_native_certs::load_native_certs();
    for error in &certs.errors {
        tracing::debug!("skipped native cert (load error): {error}");
    }
    let mut certs_loaded: usize = 0;
    for cert in certs.certs {
        root_store
            .add(cert)
            .context("failed to add certificate to root store")?;
        certs_loaded += 1;
    }
    tracing::debug!(certs_loaded, "native TLS certificate store loaded");
    if root_store.is_empty() {
        anyhow::bail!("no native root certificates could be loaded");
    }
    Ok(rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth())
}

/// Derive a human-readable display name from an HTTPS URL.
///
/// Returns the hostname component, falling back to the full URL string if
/// the URL cannot be parsed or has no host.
fn derive_display_name(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_else(|| url.to_owned())
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_display_name_extracts_host() {
        assert_eq!(
            derive_display_name("https://api.example.com/mcp"),
            "api.example.com"
        );
    }

    #[test]
    fn derive_display_name_with_port_extracts_host_only() {
        assert_eq!(
            derive_display_name("https://api.example.com:8443/mcp"),
            "api.example.com"
        );
    }

    #[test]
    fn derive_display_name_falls_back_for_unparseable_url() {
        let raw = "not-a-url";
        assert_eq!(derive_display_name(raw), raw);
    }
}
