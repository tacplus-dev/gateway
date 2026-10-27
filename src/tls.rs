use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use axum_server::tls_rustls::RustlsConfig;
use base64::Engine;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

use gateway_model::types::services::letsencrypt::letsencrypt::LetsEncryptCertData;
use gateway_model::types::sys::x509::x509::X509CertChain;

/// Build a rustls ServerConfig from the letsencrypt certificate set.
///
/// letsencrypt issues one single-name certificate per hostname. Each entry in
/// `certs` is served to a ClientHello whose SNI names its hostname; `tls_cert`
/// (hostnames[0]'s) is served when SNI is absent or names no entry.
pub fn build_server_config(data: &LetsEncryptCertData) -> Result<Arc<ServerConfig>, io::Error> {
    let chain = data
        .tls_cert
        .as_ref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no tls_cert in cert_data"))?;
    let builder = ServerConfig::builder().with_no_client_auth();
    let provider = builder.crypto_provider().clone();
    let certified = |chain: &X509CertChain| {
        let (certs, key) = decode_chain(chain)?;
        CertifiedKey::from_der(certs, key, &provider)
            .map(Arc::new)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    };

    let mut by_name = HashMap::new();
    for named in &data.certs {
        let chain = named.tls_cert.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, format!("no tls_cert for {}", named.hostname))
        })?;
        by_name.insert(named.hostname.to_ascii_lowercase(), certified(chain)?);
    }
    let resolver = SniCerts { default: certified(chain)?, by_name };

    let mut tls_config = builder.with_cert_resolver(Arc::new(resolver));
    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(tls_config))
}

/// Serve one LetsEncryptState.cert_data watch event: the primary certificate
/// and every named one in it, replacing whatever was served before. An event
/// with no tls_cert yet, or one that will not build, keeps the current config.
pub fn apply_cert_data(tls_config: &RustlsConfig, cert_data: &LetsEncryptCertData) {
    if cert_data.tls_cert.is_none() {
        return;
    }
    match build_server_config(cert_data) {
        Ok(new_config) => {
            tls_config.reload_from_config(new_config);
            tracing::info!(
                hostnames = ?cert_data.hostnames,
                sni_certs = ?cert_data.certs.iter().map(|c| &c.hostname).collect::<Vec<_>>(),
                "TLS certificate hot-reloaded"
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to build TLS config from renewed cert");
        }
    }
}

/// Picks the certificate by SNI. Keys are lowercase; rustls lowercases the SNI.
#[derive(Debug)]
struct SniCerts {
    default: Arc<CertifiedKey>,
    by_name: HashMap<String, Arc<CertifiedKey>>,
}

impl ResolvesServerCert for SniCerts {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let named = client_hello.server_name().and_then(|name| self.by_name.get(name));
        Some(named.unwrap_or(&self.default).clone())
    }
}

/// Decode an X509CertChain proto. The cert chain and private key are stored as
/// base64url-encoded PEM text in its fields.
fn decode_chain(
    chain: &X509CertChain,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), io::Error> {
    // Decode each X509Cert.base64 (base64url-encoded PEM) into DER certs.
    let mut certs = Vec::new();
    for x509 in &chain.chain {
        let pem_bytes = URL_SAFE_NO_PAD
            .decode(&x509.base64)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("base64 decode cert: {e}")))?;
        let parsed: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut &pem_bytes[..]).collect::<Result<Vec<_>, _>>()?;
        certs.extend(parsed);
    }

    // Decode private key: Key.base64 is base64url-encoded PEM.
    let key_proto = chain
        .key
        .as_ref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no private key in cert_chain"))?;
    let key_pem = URL_SAFE_NO_PAD
        .decode(&key_proto.base64)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("base64 decode key: {e}")))?;
    let key = rustls_pemfile::private_key(&mut &key_pem[..])?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no private key found in PEM"))?;

    Ok((certs, key))
}

/// Build a rustls ServerConfig from raw PEM strings.
/// Used for CERT_CHAIN mode where the cert and key come directly from config.
pub fn build_server_config_from_pem(cert_pem: &str, key_pem: &str) -> Result<Arc<ServerConfig>, io::Error> {
    if cert_pem.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "external_cert_pem is empty"));
    }
    if key_pem.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "external_key_pem is empty"));
    }

    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_pem.as_bytes()).collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "no certificates found in external_cert_pem"));
    }

    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no private key found in external_key_pem"))?;

    build_from_parts(certs, key)
}

fn build_from_parts(
    certs: Vec<CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<Arc<ServerConfig>, io::Error> {
    let mut tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(Arc::new(tls_config))
}

#[cfg(test)]
mod tests {
    use super::*;

    use gateway_key::keys;
    use gateway_model::types::services::letsencrypt::letsencrypt::NamedCert;
    use gateway_model::types::sys::key::key::Key;
    use gateway_model::types::sys::x509::x509::X509Cert;
    use gateway_x509::x509::{ImmutableCertChain, X509KeyUsage};
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{ServerName, UnixTime};
    use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, ServerConnection, SignatureScheme};

    /// A self-signed certificate, as letsencrypt would hand it over, plus its
    /// DER so a test can tell which one the server presented.
    fn cert(name: &str) -> (X509CertChain, Vec<u8>) {
        let key = keys::generate_ec_p256_key().expect("key");
        let key_pem = key.pem_bytes().to_vec();
        let expiry = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs() as i64
            + 3600;
        let cert = ImmutableCertChain::for_self_signing(key)
            .self_sign(name, expiry, X509KeyUsage::DigitalSignature, &[])
            .expect("cert");
        let der = rustls_pemfile::certs(&mut cert.pem_bytes())
            .next()
            .expect("one cert")
            .expect("der")
            .to_vec();
        let chain = X509CertChain {
            chain: vec![X509Cert { base64: URL_SAFE_NO_PAD.encode(cert.pem_bytes()), ..Default::default() }],
            key: Some(Key { base64: URL_SAFE_NO_PAD.encode(key_pem), ..Default::default() }),
            ..Default::default()
        };
        (chain, der)
    }

    /// The client only needs to see which certificate came back; whether it
    /// would be trusted is the browser's business, not this test's.
    #[derive(Debug)]
    struct AcceptAnything;

    impl ServerCertVerifier for AcceptAnything {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    /// Runs an in-memory handshake and returns the leaf the server presented.
    /// `sni` of None sends a ClientHello with no server_name at all.
    fn presented_leaf(server: Arc<ServerConfig>, sni: Option<&str>) -> Vec<u8> {
        let mut client_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnything))
            .with_no_client_auth();
        client_config.enable_sni = sni.is_some();
        let name = ServerName::try_from(sni.unwrap_or("no-sni.test").to_string()).expect("name");
        let mut client = ClientConnection::new(Arc::new(client_config), name).expect("client");
        let mut server = ServerConnection::new(server).expect("server");

        while client.is_handshaking() || server.is_handshaking() {
            let mut buf = Vec::new();
            client.write_tls(&mut buf).expect("client write");
            server.read_tls(&mut &buf[..]).expect("server read");
            server.process_new_packets().expect("server handshake");
            let mut buf = Vec::new();
            server.write_tls(&mut buf).expect("server write");
            client.read_tls(&mut &buf[..]).expect("client read");
            client.process_new_packets().expect("client handshake");
        }
        client.peer_certificates().expect("peer certs")[0].to_vec()
    }

    fn cert_data(default: &X509CertChain, named: &[(&str, &X509CertChain)]) -> LetsEncryptCertData {
        LetsEncryptCertData {
            tls_cert: Some(default.clone()),
            certs: named
                .iter()
                .map(|(hostname, chain)| NamedCert {
                    hostname: hostname.to_string(),
                    tls_cert: Some((*chain).clone()),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }
    }

    /// Each public name gets its own single-name certificate, chosen by SNI.
    #[test]
    fn each_hostname_is_served_its_own_certificate() {
        let (console, console_der) = cert("console.example.com");
        let (app, app_der) = cert("app.example.com");
        let config = build_server_config(&cert_data(
            &console,
            &[("console.example.com", &console), ("App.Example.Com", &app)],
        ))
        .expect("config");

        assert_eq!(presented_leaf(config.clone(), Some("app.example.com")), app_der);
        assert_eq!(presented_leaf(config.clone(), Some("APP.example.com")), app_der);
        assert_eq!(presented_leaf(config, Some("console.example.com")), console_der);
    }

    /// No SNI (a bare IP) or a name with no certificate of its own gets
    /// tls_cert, which is everything the gateway served before.
    #[test]
    fn no_or_unknown_sni_is_served_the_primary_certificate() {
        let (console, console_der) = cert("console.example.com");
        let (app, _) = cert("app.example.com");
        let config =
            build_server_config(&cert_data(&console, &[("app.example.com", &app)])).expect("config");

        assert_eq!(presented_leaf(config.clone(), None), console_der);
        assert_eq!(presented_leaf(config, Some("other.example.com")), console_der);
    }

    /// cert_data from a letsencrypt that predates `certs` serves exactly as
    /// before: one certificate for every name.
    #[test]
    fn cert_data_without_named_certs_serves_tls_cert_alone() {
        let (console, console_der) = cert("console.example.com");
        let config = build_server_config(&cert_data(&console, &[])).expect("config");

        assert_eq!(presented_leaf(config, Some("app.example.com")), console_der);
    }

    /// The defect-10 shape: the gateway starts serving cert_data with only the
    /// primary certificate, and letsencrypt later delivers the second name's
    /// own certificate. The next watch event has to make that name answer with
    /// it, on the config the listener already holds.
    #[test]
    fn a_named_certificate_added_after_startup_answers_its_sni() {
        let (console, console_der) = cert("console.example.com");
        let (app, app_der) = cert("app.example.com");
        let tls_config =
            RustlsConfig::from_config(build_server_config(&cert_data(&console, &[])).expect("config"));
        assert_eq!(presented_leaf(tls_config.get_inner(), Some("app.example.com")), console_der);

        apply_cert_data(
            &tls_config,
            &cert_data(&console, &[("console.example.com", &console), ("app.example.com", &app)]),
        );

        assert_eq!(presented_leaf(tls_config.get_inner(), Some("app.example.com")), app_der);
        assert_eq!(presented_leaf(tls_config.get_inner(), Some("console.example.com")), console_der);
    }

    /// A named certificate whose key does not match its leaf is rejected as a
    /// whole, so the watcher keeps serving the previous config.
    #[test]
    fn a_named_certificate_with_the_wrong_key_is_rejected() {
        let (console, _) = cert("console.example.com");
        let (mut app, _) = cert("app.example.com");
        app.key = console.key.clone();

        assert!(build_server_config(&cert_data(&console, &[("app.example.com", &app)])).is_err());
    }
}
