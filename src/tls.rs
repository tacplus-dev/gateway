//! The gateway's external TLS certificate: Config.external_cert_pem and
//! external_key_pem, the only source there is (letsencrypt mode is retired, #25).
//! The deployment's pipeline obtains and renews it and delivers it in the
//! gateway's config, and every config change that carries a new one is served
//! to new handshakes at once, with no restart
//! (tacplus-dev/roadmap:decisions/certificates-by-pipeline-2026-11-03.md).

use std::io;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum_server::tls_rustls::RustlsConfig;
use rustls::ServerConfig;
use rustls::pki_types::pem::{self, PemObject};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use gateway_model::types::services::gateway::gateway::Config as GatewayConfig;

/// Build a rustls ServerConfig from raw PEM strings: the certificate chain,
/// leaf first, and the leaf's private key.
///
/// Refused, so that nothing is served from it: an empty or unparseable PEM, a
/// leaf that has expired, and a key that is not the leaf's.
pub fn build_server_config_from_pem(cert_pem: &str, key_pem: &str) -> Result<Arc<ServerConfig>, io::Error> {
    if cert_pem.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "external_cert_pem is empty"));
    }
    if key_pem.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "external_key_pem is empty"));
    }

    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("external_cert_pem: {e}")))?;
    if certs.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "no certificates found in external_cert_pem"));
    }
    refuse_expired(&certs[0])?;

    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).map_err(|e| match e {
        pem::Error::NoItemsFound => {
            io::Error::new(io::ErrorKind::InvalidData, "no private key found in external_key_pem")
        }
        e => io::Error::new(io::ErrorKind::InvalidData, format!("external_key_pem: {e}")),
    })?;

    // with_single_cert refuses a key whose public half is not the leaf's.
    let mut tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("external_key_pem does not fit external_cert_pem: {e}"))
        })?;

    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(Arc::new(tls_config))
}

/// An expired leaf is refused rather than served: every client would reject
/// it, and the certificate it would replace may still be good.
fn refuse_expired(leaf: &CertificateDer<'_>) -> Result<(), io::Error> {
    let (_, cert) = x509_parser::parse_x509_certificate(leaf).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("external_cert_pem leaf is not X.509: {e}"))
    })?;
    let not_after = cert.validity().not_after;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| io::Error::other(format!("system clock: {e}")))?
        .as_secs() as i64;
    if not_after.timestamp() <= now {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("external_cert_pem expired at {not_after}"),
        ));
    }
    Ok(())
}

/// Hot-swaps the served certificate when the gateway config carries a new
/// external_cert_pem / external_key_pem.
///
/// The swap is RustlsConfig::reload_from_config: new handshakes get the new
/// certificate, and a connection already established keeps the session it
/// has, so nothing is dropped.
///
/// A rejected certificate is DISCARDED: the previously loaded, working
/// certificate keeps serving. Swapping in a broken cert because someone pasted a
/// malformed PEM would take the public endpoint down, which is strictly worse than
/// continuing on the old one until it is corrected.
pub struct CertChainReloader {
    tls_config: RustlsConfig,
    /// The PEMs being served, so that a config change that does not touch
    /// them (any other field) rebuilds nothing.
    serving: Mutex<(String, String)>,
}

impl CertChainReloader {
    /// `tls_config` is the listener's, already serving `initial`'s PEMs.
    pub fn new(tls_config: RustlsConfig, initial: &GatewayConfig) -> Self {
        Self {
            tls_config,
            serving: Mutex::new((initial.external_cert_pem.clone(), initial.external_key_pem.clone())),
        }
    }

    /// Serve `cfg`'s certificate if it differs from the one being served.
    /// Ok(true) when it was swapped in, Ok(false) when it is unchanged, Err
    /// (and the current certificate kept) when it is refused.
    pub fn apply(&self, cfg: &GatewayConfig) -> Result<bool, io::Error> {
        let mut serving = self.serving.lock().unwrap_or_else(|e| e.into_inner());
        if serving.0 == cfg.external_cert_pem && serving.1 == cfg.external_key_pem {
            return Ok(false);
        }
        let new_config = build_server_config_from_pem(&cfg.external_cert_pem, &cfg.external_key_pem)?;
        self.tls_config.reload_from_config(new_config);
        *serving = (cfg.external_cert_pem.clone(), cfg.external_key_pem.clone());
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::SocketAddr;

    use gateway_key::keys;
    use gateway_x509::x509::{ImmutableCertChain, X509KeyUsage};
    use http_body_util::{BodyExt, Empty};
    use hyper_util::rt::TokioIo;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{ServerName, UnixTime};
    use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};

    /// A self-signed certificate expiring `expires_in` seconds from now, as
    /// PEM, plus its key's PEM and the certificate's serial.
    struct TestCert {
        cert_pem: String,
        key_pem: String,
        serial: Vec<u8>,
    }

    fn test_cert(name: &str, expires_in: i64) -> TestCert {
        let key = keys::generate_ec_p256_key().expect("key");
        let key_pem = String::from_utf8(key.pem_bytes().to_vec()).expect("key pem");
        let expiry = SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_secs() as i64 + expires_in;
        let cert = ImmutableCertChain::for_self_signing(key)
            .self_sign(name, expiry, X509KeyUsage::DigitalSignature, &[])
            .expect("cert");
        let cert_pem = String::from_utf8(cert.pem_bytes().to_vec()).expect("cert pem");
        let der = CertificateDer::from_pem_slice(cert_pem.as_bytes()).expect("one cert");
        TestCert { cert_pem, key_pem, serial: serial_of(&der) }
    }

    /// A certificate that has expired. The signer will not sign one expiring
    /// in the past, so this one expires in a second and is returned after it.
    fn expired_cert(name: &str) -> TestCert {
        let cert = test_cert(name, 1);
        std::thread::sleep(std::time::Duration::from_millis(2100));
        cert
    }

    fn serial_of(der: &[u8]) -> Vec<u8> {
        let (_, cert) = x509_parser::parse_x509_certificate(der).expect("x509");
        cert.raw_serial().to_vec()
    }

    fn config_with(cert: &TestCert) -> GatewayConfig {
        GatewayConfig {
            external_cert_pem: cert.cert_pem.clone(),
            external_key_pem: cert.key_pem.clone(),
            ..Default::default()
        }
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

    /// Serves "ok" over TLS on a loopback port, the way main() serves the
    /// edge: axum_server::bind_rustls on the RustlsConfig the reloader swaps.
    async fn serve(tls_config: RustlsConfig) -> SocketAddr {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let handle = axum_server::Handle::new();
        let app = axum::Router::new().route("/", axum::routing::get(|| async { "ok" }));
        let server = axum_server::bind_rustls("127.0.0.1:0".parse().unwrap(), tls_config)
            .handle(handle.clone())
            .serve(app.into_make_service());
        tokio::spawn(server);
        handle.listening().await.expect("listening")
    }

    /// One client connection, kept open across requests.
    struct Conn {
        sender: hyper::client::conn::http1::SendRequest<Empty<bytes::Bytes>>,
        serial: Vec<u8>,
    }

    /// Opens a TLS connection and returns it with the serial of the leaf the
    /// server presented in its handshake.
    async fn connect(addr: SocketAddr) -> Conn {
        let mut client_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnything))
            .with_no_client_auth();
        client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let tcp = tokio::net::TcpStream::connect(addr).await.expect("tcp");
        let tls = tokio_rustls::TlsConnector::from(Arc::new(client_config))
            .connect(ServerName::try_from("console.example.com").unwrap(), tcp)
            .await
            .expect("handshake");
        let serial = serial_of(&tls.get_ref().1.peer_certificates().expect("peer certs")[0]);
        let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await.expect("http1");
        tokio::spawn(conn);
        Conn { sender, serial }
    }

    impl Conn {
        /// A request on this same connection answers "ok".
        async fn get_ok(&mut self) {
            let req = http::Request::builder()
                .uri("/")
                .header(http::header::HOST, "console.example.com")
                .body(Empty::new())
                .unwrap();
            let resp = self.sender.send_request(req).await.expect("request on the open connection");
            assert_eq!(resp.status(), http::StatusCode::OK);
            assert_eq!(&resp.into_body().collect().await.unwrap().to_bytes()[..], b"ok");
        }
    }

    /// The issue's case: the config changes twice, and each time new
    /// connections are served the new certificate (by serial) while a
    /// connection opened before either change keeps working on its own.
    #[tokio::test]
    async fn config_changes_swap_the_served_certificate_without_dropping_connections() {
        let first = test_cert("console.example.com", 3600);
        let second = test_cert("console.example.com", 7200);
        let third = test_cert("console.example.com", 10800);
        let initial = config_with(&first);
        let tls_config = RustlsConfig::from_config(
            build_server_config_from_pem(&initial.external_cert_pem, &initial.external_key_pem).expect("initial"),
        );
        let reloader = CertChainReloader::new(tls_config.clone(), &initial);
        let addr = serve(tls_config).await;

        let mut in_flight = connect(addr).await;
        assert_eq!(in_flight.serial, first.serial);
        in_flight.get_ok().await;

        assert!(reloader.apply(&config_with(&second)).expect("second applied"));
        let mut conn = connect(addr).await;
        assert_eq!(conn.serial, second.serial);
        conn.get_ok().await;
        in_flight.get_ok().await;

        assert!(reloader.apply(&config_with(&third)).expect("third applied"));
        let mut conn = connect(addr).await;
        assert_eq!(conn.serial, third.serial);
        conn.get_ok().await;
        in_flight.get_ok().await;
        assert_eq!(in_flight.serial, first.serial);
    }

    /// A config change that leaves the PEMs alone rebuilds nothing.
    #[test]
    fn a_change_to_other_fields_is_not_a_reload() {
        let cert = test_cert("console.example.com", 3600);
        let initial = config_with(&cert);
        let tls_config = RustlsConfig::from_config(
            build_server_config_from_pem(&cert.cert_pem, &cert.key_pem).expect("initial"),
        );
        let reloader = CertChainReloader::new(tls_config, &initial);

        let mut changed = initial.clone();
        changed.enable_http3 = !changed.enable_http3;
        assert!(!reloader.apply(&changed).expect("unchanged"));
    }

    /// An expired certificate is refused on reload, the error reported, and
    /// the current one kept serving.
    #[tokio::test]
    async fn an_expired_certificate_is_refused_on_reload() {
        let current = test_cert("console.example.com", 3600);
        let expired = expired_cert("console.example.com");
        let initial = config_with(&current);
        let tls_config = RustlsConfig::from_config(
            build_server_config_from_pem(&current.cert_pem, &current.key_pem).expect("initial"),
        );
        let reloader = CertChainReloader::new(tls_config.clone(), &initial);
        let addr = serve(tls_config).await;

        let err = reloader.apply(&config_with(&expired)).expect_err("expired is refused");
        assert!(err.to_string().contains("expired"), "{err}");
        assert_eq!(connect(addr).await.serial, current.serial);
    }

    /// A key that is not the certificate's is refused on reload, the error
    /// reported, and the current certificate kept serving.
    #[tokio::test]
    async fn a_key_that_does_not_match_is_refused_on_reload() {
        let current = test_cert("console.example.com", 3600);
        let next = test_cert("console.example.com", 7200);
        let other = test_cert("console.example.com", 7200);
        let initial = config_with(&current);
        let tls_config = RustlsConfig::from_config(
            build_server_config_from_pem(&current.cert_pem, &current.key_pem).expect("initial"),
        );
        let reloader = CertChainReloader::new(tls_config.clone(), &initial);
        let addr = serve(tls_config).await;

        let mismatched = GatewayConfig { external_key_pem: other.key_pem.clone(), ..config_with(&next) };
        let err = reloader.apply(&mismatched).expect_err("mismatched key is refused");
        assert!(err.to_string().contains("does not fit"), "{err}");
        assert_eq!(connect(addr).await.serial, current.serial);

        // The refusal is not remembered as served: the corrected config
        // still swaps.
        assert!(reloader.apply(&config_with(&next)).expect("corrected"));
        assert_eq!(connect(addr).await.serial, next.serial);
    }

    /// At load, an expired certificate or a key that does not match it is
    /// refused: the gateway does not start serving it.
    #[test]
    fn an_expired_certificate_or_mismatched_key_is_refused_at_load() {
        let expired = expired_cert("console.example.com");
        let err = build_server_config_from_pem(&expired.cert_pem, &expired.key_pem).expect_err("expired");
        assert!(err.to_string().contains("expired"), "{err}");

        let cert = test_cert("console.example.com", 3600);
        let other = test_cert("console.example.com", 3600);
        let err = build_server_config_from_pem(&cert.cert_pem, &other.key_pem).expect_err("mismatched");
        assert!(err.to_string().contains("does not fit"), "{err}");

        assert!(build_server_config_from_pem(&cert.cert_pem, &cert.key_pem).is_ok());
    }

    /// Each PEM field is read for its own kind of section and the others are
    /// skipped, so a bundle holding the chain and the key serves from either
    /// field; a field with none of its kind is refused by name (#31).
    #[test]
    fn each_pem_field_is_read_for_its_own_kind_of_section() {
        let cert = test_cert("console.example.com", 3600);
        let bundle = format!("{}\n{}", cert.key_pem, cert.cert_pem);
        assert!(build_server_config_from_pem(&bundle, &bundle).is_ok());

        let err = build_server_config_from_pem(&cert.key_pem, &cert.key_pem).expect_err("no cert");
        assert!(err.to_string().contains("no certificates found in external_cert_pem"), "{err}");

        let err = build_server_config_from_pem(&cert.cert_pem, &cert.cert_pem).expect_err("no key");
        assert!(err.to_string().contains("no private key found in external_key_pem"), "{err}");

        let err = build_server_config_from_pem("not pem", &cert.key_pem).expect_err("not pem");
        assert!(err.to_string().contains("no certificates found in external_cert_pem"), "{err}");
    }
}
