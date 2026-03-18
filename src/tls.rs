use std::io;

use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::config::GatewayConfig;

/// Build a rustls ServerConfig from the gateway config.
/// If cert/key paths are provided, loads from disk.
/// Otherwise generates a self-signed cert for development.
pub fn build_server_config(cfg: &GatewayConfig) -> Result<ServerConfig, io::Error> {
    let (certs, key) = match (&cfg.tls_cert_path, &cfg.tls_key_path) {
        (Some(cert_path), Some(key_path)) => load_from_files(cert_path, key_path)?,
        _ => generate_self_signed()?,
    };

    let mut tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    // ALPN: h2 first, then http/1.1
    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(tls_config)
}

fn load_from_files(
    cert_path: &str,
    key_path: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), io::Error> {
    let cert_pem = std::fs::read(cert_path)?;
    let key_pem = std::fs::read(key_path)?;

    let certs = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<Result<Vec<_>, _>>()?;

    let key = rustls_pemfile::private_key(&mut &key_pem[..])?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no private key found"))?;

    Ok((certs, key))
}

fn generate_self_signed() -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), io::Error> {
    // Use ECDSA P-256 for self-signed dev certs — Chrome/BoringSSL rejects
    // self-signed ED25519 certs with ERR_SSL_PROTOCOL_ERROR.
    // Production certs (loaded from files) use ED25519 and work fine.
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(io::Error::other)?;

    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .map_err(io::Error::other)?;

    let cert = params
        .self_signed(&key_pair)
        .map_err(io::Error::other)?;

    let cert_der = CertificateDer::from(cert.der().to_vec());

    Ok((vec![cert_der], key_der))
}
