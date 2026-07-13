use std::io;
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rustls::ServerConfig;
use rustls::pki_types::CertificateDer;

use gateway_model::types::sys::x509::x509::X509CertChain;

/// Build a rustls ServerConfig from an X509CertChain proto.
///
/// The cert chain and private key are stored as base64url-encoded PEM text
/// in the X509CertChain proto fields.
pub fn build_server_config(chain: &X509CertChain) -> Result<Arc<ServerConfig>, io::Error> {
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

    build_from_parts(certs, key)
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
