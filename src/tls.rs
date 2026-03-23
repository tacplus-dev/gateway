use std::io;
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rustls::ServerConfig;
use rustls::pki_types::CertificateDer;

use gateway_tacplus::types::services::kernel::GatewayTlsCert;

/// Build a rustls ServerConfig from a state-provided GatewayTlsCert.
///
/// The cert chain and private key are stored as base64url-encoded PEM text
/// in the X509CertChain proto fields.
pub fn build_server_config(cert: &GatewayTlsCert) -> Result<Arc<ServerConfig>, io::Error> {
    let chain = cert
        .cert_chain
        .as_ref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no cert_chain"))?;

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

    let mut tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(Arc::new(tls_config))
}
