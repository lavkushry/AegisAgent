//! Agent-to-gateway mTLS authentication (#1310).
//!
//! Pure, unit-testable helpers used by the manual TLS accept loop in
//! `main.rs`: extracting the Subject CN from a verified client certificate,
//! and building the rustls client-certificate verifier (CA root store +
//! optional CRL) from `AEGIS_MTLS_CA_CERT` / `AEGIS_MTLS_CRL_PATH`. Kept
//! separate from the hyper/rustls wiring itself, which (like the rest of
//! the accept loop) has no direct unit-test coverage — only this pure
//! logic does.

use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

use rustls::server::danger::ClientCertVerifier;
use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;
use rustls_pki_types::{CertificateDer, CertificateRevocationListDer};

/// Internal request header carrying the verified client certificate's
/// Subject CN from the TLS accept loop to `authorize_action`. A client can
/// never set this over the wire: every serving code path strips any
/// client-supplied value before (on the mTLS path) conditionally
/// re-inserting the value extracted from the just-verified handshake. See
/// `main.rs`.
pub const MTLS_CN_HEADER: &str = "x-aegis-mtls-cn";

/// Extracts the Subject Common Name from the leaf (first) certificate in a
/// verified client certificate chain. Returns `None` if the chain is empty,
/// the certificate fails to parse, or it has no CN attribute — all treated
/// identically by the caller (no usable identity to propagate).
pub fn extract_cn_from_certs(certs: &[CertificateDer<'_>]) -> Option<String> {
    let leaf = certs.first()?;
    let (_, x509) = x509_parser::parse_x509_certificate(leaf.as_ref()).ok()?;
    let cn = x509
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(|s| s.to_string());
    cn
}

/// Builds a rustls client-certificate verifier from a PEM-encoded CA
/// certificate (or chain) and an optional PEM-encoded CRL, for use with
/// `ServerConfig::builder().with_client_cert_verifier(...)`.
pub fn build_client_cert_verifier(
    ca_cert_path: &str,
    crl_path: Option<&str>,
) -> std::io::Result<Arc<dyn ClientCertVerifier>> {
    let ca_certs = load_certs(ca_cert_path)?;
    let mut roots = RootCertStore::empty();
    for cert in ca_certs {
        roots
            .add(cert)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    }

    let mut builder = WebPkiClientVerifier::builder(Arc::new(roots));
    if let Some(path) = crl_path {
        builder = builder.with_crls(load_crls(path)?);
    }
    builder
        .build()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
}

fn load_certs(path: &str) -> std::io::Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()
}

fn load_crls(path: &str) -> std::io::Result<Vec<CertificateRevocationListDer<'static>>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::crls(&mut reader).collect::<Result<Vec<_>, _>>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        date_time_ymd, BasicConstraints, CertificateParams, CertificateRevocationListParams,
        DistinguishedName, DnType, IsCa, Issuer, KeyIdMethod, KeyPair, KeyUsagePurpose,
        RevocationReason, RevokedCertParams, SerialNumber,
    };
    use std::io::Write;

    /// A throwaway CA: cert params (kept around so client certs can be
    /// signed by, and CRLs issued by, the same issuer) plus its key pair.
    struct TestCa {
        params: CertificateParams,
        key: KeyPair,
        pem: String,
    }

    fn make_ca() -> TestCa {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::CrlSign,
        ];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Test CA");
        params.distinguished_name = dn;
        let key = KeyPair::generate().expect("CA keypair");
        let cert = params.self_signed(&key).expect("self-signed CA cert");
        TestCa {
            params,
            key,
            pem: cert.pem(),
        }
    }

    fn make_client_cert(cn: &str, serial: u64, ca: &TestCa) -> CertificateDer<'static> {
        let mut params = CertificateParams::default();
        params.serial_number = Some(SerialNumber::from(serial));
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        params.distinguished_name = dn;
        let key = KeyPair::generate().expect("client keypair");
        let issuer = Issuer::from_params(&ca.params, &ca.key);
        let cert = params
            .signed_by(&key, &issuer)
            .expect("CA-signed client cert");
        cert.der().clone()
    }

    fn write_temp_pem(contents: &str) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().expect("temp file");
        file.write_all(contents.as_bytes()).expect("write pem");
        file.flush().expect("flush pem");
        file
    }

    fn revoke_serial(ca: &TestCa, serial: u64) -> String {
        let issuer = Issuer::from_params(&ca.params, &ca.key);
        let revoked = RevokedCertParams {
            serial_number: SerialNumber::from(serial),
            revocation_time: date_time_ymd(2020, 1, 1),
            reason_code: Some(RevocationReason::KeyCompromise),
            invalidity_date: None,
        };
        let crl_params = CertificateRevocationListParams {
            this_update: date_time_ymd(2020, 1, 1),
            next_update: date_time_ymd(2999, 1, 1),
            crl_number: SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs: vec![revoked],
            key_identifier_method: KeyIdMethod::Sha256,
        };
        crl_params
            .signed_by(&issuer)
            .expect("signed CRL")
            .pem()
            .expect("CRL pem")
    }

    #[test]
    fn extracts_cn_from_valid_client_cert() {
        let ca = make_ca();
        let client_der = make_client_cert("agent-007", 1, &ca);
        assert_eq!(
            extract_cn_from_certs(&[client_der]),
            Some("agent-007".to_string())
        );
    }

    #[test]
    fn returns_none_for_empty_chain() {
        assert_eq!(extract_cn_from_certs(&[]), None);
    }

    #[test]
    fn returns_none_for_garbage_bytes() {
        let bogus = CertificateDer::from(vec![0u8; 16]);
        assert_eq!(extract_cn_from_certs(&[bogus]), None);
    }

    /// Tests that exercise the rustls verifier need a process-level crypto
    /// provider installed (normally done once at startup in `main.rs`).
    /// `install_default` is idempotent-safe to call repeatedly across tests
    /// in the same process — only the first call wins, later ones just
    /// return `Err`, which is fine to ignore here.
    fn ensure_crypto_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    #[test]
    fn verifier_accepts_cert_signed_by_trusted_ca() {
        ensure_crypto_provider();
        let ca = make_ca();
        let ca_file = write_temp_pem(&ca.pem);
        let verifier = build_client_cert_verifier(ca_file.path().to_str().unwrap(), None)
            .expect("verifier should build from a valid CA cert");

        let client_der = make_client_cert("agent-good", 42, &ca);
        let now = rustls::pki_types::UnixTime::now();
        assert!(
            verifier.verify_client_cert(&client_der, &[], now).is_ok(),
            "cert signed by the trusted CA must verify"
        );
    }

    #[test]
    fn verifier_rejects_cert_from_untrusted_ca() {
        ensure_crypto_provider();
        let ca = make_ca();
        let ca_file = write_temp_pem(&ca.pem);
        let verifier = build_client_cert_verifier(ca_file.path().to_str().unwrap(), None).unwrap();

        let other_ca = make_ca();
        let forged_der = make_client_cert("agent-forged", 99, &other_ca);

        let now = rustls::pki_types::UnixTime::now();
        assert!(
            verifier.verify_client_cert(&forged_der, &[], now).is_err(),
            "cert signed by a different CA must not verify"
        );
    }

    #[test]
    fn verifier_rejects_revoked_cert_when_crl_configured() {
        ensure_crypto_provider();
        let ca = make_ca();
        let ca_file = write_temp_pem(&ca.pem);
        let client_der = make_client_cert("agent-revoked", 7, &ca);
        let crl_pem = revoke_serial(&ca, 7);
        let crl_file = write_temp_pem(&crl_pem);

        let verifier = build_client_cert_verifier(
            ca_file.path().to_str().unwrap(),
            Some(crl_file.path().to_str().unwrap()),
        )
        .expect("verifier with CRL should build");

        let now = rustls::pki_types::UnixTime::now();
        assert!(
            verifier.verify_client_cert(&client_der, &[], now).is_err(),
            "a CRL-revoked cert must not verify"
        );
    }

    #[test]
    fn verifier_still_accepts_non_revoked_cert_when_crl_configured() {
        ensure_crypto_provider();
        let ca = make_ca();
        let ca_file = write_temp_pem(&ca.pem);
        let revoked_der = make_client_cert("agent-revoked", 7, &ca);
        let live_der = make_client_cert("agent-live", 8, &ca);
        let crl_pem = revoke_serial(&ca, 7);
        let crl_file = write_temp_pem(&crl_pem);

        let verifier = build_client_cert_verifier(
            ca_file.path().to_str().unwrap(),
            Some(crl_file.path().to_str().unwrap()),
        )
        .unwrap();

        let now = rustls::pki_types::UnixTime::now();
        assert!(verifier.verify_client_cert(&revoked_der, &[], now).is_err());
        assert!(
            verifier.verify_client_cert(&live_der, &[], now).is_ok(),
            "an unrevoked cert from the same CA must still verify"
        );
    }

    #[test]
    fn build_client_cert_verifier_errors_on_missing_ca_file() {
        assert!(build_client_cert_verifier("/nonexistent/ca.pem", None).is_err());
    }
}
