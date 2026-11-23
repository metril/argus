//! Certificate Authority generation and management

use crate::{Error, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use time::{Duration, OffsetDateTime};
use tracing::{debug, info};

/// Certificate Authority for generating and signing certificates
pub struct CertificateAuthority {
    /// Signing identity built from the stored CA certificate itself (subject DN, key id), so
    /// leaves always chain to the exact certificate on disk.
    issuer: Issuer<'static, KeyPair>,
    /// The CA certificate in DER format
    ca_cert_der: CertificateDer<'static>,
    /// The CA private key in DER format
    ca_key_der: PrivateKeyDer<'static>,
}

impl CertificateAuthority {
    /// Load or generate a Certificate Authority
    pub fn load_or_generate<P: AsRef<Path>>(cert_path: P, key_path: P) -> Result<Self> {
        let cert_path = cert_path.as_ref();
        let key_path = key_path.as_ref();

        // Try to load existing CA
        if cert_path.exists() && key_path.exists() {
            info!(
                "Loading existing CA from {:?} and {:?}",
                cert_path, key_path
            );
            Self::load(cert_path, key_path)
        } else {
            info!("Generating new CA at {:?} and {:?}", cert_path, key_path);
            Self::generate(cert_path, key_path)
        }
    }

    /// Load an existing Certificate Authority from disk
    fn load<P: AsRef<Path>>(cert_path: P, key_path: P) -> Result<Self> {
        let cert_path = cert_path.as_ref();
        let key_path = key_path.as_ref();

        // Read certificate PEM
        let cert_pem = fs::read_to_string(cert_path)
            .map_err(|e| Error::Certificate(format!("Failed to read CA certificate: {}", e)))?;

        // Read private key PEM
        let key_pem = fs::read_to_string(key_path)
            .map_err(|e| Error::Certificate(format!("Failed to read CA private key: {}", e)))?;

        // Parse the key pair from PEM
        let ca_key_pair = KeyPair::from_pem(&key_pem)
            .map_err(|e| Error::Certificate(format!("Failed to parse CA private key: {}", e)))?;

        // Parse PEM to get DER formats
        let cert_der_bytes = pem::parse(&cert_pem)
            .map_err(|e| Error::Certificate(format!("Failed to parse CA certificate PEM: {}", e)))?
            .contents()
            .to_vec();
        let ca_cert_der = CertificateDer::from(cert_der_bytes);

        let ca_key_der = PrivateKeyDer::try_from(ca_key_pair.serialize_der())
            .map_err(|_| Error::Certificate("Failed to convert key to DER".to_string()))?;
        let issuer = Issuer::from_ca_cert_pem(&cert_pem, ca_key_pair).map_err(|e| {
            Error::Certificate(format!("CA certificate does not match its key: {}", e))
        })?;

        Ok(Self {
            issuer,
            ca_cert_der,
            ca_key_der,
        })
    }

    /// Generate a new Certificate Authority
    fn generate<P: AsRef<Path>>(cert_path: P, key_path: P) -> Result<Self> {
        let cert_path = cert_path.as_ref();
        let key_path = key_path.as_ref();

        // Create parent directories if they don't exist
        if let Some(parent) = cert_path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                Error::Certificate(format!("Failed to create certificate directory: {}", e))
            })?;
        }

        // Generate CA parameters
        let mut params = CertificateParams::default();

        // Set distinguished name
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Argus Proxy CA");
        dn.push(DnType::OrganizationName, "Argus Proxy");
        dn.push(DnType::CountryName, "US");
        params.distinguished_name = dn;

        // Set as CA certificate
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

        // Set key usages
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];

        // Set validity period (10 years)
        params.not_before = OffsetDateTime::now_utc();
        params.not_after = OffsetDateTime::now_utc() + Duration::days(3650);

        // Generate key pair
        let ca_key_pair = KeyPair::generate()
            .map_err(|e| Error::Certificate(format!("Failed to generate key pair: {}", e)))?;

        // Generate self-signed certificate
        let ca_cert = params
            .self_signed(&ca_key_pair)
            .map_err(|e| Error::Certificate(format!("Failed to generate CA certificate: {}", e)))?;

        // Get PEM formats
        let cert_pem = ca_cert.pem();
        let key_pem = ca_key_pair.serialize_pem();

        // Write certificate to file
        fs::write(cert_path, &cert_pem)
            .map_err(|e| Error::Certificate(format!("Failed to write CA certificate: {}", e)))?;

        // Write private key to file
        fs::write(key_path, &key_pem)
            .map_err(|e| Error::Certificate(format!("Failed to write CA private key: {}", e)))?;

        // Set restrictive permissions on the private key (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(key_path)
                .map_err(|e| Error::Certificate(format!("Failed to get key file metadata: {}", e)))?
                .permissions();
            perms.set_mode(0o600);
            fs::set_permissions(key_path, perms).map_err(|e| {
                Error::Certificate(format!("Failed to set key file permissions: {}", e))
            })?;
        }

        info!("Generated new CA certificate");

        // Use the same path as a restart: the signing identity comes from the stored cert.
        Self::load(cert_path, key_path)
    }

    /// Generate a leaf certificate for a host (DNS name or IP literal).
    ///
    /// CPU-bound (key generation + signing); call from `spawn_blocking` on async paths.
    pub fn generate_cert(
        &self,
        domain: &str,
    ) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
        debug!("Generating certificate for host: {}", domain);
        let (cert, key_pair) = self.issue(domain, subject_alt_names(domain)?, 30)?;
        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = PrivateKeyDer::try_from(key_pair.serialize_der())
            .map_err(|_| Error::Certificate("Failed to convert key to DER".to_string()))?;
        Ok((cert_der, key_der))
    }

    /// Issue a server certificate valid for `days` covering every entry of `sans` (DNS names and
    /// IP literals, taken as given: no wildcard is added). Returns `(certificate PEM, key PEM)`.
    pub fn generate_server_cert_pem(&self, sans: &[String], days: i64) -> Result<(String, String)> {
        let mut names = Vec::new();
        for s in sans {
            let s = s.trim();
            let bare = s
                .strip_prefix('[')
                .and_then(|h| h.strip_suffix(']'))
                .unwrap_or(s);
            if let Ok(ip) = bare.parse::<IpAddr>() {
                names.push(SanType::IpAddress(ip));
            } else {
                names.push(SanType::DnsName(s.try_into().map_err(|e| {
                    Error::Certificate(format!("Invalid name {s:?}: {e:?}"))
                })?));
            }
        }
        let cn = sans
            .first()
            .ok_or_else(|| Error::Certificate("At least one name is required".into()))?
            .trim()
            .to_string();
        let (cert, key) = self.issue(&cn, names, days)?;
        Ok((cert.pem(), key.serialize_pem()))
    }

    fn issue(
        &self,
        cn: &str,
        sans: Vec<SanType>,
        days: i64,
    ) -> Result<(rcgen::Certificate, KeyPair)> {
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        params.distinguished_name = dn;
        params.subject_alt_names = sans;
        params.not_before = OffsetDateTime::now_utc();
        params.not_after = OffsetDateTime::now_utc() + Duration::days(days);
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        let key_pair = KeyPair::generate()
            .map_err(|e| Error::Certificate(format!("Failed to generate key pair: {}", e)))?;
        let cert = params
            .signed_by(&key_pair, &self.issuer)
            .map_err(|e| Error::Certificate(format!("Failed to sign certificate: {}", e)))?;
        Ok((cert, key_pair))
    }

    /// Get the CA certificate in DER format
    pub fn ca_cert_der(&self) -> &CertificateDer<'static> {
        &self.ca_cert_der
    }

    /// Get the CA private key in DER format
    pub fn ca_key_der(&self) -> &PrivateKeyDer<'static> {
        &self.ca_key_der
    }
}

/// Subject alternative names for a leaf certificate.
///
/// IP literals get an IP SAN only. DNS names get the name itself plus `*.name` when the name has
/// at least two labels (a wildcard under a single-label host like `localhost` is meaningless).
pub fn subject_alt_names(host: &str) -> Result<Vec<SanType>> {
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return Ok(vec![SanType::IpAddress(ip)]);
    }
    let mut sans =
        vec![SanType::DnsName(host.try_into().map_err(|e| {
            Error::Certificate(format!("Invalid domain name: {:?}", e))
        })?)];
    if host.contains('.') && !host.starts_with("*.") {
        sans.push(SanType::DnsName(format!("*.{host}").try_into().map_err(
            |e| Error::Certificate(format!("Invalid wildcard domain: {:?}", e)),
        )?));
    }
    Ok(sans)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;

    fn subject_cn(der: &CertificateDer<'_>) -> String {
        let (_, cert) = x509_parser::parse_x509_certificate(der.as_ref()).unwrap();
        let cn = cert
            .subject()
            .iter_common_name()
            .next()
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        cn
    }

    /// A CA issued before the rename (CN "Adblocker Proxy CA") must load untouched: same files,
    /// same certificate, never regenerated.
    #[test]
    fn pre_rename_ca_is_kept_unchanged() {
        let tmp = tempfile::tempdir().unwrap();
        let cert_path = tmp.path().join("root-ca.crt");
        let key_path = tmp.path().join("root-ca.key");
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Adblocker Proxy CA");
        dn.push(DnType::OrganizationName, "Adblocker Proxy");
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        fs::write(&cert_path, cert.pem()).unwrap();
        fs::write(&key_path, key.serialize_pem()).unwrap();
        let (cert_before, key_before) =
            (fs::read(&cert_path).unwrap(), fs::read(&key_path).unwrap());

        let ca = CertificateAuthority::load_or_generate(&cert_path, &key_path).unwrap();

        assert_eq!(ca.ca_cert_der().as_ref(), cert.der().as_ref());
        assert_eq!(subject_cn(ca.ca_cert_der()), "Adblocker Proxy CA");
        assert_eq!(fs::read(&cert_path).unwrap(), cert_before);
        assert_eq!(fs::read(&key_path).unwrap(), key_before);
    }

    #[test]
    fn fresh_ca_is_named_argus() {
        let tmp = tempfile::tempdir().unwrap();
        let ca = CertificateAuthority::load_or_generate(
            tmp.path().join("root-ca.crt"),
            tmp.path().join("root-ca.key"),
        )
        .unwrap();
        assert_eq!(subject_cn(ca.ca_cert_der()), "Argus Proxy CA");
    }

    #[test]
    fn test_ca_generation() {
        let tmp = tempfile::tempdir().unwrap();
        let temp_dir = tmp.path().to_path_buf();
        let cert_path = temp_dir.join("test-ca.crt");
        let key_path = temp_dir.join("test-ca.key");

        // Clean up any existing files
        let _ = fs::remove_file(&cert_path);
        let _ = fs::remove_file(&key_path);

        // Generate CA
        let ca = CertificateAuthority::load_or_generate(&cert_path, &key_path);
        assert!(ca.is_ok());

        // Verify files were created
        assert!(cert_path.exists());
        assert!(key_path.exists());

        // Clean up
        let _ = fs::remove_file(&cert_path);
        let _ = fs::remove_file(&key_path);
    }

    #[test]
    fn test_cert_generation() {
        let tmp = tempfile::tempdir().unwrap();
        let temp_dir = tmp.path().to_path_buf();
        let cert_path = temp_dir.join("test-ca2.crt");
        let key_path = temp_dir.join("test-ca2.key");

        // Clean up any existing files
        let _ = fs::remove_file(&cert_path);
        let _ = fs::remove_file(&key_path);

        // Generate CA
        let ca = CertificateAuthority::load_or_generate(&cert_path, &key_path).unwrap();

        // Generate certificate for a domain
        let result = ca.generate_cert("example.com");
        assert!(result.is_ok());

        let (cert_der, _key_der) = result.unwrap();
        assert!(!cert_der.is_empty());

        // Clean up
        let _ = fs::remove_file(&cert_path);
        let _ = fs::remove_file(&key_path);
    }

    fn dns(s: &str) -> SanType {
        SanType::DnsName(s.try_into().unwrap())
    }

    #[test]
    fn san_dns_has_wildcard() {
        assert_eq!(
            subject_alt_names("example.com").unwrap(),
            vec![dns("example.com"), dns("*.example.com")]
        );
    }

    #[test]
    fn san_single_label_has_no_wildcard() {
        assert_eq!(
            subject_alt_names("localhost").unwrap(),
            vec![dns("localhost")]
        );
    }

    #[test]
    fn san_ip_literals() {
        assert_eq!(
            subject_alt_names("127.0.0.1").unwrap(),
            vec![SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST))]
        );
        assert_eq!(
            subject_alt_names("::1").unwrap(),
            vec![SanType::IpAddress(IpAddr::V6(Ipv6Addr::LOCALHOST))]
        );
        assert_eq!(
            subject_alt_names("[2001:db8::1]").unwrap(),
            vec![SanType::IpAddress("2001:db8::1".parse().unwrap())]
        );
    }

    #[test]
    fn ip_and_single_label_certs_generate() {
        let tmp = tempfile::tempdir().unwrap();
        let ca = CertificateAuthority::load_or_generate(
            tmp.path().join("ca.crt"),
            tmp.path().join("ca.key"),
        )
        .unwrap();
        for host in ["10.1.2.3", "::1", "localhost", "a.example"] {
            assert!(ca.generate_cert(host).is_ok(), "{host}");
        }
    }

    #[test]
    fn multi_san_server_cert_has_dns_and_ip_and_397_days() {
        let tmp = tempfile::tempdir().unwrap();
        let ca = CertificateAuthority::load_or_generate(
            tmp.path().join("ca.crt"),
            tmp.path().join("ca.key"),
        )
        .unwrap();
        let sans = [
            "argus.lan".to_string(),
            "192.168.1.5".into(),
            "[::1]".into(),
        ];
        let (cert_pem, key_pem) = ca.generate_server_cert_pem(&sans, 397).unwrap();
        assert!(key_pem.contains("PRIVATE KEY"));
        let der = pem::parse(&cert_pem).unwrap().into_contents();
        let (_, cert) = x509_parser::parse_x509_certificate(&der).unwrap();
        let mut dns = Vec::new();
        let mut ips = Vec::new();
        for ext in cert.extensions() {
            if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) =
                ext.parsed_extension()
            {
                for n in &san.general_names {
                    match n {
                        x509_parser::extensions::GeneralName::DNSName(d) => dns.push(d.to_string()),
                        x509_parser::extensions::GeneralName::IPAddress(b) => ips.push(b.to_vec()),
                        _ => {}
                    }
                }
            }
        }
        assert_eq!(dns, vec!["argus.lan"]);
        assert_eq!(ips.len(), 2);
        assert!(ips.contains(&vec![192, 168, 1, 5]));
        let v = cert.validity();
        let days = (v.not_after.timestamp() - v.not_before.timestamp()) / 86400;
        assert!((396..=398).contains(&days), "{days}");
        assert!(ca.generate_server_cert_pem(&[], 397).is_err());
    }

    /// Verify `leaf` for `host` against only the on-disk CA certificate, with a real verifier.
    fn verify_against_disk(cert_path: &Path, leaf: &CertificateDer<'static>, host: &str) {
        use rustls::client::danger::ServerCertVerifier;
        use rustls::client::WebPkiServerVerifier;
        let ca_pem = fs::read(cert_path).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        for c in rustls_pemfile::certs(&mut ca_pem.as_slice()) {
            roots.add(c.unwrap()).unwrap();
        }
        let verifier = WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .unwrap();
        let name = rustls::pki_types::ServerName::try_from(host.to_string()).unwrap();
        verifier
            .verify_server_cert(leaf, &[], &name, &[], rustls::pki_types::UnixTime::now())
            .unwrap_or_else(|e| panic!("leaf for {host} does not chain to on-disk CA: {e}"));
    }

    #[test]
    fn leaf_from_reloaded_ca_chains_to_on_disk_cert() {
        let tmp = tempfile::tempdir().unwrap();
        let (cert, key) = (tmp.path().join("ca.crt"), tmp.path().join("ca.key"));
        let first = CertificateAuthority::load_or_generate(&cert, &key).unwrap();
        let (leaf, _) = first.generate_cert("example.com").unwrap();
        verify_against_disk(&cert, &leaf, "example.com");
        drop(first);

        // "Restart": reload from disk and issue again.
        let reloaded = CertificateAuthority::load_or_generate(&cert, &key).unwrap();
        for host in ["example.com", "www.example.com", "127.0.0.1"] {
            let (leaf, _) = reloaded.generate_cert(host).unwrap();
            verify_against_disk(&cert, &leaf, host);
        }
        let on_disk = pem::parse(fs::read(&cert).unwrap()).unwrap();
        assert_eq!(reloaded.ca_cert_der().as_ref(), on_disk.contents());
    }
}
