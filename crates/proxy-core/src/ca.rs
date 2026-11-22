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
    /// The CA key pair
    ca_key_pair: KeyPair,
    /// The CA certificate parameters (for issuer)
    ca_params: CertificateParams,
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

        // For loading existing CA, we create default params
        // The actual certificate parameters will be extracted when creating an Issuer
        let ca_params = CertificateParams::default();

        // Parse PEM to get DER formats
        let cert_der_bytes = pem::parse(&cert_pem)
            .map_err(|e| Error::Certificate(format!("Failed to parse CA certificate PEM: {}", e)))?
            .contents()
            .to_vec();
        let ca_cert_der = CertificateDer::from(cert_der_bytes);

        let ca_key_der = PrivateKeyDer::try_from(ca_key_pair.serialize_der())
            .map_err(|_| Error::Certificate("Failed to convert key to DER".to_string()))?;

        Ok(Self {
            ca_key_pair,
            ca_params,
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
        dn.push(DnType::CommonName, "Adblocker Proxy CA");
        dn.push(DnType::OrganizationName, "Adblocker Proxy");
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

        // Get DER formats
        let ca_cert_der = CertificateDer::from(ca_cert.der().to_vec());
        let ca_key_der = PrivateKeyDer::try_from(ca_key_pair.serialize_der())
            .map_err(|_| Error::Certificate("Failed to convert key to DER".to_string()))?;

        Ok(Self {
            ca_key_pair,
            ca_params: params,
            ca_cert_der,
            ca_key_der,
        })
    }

    /// Generate a leaf certificate for a host (DNS name or IP literal).
    ///
    /// CPU-bound (key generation + signing); call from `spawn_blocking` on async paths.
    pub fn generate_cert(
        &self,
        domain: &str,
    ) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
        debug!("Generating certificate for host: {}", domain);

        // Create certificate parameters
        let mut params = CertificateParams::default();

        // Set distinguished name
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, domain);
        params.distinguished_name = dn;

        params.subject_alt_names = subject_alt_names(domain)?;

        // Set validity period (30 days)
        params.not_before = OffsetDateTime::now_utc();
        params.not_after = OffsetDateTime::now_utc() + Duration::days(30);

        // Set key usages for server certificate
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];

        // Generate key pair for the server certificate
        let key_pair = KeyPair::generate()
            .map_err(|e| Error::Certificate(format!("Failed to generate key pair: {}", e)))?;

        // Create an Issuer from our CA
        let issuer = Issuer::from_params(&self.ca_params, &self.ca_key_pair);

        // Sign the certificate with our CA
        let cert = params
            .signed_by(&key_pair, &issuer)
            .map_err(|e| Error::Certificate(format!("Failed to sign certificate: {}", e)))?;

        // Convert to DER format for rustls
        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = PrivateKeyDer::try_from(key_pair.serialize_der())
            .map_err(|_| Error::Certificate("Failed to convert key to DER".to_string()))?;

        Ok((cert_der, key_der))
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
}
