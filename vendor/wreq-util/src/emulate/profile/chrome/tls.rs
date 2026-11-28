use super::*;

macro_rules! tls_options {
    (@build $builder:expr) => {
        $builder.build().into()
    };

    (1) => {
        tls_options!(@build ChromeTlsConfig::builder())
    };
    (2) => {
        tls_options!(@build ChromeTlsConfig::builder().enable_ech_grease(true))
    };
    (3) => {
        tls_options!(@build ChromeTlsConfig::builder().permute_extensions(true))
    };
    (4) => {
        tls_options!(@build ChromeTlsConfig::builder()
            .permute_extensions(true)
            .enable_ech_grease(true))
    };
    (5) => {
        tls_options!(@build ChromeTlsConfig::builder()
            .permute_extensions(true)
            .enable_ech_grease(true)
            .pre_shared_key(true))
    };
    (6, $curves:expr) => {
        tls_options!(@build ChromeTlsConfig::builder()
            .permute_extensions(true)
            .enable_ech_grease(true)
            .pre_shared_key(true)
            .curves($curves))
    };
    (7, $curves:expr) => {
        tls_options!(@build ChromeTlsConfig::builder()
            .permute_extensions(true)
            .enable_ech_grease(true)
            .pre_shared_key(true)
            .curves($curves)
            .alps_use_new_codepoint(true))
    };
    // Chrome 151: ML-DSA signature algorithms (Modified by Argus).
    (8, $curves:expr) => {
        tls_options!(@build ChromeTlsConfig::builder()
            .permute_extensions(true)
            .enable_ech_grease(true)
            .pre_shared_key(true)
            .curves($curves)
            .alps_use_new_codepoint(true)
            .sigalgs_list(SIGALGS_LIST_ML_DSA))
    };
    // Chrome 153+: GREASE signature algorithm and the trust_anchors extension (Modified by Argus).
    (9, $curves:expr, $trust_anchors:expr) => {
        tls_options!(@build ChromeTlsConfig::builder()
            .permute_extensions(true)
            .enable_ech_grease(true)
            .pre_shared_key(true)
            .curves($curves)
            .alps_use_new_codepoint(true)
            .sigalgs_list(SIGALGS_LIST_ML_DSA)
            .grease_signature_algorithm(true)
            .requested_trust_anchors($trust_anchors))
    };
}

pub const CURVES_1: &str = join!(":", "X25519", "P-256", "P-384");
pub const CURVES_2: &str = join!(":", "X25519Kyber768Draft00", "X25519", "P-256", "P-384");
pub const CURVES_3: &str = join!(":", "X25519MLKEM768", "X25519", "P-256", "P-384");

pub const CIPHER_LIST: &str = join!(
    ":",
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA"
);

pub const SIGALGS_LIST: &str = join!(
    ":",
    "ecdsa_secp256r1_sha256",
    "rsa_pss_rsae_sha256",
    "rsa_pkcs1_sha256",
    "ecdsa_secp384r1_sha384",
    "rsa_pss_rsae_sha384",
    "rsa_pkcs1_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pkcs1_sha512"
);

/// Chrome 151+ also offers the ML-DSA signature algorithms (draft-ietf-tls-mldsa) first.
pub const SIGALGS_LIST_ML_DSA: &str = join!(
    ":",
    "mldsa44",
    "mldsa65",
    "mldsa87",
    "ecdsa_secp256r1_sha256",
    "rsa_pss_rsae_sha256",
    "rsa_pkcs1_sha256",
    "ecdsa_secp384r1_sha384",
    "rsa_pss_rsae_sha384",
    "rsa_pkcs1_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pkcs1_sha512"
);

/// The `trust_anchors` extension list (trust anchor IDs, wire format) of Chrome 153, as captured.
pub const TRUST_ANCHORS_153: &[u8] = &[
    0x04, 0xd6, 0x79, 0x09, 0x0c,
    0x05, 0x82, 0xdf, 0x13, 0x02, 0x0f,
    0x04, 0xd6, 0x79, 0x09, 0x08,
    0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x08,
    0x05, 0x82, 0xdf, 0x13, 0x02, 0x06,
    0x05, 0x82, 0xdf, 0x13, 0x02, 0x13,
    0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x12,
    0x04, 0xd6, 0x79, 0x09, 0x05,
    0x04, 0xd6, 0x79, 0x09, 0x01,
    0x04, 0xd6, 0x79, 0x09, 0x04,
    0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x13,
    0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0c,
    0x04, 0xd6, 0x79, 0x09, 0x0a,
    0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0b,
    0x04, 0xd6, 0x79, 0x09, 0x07,
    0x05, 0x82, 0xdf, 0x13, 0x02, 0x0d,
    0x05, 0x82, 0xdf, 0x13, 0x02, 0x12,
    0x04, 0xd6, 0x79, 0x09, 0x06,
    0x04, 0xd6, 0x79, 0x09, 0x0d,
    0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x07,
    0x05, 0x82, 0xdf, 0x13, 0x02, 0x0e,
    0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0d,
    0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0a,
    0x05, 0x82, 0xdf, 0x13, 0x02, 0x01,
    0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x09,
    0x04, 0xd6, 0x79, 0x09, 0x0b,
    0x05, 0x82, 0xdf, 0x13, 0x02, 0x14,
    0x04, 0xd6, 0x79, 0x09, 0x0f,
];

/// The `trust_anchors` extension list of Chrome 156 and later, as captured (Chrome 159 sends the
/// same).
pub const TRUST_ANCHORS_156: &[u8] = &[
    0x05, 0x82, 0xdf, 0x13, 0x02, 0x01,
    0x05, 0x82, 0xdf, 0x13, 0x02, 0x06,
    0x05, 0x82, 0xdf, 0x13, 0x02, 0x0d,
    0x05, 0x82, 0xdf, 0x13, 0x02, 0x0e,
    0x05, 0x82, 0xdf, 0x13, 0x02, 0x0f,
    0x05, 0x82, 0xdf, 0x13, 0x02, 0x12,
    0x05, 0x82, 0xdf, 0x13, 0x02, 0x13,
    0x05, 0x82, 0xdf, 0x13, 0x02, 0x14,
    0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x07,
    0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x08,
    0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x09,
    0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0a,
    0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0b,
    0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0c,
    0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0d,
    0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x12,
    0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x13,
    0x04, 0xd6, 0x79, 0x09, 0x01,
    0x04, 0xd6, 0x79, 0x09, 0x04,
    0x04, 0xd6, 0x79, 0x09, 0x05,
    0x04, 0xd6, 0x79, 0x09, 0x06,
    0x04, 0xd6, 0x79, 0x09, 0x07,
    0x04, 0xd6, 0x79, 0x09, 0x08,
    0x04, 0xd6, 0x79, 0x09, 0x0a,
    0x04, 0xd6, 0x79, 0x09, 0x0b,
    0x04, 0xd6, 0x79, 0x09, 0x0c,
    0x04, 0xd6, 0x79, 0x09, 0x0d,
    0x04, 0xd6, 0x79, 0x09, 0x0f,
];

pub const CERTIFICATE_COMPRESSORS: &[&'static dyn CertificateCompressor] = &[&BrotliCompressor];

#[derive(TypedBuilder)]
pub struct ChromeTlsConfig {
    #[builder(default = CURVES_1)]
    curves: &'static str,

    #[builder(default = SIGALGS_LIST)]
    sigalgs_list: &'static str,

    #[builder(default = CIPHER_LIST)]
    cipher_list: &'static str,

    #[builder(default = AlpsProtocol::HTTP2, setter(into))]
    alps_protos: AlpsProtocol,

    #[builder(default = false)]
    alps_use_new_codepoint: bool,

    #[builder(default = false, setter(into))]
    enable_ech_grease: bool,

    #[builder(default = false, setter(into))]
    permute_extensions: bool,

    #[builder(default = false, setter(into))]
    pre_shared_key: bool,

    #[builder(default = false)]
    grease_signature_algorithm: bool,

    #[builder(default = None, setter(into))]
    requested_trust_anchors: Option<&'static [u8]>,
}

impl From<ChromeTlsConfig> for TlsOptions {
    fn from(val: ChromeTlsConfig) -> Self {
        TlsOptions::builder()
            .grease_enabled(true)
            .enable_ocsp_stapling(true)
            .enable_signed_cert_timestamps(true)
            .curves_list(val.curves)
            .sigalgs_list(val.sigalgs_list)
            .cipher_list(val.cipher_list)
            .min_tls_version(TlsVersion::TLS_1_2)
            .max_tls_version(TlsVersion::TLS_1_3)
            .permute_extensions(val.permute_extensions)
            .pre_shared_key(val.pre_shared_key)
            .enable_ech_grease(val.enable_ech_grease)
            .alps_protocols([val.alps_protos])
            .alps_use_new_codepoint(val.alps_use_new_codepoint)
            .grease_signature_algorithm(val.grease_signature_algorithm)
            .requested_trust_anchors(val.requested_trust_anchors.map(std::borrow::Cow::Borrowed))
            .aes_hw_override(true)
            .certificate_compressors(CERTIFICATE_COMPRESSORS)
            .build()
    }
}
