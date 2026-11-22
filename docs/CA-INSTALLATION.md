# Certificate Authority Installation Guide

This guide explains how to install the Adblocker Proxy CA certificate on different platforms to avoid SSL/TLS warnings when using MITM mode.

## Table of Contents

- [Understanding the CA Certificate](#understanding-the-ca-certificate)
- [Locating the CA Certificate](#locating-the-ca-certificate)
- [Installation Instructions](#installation-instructions)
  - [Windows](#windows)
  - [macOS](#macos)
  - [Linux](#linux)
  - [Firefox (All Platforms)](#firefox-all-platforms)
  - [Chrome/Chromium (All Platforms)](#chromechromium-all-platforms)
  - [Android](#android)
  - [iOS](#ios)
- [Verification](#verification)
- [Removal](#removal)
- [Security Considerations](#security-considerations)

## Understanding the CA Certificate

The Adblocker Proxy uses a self-signed Certificate Authority (CA) to generate certificates on-the-fly for intercepted HTTPS connections. When you install this CA certificate in your system's trust store, your browser will trust certificates signed by this CA.

**Certificate Details:**
- Common Name: `Adblocker Proxy CA`
- Organization: `Adblocker Proxy`
- Validity: 10 years
- Location: `certs/root-ca.crt`

## Locating the CA Certificate

The easiest way to get the certificate onto a device is to **download it from the running proxy**:

- **Web UI**: log in and go to **Settings → CA Certificate → Download CA Certificate**.
- **Direct URL** (public, no login — convenient for phones and other machines):
  ```
  http://<server>:3000/api/v1/ca.crt
  ```
  e.g. `curl -O http://192.168.1.50:3000/api/v1/ca.crt` (saved as `adblocker-ca.crt`).

Alternatively, the CA certificate is automatically generated on first run and stored on the server
file system at:

**Docker**:
```bash
./certs/root-ca.crt
```

**Local Build**:
```bash
<project-dir>/certs/root-ca.crt
```

If the file doesn't exist, start the proxy once to generate it:
```bash
./target/release/adblocker
# or
docker-compose up -d
```

## Installation Instructions

### Windows

#### Method 1: Using Microsoft Management Console (Recommended)

1. Press `Win + R` and type `mmc`
2. File → Add/Remove Snap-in
3. Select "Certificates" → Add → Computer Account → Local Computer
4. Navigate to: Trusted Root Certification Authorities → Certificates
5. Right-click → All Tasks → Import
6. Browse to `certs/root-ca.crt`
7. Place certificate in: Trusted Root Certification Authorities
8. Finish and restart your browser

#### Method 2: Using Command Line

```powershell
# As Administrator
certutil -addstore "Root" certs\root-ca.crt
```

### macOS

#### Method 1: Using Keychain Access (Recommended)

1. Double-click `certs/root-ca.crt` to open Keychain Access
2. Select "System" keychain
3. Find "Adblocker Proxy CA" in the list
4. Double-click the certificate
5. Expand "Trust" section
6. Set "When using this certificate" to "Always Trust"
7. Close window (will prompt for password)
8. Restart your browser

#### Method 2: Using Command Line

```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain certs/root-ca.crt
```

### Linux

#### Ubuntu/Debian

```bash
# Copy certificate to system directory
sudo cp certs/root-ca.crt /usr/local/share/ca-certificates/adblocker-proxy-ca.crt

# Update certificate store
sudo update-ca-certificates

# Restart browser
```

#### Fedora/RHEL/CentOS

```bash
# Copy certificate
sudo cp certs/root-ca.crt /etc/pki/ca-trust/source/anchors/adblocker-proxy-ca.crt

# Update trust
sudo update-ca-trust

# Restart browser
```

#### Arch Linux

```bash
# Copy certificate
sudo cp certs/root-ca.crt /etc/ca-certificates/trust-source/anchors/adblocker-proxy-ca.crt

# Update trust
sudo trust extract-compat

# Restart browser
```

### Firefox (All Platforms)

Firefox uses its own certificate store, so system installation isn't sufficient.

1. Open Firefox
2. Settings → Privacy & Security → Certificates → View Certificates
3. Click "Authorities" tab
4. Click "Import"
5. Select `certs/root-ca.crt`
6. Check "Trust this CA to identify websites"
7. Click OK
8. Restart Firefox

### Chrome/Chromium (All Platforms)

Chrome typically uses the system certificate store, but can be configured manually:

1. Settings → Privacy and security → Security
2. Scroll to "Manage certificates"
3. Authorities tab
4. Import `certs/root-ca.crt`
5. Check "Trust this certificate for identifying websites"
6. Restart Chrome

### Android

1. Transfer `root-ca.crt` to your device
2. Settings → Security → Encryption & credentials
3. Install a certificate → CA certificate
4. Select the file
5. Enter screen lock PIN/password
6. Certificate installed successfully

**Note**: On Android 7+, apps may not trust user-installed CAs by default for security reasons.

### iOS

1. Transfer `root-ca.crt` to your iOS device (email, AirDrop, etc.)
2. Open the file → Install Profile
3. Settings → General → VPN & Device Management
4. Select "Adblocker Proxy CA" profile → Install
5. Settings → General → About → Certificate Trust Settings
6. Enable "Adblocker Proxy CA"

## Verification

### Browser Method

1. Configure browser to use proxy (localhost:8080)
2. Visit `https://example.com`
3. Click padlock icon in address bar
4. View certificate → Should show "Adblocker Proxy CA" as issuer

### Command Line Method

**Linux/macOS**:
```bash
# System store
security find-certificate -a -c "Adblocker Proxy CA"  # macOS
trust list | grep -i adblocker  # Linux

# Test with curl
curl -v --proxy localhost:8080 https://example.com 2>&1 | grep -i "issuer"
# Should show: issuer: C=US; O=Adblocker Proxy; CN=Adblocker Proxy CA
```

**Windows**:
```powershell
certutil -store "Root" | findstr "Adblocker"
```

## Removal

### Windows

```powershell
# As Administrator
certutil -delstore "Root" "Adblocker Proxy CA"
```

Or use MMC as described in installation, but select Delete instead.

### macOS

```bash
sudo security delete-certificate -c "Adblocker Proxy CA" -t /Library/Keychains/System.keychain
```

Or use Keychain Access and delete the certificate manually.

### Linux

#### Ubuntu/Debian
```bash
sudo rm /usr/local/share/ca-certificates/adblocker-proxy-ca.crt
sudo update-ca-certificates --fresh
```

#### Fedora/RHEL/CentOS
```bash
sudo rm /etc/pki/ca-trust/source/anchors/adblocker-proxy-ca.crt
sudo update-ca-trust
```

### Firefox

Settings → Privacy & Security → View Certificates → Authorities → Find "Adblocker Proxy CA" → Delete

### Chrome

Settings → Privacy and security → Manage certificates → Authorities → Find "Adblocker Proxy CA" → Delete

### Android/iOS

Settings → Security → Trusted credentials → User → Select certificate → Remove

## Security Considerations

### Important Warnings

1. **Trust Implications**: Installing this CA means you trust the proxy to decrypt all HTTPS traffic
2. **Private Key Security**: The private key (`certs/root-ca.key`) must remain secure
3. **Scope**: Only install on devices you personally control
4. **Removal**: Remove the CA when no longer using the proxy

### Best Practices

- **Never** share your CA certificate/key with others
- **Never** use the same CA in production environments
- **Always** generate a new CA for each installation
- **Remove** the CA when finished testing
- **Protect** the `certs/` directory with appropriate permissions

### Regenerating the CA

If your CA is compromised or you want a fresh start:

```bash
# Stop the proxy
docker-compose down
# or kill the process

# Delete old certificates
rm certs/root-ca.*

# Start proxy (will generate new CA)
docker-compose up -d

# Reinstall the NEW CA certificate on all devices
```

## Troubleshooting

### Still Seeing Certificate Warnings

1. Verify CA is installed: Follow verification steps above
2. Clear browser cache and restart
3. Check certificate validity: `openssl x509 -in certs/root-ca.crt -text -noout`
4. Ensure proxy is running: `nc -zv localhost 8080`
5. Check browser proxy settings

### Certificate Not Trusted

- **Firefox**: Must install in Firefox's own certificate store
- **Chrome on Linux**: May require restarting Chrome completely
- **Corporate networks**: May have policies blocking custom CAs

### "NET::ERR_CERT_AUTHORITY_INVALID"

This means the CA isn't installed or trusted. Follow installation instructions for your platform.

## Additional Resources

- [How HTTPS and SSL/TLS Work](https://www.cloudflare.com/learning/ssl/what-is-ssl/)
- [Certificate Authority Overview](https://en.wikipedia.org/wiki/Certificate_authority)
- [MITM Proxy Explanation](https://docs.mitmproxy.org/stable/concepts-certificates/)

## Support

If you encounter issues:
1. Check proxy logs: `docker-compose logs -f`
2. Verify certificate: `openssl x509 -in certs/root-ca.crt -text -noout`
3. Create an issue on GitHub with:
   - Platform and browser
   - Error messages
   - Installation steps tried
