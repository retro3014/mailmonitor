/*
 * CertGenerator.h
 * ================
 * Dynamic TLS certificate generator for SMTP TLS MITM proxy.
 *
 * Works like Fiddler's certificate engine:
 *   1. Loads a CA key + certificate from PEM files
 *   2. For each intercepted connection, generates a server certificate
 *      signed by the CA, with the target hostname as CN/SAN
 *   3. Caches generated certificates to avoid regeneration
 *
 * Dependencies: OpenSSL (libssl, libcrypto)
 */

#ifndef CERT_GENERATOR_H
#define CERT_GENERATOR_H

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#include <string>
#include <map>

// A generated certificate + its private key
struct GeneratedCert
{
    X509*     cert;
    EVP_PKEY* key;

    GeneratedCert() : cert(NULL), key(NULL) {}
};

class CertGenerator
{
public:
    CertGenerator()
        : m_caKey(NULL)
        , m_caCert(NULL)
        , m_initialized(false)
    {
    }

    ~CertGenerator()
    {
        cleanup();
    }

    // Load CA key and certificate from PEM files
    bool init(const std::string& caKeyPath, const std::string& caCertPath)
    {
        // Load CA private key
        FILE* keyFile = fopen(caKeyPath.c_str(), "r");
        if (!keyFile)
        {
            printf("[CertGen] Cannot open CA key: %s\n", caKeyPath.c_str());
            return false;
        }
        m_caKey = PEM_read_PrivateKey(keyFile, NULL, NULL, NULL);
        fclose(keyFile);

        if (!m_caKey)
        {
            printf("[CertGen] Failed to parse CA key: %s\n", caKeyPath.c_str());
            printSslErrors();
            return false;
        }

        // Load CA certificate
        FILE* certFile = fopen(caCertPath.c_str(), "r");
        if (!certFile)
        {
            printf("[CertGen] Cannot open CA cert: %s\n", caCertPath.c_str());
            return false;
        }
        m_caCert = PEM_read_X509(certFile, NULL, NULL, NULL);
        fclose(certFile);

        if (!m_caCert)
        {
            printf("[CertGen] Failed to parse CA cert: %s\n", caCertPath.c_str());
            printSslErrors();
            return false;
        }

        m_initialized = true;
        printf("[CertGen] CA loaded successfully\n");
        printf("[CertGen]   Key:  %s\n", caKeyPath.c_str());
        printf("[CertGen]   Cert: %s\n", caCertPath.c_str());
        return true;
    }

    bool isInitialized() const { return m_initialized; }

    // Get or generate a certificate for the given hostname
    // Returns false if generation fails
    bool getCertForHost(const std::string& hostname, X509** outCert, EVP_PKEY** outKey)
    {
        if (!m_initialized) return false;

        // Check cache
        std::map<std::string, GeneratedCert>::iterator it = m_cache.find(hostname);
        if (it != m_cache.end())
        {
            *outCert = it->second.cert;
            *outKey = it->second.key;
            return true;
        }

        // Generate new certificate
        GeneratedCert gc;
        if (!generateCert(hostname, gc))
            return false;

        m_cache[hostname] = gc;
        *outCert = gc.cert;
        *outKey = gc.key;

        printf("[CertGen] Generated certificate for: %s\n", hostname.c_str());
        return true;
    }

private:
    EVP_PKEY*  m_caKey;
    X509*      m_caCert;
    bool       m_initialized;
    std::map<std::string, GeneratedCert> m_cache;

    bool generateCert(const std::string& hostname, GeneratedCert& out)
    {
        // 1. Generate RSA key pair for the server certificate
        EVP_PKEY* serverKey = NULL;
        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
        if (!pctx) return false;

        if (EVP_PKEY_keygen_init(pctx) <= 0 ||
            EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) <= 0 ||
            EVP_PKEY_keygen(pctx, &serverKey) <= 0)
        {
            EVP_PKEY_CTX_free(pctx);
            return false;
        }
        EVP_PKEY_CTX_free(pctx);

        // 2. Create X509 certificate
        X509* cert = X509_new();
        if (!cert)
        {
            EVP_PKEY_free(serverKey);
            return false;
        }

        // Version 3 (0-indexed, so 2 = v3)
        X509_set_version(cert, 2);

        // Random serial number
        ASN1_INTEGER* serial = ASN1_INTEGER_new();
        if (serial)
        {
            BIGNUM* bn = BN_new();
            if (bn)
            {
                BN_rand(bn, 64, 0, 0);
                BN_to_ASN1_INTEGER(bn, serial);
                X509_set_serialNumber(cert, serial);
                BN_free(bn);
            }
            ASN1_INTEGER_free(serial);
        }

        // Validity: now to +1 year
        X509_gmtime_adj(X509_getm_notBefore(cert), 0);
        X509_gmtime_adj(X509_getm_notAfter(cert), 365 * 24 * 3600);

        // Subject: CN = hostname
        X509_NAME* name = X509_get_subject_name(cert);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            (const unsigned char*)hostname.c_str(), -1, -1, 0);
        X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
            (const unsigned char*)"SmtpMailMonitor Proxy", -1, -1, 0);

        // Issuer = CA's subject
        X509_set_issuer_name(cert, X509_get_subject_name(m_caCert));

        // Public key = server's key
        X509_set_pubkey(cert, serverKey);

        // 3. Add Subject Alternative Name (SAN) extension
        // Modern TLS clients check SAN, not just CN
        addSanExtension(cert, hostname);

        // 4. Add Basic Constraints (not a CA)
        addExtension(cert, NID_basic_constraints, "critical,CA:FALSE");

        // 5. Key Usage
        addExtension(cert, NID_key_usage, "critical,digitalSignature,keyEncipherment");

        // 6. Extended Key Usage (server auth)
        addExtension(cert, NID_ext_key_usage, "serverAuth");

        // 7. Subject Key Identifier
        addExtension(cert, NID_subject_key_identifier, "hash");

        // 8. Authority Key Identifier (links to CA)
        addExtension(cert, NID_authority_key_identifier, "keyid,issuer");

        // 9. Sign with CA's private key
        if (X509_sign(cert, m_caKey, EVP_sha256()) <= 0)
        {
            X509_free(cert);
            EVP_PKEY_free(serverKey);
            printSslErrors();
            return false;
        }

        out.cert = cert;
        out.key = serverKey;
        return true;
    }

    void addExtension(X509* cert, int nid, const char* value)
    {
        X509V3_CTX ctx;
        X509V3_set_ctx_nodb(&ctx);
        X509V3_set_ctx(&ctx, m_caCert, cert, NULL, NULL, 0);

        X509_EXTENSION* ext = X509V3_EXT_nconf_nid(NULL, &ctx, nid, value);
        if (ext)
        {
            X509_add_ext(cert, ext, -1);
            X509_EXTENSION_free(ext);
        }
    }

    void addSanExtension(X509* cert, const std::string& hostname)
    {
        std::string sanValue = "DNS:" + hostname;

        X509V3_CTX ctx;
        X509V3_set_ctx_nodb(&ctx);
        X509V3_set_ctx(&ctx, m_caCert, cert, NULL, NULL, 0);

        X509_EXTENSION* ext = X509V3_EXT_nconf_nid(NULL, &ctx,
            NID_subject_alt_name, sanValue.c_str());
        if (ext)
        {
            X509_add_ext(cert, ext, -1);
            X509_EXTENSION_free(ext);
        }
    }

    void printSslErrors()
    {
        unsigned long err;
        while ((err = ERR_get_error()) != 0)
        {
            char buf[256];
            ERR_error_string_n(err, buf, sizeof(buf));
            printf("[CertGen] SSL error: %s\n", buf);
        }
    }

    void cleanup()
    {
        // Free cached certificates
        for (std::map<std::string, GeneratedCert>::iterator it = m_cache.begin();
            it != m_cache.end(); ++it)
        {
            if (it->second.cert) X509_free(it->second.cert);
            if (it->second.key)  EVP_PKEY_free(it->second.key);
        }
        m_cache.clear();

        if (m_caKey)  { EVP_PKEY_free(m_caKey);  m_caKey = NULL; }
        if (m_caCert) { X509_free(m_caCert);     m_caCert = NULL; }
        m_initialized = false;
    }
};

#endif // CERT_GENERATOR_H
