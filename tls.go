package fearless

import (
    "bytes"
    "crypto/rand"
    "crypto/rsa"
    "crypto/tls"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "math/big"
    "time"
)

type GenerateTLSOption struct {
    Organization string
    Country string
    Province string
    Locality string
    StreetAddress string
    PostalCode string
}

type GenerateTLSOptionFunc func(*GenerateTLSOption)

func defaultTLSConfigInfo() GenerateTLSOption {
    return GenerateTLSOption{
        Organization:  "ORGANIZATION_NAME",
        Country:       "COUNTRY_CODE",
        Province:      "PROVINCE",
        Locality:      "CITY",
        StreetAddress: "ADDRESS",
        PostalCode:    "POSTAL_CODE",
    }
}

func GenerateTLSCa(opts... GenerateTLSOptionFunc) (certBytes []byte, keyBytes []byte, err error) {
    option := defaultTLSConfigInfo()
    for _, opt := range opts { opt(&option)}

    ca := &x509.Certificate{
        SerialNumber: big.NewInt(1653),
        Subject: pkix.Name{
            Organization:  []string{option.Organization},
            Country:       []string{option.Country},
            Province:      []string{option.Province},
            Locality:      []string{option.Locality},
            StreetAddress: []string{option.StreetAddress},
            PostalCode:    []string{option.PostalCode},
        },
        NotBefore:             time.Now(),
        NotAfter:              time.Now().AddDate(10, 0, 0),
        IsCA:                  true,
        ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
        KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
        BasicConstraintsValid: true,
    }
    priv, _ := rsa.GenerateKey(rand.Reader, 2048)
    pub := &priv.PublicKey
    ca_b, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, priv)
    if err != nil {
        return
    }
    // Public key
    certOut := bytes.NewBuffer([]byte{})
    err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: ca_b})
    if err != nil {
        return
    }
    // Private key
    keyOut := bytes.NewBuffer([]byte{})
    err = pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
    if err != nil {
        return
    }
    certBytes = certOut.Bytes()
    keyBytes = keyOut.Bytes()
    return
}

func GenerateTLSSign(certPEMBlock, keyPEMBlock []byte, opts... GenerateTLSOptionFunc) (certBytes []byte, keyBytes []byte, err error) {
    option := defaultTLSConfigInfo()
    for _, opt := range opts { opt(&option)}

    var (
        catls tls.Certificate
        ca    *x509.Certificate
    )
    // Load CA
    catls, err = tls.X509KeyPair(certPEMBlock, keyPEMBlock)
    if err != nil {
        return
    }
    ca, err = x509.ParseCertificate(catls.Certificate[0])
    if err != nil {
        return
    }

    // Prepare certificate
    cert := &x509.Certificate{
        SerialNumber: big.NewInt(1658),
        Subject: pkix.Name{
            Organization:  []string{option.Organization},
            Country:       []string{option.Country},
            Province:      []string{option.Province},
            Locality:      []string{option.Locality},
            StreetAddress: []string{option.StreetAddress},
            PostalCode:    []string{option.PostalCode},
        },
        NotBefore:    time.Now(),
        NotAfter:     time.Now().AddDate(10, 0, 0),
        SubjectKeyId: []byte{1, 2, 3, 4, 6},
        ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
        KeyUsage:     x509.KeyUsageDigitalSignature,
    }
    priv, _ := rsa.GenerateKey(rand.Reader, 2048)
    pub := &priv.PublicKey

    // Sign the certificate
    cert_b, err := x509.CreateCertificate(rand.Reader, cert, ca, pub, catls.PrivateKey)

    // Public key
    certOut := bytes.NewBuffer([]byte{})
    err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert_b})
    if err != nil {
        return
    }

    keyOut := bytes.NewBuffer([]byte{})
    err = pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
    if err != nil {
        return
    }

    certBytes = certOut.Bytes()
    keyBytes = keyOut.Bytes()
    return
}