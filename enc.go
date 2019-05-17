package fearless

import (
    "crypto/tls"
    "crypto/x509"
    "github.com/pkg/errors"
)
var (
    errPemDataError = errors.New("failed to parse root certificate")
)

func ReadServerTLS(ca, pem, key []byte) (config *tls.Config, err error) {
    var (
        cert      tls.Certificate
    )
    cert, err = tls.X509KeyPair(pem, key)
    if err != nil {
        return
    }
    clientCertPool := x509.NewCertPool()
    ok := clientCertPool.AppendCertsFromPEM(ca)
    if !ok {
        err = errPemDataError
        return
    }
    config = &tls.Config{
        Certificates: []tls.Certificate{cert},
        ClientAuth:   tls.RequireAndVerifyClientCert,
        ClientCAs:    clientCertPool,
    }
    return
}

func ReadClientTLS(ca, pem, key []byte) (config *tls.Config, err error) {
    var (
        cert      tls.Certificate
    )
    cert, err = tls.X509KeyPair(pem, key)
    if err != nil {
        return
    }

    clientCertPool := x509.NewCertPool()
    ok := clientCertPool.AppendCertsFromPEM(ca)
    if !ok {
        err = errPemDataError
        return
    }
    config = &tls.Config{
        RootCAs:            clientCertPool,
        Certificates:       []tls.Certificate{cert},
        InsecureSkipVerify: true,
    }
    return
}