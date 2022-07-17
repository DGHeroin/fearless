package main

import (
    "bytes"
    "encoding/json"
    "flag"
    "github.com/DGHeroin/fearless"
    "io/ioutil"
    "log"
    "net/http"
    "os"
)

type Config struct {
}

func init() {
    log.SetFlags(log.LstdFlags | log.Lshortfile)
    flag.StringVar(&ca, "ca", "", "ca file path")
    flag.StringVar(&cert, "cert", "", "cert file path")
    flag.StringVar(&key, "key", "", "key file path")
    flag.BoolVar(&isServer, "s", false, "当做服务器运行")
    flag.StringVar(&socks5LocalPort, "port", ":11080", "本地 Sock5 Proxy 服务地址")
    flag.StringVar(&httpLocalPort, "httpPort", ":11081", "本地 HTTP Proxy 服务地址")
    flag.StringVar(&remote, "remote", "127.0.0.1:18089", "服务地址")
    flag.BoolVar(&auto, "auto", true, "auto config")
    flag.StringVar(&httpToken, "token", "kungfu", "key share token")
    flag.StringVar(&httpAddress, "http", ":18089", "http share address")

    flag.Parse()
}

var (
    ca              string
    cert            string
    key             string
    isServer        bool
    socks5LocalPort string
    httpLocalPort   string
    remote          string
    auto            bool
    httpToken       string
    httpAddress     string
)

func readTLS(ca, cert, key string) (caBytes, certBytes, keyBytes []byte, err error) {
    caBytes, err = ioutil.ReadFile(ca)
    if err != nil {
        return
    }

    certBytes, err = ioutil.ReadFile(cert)
    if err != nil {
        return
    }

    keyBytes, err = ioutil.ReadFile(key)
    if err != nil {
        return
    }

    return
}
func checkErr(err error) bool {
    if err != nil {
        panic(err)
    }
    return true
}

type TLSJson struct {
    CA   []byte
    Cert []byte
    Key  []byte
    Port string
}

func main() {

    var (
        caBytes, certBytes, keyBytes []byte
        err                          error
    )

    if !auto { // 手动指定证书
        caBytes, certBytes, keyBytes, err = readTLS(ca, cert, key)
        if err != nil {
            log.Println(err)
            return
        }
    } else { // 自动管理证书
        var files = []string{
            ".tls/ca.cert",
            ".tls/client.key", ".tls/client.cert",
        }
        var serverFiels = []string{".tls/ca.key",
            ".tls/server.key", ".tls/server.cert"}
        // 检查文件是否存在
        var passCheck = true
        for _, file := range files {
            _, err := os.Stat(file)
            if err != nil && os.IsNotExist(err) {
                passCheck = false
                break
            }
        }
        if isServer {
            for _, file := range serverFiels {
                _, err := os.Stat(file)
                if err != nil && os.IsNotExist(err) {
                    passCheck = false
                    break
                }
            }
        }
        if !passCheck { // 文件不完整, 重新生成文件
            perm := os.FileMode(0777)
            err = os.Mkdir(".tls", perm)
            if os.IsNotExist(err) {
                log.Println(err)
                return
            }
            if isServer {
                caCert, caKey, err := fearless.GenerateTLSCa()
                if !checkErr(err) {
                    return
                }
                err = ioutil.WriteFile(".tls/ca.cert", caCert, perm)
                if !checkErr(err) {
                    return
                }
                err = ioutil.WriteFile(".tls/ca.key", caKey, perm)
                if !checkErr(err) {
                    return
                }

                clientCert, clientKey, err := fearless.GenerateTLSSign(caCert, caKey)
                if !checkErr(err) {
                    return
                }
                err = ioutil.WriteFile(".tls/client.cert", clientCert, perm)
                if !checkErr(err) {
                    return
                }
                err = ioutil.WriteFile(".tls/client.key", clientKey, perm)
                if !checkErr(err) {
                    return
                }

                serverCert, serverKey, err := fearless.GenerateTLSSign(caCert, caKey)
                if !checkErr(err) {
                    return
                }
                err = ioutil.WriteFile(".tls/server.cert", serverCert, perm)
                if !checkErr(err) {
                    return
                }
                err = ioutil.WriteFile(".tls/server.key", serverKey, perm)
                if !checkErr(err) {
                    return
                }

                caBytes = caCert
                certBytes = serverCert
                keyBytes = serverKey
            } else { // 作为客户端, 不自动生成tls文件
                log.Println("client not found TLS files")
                // 连接到远程获取tls文件
                req, err := http.NewRequest(http.MethodPost, httpAddress+"/key", bytes.NewBufferString(httpToken))
                if !checkErr(err) {
                    return
                }
                resp, err := http.DefaultClient.Do(req)
                if resp != nil {
                    defer func() { _ = resp.Body.Close() }()
                }
                if !checkErr(err) {
                    return
                }
                data, err := ioutil.ReadAll(resp.Body)
                if !checkErr(err) {
                    return
                }
                var info TLSJson
                err = json.Unmarshal(data, &info)
                if !checkErr(err) {
                    return
                }
                caBytes = info.CA
                certBytes = info.Cert
                keyBytes = info.Key
                socks5LocalPort = info.Port
                // 写文件
                err = ioutil.WriteFile(".tls/ca.cert", caBytes, perm)
                if !checkErr(err) {
                    return
                }
                if !checkErr(err) {
                    return
                }
                err = ioutil.WriteFile(".tls/client.cert", certBytes, perm)
                if !checkErr(err) {
                    return
                }
                err = ioutil.WriteFile(".tls/client.key", keyBytes, perm)
                if !checkErr(err) {
                    return
                }
            }
        } else { // 加载文件
            caBytes, err = ioutil.ReadFile(".tls/ca.cert")
            if !checkErr(err) {
                return
            }
            if isServer {
                certBytes, err = ioutil.ReadFile(".tls/server.cert")
                if !checkErr(err) {
                    return
                }
                keyBytes, err = ioutil.ReadFile(".tls/server.key")
                if !checkErr(err) {
                    return
                }
            } else {
                certBytes, err = ioutil.ReadFile(".tls/client.cert")
                if !checkErr(err) {
                    return
                }
                keyBytes, err = ioutil.ReadFile(".tls/client.key")
                if !checkErr(err) {
                    return
                }
            }
        }
    }

    if isServer {
        go func() { // 启动秘钥共享http服务器
            http.HandleFunc("/key", func(w http.ResponseWriter, r *http.Request) {
                body, err := ioutil.ReadAll(r.Body)
                if err != nil {
                    return
                }
                err = r.Body.Close()
                if err != nil {
                    return
                }

                if string(body) != httpToken {
                    w.WriteHeader(http.StatusForbidden)
                } else { // 通过验证
                    resp := &TLSJson{
                        CA:   caBytes,
                        Cert: certBytes,
                        Key:  keyBytes,
                        Port: socks5LocalPort,
                    }
                    data, err := json.Marshal(resp)
                    if err != nil {
                        log.Println(err)
                        w.WriteHeader(http.StatusInternalServerError)
                    } else {
                        _, err = w.Write(data)
                        if err != nil {
                            log.Println(err)
                        }
                    }
                }
            })
            log.Println("API地址:", httpAddress)
            if err := http.ListenAndServe(httpAddress, nil); err != nil {
                log.Println(err)
            }
        }()

        fearless.RunServer(socks5LocalPort, caBytes, certBytes, keyBytes)
    } else {
        go fearless.HTTPToSocks5(httpLocalPort, socks5LocalPort) // 接收 HTTP 代理请求, 并将其转换到socks
        log.Println("服务地址:", remote)
        fearless.RunLocal(socks5LocalPort, remote, caBytes, certBytes, keyBytes)
    }
}
