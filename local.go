package fearless

import (
    "bytes"
    "crypto/tls"
    "fmt"
    "golang.org/x/net/proxy"
    "io"
    "log"
    "net"
    "net/url"
    "strings"
)

func bytesCount(n uint64) string {
    unit := ""
    if n > 1024 {
        n = n / 1024
        unit = "K"
    }

    if n > 1024 {
        n = n / 1024
        unit = "M"
    }

    if n > 1024 {
        n = n / 1024
        unit = "G"
    }

    if n > 1024 {
        n = n / 1024
        unit = "T"
    }

    return fmt.Sprintf("%v%v", n, unit)
}

func handleSocks5Request(conn net.Conn, server string, ca, pem, key []byte) {
    var (
        err             error  = nil
        hasError               = false
        readBytesCount  uint64 // 发送流量统计
        writeBytesCount uint64 // 接收流量统计
        addr            string // 连接远程的地址
        localAddr       string // 本地地址
        addrToSend      []byte
    )
    defer func() {
        if e := recover(); e != nil {
            log.Println(e)
        }
        log.Printf("连接统计(%v<=>%v): 发送: %v 接收: %v", localAddr, addr, bytesCount(readBytesCount), bytesCount(writeBytesCount))
    }()
    localAddr = conn.RemoteAddr().String()
    b := make([]byte, 262)

    for {
        buf := make([]byte, 4096)
        _, err = conn.Read(b)
        if err != nil {
            hasError = true
            break
        }
        _, err = conn.Write([]byte{0x05, 0x00})
        if err != nil {
            log.Printf("%v\n", err)
            break
        }
        _, err = conn.Read(buf)
        mode := buf[1]
        if mode != 1 {
            hasError = true
            log.Println("mode != 1")
            break
        }
        addrType := buf[3]
        if addrType == 1 {
            var addrIp = make(net.IP, 4)
            copy(addrIp, buf[4:8])
            addr = addrIp.String()
            addrToSend = buf[3:10]
        } else if addrType == 3 {
            addrLen := buf[4]
            sb := bytes.NewBuffer(buf[5 : 5+addrLen])
            addr = sb.String()
            addrToSend = buf[3 : 5+addrLen+2]
        } else {
            hasError = true
            log.Println("unsupported addr type")
            break
        }
        log.Println("connecting ", server, " => ", addr)
        _, err = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x43})
        if err != nil {
            log.Printf("%v\n", err)
            break
        }
        var remote net.Conn
        // remote, err = net.Dial("tcp", server)
        config, err := ReadClientTLS(ca, pem, key)
        if err != nil {
            log.Println(err)
            return
        }
        remote, err = tls.Dial("tcp", server, config)

        if err != nil {
            hasError = true
            break
        }

        _, err = remote.Write(addrToSend)
        if err != nil {
            hasError = true
            break
        }
        c := make(chan int, 2)

        go PipeTLS(conn, remote, c, &readBytesCount)
        go PipeTLS(remote, conn, c, &writeBytesCount)
        <-c // close the other connection whenever one connection is closed
        err = conn.Close()
        err1 := remote.Close()
        if err == nil {
            err = err1
        }
        break
    }
    if err != nil || hasError {
        if err != nil && err != io.EOF {
            log.Println("error ", err)
        }
        err = conn.Close()
        if err != nil && err != io.EOF {
            log.Println("close:", err)
        }
        return
    }
}

func RunLocal(address string, server string, ca, pem, key []byte) {
    ln, err := net.Listen("tcp", address)
    if err != nil {
        log.Println(err)
        return
    }
    log.Printf("本地Sock5地址: %v\n", ln.Addr().String())
    for {
        conn, err := ln.Accept()
        if err != nil {
            log.Println("accept:", err)
            continue
        }
        go handleSocks5Request(conn, server, ca, pem, key)
    }
}

func HTTPToSocks5(httpAddr string, socks5Addr string) {
    l, err := net.Listen("tcp", httpAddr)
    if err != nil {
        log.Panic(err)
    }
    log.Printf("本地HTTP Proxy地址: %v", l.Addr())
    for {
        client, err := l.Accept()
        if err != nil {
            log.Panic(err)
        }

        go handleClientRequest(client, socks5Addr)
    }
}

func handleClientRequest(client net.Conn, socks5Addr string) {
    if client == nil {
        return
    }
    defer func() {
        if e := recover(); e != nil {
            log.Println(e)
        }
        _ = client.Close()
    }()

    var b [1024]byte
    n, err := client.Read(b[:])
    if err != nil {
        log.Println(err)
        return
    }
    data := b[:n]
    content := string(data)
    if strings.HasPrefix(content, "CONNECT") {
        // https
        // log.Printf("not support: %v", content)
        // return
    } else {
        // normal
    }
    // log.Printf("http proxying: %v", content)

    var method, host, address string
    _, err = fmt.Sscanf(content, "%s%s", &method, &host)
    if err != nil {
        log.Println(err)
        return
    }
    hostPortURL, err := url.Parse(host)
    if err != nil {
        log.Println(err)
        return
    }

    if hostPortURL.Opaque == "443" { // https访问
        address = hostPortURL.Scheme + ":443"
    } else {                                            // http访问
        if strings.Index(hostPortURL.Host, ":") == -1 { // host不带端口， 默认80
            address = hostPortURL.Host + ":80"
        } else {
            address = hostPortURL.Host
        }
    }

    // 连接本地socks5
    dialer, err := proxy.SOCKS5("tcp", socks5Addr, nil, proxy.Direct)
    if err != nil {
        log.Println(err)
        return
    }
    // server, err := net.Dial("tcp", address)
    server, err := dialer.Dial("tcp", address)
    if err != nil {
        log.Println(err)
        return
    }
    if method == "CONNECT" {
        _, err = fmt.Fprint(client, "HTTP/1.1 200 Connection established\r\n\r\n")
    } else {
        _, err = server.Write(data)
    }
    // 进行转发
    go func() { _, _ = io.Copy(server, client) }()
    _, _ = io.Copy(client, server)
}
