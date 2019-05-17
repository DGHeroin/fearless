package fearless

import (
    "bytes"
    "crypto/tls"
    "fmt"
    log "github.com/sirupsen/logrus"
    "io"
    "net"
)

func handleSocks5Request(conn net.Conn, server string, ca, pem, key []byte) {
    log.Printf("socks connect from %s\n", conn.RemoteAddr().String())
    b := make([]byte, 262)
    var err error = nil
    var hasError = false
    for {
        var _ int
        buf := make([]byte, 4096)
        _, err = conn.Read(b)
        if err != nil {
            hasError = true
            break
        }
        _, err = conn.Write([]byte{0x05, 0x00})
        if err != nil {
            log.Errorf("%v\n", err)
            break
        }
        _, err = conn.Read(buf)
        mode := buf[1]
        if mode != 1 {
            hasError = true
            log.Println("mode != 1")
            break
        }
        var addr string
        addrType := buf[3]
        var addrToSend []byte
        if addrType == 1 {
            var addrIp net.IP = make(net.IP, 4)
            copy(addrIp, buf[4:8])
            addr = addrIp.String()
            addrToSend = buf[3:10]
        } else if addrType == 3 {
            addrLen := buf[4]
            sb := bytes.NewBuffer(buf[5:5 + addrLen])
            addr = sb.String()
            addrToSend = buf[3:5 + addrLen + 2]
        } else {
            hasError = true
            log.Println("unsurpported addr type")
            break
        }
        log.Println("connecting ", addr)
        _, err = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x43})
        if err != nil {
            log.Errorf("%v\n", err)
            break
        }
        var remote net.Conn
        //remote, err = net.Dial("tcp", server)
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
        go PipeTLS(conn, remote, c)
        go PipeTLS(remote, conn, c)
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

func RunLocal(port int, server string, ca, pem, key []byte) {
    ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
    if err != nil {
        log.Println(err)
        return
    }
    log.Printf("starting socks5 at port %v ...\n", ln.Addr().String())
    for {
        conn, err := ln.Accept()
        if err != nil {
            log.Println("accept:", err)
            continue
        }
        go handleSocks5Request(conn, server, ca, pem, key)
    }
}

