package fearless

import (
    "bytes"
    "crypto/tls"
    "encoding/binary"
    "fmt"
    log "github.com/sirupsen/logrus"
    "net"
)

func handleFearlessRequest(conn net.Conn) {
    log.Printf("socks connect from %s\n", conn.RemoteAddr().String())
    var err error = nil
    var hasError = false
    for {
        var _ int
        buf := make([]byte, 1)
        _, err = conn.Read(buf)
        if err != nil {
            hasError = true
            break
        }
        addrType := buf[0]
        var addr string
        var port int16
        if addrType == 1 {
            buf = make([]byte, 6)
            _, err = conn.Read(buf)
            if err != nil {
                hasError = true
                break
            }
            var addrIp net.IP = make(net.IP, 4)
            copy(addrIp, buf[0:4])
            addr = addrIp.String()
            sb := bytes.NewBuffer(buf[4:6])
            err = binary.Read(sb, binary.BigEndian, &port)
            if err != nil {
                log.Errorf("%v\n", err)
                break
            }
        } else if addrType == 3 {
            _, err = conn.Read(buf)
            if err != nil {
                hasError = true
                break
            }
            addrLen := buf[0]
            buf = make([]byte, addrLen + 2)
            _, err = conn.Read(buf)
            if err != nil {
                hasError = true
                break
            }
            sb := bytes.NewBuffer(buf[0:addrLen])
            addr = sb.String()
            sb = bytes.NewBuffer(buf[addrLen:addrLen + 2])
            err = binary.Read(sb, binary.BigEndian, &port)
            if err != nil {
                log.Errorf("%v\n", err)
                break
            }
        } else {
            hasError = true
            log.Println("unsurpported addr type")
            break
        }
        log.Println("connecting ", addr)
        var remote net.Conn
        remote, err = net.Dial("tcp", fmt.Sprintf("%s:%d", addr, port))
        if err != nil {
            hasError = true
            break
        }
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
        if err != nil {
            log.Println("error ", err)
        }
        err = conn.Close()
        if err != nil {
            log.Println("close:", err)
        }
        return
    }

}

func RunServer(port int, ca, pem, key []byte) {
    /*
    ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
    if err != nil {
        log.Println(err)
        return
    }
    */

    config, err := ReadServerTLS(ca, pem, key)
    if err != nil {
        log.Println(err)
        return
    }
    ln, err := tls.Listen("tcp", fmt.Sprintf(":%d", port), config)

    log.Printf("starting server at port %v ...\n", ln.Addr().String())
    for {
        conn, err := ln.Accept()
        if err != nil {
            log.Println("accept:", err)
            continue
        }
        go handleFearlessRequest(conn)
    }
}

