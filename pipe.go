package fearless

import (
    "io"
    "net"
)

func PipeTLS(src net.Conn, dst net.Conn, end chan int) {
    buf := make([]byte, 4096)
    for {
        num, err := src.Read(buf)
        if err == nil {
            _, err := dst.Write( buf[0:num])
            if err != nil {
                //log.Println("write:", err)
                end <- 1
                return
            }
        } else {
            if err != io.EOF {
                //log.Println("read:", err)
            }

            end <- 1
            return
        }
        if num == 0 {
            end <- 1
            return
        }
    }
}
