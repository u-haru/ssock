package main

import (
	"crypto/rand"
	"crypto/rsa"
	"log"
	"net"

	"github.com/u-haru/ssock"
)

func main() {
	ln, err := net.Listen("tcp", ":17777")
	if err != nil {
		return
	}

	test := make(chan bool)
	go func() {
		key, _ := rsa.GenerateKey(rand.Reader, 4096)
		sv := ssock.New(key)
		conn, _ := ln.Accept()
		log.Println("Client accepted!")
		econn, _ := sv.GenSConn(conn)

		buf := make([]byte, 300)
		n, _ := econn.Read(buf)
		log.Println("server:", string(buf[:n]))
		econn.Write([]byte(`Server Hello`))

		conn.Close()
		close(test)
	}()
	conn, err := net.Dial("tcp", ":17777")
	if err != nil {
		log.Println(err)
	}
	econn, _ := ssock.GenSConn(conn)

	econn.Write([]byte(`Client Hello`))
	buf := make([]byte, 300)
	n, _ := econn.Read(buf)
	log.Println("client:", string(buf[:n]))

	conn.Close()
	<-test
}
