package ssock

import (
	"encoding/pem"
	"errors"
	"io"
	"net"

	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
)

type Server struct {
	key *rsa.PrivateKey
}

func New(key *rsa.PrivateKey) *Server {
	return &Server{
		key: key,
	}
}

// server: serverhello(return pubkey (rsa))
// client: pubkey -> gen sharedkey, encrypt and send to server
// server: get encrypted sharedkey -> decrypt key
// handshake conplete

// serverhello
// len 2 byte
// key n byte

// clienthello
// cryptokey 32 byte

func (ln *Server) GenSConn(conn net.Conn) (*Conn, error) {
	// conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	// conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	//1 serverhello
	pubASN1 := x509.MarshalPKCS1PublicKey(&ln.key.PublicKey)

	pubkey := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})

	pubkeylen := make([]byte, 2)
	pubkeylen[0] = uint8(len(pubkey) >> 8)
	pubkeylen[1] = uint8(len(pubkey))

	conn.Write(pubkeylen)
	conn.Write(pubkey)

	//2 clienthello
	ckeylen := make([]byte, 2)
	io.ReadFull(conn, ckeylen)
	ckey := make([]byte, uint(ckeylen[0])<<8+uint(ckeylen[1]))
	io.ReadFull(conn, ckey)

	//3 get sessionkey
	skey := make([]byte, 32)
	rsa.DecryptPKCS1v15SessionKey(rand.Reader, ln.key, ckey, skey)

	// do connnection
	cblock, err := aes.NewCipher(skey)
	if err != nil {
		return nil, err
	}
	econn, _ := NewReadWriter(conn, cblock)
	return econn, nil
}

func GenSConn(conn net.Conn) (*Conn, error) {
	pkeylen := make([]byte, 2)
	io.ReadFull(conn, pkeylen)
	pkey := make([]byte, uint(pkeylen[0])<<8+uint(pkeylen[1]))
	io.ReadFull(conn, pkey)

	block, _ := pem.Decode(pkey)
	if block == nil {
		return nil, errors.New("key decode failed")
	}

	pubkey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	//sessionkey
	skey := make([]byte, 32)
	io.ReadFull(rand.Reader, skey)

	//crypted
	c_sKey, err := rsa.EncryptPKCS1v15(rand.Reader, pubkey, skey)
	if err != nil {
		return nil, err
	}

	cskeylen := make([]byte, 2)
	cskeylen[0] = uint8(len(c_sKey) >> 8)
	cskeylen[1] = uint8(len(c_sKey))

	conn.Write(cskeylen)
	conn.Write(c_sKey)

	cblock, err := aes.NewCipher(skey)
	if err != nil {
		return nil, err
	}
	econn, _ := NewReadWriter(conn, cblock)

	return econn, nil
}
