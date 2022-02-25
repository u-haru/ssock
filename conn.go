package ssock

import (
	"crypto/cipher"
	"crypto/rand"
	"io"
	"log"
	"sync"
)

const Blocksize = 512

type Conn struct {
	nonce []byte
	once  sync.Once

	src   io.ReadWriteCloser
	gcm   cipher.AEAD
	block cipher.Block
}

func NewReadWriter(src io.ReadWriteCloser, block cipher.Block) (*Conn, error) {
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &Conn{
		src:   src,
		gcm:   aesgcm,
		block: block,
	}, nil
}

//https://stackoverflow.com/questions/39378051/making-gcm-cbc-ciphers-streamable-in-golang
func (c *Conn) Read(b []byte) (int, error) {
	c.once.Do(func() {
		c.nonce = make([]byte, c.gcm.NonceSize())
		c.src.Read(c.nonce)
	})

	buf := make([]byte, Blocksize+c.block.BlockSize())
	n := 0

	for {
		m, err := c.src.Read(buf)
		if m > 0 {
			tmp, err := c.gcm.Open(nil, c.nonce, buf[:m], nil)
			if err != nil {
				return 0, err
			}
			n += copy(b[n:], tmp)
		}
		if err != nil {
			return n, err
		}
		if n >= len(b) || len(buf) >= m { // capacity over , or all data readed (buffer isnt used fully)
			return n, nil
		}
	}
}

func (c *Conn) Write(b []byte) (int, error) {
	c.once.Do(func() {
		c.nonce = make([]byte, c.gcm.NonceSize())
		m, err := rand.Reader.Read(c.nonce)
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			log.Println(err)
		}
		if m != len(c.nonce) {
			log.Println(io.ErrUnexpectedEOF)
		}
		c.src.Write(c.nonce)
	})

	r := 0
	rbuf := make([]byte, Blocksize)

	for {
		m := copy(rbuf, b[r:])
		buf := c.gcm.Seal(nil, c.nonce, rbuf[:m], nil)
		r += m

		_, err := c.src.Write(buf)
		if err != nil {
			return r, err
		}

		if r >= len(b) { // all data written
			return r, nil
		}
	}
}
