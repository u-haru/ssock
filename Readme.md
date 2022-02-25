# ssock
暗号化の勉強を目的として作成したソケットで暗号通信を行うサンプル  
RSAを用いて公開鍵認証を行い、AES鍵を交換してその鍵を用いて通信を行う。  
AESの暗号利用モードはGCM。

## Usage

```go
import "github.com/u-haru/ssock"

/* ~~~ */

key, _ := rsa.GenerateKey(rand.Reader, 4096)
sv := ssock.New(key)
ln, _ := net.Listen("tcp", ":17777")
conn, _ := ln.Accept()
econn, _ := sv.GenSConn(conn)
econn.Write([]byte("This message is encrypted"))
```

## Example

```go
go run ./example/hello
```
