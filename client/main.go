package main

import (
	"DePlus/noise"
	"DePlus/tai64n"
	"bytes"
	"crypto/rand"
	"fmt"
	"github.com/songgao/water"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"
	"io/ioutil"
	mrand "math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"
)

type Client struct {
	endIp       string
	endHttpPort int
	endUdpPort  int
	tunnelIP    net.IPNet

	// interface
	iface *water.Interface
	// session id
	sid [4]byte
	// session state
	state int32
	// sequence number
	seq uint32

	ErPub     noise.NoisePublicKey
	EiPriv    noise.NoisePrivateKey
	EiPub     noise.NoisePublicKey
	SiPriv    noise.NoisePrivateKey
	SiPub     noise.NoisePublicKey
	EncStatic [noise.NoisePublicKeySize + poly1305.TagSize]byte
	EncTime   [tai64n.TimestampSize + poly1305.TagSize]byte
	SrPub     noise.NoisePublicKey
	TiSend    noise.NoiseSymmetricKey
	TiRecv    noise.NoiseSymmetricKey

	Hash     [blake2s.Size]byte
	ChainKey [blake2s.Size]byte
	Key      [chacha20poly1305.KeySize]byte
	Nonce    [chacha20poly1305.NonceSize]byte

	handshakeDone chan struct{}

	pktHandle map[byte](func(*net.UDPConn, *noise.Packet))
}

func main() {
	fmt.Println("Initiator...")

	// 初始化客户端结构体。
	client := new(Client)
	client.endIp = "0.0.0.0"
	client.endHttpPort = 51820
	client.endUdpPort = 51821
	_, err := rand.Read(client.sid[:])
	if err != nil {
		fmt.Println("客户端会话ID生成失败:", err)
		return
	}

	client.EiPriv, client.EiPub = noise.NewKeyPair()
	client.SiPriv, client.SiPub = noise.NewKeyPair()

	client.state = noise.STAT_INIT
	client.handshakeDone = make(chan struct{})

	// 从服务端获取到ErPub。
	serverURL := fmt.Sprintf("http://%s:%d", client.endIp, client.endHttpPort)
	response, err := http.Get(serverURL)
	if err != nil {
		fmt.Println("HTTP请求失败:", err)
		return
	}
	defer response.Body.Close()

	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Println("读取响应体失败:", err)
		return
	}
	copy(client.ErPub[:], responseBody)
	fmt.Println("获取服务端临时公钥:", client.ErPub[:])

	// 处理和服务端对接的UDP数据流。
	serverUdpAddr := fmt.Sprintf("%s:%d", client.endIp, client.endUdpPort)
	fmt.Printf("正在向%s发起UDP连接...\n", serverUdpAddr)
	go client.handleUDP(serverUdpAddr)

	termSignal := make(chan os.Signal, 1)
	signal.Notify(termSignal, os.Interrupt, syscall.SIGTERM)
	<-termSignal
	fmt.Println("客户端关闭。")
}

func (clt *Client) handleUDP(serverUdpAddr string) {
	udpAddr, _ := net.ResolveUDPAddr("udp", serverUdpAddr)
	udpConn, _ := net.DialUDP("udp", nil, udpAddr)

	// 注册和Flag相对应的处理函数。
	clt.pktHandle = map[byte](func(*net.UDPConn, *noise.Packet)){
		noise.FLG_HSH | noise.FLG_ACK: clt.handleHandshakeAck,
		noise.FLG_HSH | noise.FLG_FIN: clt.handleHandshakeError,
	}

	// 用于发送握手报文，在收到handshakeAck报文后通过handshakeDone通知，否则在5秒左右超时重传。
	go func() {
		for {
			n := mrand.Intn(1000)
			time.Sleep(time.Duration(n) * time.Millisecond)
			clt.handshake(udpConn)
			select {
			case <-clt.handshakeDone:
				fmt.Println("握手阶段完成，进入数据交换阶段...")
				return
			case <-time.After(5 * time.Second):
				fmt.Println("握手报文超时重传...")
			}
		}
	}()

	// 从UDP数据流中读取数据包并调用相关的处理函数。
	buf := make([]byte, noise.UDP_BUFFER)
	for {
		n, err := udpConn.Read(buf)
		if err != nil {
			fmt.Println("客户端的UDP数据流异常，读取失败:", err)
			continue
		}
		p, err := noise.UnPack(buf[:n])
		if err != nil {
			fmt.Println("客户端解包失败:", err)
		}
		if handle_func, ok := clt.pktHandle[p.Flag]; ok {
			handle_func(udpConn, p)
		}
	}

}

func (clt *Client) handshake(u *net.UDPConn) {
	res := atomic.CompareAndSwapInt32(&clt.state, noise.STAT_INIT, noise.STAT_HANDSHAKE)

	if res {
		fmt.Println("状态转换成功，发送Handshake Initiation报文...")
		clt.toServer(u, noise.FLG_HSH, clt.initiationPayload())
	}
}

func (clt *Client) toServer(u *net.UDPConn, flag byte, payload []byte) {
	p := new(noise.Packet)
	p.Flag = flag
	p.Seq = clt.Seq()
	p.SetSid(clt.sid)
	p.SetPayload(payload)
	u.Write(p.Pack())
}

func (clt *Client) Seq() uint32 {
	return atomic.AddUint32(&clt.seq, 1)
}

func (clt *Client) handleHandshakeAck(u *net.UDPConn, p *noise.Packet) {
	if atomic.LoadInt32(&clt.state) == noise.STAT_HANDSHAKE {
		// 将Payload中的数据反序列化为Client的字段。
		left := 0
		right := noise.NoisePublicKeySize + poly1305.TagSize
		copy(clt.EncStatic[:], p.Payload[left:right])
		left = right
		right += 5
		by := p.Payload[left:right]
		ipStr := fmt.Sprintf("%d.%d.%d.%d/%d", by[0], by[1], by[2], by[3], by[4])

		ip, subnet, _ := net.ParseCIDR(ipStr)

		// 配置TUN设备地址。
		fmt.Println("待写:配置本地TUN设备的地址:", ip, subnet.Mask)

		// 密码学处理。
		aead, err := chacha20poly1305.New(clt.Key[:])
		if err != nil {
			fmt.Println("生成EncStatic解密器失败:", err)
			return
		}
		aead.Open(clt.SrPub[:0], clt.Nonce[:], clt.EncStatic[:], clt.Hash[:])
		if err != nil {
			fmt.Println("EncStatic解密失败:", err)
		}

		// 派生出用于加解密的密钥。
		es := clt.EiPriv.SharedSecret(clt.SrPub)
		noise.KDF2((*[chacha20poly1305.KeySize]byte)(&clt.TiSend),
			(*[chacha20poly1305.KeySize]byte)(&clt.TiRecv),
			clt.ChainKey[:],
			es[:]) // (TiSend, TiRecv) = HKDF2(ck2, DH(EiPriv, SrPub))

		// 改变当前的握手状态。
		res := atomic.CompareAndSwapInt32(&clt.state, noise.STAT_HANDSHAKE, noise.STAT_WORKING)
		if !res {
			fmt.Println("握手状态改变失败:", err)
			return
		}
		close(clt.handshakeDone)
	}
}

func (clt *Client) handleHandshakeError(u *net.UDPConn, p *noise.Packet) {

}

// 生成用于握手的Payload。
func (clt *Client) initiationPayload() []byte {
	// 密码学处理。
	clt.ChainKey = blake2s.Sum256([]byte(noise.NoiseConstruction))         // h1
	noise.MixHash(&clt.Hash, &clt.ChainKey, []byte(noise.NoiseIdentifier)) // ck0

	noise.MixHash(&clt.Hash, &clt.Hash, clt.ErPub[:])        // h2 = Hash(h1 || ErPub)
	noise.MixHash(&clt.Hash, &clt.Hash, clt.EiPub[:])        // h3 = Hash(h2 || EiPub)
	noise.MixKey(&clt.ChainKey, &clt.ChainKey, clt.EiPub[:]) // ck1 = HKDF1(ck0, EiPub)
	ee := clt.EiPriv.SharedSecret(clt.ErPub)
	noise.KDF2(&clt.ChainKey, &clt.Key, clt.ChainKey[:], ee[:]) // (ck2, k0) = HKDF2(ck1, DH(EiPriv, ErPub))

	// 生成EncStatic。
	aead, err := chacha20poly1305.New(clt.Key[:])
	if err != nil {
		fmt.Println("生成EncStatic加密器失败:", err)
		return nil
	}
	aead.Seal(clt.EncStatic[:0], clt.Nonce[:], clt.SiPub[:], clt.Hash[:])

	// 密码学处理。
	noise.MixHash(&clt.Hash, &clt.Hash, clt.EncStatic[:]) // h4 = Hash(h3 || enc-id)
	se := clt.SiPriv.SharedSecret(clt.ErPub)
	noise.KDF2(&clt.ChainKey, &clt.Key, clt.ChainKey[:], se[:]) // (ck3, k1) = HKDF2(ck2, DH(SiPriv, ErPub))

	// 生成EncTime。
	aead, err = chacha20poly1305.New(clt.Key[:])
	if err != nil {
		fmt.Println("生成EncTime加密器失败:", err)
		return nil
	}
	timestamp := tai64n.Now()
	aead.Seal(clt.EncTime[:0], clt.Nonce[:], timestamp[:], clt.Hash[:])

	// 将EiPub，EncStatic和EncTime组装成Payload。
	buf := bytes.NewBuffer(make([]byte, 0, noise.NoisePublicKeySize+
		noise.NoisePublicKeySize+poly1305.TagSize+
		tai64n.TimestampSize+poly1305.TagSize))
	buf.Write(clt.EiPub[:])
	buf.Write(clt.EncStatic[:])
	buf.Write(clt.EncTime[:])

	return buf.Bytes()
}
