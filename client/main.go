package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"github.com/songgao/water"
	"github.com/tiqio/DePlus/noise"
	"github.com/tiqio/DePlus/tai64n"
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
	TSend     noise.NoiseSymmetricKey // TiSend
	TRecv     noise.NoiseSymmetricKey // TiRecv

	chanBufSize int
	toIface     chan *noise.Packet
	recvBuffer  *noise.PacketBuffer
	toNet       chan *noise.Packet

	Hash     [blake2s.Size]byte
	ChainKey [blake2s.Size]byte
	Key      [chacha20poly1305.KeySize]byte
	Nonce    [chacha20poly1305.NonceSize]byte

	handshakeDone chan struct{}

	pktHandle   map[byte](func(*net.UDPConn, *noise.Packet))
	subnet      string
	otherSubnet string
}

func main() {
	fmt.Println("Initiator...")

	// 初始化客户端结构体。
	client := new(Client)
	client.endIp = "22.22.22.1"
	client.endHttpPort = 51820
	client.endUdpPort = 51821
	client.subnet = "192.168.1.0/24"
	client.otherSubnet = "192.168.2.0/24"

	_, err := rand.Read(client.sid[:])
	if err != nil {
		fmt.Println("客户端会话ID生成失败:", err)
		return
	}

	client.EiPriv, client.EiPub = noise.NewKeyPair()
	client.SiPriv, client.SiPub = noise.NewKeyPair()

	client.chanBufSize = 128
	client.toIface = make(chan *noise.Packet, client.chanBufSize)
	client.recvBuffer = noise.NewPacketBuffer(client.toIface)
	client.toNet = make(chan *noise.Packet, client.chanBufSize)

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

	// 处理与服务端对接的UDP数据流。
	go client.handleUDP(serverUdpAddr)

	// 处理和TUN设备相关的流量。
	// 必须放到handleHandshakeAck完成，TUN设备被创建后。
	//go client.handleInterface()

	termSignal := make(chan os.Signal, 1)
	signal.Notify(termSignal, os.Interrupt, syscall.SIGTERM)
	<-termSignal
	fmt.Println("客户端关闭。")
}

func (clt *Client) handleInterface() {
	// 从toIface中获取数据包并写入TUN设备。
	go func() {
		for {
			p := <-clt.toIface
			_, err := clt.iface.Write(p.Payload)
			if err != nil {
				fmt.Println("写入TUN设备失败:", err)
				return
			}
		}
	}()

	// 从TUN设备中读取数据包并写入toNet。
	frame := make([]byte, noise.UDP_BUFFER-noise.HDR_LEN)
	for {
		n, err := clt.iface.Read(frame)
		if err != nil {
			fmt.Println("从TUN设备中读取失败:", err)
			return
		}

		p := new(noise.Packet)
		p.Flag = noise.FLG_DAT
		p.Seq = clt.Seq()
		p.Payload = make([]byte, n)
		copy(p.Payload, frame[:n])

		clt.toNet <- p
	}
}

func (clt *Client) handleUDP(serverUdpAddr string) {
	udpAddr, _ := net.ResolveUDPAddr("udp", serverUdpAddr)
	udpConn, _ := net.DialUDP("udp", nil, udpAddr)

	// 注册和Flag相对应的处理函数。
	clt.pktHandle = map[byte](func(*net.UDPConn, *noise.Packet)){
		noise.FLG_HSH | noise.FLG_ACK: clt.handleHandshakeAck,
		noise.FLG_DAT:                 clt.handleDataPacket,
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

	// 将从TUN设备来的数据包封装为报文并传送到UDP数据流上。
	go func() {
		for {
			p := <-clt.toNet
			p.SetSid(clt.sid)
			udpConn.Write(p.Pack(clt.TSend))
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

		// 反序列化为Packet结构。
		var p *noise.Packet
		p, err = noise.UnPack(buf[:n])
		// 去除从UDP数据流读取的过多的0。
		p.Payload = bytes.TrimRight(p.Payload, "\x00")

		fmt.Printf("* 接收到从服务端来到的报文[%d]。\n", p.Flag)

		if p.Flag == noise.FLG_DAT {
			p.Payload = clt.TRecv.Decrypt(p.Payload[:])
			fmt.Println("数据报文处理中...")
		}

		if handle_func, ok := clt.pktHandle[p.Flag]; ok {
			handle_func(udpConn, p)
		} else {
			fmt.Println("报文的Flag标志未被注册。")
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
	u.Write(p.Pack(clt.TSend))
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
		fmt.Println("配置本地TUN设备的地址:", ip, subnet.Mask)
		clt.iface, _ = noise.NewTun(ipStr)

		// 在客户端配置路由。
		out, err := noise.RunCommand(fmt.Sprintf("sudo ip route add %s dev %s", clt.otherSubnet, clt.iface.Name()))
		if err != nil {
			fmt.Println("标准输出:", out)
			fmt.Println("客户端本地设置其他客户端子网路由失败:", err)
			return
		}

		// 处理和TUN设备相关的流量。
		go clt.handleInterface()

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
		noise.KDF2((*[chacha20poly1305.KeySize]byte)(&clt.TSend),
			(*[chacha20poly1305.KeySize]byte)(&clt.TRecv),
			clt.ChainKey[:],
			es[:]) // (TSend, TRecv) = HKDF2(ck2, DH(EiPriv, SrPub))

		// 改变当前的握手状态。
		res := atomic.CompareAndSwapInt32(&clt.state, noise.STAT_HANDSHAKE, noise.STAT_WORKING)
		if !res {
			fmt.Println("握手状态改变失败:", err)
			return
		}
		close(clt.handshakeDone)
	}

	clt.toServer(u, noise.FLG_HSH|noise.FLG_ACK, nil)
}

func (clt *Client) handleDataPacket(u *net.UDPConn, p *noise.Packet) {
	clt.recvBuffer.Push(p)
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
		tai64n.TimestampSize+poly1305.TagSize+
		4+1))
	buf.Write(clt.EiPub[:])
	buf.Write(clt.EncStatic[:])
	buf.Write(clt.EncTime[:])

	// 解析本地通告的子网。
	_, subnet, err := net.ParseCIDR(clt.subnet)
	if err != nil {
		fmt.Println("通告的当地子网的格式不对:", err)
		return nil
	}
	ip := subnet.IP.To4()
	mask, _ := subnet.Mask.Size()

	buf.Write(ip)
	buf.WriteByte(byte(mask))

	return buf.Bytes()
}
