package main

import (
	"DePlus/noise"
	"DePlus/tai64n"
	"DePlus/util"
	"bytes"
	"fmt"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
)

type Peer struct {
	ip    net.IP
	mask  int
	sid   uint64
	addr  *net.UDPAddr
	seq   uint32
	state int32
	srv   *Server
	buf   []byte

	ErPriv noise.NoisePrivateKey
	ErPub  noise.NoisePublicKey
	EiPub  noise.NoisePublicKey
	SiPub  noise.NoisePublicKey
	TrRecv noise.NoiseSymmetricKey
	TrSend noise.NoiseSymmetricKey

	Hash     [blake2s.Size]byte
	ChainKey [blake2s.Size]byte
	Key      [chacha20poly1305.KeySize]byte
	Nonce    [chacha20poly1305.NonceSize]byte

	EncStatic [noise.NoisePublicKeySize + poly1305.TagSize]byte
	EncTime   [tai64n.TimestampSize + poly1305.TagSize]byte
	Timestamp tai64n.Timestamp
}

type Server struct {
	// 监听地址
	ip string
	// 端口
	httpPort int
	udpPort  int
	tunnelIP string

	// 键是会话ID（前32字节）或者隧道IP（后32字节），值是Peer结构体，对应着某个客户端。
	peers map[uint64]*Peer
	pool  *util.Pool

	ErPriv noise.NoisePrivateKey // peer
	ErPub  noise.NoisePublicKey  // peer
	SrPriv noise.NoisePrivateKey
	SrPub  noise.NoisePublicKey
	//EiPub     noise.NoisePublicKey // peer
	//EncStatic [noise.NoisePublicKeySize + poly1305.TagSize]byte // peer
	//EncTime   [tai64n.TimestampSize + poly1305.TagSize]byte     // peer
	//SiPub     noise.NoisePublicKey // peer
	//Timestamp tai64n.Timestamp
	//TrRecv    noise.NoiseSymmetricKey // peer
	//TrSend noise.NoiseSymmetricKey // peer

	chanBufSize int
	fromNet     chan *noise.UdpPacket
	toNet       chan *noise.UdpPacket

	//Hash     [blake2s.Size]byte               // peer
	//ChainKey [blake2s.Size]byte               // peer
	//Key      [chacha20poly1305.KeySize]byte   // peer
	//Nonce    [chacha20poly1305.NonceSize]byte // peer

	pktHandle map[byte](func(*noise.UdpPacket, *noise.Packet))
}

func (srv Server) handler(w http.ResponseWriter, r *http.Request) {
	_, err := w.Write(srv.ErPub[:])
	if err != nil {
		http.Error(w, "Er_pub放入ResponseWriter失败:", http.StatusInternalServerError)
	}
}

func main() {
	fmt.Println("Responder...")

	// 初始化服务端结构体。
	server := new(Server)
	server.ip = "0.0.0.0"
	server.httpPort = 51820
	server.udpPort = 51821
	server.tunnelIP = "10.10.10.1/24"

	server.ErPriv, server.ErPub = noise.NewKeyPair()
	server.SrPriv, server.SrPub = noise.NewKeyPair()

	server.chanBufSize = 2048
	server.fromNet = make(chan *noise.UdpPacket, server.chanBufSize)
	server.toNet = make(chan *noise.UdpPacket, server.chanBufSize)

	server.peers = make(map[uint64]*Peer)
	server.pool = new(util.Pool)
	ip, subnet, err := net.ParseCIDR(server.tunnelIP)
	if err != nil {
		fmt.Println("配置的隧道地址格式不对:", err)
		return
	}
	server.pool.Subnet = subnet

	// 配置本地TUN设备的地址。
	fmt.Println("待写:配置本地TUN设备的地址:", ip, " & ", subnet.Mask)

	// 利用生成的ErPub开启HTTP服务。
	http.HandleFunc("/", server.handler)
	serverHttpAddr := fmt.Sprintf("%s:%d", server.ip, server.httpPort)
	go func() {
		//fmt.Println("加载服务端临时公钥:", server.ErPub)
		fmt.Println("开启HTTP服务，服务地址:", serverHttpAddr)
		err := http.ListenAndServe(serverHttpAddr, nil)
		if err != nil {
			fmt.Println("服务端HTTP服务开启失败:", err)
			return
		}
	}()

	// 处理与客户端对接的UDP数据流。
	serverUdpAddr := fmt.Sprintf("%s:%d", server.ip, server.udpPort)
	go server.handleUDP(serverUdpAddr)

	// 处理客户端的数据结构，即UdpPacket。
	go server.forwardFrames()

	termSignal := make(chan os.Signal, 1)
	signal.Notify(termSignal, os.Interrupt, syscall.SIGTERM)
	<-termSignal
	fmt.Println("服务端关闭。")
}

func (srv *Server) forwardFrames() {

	// 注册和Flag相对应的处理函数。
	srv.pktHandle = map[byte](func(*noise.UdpPacket, *noise.Packet)){
		noise.FLG_HSH: srv.handleHandshake,
	}

	for {
		select {
		case up := <-srv.fromNet:
			srv.handlePacket(up)
		}
	}

}

func (srv *Server) handlePacket(up *noise.UdpPacket) {
	p, err := noise.UnPack(up.Data)
	if err == nil {
		fmt.Printf("新的UDP报文[%v]来自: %v\n", p.Flag, up.Addr)
		if handle_func, ok := srv.pktHandle[p.Flag]; ok {
			handle_func(up, p)
		} else {
			fmt.Println("报文的Flag标志未被注册。")
			return
		}
	} else {
		fmt.Println("针对UdpPacket的解密失败。")
		return
	}
}

func (srv *Server) handleHandshake(up *noise.UdpPacket, p *noise.Packet) {
	sid := uint64(p.Sid)
	sid = (sid << 32) & uint64(0xFFFFFFFF00000000)
	fmt.Printf("接收到从客户端来到的握手报文 addr: %v, sid: %d\n", up.Addr, sid)

	peer, ok := srv.peers[sid]
	if !ok {
		peer = srv.newPeer(sid, up.Addr)
		srv.peers[sid] = peer
	} else {
		fmt.Println("服务端已经有该客户端的记录。")
	}

	// 为peer结构初始化对应的字段。
	peer.ErPub = srv.ErPub
	peer.ErPriv = srv.ErPriv

	// 为客户端分配一个隧道地址。
	cltIP, err := srv.pool.Next()
	if err != nil {
		fmt.Println("为客户端分配隧道地址失败。")
		return
	} else {
		peer.ip = cltIP.IP.To4()
		peer.mask, _ = cltIP.Mask.Size()
	}

	// 将Payload中的数据反序列化为Server的字段。
	left := 0
	right := noise.NoisePublicKeySize
	copy(peer.EiPub[:], p.Payload[left:right])
	left = right
	right += noise.NoisePublicKeySize + poly1305.TagSize
	copy(peer.EncStatic[:], p.Payload[left:right])
	left = right
	right += tai64n.TimestampSize + poly1305.TagSize
	copy(peer.EncTime[:], p.Payload[left:right])

	// 消耗接收到的Handshake Initiation并生成用于传输的Handshake Response。
	peer.srv = srv
	peer.buf = peer.responsePayload()

	// 基于隧道地址注册peer。
	key := util.IP4_uint64(peer.ip)
	srv.peers[key] = peer

	// 更新当前peer的状态为握手状态，并向对应客户端发送响应报文。
	atomic.StoreInt32(&peer.state, noise.STAT_HANDSHAKE)
	peer.toClient(noise.FLG_HSH | noise.FLG_ACK)
}

func (peer *Peer) toClient(flag byte) {
	p := new(noise.Packet)
	p.Seq = peer.Seq()
	p.Flag = flag
	p.Payload = peer.buf

	// 封装为UdpPacket，之后传入toNet队列中进行发送。
	up := &noise.UdpPacket{peer.addr, p.Pack()}
	peer.srv.toNet <- up
}

func (peer *Peer) Seq() uint32 {
	return atomic.AddUint32(&peer.seq, 1)
}

func (peer *Peer) responsePayload() []byte {
	// 密码学处理。
	srv := peer.srv
	peer.ChainKey = blake2s.Sum256([]byte(noise.NoiseConstruction))          // h1
	noise.MixHash(&peer.Hash, &peer.ChainKey, []byte(noise.NoiseIdentifier)) // ck0

	noise.MixHash(&peer.Hash, &peer.Hash, peer.ErPub[:])        // h2 = Hash(h1 || Er_pub)
	noise.MixHash(&peer.Hash, &peer.Hash, peer.EiPub[:])        // h3 = Hash(h2 || Ei_pub)
	noise.MixKey(&peer.ChainKey, &peer.ChainKey, peer.EiPub[:]) // ck1 = HKDF1(ck0, Ei_pub)
	ee := peer.ErPriv.SharedSecret(peer.EiPub)
	noise.KDF2(&peer.ChainKey, &peer.Key, peer.ChainKey[:], ee[:]) // (ck2, k0) = HKDF2(ck1, DH(ErPriv, ErPub))

	// 解密出SiPub。
	aead, err := chacha20poly1305.New(peer.Key[:])
	if err != nil {
		fmt.Println("生成EncStatic解密器失败:", err)
		return nil
	}
	_, err = aead.Open(peer.SiPub[:0], peer.Nonce[:], peer.EncStatic[:], peer.Hash[:])
	if err != nil {
		fmt.Print("针对EncStatic的解密失败:", err)
		return nil
	}

	// 密码学处理。
	noise.MixHash(&peer.Hash, &peer.Hash, peer.EncStatic[:]) // h4 = Hash(h3 || enc-id)
	se := srv.ErPriv.SharedSecret(peer.SiPub)
	noise.KDF2(&peer.ChainKey, &peer.Key, peer.ChainKey[:], se[:]) // (ck3, k1) = HKDF2(ck2, DH(ErPriv, SiPub))

	// 解密出Timestamp。
	aead, err = chacha20poly1305.New(peer.Key[:])
	if err != nil {
		fmt.Println("生成Timestamp解密器失败:", err)
		return nil
	}
	_, err = aead.Open(peer.Timestamp[:0], peer.Nonce[:], peer.EncTime[:], peer.Hash[:]) // aead-dec(k1, 0, enc-time, h4)
	if err != nil {
		fmt.Println("针对EncTime的解密失败:", err)
	}

	// 利用上一步生成的Key对SrPub进行加密，生成EncStatic。
	aead.Seal(peer.EncStatic[:0], peer.Nonce[:], srv.SrPub[:], peer.Hash[:]) // enc-id = aead-enc(k0, 0, SiPub, h3)

	// 派生出用于加解密的密钥。
	es := srv.SrPriv.SharedSecret(peer.EiPub)
	noise.KDF2((*[chacha20poly1305.KeySize]byte)(&peer.TrRecv),
		(*[chacha20poly1305.KeySize]byte)(&peer.TrSend),
		peer.ChainKey[:],
		es[:]) // (TrRecv, TrSend) = HKDF2(ck2, DH(SrPriv, EiPub))

	// 将EncStatic，IP和Mask组装成Payload，IP和Mask分别占4个和1个字节。
	buf := bytes.NewBuffer(make([]byte, 0, noise.NoisePublicKeySize+poly1305.TagSize+4+1))
	buf.Write(peer.EncStatic[:])
	buf.Write(peer.ip)
	buf.WriteByte(byte(peer.mask))

	return buf.Bytes()
}

func (srv *Server) newPeer(sid uint64, addr *net.UDPAddr) *Peer {
	peer := new(Peer)
	peer.sid = sid
	peer.addr = addr
	peer.seq = 0
	peer.state = noise.STAT_INIT

	return peer
}

func (srv *Server) handleUDP(serverUdpAddr string) {
	udpAddr, err := net.ResolveUDPAddr("udp", serverUdpAddr)
	if err != nil {
		fmt.Println("解析UDP地址失败:", err)
		return
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("创建UDP监听器失败:", err)
		return
	}
	defer udpConn.Close()
	fmt.Println("开启UDP服务，服务地址:", serverUdpAddr)
	fmt.Println("等待客户端连接...")

	// 将toNet队列中的UdpPacket发送到UDP数据流的对端。
	go func() {
		for {
			up := <-srv.toNet
			udpConn.WriteTo(up.Data, up.Addr)
		}
	}()

	// 从UDP数据流中读取数据并传入fromNet队列。
	for {
		var plen int
		up := new(noise.UdpPacket)
		buf := make([]byte, noise.UDP_BUFFER)
		plen, up.Addr, err = udpConn.ReadFromUDP(buf)

		up.Data = buf[:plen]
		if err != nil {
			fmt.Println("客户端接收握手信息失败:", err)
			return
		}

		srv.fromNet <- up
	}
}
