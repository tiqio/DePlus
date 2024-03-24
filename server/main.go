package main

import (
	"bytes"
	"fmt"
	"github.com/songgao/water"
	"github.com/songgao/water/waterutil"
	"github.com/tiqio/DePlus/noise"
	"github.com/tiqio/DePlus/tai64n"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"
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
	TRecv  noise.NoiseSymmetricKey
	TSend  noise.NoiseSymmetricKey

	Hash     [blake2s.Size]byte
	ChainKey [blake2s.Size]byte
	Key      [chacha20poly1305.KeySize]byte
	Nonce    [chacha20poly1305.NonceSize]byte

	EncStatic [noise.NoisePublicKeySize + poly1305.TagSize]byte
	EncTime   [tai64n.TimestampSize + poly1305.TagSize]byte
	Timestamp tai64n.Timestamp

	recvBuffer *noise.PacketBuffer

	hsDone chan struct{}
	subnet *net.IPNet
}

type Server struct {
	// 监听地址
	ip string
	// 端口
	httpPort int
	udpPort  int
	// 隧道地址
	tunnelIP string
	// TUN设备接口
	iface *water.Interface

	// 键是会话ID（前32字节）或者隧道IP（后32字节），值是Peer结构体，对应着某个客户端。
	peers map[uint64]*Peer
	pool  *noise.Pool

	ErPriv noise.NoisePrivateKey // peer
	ErPub  noise.NoisePublicKey  // peer
	SrPriv noise.NoisePrivateKey
	SrPub  noise.NoisePublicKey
	//EiPub     noise.NoisePublicKey // peer
	//EncStatic [noise.NoisePublicKeySize + poly1305.TagSize]byte // peer
	//EncTime   [tai64n.TimestampSize + poly1305.TagSize]byte     // peer
	//SiPub     noise.NoisePublicKey // peer
	//Timestamp tai64n.Timestamp
	//TRecv    noise.NoiseSymmetricKey // peer
	//TSend noise.NoiseSymmetricKey // peer

	chanBufSize int
	toNet       chan *noise.UdpPacket
	toIface     chan *noise.Packet
	fromIface   chan *noise.Packet

	//Hash     [blake2s.Size]byte               // peer
	//ChainKey [blake2s.Size]byte               // peer
	//Key      [chacha20poly1305.KeySize]byte   // peer
	//Nonce    [chacha20poly1305.NonceSize]byte // peer

	pktHandle map[byte](func(*noise.UdpPacket, *noise.Packet, *Peer))
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
	server.ip = "22.22.22.1"
	server.httpPort = 51820
	server.udpPort = 51821
	server.tunnelIP = "10.10.10.1/24"

	server.ErPriv, server.ErPub = noise.NewKeyPair()
	server.SrPriv, server.SrPub = noise.NewKeyPair()

	server.chanBufSize = 2048
	server.toNet = make(chan *noise.UdpPacket, server.chanBufSize)
	server.toIface = make(chan *noise.Packet, server.chanBufSize)
	server.fromIface = make(chan *noise.Packet, server.chanBufSize)

	server.peers = make(map[uint64]*Peer)
	server.pool = new(noise.Pool)
	ip, subnet, err := net.ParseCIDR(server.tunnelIP)
	if err != nil {
		fmt.Println("配置的隧道地址格式不对:", err)
		return
	}
	server.pool.Subnet = subnet

	// 配置本地TUN设备的地址。
	fmt.Println("配置本地TUN设备的地址:", ip, " & ", subnet.Mask)
	server.iface, _ = noise.NewTun(server.tunnelIP)

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

	// 将从TUN设备获得的数据包处理成客户端的数据结构，即将Packet包装为UdpPacket。
	go func() {
		for {
			p := <-server.fromIface
			dest := waterutil.IPv4Destination(p.Payload).To4()
			fmt.Printf("===== 接收到目标地址为%s的数据包。=====\n", dest)
			sid := noise.IP4_uint64(dest)

			if peer, found := server.peers[sid]; found {
				p.Seq = peer.Seq()
				up := &noise.UdpPacket{peer.addr, p.Pack(peer.TSend)}
				server.toNet <- up
			} else {
				fmt.Println("没有找到隧道地址相对应的客户端。")
				for _, peer = range server.peers {
					if peer.subnet.Contains(dest) {
						fmt.Println("可以在客户端通告的子网中找到目的地址，回路打通。")
						p.Seq = peer.Seq()
						up := &noise.UdpPacket{peer.addr, p.Pack(peer.TSend)}
						server.toNet <- up
						break
					}
				}
			}
		}
	}()

	// 处理和TUN设备相关的流量。
	go server.handleInterface()

	termSignal := make(chan os.Signal, 1)
	signal.Notify(termSignal, os.Interrupt, syscall.SIGTERM)
	<-termSignal
	fmt.Println("服务端关闭。")
}

func (srv *Server) handleInterface() {
	// 从toIface中获取数据包并写入TUN设备。
	go func() {
		for {
			p := <-srv.toIface
			_, err := srv.iface.Write(p.Payload)
			if err != nil {
				fmt.Println("写入TUN设备失败:", err)
				return
			}
		}
	}()

	// 从TUN设备中读取数据包并写入toNet。
	frame := make([]byte, noise.UDP_BUFFER-noise.HDR_LEN)
	go func() {
		for {
			n, err := srv.iface.Read(frame)
			if err != nil {
				fmt.Println("从TUN设备中读取失败:", err)
				return
			}

			p := new(noise.Packet)
			p.Flag = noise.FLG_DAT
			// 和客户端相比，Seq需要在查找到peer后赋值。
			p.Payload = make([]byte, n)
			copy(p.Payload, frame[:n])

			srv.fromIface <- p
		}
	}()

}

func (srv *Server) handleHandshake(up *noise.UdpPacket, p *noise.Packet, peer *Peer) {
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

	// 获取到客户端通告的子网网段。
	left = right
	right += 4 + 1
	by := p.Payload[left:right]
	ipStr := fmt.Sprintf("%d.%d.%d.%d/%d", by[0], by[1], by[2], by[3], by[4])
	_, subnet, _ := net.ParseCIDR(ipStr)
	peer.subnet = subnet

	// 在服务端配置路由。
	out, err := noise.RunCommand(fmt.Sprintf("sudo ip route add %s dev %s", ipStr, srv.iface.Name()))
	if err != nil {
		fmt.Println("标准输出:", out)
		fmt.Println("服务端本地设置客户端子网路由失败:", err)
		return
	}

	// 消耗接收到的Handshake Initiation并生成用于传输的Handshake Response。
	peer.srv = srv
	peer.buf = peer.responsePayload()

	// 基于隧道地址注册peer。
	sid := noise.IP4_uint64(peer.ip)
	srv.peers[sid] = peer

	// 更新当前peer的状态为握手状态，并向对应客户端发送响应报文。
	atomic.StoreInt32(&peer.state, noise.STAT_HANDSHAKE)
	peer.toClient(noise.FLG_HSH | noise.FLG_ACK)

	// 等待确认报文。
	peer.hsDone = make(chan struct{})
	go func() {
		for i := 0; i < 5; i++ {
			select {
			case <-peer.hsDone:
				peer.state = noise.STAT_WORKING
				fmt.Printf("Sid为[%d]，Addr为[%v]的Peer的握手成功完成。\n", peer.sid, peer.addr)
				return
			case <-time.After(2 * time.Second):
				fmt.Println("等待客户端握手的计时器超时。")
				peer.toClient(noise.FLG_HSH | noise.FLG_ACK)
			}
		}
	}()
}

func (peer *Peer) toClient(flag byte) {
	p := new(noise.Packet)
	p.Seq = peer.Seq()
	p.Flag = flag
	p.Payload = peer.buf

	// 封装为UdpPacket，之后传入toNet队列中进行发送。
	up := &noise.UdpPacket{peer.addr, p.Pack(peer.TSend)}
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
	noise.KDF2((*[chacha20poly1305.KeySize]byte)(&peer.TRecv),
		(*[chacha20poly1305.KeySize]byte)(&peer.TSend),
		peer.ChainKey[:],
		es[:]) // (TRecv, TSend) = HKDF2(ck2, DH(SrPriv, EiPub))

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
	peer.recvBuffer = noise.NewPacketBuffer(srv.toIface)

	return peer
}

func (srv *Server) handleUDP(serverUdpAddr string) {
	// 构造UDP数据流并处理连接。
	udpAddr, err := net.ResolveUDPAddr("udp", serverUdpAddr)
	if err != nil {
		fmt.Println("解析UDP地址失败:", err)
		return
	}
	var udpConn *net.UDPConn
	udpConn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("创建UDP监听器失败:", err)
		return
	}
	defer udpConn.Close()
	fmt.Println("开启UDP服务，服务地址:", serverUdpAddr)
	fmt.Println("等待客户端连接...")

	// 注册和Flag相对应的处理函数。
	srv.pktHandle = map[byte](func(*noise.UdpPacket, *noise.Packet, *Peer)){
		noise.FLG_HSH:                 srv.handleHandshake,
		noise.FLG_HSH | noise.FLG_ACK: srv.handleHandshakeAck,
		noise.FLG_DAT:                 srv.handleDataPacket,
	}

	// 将toNet队列中的UdpPacket发送到UDP数据流的对端。
	go func() {
		for {
			up := <-srv.toNet
			udpConn.WriteTo(up.Data, up.Addr)
		}
	}()

	// 从UDP数据流中读取数据包并调用相关的处理函数。
	for {
		var n int
		up := new(noise.UdpPacket)
		buf := make([]byte, noise.UDP_BUFFER)
		n, up.Addr, err = udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("客户端从UDP数据流中读取失败:", err)
			return
		}

		// 反序列化为Packet结构。
		var p *noise.Packet
		p, err = noise.UnPack(buf[:n])
		// 去除从UDP数据流读取的过多的0。
		p.Payload = bytes.TrimRight(p.Payload, "\x00")

		// 会在这里注册对端的Peer结构。
		sid := uint64(p.Sid)
		sid = (sid << 32) & uint64(0xFFFFFFFF00000000)
		fmt.Printf("* 接收到从客户端来到的报文[%d] addr: %v, sid: %d。\n", p.Flag, up.Addr, sid)

		peer, ok := srv.peers[sid]
		if !ok {
			peer = srv.newPeer(sid, up.Addr)
			srv.peers[sid] = peer
		} else {
			fmt.Println("服务端已经有该客户端的记录。")
		}

		// 使用Peer结构对数据包的Payload进行解密。
		if p.Flag == noise.FLG_DAT {
			p.Payload = peer.TRecv.Decrypt(p.Payload)
			fmt.Println("数据报文处理中...")
		}

		if handle_func, ok := srv.pktHandle[p.Flag]; ok {
			handle_func(up, p, peer)
		} else {
			fmt.Println("报文的Flag标志未被注册。")
		}
	}
}

func (srv *Server) handleDataPacket(up *noise.UdpPacket, p *noise.Packet, peer *Peer) {
	if peer.state == noise.STAT_WORKING {
		peer.recvBuffer.Push(p)
	}
}

func (srv *Server) handleHandshakeAck(up *noise.UdpPacket, p *noise.Packet, peer *Peer) {
	if ok := atomic.CompareAndSwapInt32(&peer.state, noise.STAT_HANDSHAKE, noise.STAT_WORKING); ok {
		peer.hsDone <- struct{}{}
	} else {
		fmt.Println("当前Peer结构的状态不合法。")
	}
}
