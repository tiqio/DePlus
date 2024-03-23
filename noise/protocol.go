package noise

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

type Header struct {
	Flag byte
	Seq  uint32
	Sid  uint32
}

type Packet struct {
	Header
	Payload []byte
}

type UdpPacket struct {
	// 客户端的UDP地址。
	Addr *net.UDPAddr
	// 客户端传入的数据包。
	Data []byte
}

func (p *Packet) SetSid(sid [4]byte) {
	p.Sid = binary.BigEndian.Uint32(sid[:])
}

func (p *Packet) SetPayload(payload []byte) {
	p.Payload = payload
}

func (p *Packet) Pack(TSend NoiseSymmetricKey) []byte {
	var buf *bytes.Buffer
	buf = bytes.NewBuffer(make([]byte, 0, p.Size()))
	binary.Write(buf, binary.BigEndian, p.Header)

	switch p.Flag {
	case FLG_HSH | FLG_ACK, FLG_HSH:
		buf.Write(p.Payload)
	case FLG_DAT:
		// 需要利用TiSend或着TrSend对数据流进行加密。
		buf.Write(TSend.Encrypt(p.Payload))
	default:
		fmt.Println("要加密的报文的Flag无法受理。")
	}

	return buf.Bytes()
}

func (p *Packet) Size() int {
	return HDR_LEN + len(p.Payload)
}

func UnPack(b []byte) (*Packet, error) {
	p := new(Packet)
	buf := bytes.NewBuffer(b)
	binary.Read(buf, binary.BigEndian, &p.Header)
	p.Payload = make([]byte, UDP_BUFFER-HDR_LEN)
	buf.Read(p.Payload)

	return p, nil
}
