package noise

import (
	"bytes"
	"encoding/binary"
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

func (p *Packet) Pack() []byte {
	var buf *bytes.Buffer
	switch p.Flag {
	case FLG_HSH | FLG_ACK, FLG_HSH:
		buf = bytes.NewBuffer(make([]byte, 0, p.Size()))
		binary.Write(buf, binary.BigEndian, p.Header)
		buf.Write(p.Payload)
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
	switch p.Flag {
	case FLG_HSH | FLG_ACK, FLG_HSH:
		p.Payload = make([]byte, PAYLOAD_BUFFER)
		buf.Read(p.Payload)
	}
	return p, nil
}
