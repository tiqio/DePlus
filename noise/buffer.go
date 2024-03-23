package noise

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

type PacketBuffer struct {
	buf       *bufferList
	rate      int32
	mutex     sync.Mutex
	flushChan chan *Packet
	newPack   chan struct{}
}

func NewPacketBuffer(flushChan chan *Packet) *PacketBuffer {
	hb := new(PacketBuffer)
	hb.buf = newBufferList()
	hb.flushChan = flushChan
	hb.newPack = make(chan struct{}, 9184)
	go func() {
		for {
			p := hb.Pop()
			if p != nil {
				hb.flushChan <- p
			}
		}
	}()
	return hb
}

func (hb *PacketBuffer) Push(p *Packet) {
	atomic.AddInt32(&hb.rate, 1)
	hb.buf.Push(int64(p.Seq), p)
	hb.newPack <- struct{}{}
}

func (hb *PacketBuffer) Pop() *Packet {
	<-hb.newPack
	r := int(hb.rate & 0x10)
	if hb.buf.count < 8+r {
		time.Sleep(time.Duration(r*20+50) * time.Microsecond)
		hb.rate = hb.rate >> 1
	}
	p := hb.buf.Pop().(*Packet)
	return p
}

type bufferElem struct {
	p    interface{}
	key  int64
	next *bufferElem
	prev *bufferElem
}

type bufferList struct {
	count       int
	head        *bufferElem
	mutex       sync.Mutex
	_lastpopped int64
}

func newBufferList() *bufferList {
	l := new(bufferList)
	l.count = 0
	l._lastpopped = -1
	l.head = new(bufferElem)
	l.head.p = nil
	l.head.next = l.head
	l.head.prev = l.head
	return l
}

func (l *bufferList) Push(key int64, p interface{}) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	elem := &bufferElem{p, key, nil, nil}

	uninserted := true
	i := 0
	for cur := l.head.prev; cur != l.head; cur = cur.prev {
		if cur.key < key {
			uninserted = false
			elem.next = cur.next
			elem.prev = cur
			cur.next = elem
			elem.next.prev = elem
			break
		}
		i++
	}

	if uninserted {
		elem.next = l.head.next
		elem.prev = l.head
		l.head.next = elem
		elem.next.prev = elem
	}

	l.count++
}

func (l *bufferList) Pop() interface{} {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	if l.count == 0 {
		fmt.Println("Error")
		return nil
	}

	elem := l.head.next
	l.head.next = elem.next
	elem.next.prev = l.head
	l.count--
	return elem.p
}
