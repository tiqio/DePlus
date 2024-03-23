package noise

import (
	"errors"
	"net"
	"sync/atomic"
)

type Pool struct {
	Subnet *net.IPNet
	// 可用地址除了网络的0、本机的1和广播的255，一共有256-3=253种取值。
	pool [253]int32
}

func (p *Pool) Next() (*net.IPNet, error) {
	found := false
	var i int
	for i = 2; i < 255; i += 1 {
		if atomic.CompareAndSwapInt32(&p.pool[i], 0, 1) {
			found = true
			break
		}
	}
	if !found {
		return nil, errors.New("IP池满，找不到空闲的IP地址。")
	}

	tunnelIP := &net.IPNet{
		make([]byte, 4),
		make([]byte, 4),
	}
	copy(tunnelIP.IP, p.Subnet.IP)
	copy(tunnelIP.Mask, p.Subnet.Mask)
	tunnelIP.IP[3] = byte(i)
	return tunnelIP, nil
}

func IP4_uint64(ip net.IP) (i uint64) {
	i = 0
	for _, a := range ip {
		i = (i << 8) + uint64(a)
	}
	return i
}
