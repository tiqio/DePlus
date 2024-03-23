package util

import (
	"bytes"
	"fmt"
	"github.com/songgao/water"
	"os/exec"
)

func NewTun(ip string) (iface *water.Interface, err error) {
	config := water.Config{
		DeviceType: water.TUN,
	}

	iface, err = water.New(config)
	if err != nil {
		fmt.Println("water库创建TUN设备失败:", err)
		return nil, err
	}

	out, err := RunCommand(fmt.Sprintf("sudo ip addr add %s/24 dev %s", ip, iface.Name()))
	if err != nil {
		fmt.Println("标准输出:", out)
		fmt.Println("对TUN设备配置地址失败:", err)
		return nil, err
	}

	out, err = RunCommand(fmt.Sprintf("sudo ip link set dev %s up", iface.Name()))
	if err != nil {
		fmt.Println("标准输出:", out)
		fmt.Println("开启TUN设备失败:", err)
		return nil, err
	}

	return iface, nil
}

func RunCommand(command string) (string, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := exec.Command("bash", "-c", command)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if stderr.String() != "" {
		return stderr.String(), err
	}
	return stdout.String(), err

}
