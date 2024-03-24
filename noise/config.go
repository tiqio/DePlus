package noise

import (
	"errors"
	"gopkg.in/gcfg.v1"
)

type ServerConfig struct {
	IP       string
	HttpPort int
	UdpPort  int
	TunnelIP string
}

type ClientConfig struct {
	EndIP       string
	EndHttpPort int
	EndUdpPort  int
	Subnet      string
	OtherSubnet string
}

type Config struct {
	Default struct {
		Mode string
	}
	Server ServerConfig
	Client ClientConfig
}

func ParseConfig(filename string) (interface{}, error) {
	cfg := new(Config)
	err := gcfg.ReadFileInto(cfg, filename)
	switch cfg.Default.Mode {
	case "server":
		return cfg.Server, err
	case "client":
		return cfg.Client, err
	default:
		return nil, errors.New("配置文件模式错误。")
	}
}
