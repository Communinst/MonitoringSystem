package config

import (
	"log"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
	_ "github.com/ilyakaznacheev/cleanenv"
)

type BootCfg struct {
	BPF struct {
		XDPIfaceName string `env:"XDP_IFACE_NAME" env-default:"enp0s3"`
		MaxDnsSize   uint32 `env:"MAX_DNS_SIZE" env-default:"512"`
	}
	HTTPServer struct {
		Address string        `env:"HTTP_ADDRESS" env-default:"localhost:8080"`
		Timeout time.Duration `env:"HTTP_TIMEOUT" env-default:"10s"`
	}
}

func LoadNewBootCfg() (*BootCfg, error) {
	var cfg BootCfg
	if err := cleanenv.ReadEnv(&cfg); err != nil {
		log.Fatalf("Failed to read boot config: %v", err)
		return nil, err
	}

	return &cfg, nil
}
