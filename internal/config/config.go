package config

import (
	"log"

	"github.com/ilyakaznacheev/cleanenv"
	_ "github.com/ilyakaznacheev/cleanenv"
)

type BootCfg struct {
	HookPoint struct {
		HookIfaceName string `env:"HookIfaceName" env-default:"enp0s3"`
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
