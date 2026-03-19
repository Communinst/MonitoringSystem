package config

import (
	"log"
	"strings"

	"github.com/lpernett/godotenv"
)

func LoadAllEnv() error {
	mainEnv, err := godotenv.Read()
	if err != nil {
		log.Printf("Failed to read .env file: %v", err)
		return err
	}

	var extraEnv []string
	for key, path := range mainEnv {
		if strings.HasSuffix(key, "_ENV") {
			extraEnv = append(extraEnv, path)
		}
	}

	if err := godotenv.Load(extraEnv...); err != nil {
		log.Printf("Warning: some extra .env files could not be loaded: %v", err)
	}

	if err := godotenv.Load(); err != nil {
		log.Printf("Error loading main .env into environment:", err)
	}

	return nil
}
