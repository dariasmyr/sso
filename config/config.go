package config

import (
	"flag"
	"fmt"
	"github.com/ilyakaznacheev/cleanenv"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Env             string        `yaml:"env" env-default:"local"`
	StoragePath     string        `yaml:"storage_path" env-required:"true"`
	GRPC            GRPCConfig    `yaml:"grpc"`
	MigrationsPath  string        `yaml:"migrations_path" env-default:"./migrations"`
	MigrationsTable string        `yaml:"migrations_table" env-default:"migrations"`
	TokenTTL        time.Duration `yaml:"token_ttl" env-default:"1h"`
	RefreshTTL      time.Duration `yaml:"refresh_ttl" env-default:"24h"`
}

type GRPCConfig struct {
	Port    int           `yaml:"port" env:"GRPC_PORT"`
	Timeout time.Duration `yaml:"timeout" env:"GRPC_TIMEOUT"`
}

func MustLoad() *Config {
	configPathFlag := flag.String("config", "", "Path to the config file")
	storagePathFlag := flag.String("storage-path", "", "Path to the storage file")
	migrationsPathFlag := flag.String("migrations-path", "", "Path to the migrations folder")
	migrationsTableFlag := flag.String("migrations-table", "migrations", "Table name for migrations")
	flag.Parse()

	configPath := *configPathFlag
	if configPath == "" {
		configPath = fetchConfigPath() // fallback to default method
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		panic("config file does not exist: " + configPath)
	}

	var cfg Config
	if err := cleanenv.ReadConfig(configPath, &cfg); err != nil {
		panic("error loading config file: " + err.Error())
	}

	if *storagePathFlag != "" {
		cfg.StoragePath = *storagePathFlag
	}
	if *migrationsPathFlag != "" {
		cfg.MigrationsPath = *migrationsPathFlag
	}
	if *migrationsTableFlag != "" {
		cfg.MigrationsTable = *migrationsTableFlag
	}

	if grpcPortEnv := os.Getenv("GRPC_PORT"); grpcPortEnv != "" {
		port, err := strconv.Atoi(grpcPortEnv)
		if err != nil {
			panic("invalid GRPC_PORT value: " + grpcPortEnv)
		}
		cfg.GRPC.Port = port
	}

	if cfg.GRPC.Port == 0 {
		cfg.GRPC.Port = 44044
	}

	return &cfg
}

// fetchConfigPath fetches domain path from environment variable or default if it was not set in command line flag.
// Priority: flag > env > default.
// Default value is empty string.
func fetchConfigPath() string {
	var res string

	res = os.Getenv("CONFIG_PATH")
	if res == "" {
		cwd, _ := os.Getwd()
		fmt.Println("Current working directory:", cwd)
	}

	if res == "" {
		res = "./config/config_local.yaml" // default path
	}

	fmt.Println("Config path:", res)
	return res
}

func MustLoadFromPath(configPath string) *Config {
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		panic("config file does not exist: " + configPath)
	}

	var cfg Config

	if err := cleanenv.ReadConfig(configPath, &cfg); err != nil {
		panic("cannot read config: " + err.Error())
	}

	return &cfg
}
