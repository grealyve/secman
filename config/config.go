package config

import (
	"os"

	"github.com/grealyve/secman/logger"
	"gopkg.in/yaml.v3"
)

type Config struct {
	ACUNETIX_IP      string `yaml:"acunetix_ip"`
	ACUNETIX_PORT    int    `yaml:"acunetix_port"`
	ACUNETIX_API_KEY string `yaml:"acunetix_apikey"`
	ZAP_API_KEY      string `yaml:"zap_apikey"`
	SEMGREP_API_KEY  string `yaml:"semgrep_apikey"`
	DB_HOST          string `yaml:"db_host"`
	DB_PORT          string `yaml:"db_port"`
	DB_USER          string `yaml:"db_user"`
	DB_PASSWORD      string `yaml:"db_pass"`
	DB_NAME          string `yaml:"db_name"`
	SSLMode          string `yaml:"db_sslmode"`
	SECRET           string `yaml:"jwt_secret"`
}

var ConfigInstance *Config

func LoadConfig() {
	ConfigInstance = &Config{}
	yamlFile, err := os.ReadFile("config.yaml")
	if err != nil {
		logger.Log.Errorf("Read the config file %v", err)
	}

	err = yaml.Unmarshal(yamlFile, ConfigInstance)
	if err != nil {
		logger.Log.Errorf("Couldn't unmarshal the yaml file %v", err)
	}
}
