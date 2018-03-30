package config

import (
	"io/ioutil"
	"gopkg.in/yaml.v2"
	"fmt"
	"os"
)

const configFile = "/etc/puppetlabs/puppet/autosign.yaml"
const logFile = "puppetlabs-autosign.log"

type AutosignConfig struct {
	AutosignChallenge string   `yaml:"challengePassword"`
	AutosignPatterns  []string `yaml:"autosignPatterns"`
	LogFile           string   `yaml:"logFile"`
}

func NewAutosignConfig() AutosignConfig {
	t := AutosignConfig{LogFile: logFile}
	configYaml := pickFile(configFile, "autosign.yaml")
	if configYaml != "" {
		autosign, err := ioutil.ReadFile(configYaml)
		yaml.Unmarshal(autosign, &t)
		fmt.Printf("Loaded config map of:\n\tPatterns: %s\n\tLogfile: %s\n\tChallenge: %s\n", t.AutosignPatterns, t.LogFile, t.AutosignChallenge)
		if err != nil {
			if err := yaml.Unmarshal([]byte(autosign), &t); err != nil {
				fmt.Errorf("Unable to read config file;\n%s", err)
			}
		}
	} else {
		fmt.Printf("Unable to read file %s\n", configYaml)
	}
	fmt.Printf("Loaded config file %s, with values %s \n", configYaml, t)
	return t
}

func pickFile(file1 string, file2 string) string {
	if fileExists(file1) {
		return file1
	}
	if fileExists(file2) {
		return file2
	}
	return ""
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
}