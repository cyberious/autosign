package main

import (
	"encoding/json"
	"fmt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"os"
	"regexp"
)

const configDefaultLocation = "/etc/puppetlabs/puppet/"
const configFile = "/etc/puppetlabs/puppet/autosign.yaml"
const logFile = "puppetlabs-autosign.log"

type AutosignConfig struct {
	AutosignChallenge string   `json:"challengePassword", yaml:"challengePassword"`
	AutosignPatterns  []string `json:"autosignPatterns", yaml:"autosignPatterns"`
	LogFile           string   `json:"logFile", yaml:"logFile"`
	Debug             bool     `json:"debug", yaml:debug"`
	Logger            *log.Logger
}

func matchPattern(pattern string, subject string) bool {
	matched, err := regexp.MatchString(pattern, subject)
	if err != nil {
		fmt.Errorf("Pattern %s was unable to be read;\n\t%s", pattern, err)
		return false
	} else {
		return matched
	}
}

func readConfigFile(config string) []byte {
	autosign, err := ioutil.ReadFile(config)
	if err != nil {
		fmt.Errorf("Unable to read config file %s\n", config)
	}
	return autosign
}

func NewAutosignConfig(autoloadConfigFiles []string) AutosignConfig {
	t := AutosignConfig{LogFile: logFile}
	currentConfigFile := pickFile(autoloadConfigFiles)

	if currentConfigFile == "" {
		fmt.Printf("Unable to read file %s\n", currentConfigFile)
		return t
	}

	autosign := readConfigFile(currentConfigFile)
	fmt.Printf("Parsing config file %s\n", currentConfigFile)
	if matchPattern("/.*.yaml/", currentConfigFile) {
		if err := yaml.Unmarshal([]byte(autosign), &t); err != nil {
			fmt.Errorf("Unable to read config file;\n%s", err)
		}
	}
	if matchPattern(".*.json", currentConfigFile) {
		json.Valid(autosign)
		if err := json.Unmarshal(autosign, &t); err != nil {
			fmt.Errorf("Unable to read config file;\n%s\n", err)
		}
	}

	fmt.Printf(
		"Loaded config map of:\n\tPatterns: %s\n\tLogfile: %s\n\tChallenge: %s\n",
		t.AutosignPatterns,
		t.LogFile,
		t.AutosignChallenge)

	return t
}

func pickFile(possibleConfigFiles []string) string {
	for _, configFile := range possibleConfigFiles {
		if fileExists(configFile) {
			return configFile
		}
	}
	return ""
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
}
