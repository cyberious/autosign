package main

import (
	"encoding/json"
	"fmt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"regexp"
	"path/filepath"
)

const logFile = "puppetlabs-autosign.log"

// AutosignConfig is the struct representation of the config file we should be loading from the file system
// it has 4 parts to it:
// AutosignChallenge string is the challengePassword string to be tested
// AutosignPatterns []string of golang regexp to attempt to match against
// LogFile string of the file to logfile location
// Debug bool whether to increase loglevel to debug
// Logger is a point
type AutosignConfig struct {
	AutosignChallenge string   `json:"challengePassword" yaml:"challengePassword"`
	AutosignPatterns  []string `json:"autosignPatterns" yaml:"autosignPatterns"`
	LogFile           string   `json:"logFile" yaml:"logFile"`
	Debug             bool     `json:"debug" yaml:"debug"`
}

func matchPattern(pattern string, subject string) bool {
	matched, err := regexp.MatchString(pattern, subject)
	if err != nil {
		fmt.Printf("Pattern %s was unable to be read;\n\t%s", pattern, err)
		return false
	}

	return matched
}

func readConfigFile(config string) ([]byte, error) {
	autosign, err := ioutil.ReadFile(filepath.Clean(config))
	if err != nil {
		configFileError := fmt.Errorf("unable to read config file %s", config)
		return []byte{}, configFileError
	}
	return autosign, nil
}

// NewAutosignConfig will load the first config file found and return a new AutosignConfig
func NewAutosignConfig(autoloadConfigFiles []string) (*AutosignConfig, error) {
	t := &AutosignConfig{LogFile: logFile}
	currentConfigFile := pickFile(autoloadConfigFiles)

	if currentConfigFile == "" {
		return t, fmt.Errorf("unable to read file %s", currentConfigFile)
	}

	autosign, err := readConfigFile(currentConfigFile)
	if err != nil {
		fmt.Printf("An error occured reading the config file\n%s", err)
		os.Exit(1)
	}
	fmt.Printf("Parsing config file %s\n", currentConfigFile)

	if matchPattern("/.*.yaml/", currentConfigFile) {
		if err := yaml.Unmarshal(autosign, &t); err != nil {
			return nil, fmt.Errorf("Unable to read config file;\n%s", err)
		}
	}

	if matchPattern(".*.json", currentConfigFile) {
		json.Valid(autosign)
		if err := json.Unmarshal(autosign, &t); err != nil {
			return nil, fmt.Errorf("unable to read config file: %s", err)
		}
	}

	if debug {
		fmt.Printf(
			"Loaded config map of:\n\tPatterns: %s\n\tLogfile: %s\n\tChallenge: %s\n",
			t.AutosignPatterns,
			t.LogFile,
			t.AutosignChallenge)
	}

	return t, nil
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
