package main

import (
	"fmt"
	"log"
	"os"
)

type autosignLogger struct {
	*log.Logger
}

// Info logs to both println as well as the log file
func (l *autosignLogger) Info(msg string, int ...interface{}) {
	fmt.Printf("[INFO] "+msg, int...)
	l.Logger.Printf("[INFO] "+msg, int...)
}

// Error logs to both fmt.Errorf as well as the log file with fatal
func (l *autosignLogger) Error(err error, msg string, int ...interface{}) {
	fmt.Printf("[ERROR] "+msg, int...)
	l.Fatal(err)
}

// Warn will log with a ["Warning"] label
func (l *autosignLogger) Warn(msg string, int ...interface{}) {
	fmt.Printf("[WARNING] "+msg, int...)
	l.Printf("[WARNING] "+msg, int)
}

func createLogger(autosignConfig *AutosignConfig) *autosignLogger {
	fmt.Println("Creating log")
	if f, err := os.Create(autosignConfig.LogFile); err != nil {
		fmt.Printf("Unable to create logfile: %s\n", err)
	} else {
		// gosec disabled b/c we need other systems to read this file for log parsing such as splunk, datadog and others
		writer, err := os.OpenFile(f.Name(), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644) // nolint: gosec

		if err != nil {
			fmt.Printf("error opening file: %v", err)
			os.Exit(1)
		}
		defer closeFile(f)
		logger := log.New(writer, "[autosign]", 1)
		l := autosignLogger{}
		l.Logger = logger
		return &l
	}
	return nil
}
