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
	fmt.Errorf("[ERROR] "+msg, int...)
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
		writer, err := os.OpenFile(f.Name(), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			fmt.Errorf("error opening file: %v", err)
		}
		defer f.Close()
		logger := log.New(writer, "[autosign]", 1)
		l := autosignLogger{}
		l.Logger = logger
		return &l
	}
	return nil
}
