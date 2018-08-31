package main

import (
	"fmt"
	"log"
	"os"
)

type Log struct {
	Logger *log.Logger
}

func (l *Log) Info(msg string, int ...interface{}) {
	fmt.Printf(msg, int...)
	l.Logger.Printf(msg, int...)
}

func (l *Log) Error(err error, msg string, int ...interface{}) {
	fmt.Errorf(msg, int...)
	l.Logger.Fatal(err)
}

func Warn(msg string, int ...interface{}) {
	fmt.Printf("[WARNING] "+msg, int...)
	log.Logger.Printf("[WARNING] "+msg, int)
}

func createLogger(autosignConfig AutosignConfig) *Log {
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
		l := Log{}
		l.Logger = logger
		return &l
	}
	return nil
}
