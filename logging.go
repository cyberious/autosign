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

func createLogger(autosignConfig AutosignConfigFile) *Log {
	fmt.Println("Creating log")
	f, err := os.Create(autosignConfig.LogFile)
	checkError(err)
	writer, err := os.OpenFile(f.Name(), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Errorf("error opening file: %v", err)
	}
	defer f.Close()
	return *Log{log.New(writer, "[autosign]", 1)}
}
