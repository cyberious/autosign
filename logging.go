package main

import (
	"fmt"
	"log"
	"os"
)

func logInfo(msg string, int ...interface{}) {
	fmt.Printf(msg, int...)
	logger.Printf(msg, int...)
}

func logError(err error, msg string, int ...interface{}) {
	fmt.Errorf(msg, int...)
	logger.Fatal(err)
}

func createLogger() {
	fmt.Println("Creating log")
	f, err := os.Create(autosignConfig.LogFile)
	checkError(err)
	writer, err := os.OpenFile(f.Name(), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Errorf("error opening file: %v", err)
	}
	defer f.Close()
	logger = log.New(writer, "[autosign]", 1)
}
