package main

import (
	"testing"

	"flag"
	"strconv"
)

// Default value should be false
func Test_isDebug_False(t *testing.T) {
	expect := false
	got := isDebug()
	if expect != got {
		t.Errorf("Expected %s but got %s", strconv.FormatBool(expect), strconv.FormatBool(got))
	}
}

// Should properly set and return isDebug true when set
func Test_isDebug_True(t *testing.T) {
	expect := true
	flag.Lookup("debug").Value.Set(strconv.FormatBool(expect))
	got := isDebug()
	if expect != got {
		t.Errorf("Expected %s but got %s", strconv.FormatBool(expect), strconv.FormatBool(got))
	}
}
