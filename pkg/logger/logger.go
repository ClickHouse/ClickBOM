// Package logger provides a simple logging interface.
package logger

import (
	"fmt"
	"log"
	"os"
)

// Logger is a simple logger with different log levels.
type Logger struct {
	debug bool
}

var defaultLogger *Logger

func init() {
	defaultLogger = &Logger{
		debug: os.Getenv("DEBUG") == "true",
	}
}

// SetDebug enables or disables debug logging.
func SetDebug(debug bool) {
	defaultLogger.debug = debug
}

// Debug logs the message as debug information.
func Debug(format string, args ...interface{}) {
	if defaultLogger.debug {
		msg := fmt.Sprintf(format, args...)
		log.Printf("\033[0;33m[DEBUG]\033[0m %s", msg)
	}
}

// Info logs the message as informational.
func Info(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Printf("\033[0;34m[INFO]\033[0m %s", msg)
}

// Success logs the message as a success.
func Success(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Printf("\033[0;32m[SUCCESS]\033[0m %s", msg)
}

// Warning logs the message as a warning.
func Warning(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Printf("\033[1;33m[WARNING]\033[0m %s", msg)
}

// Error logs the message as an error.
func Error(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Printf("\033[0;31m[ERROR]\033[0m %s", msg)
}

// Fatal logs the message and exits the program.
func Fatal(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Fatalf("\033[0;31m[ERROR]\033[0m %s", msg)
}
