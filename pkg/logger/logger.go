package logger

import (
    "fmt"
    "log"
    "os"
)

type Logger struct {
    debug bool
}

var defaultLogger *Logger

func init() {
    defaultLogger = &Logger{
        debug: os.Getenv("DEBUG") == "true",
    }
}

func SetDebug(debug bool) {
    defaultLogger.debug = debug
}

func Debug(format string, args ...interface{}) {
    if defaultLogger.debug {
        msg := fmt.Sprintf(format, args...)
        log.Printf("\033[0;33m[DEBUG]\033[0m %s", msg)
    }
}

func Info(format string, args ...interface{}) {
    msg := fmt.Sprintf(format, args...)
    log.Printf("\033[0;34m[INFO]\033[0m %s", msg)
}

func Success(format string, args ...interface{}) {
    msg := fmt.Sprintf(format, args...)
    log.Printf("\033[0;32m[SUCCESS]\033[0m %s", msg)
}

func Warning(format string, args ...interface{}) {
    msg := fmt.Sprintf(format, args...)
    log.Printf("\033[1;33m[WARNING]\033[0m %s", msg)
}

func Error(format string, args ...interface{}) {
    msg := fmt.Sprintf(format, args...)
    log.Printf("\033[0;31m[ERROR]\033[0m %s", msg)
}

func Fatal(format string, args ...interface{}) {
    msg := fmt.Sprintf(format, args...)
    log.Fatalf("\033[0;31m[ERROR]\033[0m %s", msg)
}
