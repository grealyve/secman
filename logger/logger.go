package logger

import (
	"io"
	logging "log"
	"os"

	"github.com/sirupsen/logrus"
)

var (
	Log       *logrus.Logger // share will all packages
)

func init() {
	// The file needs to exist prior
	f, err := os.OpenFile("secman.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)

	if err != nil {
		logging.Fatalf("error opening file: %v", err)
	}

	Log = logrus.New()

	Log.Formatter = &logrus.TextFormatter{}
	Log.SetReportCaller(true)
	mw := io.MultiWriter(os.Stdout, f)
	Log.SetOutput(mw)
}