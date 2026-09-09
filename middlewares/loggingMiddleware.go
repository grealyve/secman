package middlewares

import (
	"net/http/httputil"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/grealyve/secman/logger"
	log "github.com/sirupsen/logrus"
)

// Logs each HTTP Request
func LoggingMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Starting time request
		startTime := time.Now()

		// End Time request
		endTime := time.Now()

		// execution time
		latencyTime := endTime.Sub(startTime)

		// Request method
		reqMethod := ctx.Request.Method

		// Request route
		reqUri := ctx.Request.RequestURI

		// status code
		statusCode := ctx.Writer.Status()

		// Request IP
		clientIP := ctx.ClientIP()

		//Use global logger as middleware logger
		logger.Log.WithFields(log.Fields{
			"METHOD":    reqMethod,
			"URI":       reqUri,
			"STATUS":    statusCode,
			"LATENCY":   latencyTime,
			"CLIENT_IP": clientIP,
		}).Info("HTTP REQUEST")

		requestDump, err := httputil.DumpRequest(ctx.Request, true)
		if err != nil {
			logger.Log.Debugln("Raw requst dump error:", err)
		}
		logger.Log.Debugln(string(requestDump))

		ctx.Next()
	}
}
