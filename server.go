package main

import (
	"fmt"

	"github.com/globocom/husky/analysis"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
)

func main() {

	echoInstance := echo.New()

	echoInstance.Use(middleware.Logger())
	echoInstance.Use(middleware.Recover())
	echoInstance.Use(middleware.RequestID())

	echoInstance.GET("/healthcheck", analysis.HealthCheck)
	echoInstance.GET("/husky/:id", analysis.StatusAnalysis)
	echoInstance.POST("/husky", analysis.ReceiveRequest)
	echoInstance.POST("/securitytest", analysis.CreateNewSecurityTest)
	echoInstance.POST("/repository", analysis.CreateNewRepository)

	echoInstance.Logger.Fatal(echoInstance.Start(":9999"))

}

func FailCI() {
	fmt.Println("Just checking CI!")
}
