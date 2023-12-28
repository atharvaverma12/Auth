package routes

import (
	controller "auth/controllers"
	"auth/middleware"

	"github.com/gin-gonic/gin"
)

func UserRoutes(incomingRoutes *gin.Engine) {
	//firstly authenticate the token
	incomingRoutes.Use(middleware.Authenticate())
	incomingRoutes.GET("/users", controller.GetUsers())
	incomingRoutes.GET("users/:user_id", controller.GetUser())
}
