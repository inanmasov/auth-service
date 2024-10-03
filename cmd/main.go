package main

import (
	"auth-service/internal/auth"
	"log"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

func main() {
	viper.AddConfigPath("configs")
	viper.SetConfigName("config")
	if err := viper.ReadInConfig(); err != nil {
		panic(err)
	}

	r := gin.Default()

	r.GET("/token", auth.TokenHandler)
	r.POST("/refresh", auth.RefreshHandler)

	log.Println("server start listening on port", viper.GetString("port"))
	r.Run(":" + viper.GetString("port"))
}
