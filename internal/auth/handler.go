package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func TokenHandler(c *gin.Context) {
	userID := c.Query("user_id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing user_id"})
		return
	}
	// Получение ip-адреса
	ip := c.ClientIP()

	// Генерация токенов
	accessToken, refreshToken, err := GenerateTokens(userID, ip)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error generating tokens"})
		return
	}

	response := gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	}

	c.JSON(http.StatusOK, response)
}

func RefreshHandler(c *gin.Context) {
	var requestBody struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}

	// Парсинг тела запроса
	if err := c.BindJSON(&requestBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	// Получение ip-адреса
	ip := c.ClientIP()

	// Обновление пары токенов
	newAccessToken, newRefreshToken, err := RefreshTokens(requestBody.AccessToken, requestBody.RefreshToken, ip)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	response := gin.H{
		"access_token":  newAccessToken,
		"refresh_token": newRefreshToken,
	}

	c.JSON(http.StatusOK, response)
}
