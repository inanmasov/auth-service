package auth

import (
	"auth-service/internal/db"
	"auth-service/pkg/jwt"
	"errors"
	"fmt"
)

// Функция для генерации пары Access и Refresh токенов
func GenerateTokens(userID, ip string) (string, string, error) {
	// Генерация Access токена
	accessToken, err := jwt.GenerateAccessToken(userID, ip)
	if err != nil {
		return "", "", err
	}

	// Генерация Refresh токена
	refreshToken, hashedRefreshToken, err := jwt.GenerateRefreshToken()
	if err != nil {
		return "", "", err
	}

	// Сохраняем хэшированный Refresh токен в базе данных
	err = db.SaveRefreshToken(userID, hashedRefreshToken)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

// Функция для обновления токенов
func RefreshTokens(accessToken, refreshToken, ip string) (string, string, error) {
	// Валидация Access токена
	payload, err := jwt.ValidateAccessToken(accessToken)
	if err != nil {
		return "", "", err
	}

	// Проверка IP
	if payload.IP != ip {
		SendWarningEmail("qwerty@gmail.com", "There was an attempt to log in from another region.")
		return "", "", errors.New("IP address mismatch")
	}

	// Валидация Refresh токена
	if err := db.ValidateRefreshToken(payload.UserID, refreshToken); err != nil {
		return "", "", err
	}

	// Генерация новых токенов
	newAccessToken, newRefreshToken, err := GenerateTokens(payload.UserID, ip)
	if err != nil {
		return "", "", err
	}

	return newAccessToken, newRefreshToken, nil
}

func SendWarningEmail(email, message string) error {
	// В реальной ситуации, здесь будет код для отправки email через SMTP-сервер
	fmt.Printf("Sending email to %s: %s\n", email, message)
	return nil
}
