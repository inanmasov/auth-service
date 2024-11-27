package jwt

import (
	"encoding/base64"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var jwtSecret = []byte(os.Getenv("JWT_KEY"))

type Payload struct {
	UserID string `json:"user_id"`
	IP     string `json:"ip"`
	jwt.RegisteredClaims
}

// Генерация JWT Access токена
func GenerateAccessToken(userID, ip string) (string, error) {
	// Устанавлваем жизненный цикл токена
	expirationTime := time.Now().Add(15 * time.Minute)

	// Заполянем Payload токена
	payload := &Payload{
		UserID: userID,
		IP:     ip,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	// Создаем новый токен
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, payload)

	// Подписываем токен
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// Генерация Refresh токена
func GenerateRefreshToken() (string, string, error) {
	// Генерация токена в виде уникальной строки
	refreshToken := uuid.New().String()

	// Кодируем токен в формат base64
	encodedRefreshToken := base64.StdEncoding.EncodeToString([]byte(refreshToken))

	// Хешируем токен для хранения в базе данных
	hashedRefreshToken, err := bcrypt.GenerateFromPassword([]byte(encodedRefreshToken), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}

	return encodedRefreshToken, string(hashedRefreshToken), nil
}

// Валидация JWT Access токена
func ValidateAccessToken(tokenString string) (*Payload, error) {
	payload := &Payload{}
	// Парсинг JWT Access токена
	_, err := jwt.ParseWithClaims(tokenString, payload, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	// Проверка подписи токена
	if err == jwt.ErrSignatureInvalid {
		return nil, fmt.Errorf("invalid token signature")
	}

	return payload, nil
}
