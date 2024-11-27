package jwt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateAccessTokens(t *testing.T) {
	userID := "test_user"
	ip := "192.168.1.1"

	accessToken, err := GenerateAccessToken(userID, ip)

	assert.NoError(t, err)
	assert.NotEmpty(t, accessToken)
}

func TestGenerateRefreshTokens(t *testing.T) {
	refreshToken, hashedRefreshToken, err := GenerateRefreshToken()

	assert.NoError(t, err)
	assert.NotEmpty(t, refreshToken)
	assert.NotEmpty(t, hashedRefreshToken)
}

func TestValidateAccessToken(t *testing.T) {
	userID := "test_user"
	ip := "192.168.1.1"

	accessToken, err := GenerateAccessToken(userID, ip)

	assert.NoError(t, err)
	assert.NotEmpty(t, accessToken)

	payload, err := ValidateAccessToken(accessToken)

	assert.NoError(t, err)
	assert.NotEmpty(t, payload)
}
