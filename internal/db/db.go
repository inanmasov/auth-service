package db

import (
	"database/sql"
	"errors"

	_ "github.com/lib/pq"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
)

// Подключение к базе данных
func Initialize() (*sql.DB, error) {
	viper.AddConfigPath("configs")
	viper.SetConfigName("config")
	if err := viper.ReadInConfig(); err != nil {
		panic(err)
	}

	connect_db := "host=" + viper.GetString("db.host") + " " + "user=" + viper.GetString("db.username") + " " + "port=" + viper.GetString("db.port") + " " + "password=" + viper.GetString("db.password") + " " + "dbname=" + viper.GetString("db.dbname") + " " + "sslmode=" + viper.GetString("db.sslmode")
	db, err := sql.Open("postgres", connect_db)
	if err != nil {
		panic(err)
	}

	if err = db.Ping(); err != nil {
		return nil, err
	}

	return db, nil
}

// Сохранение хэшированного Refresh токена в базе данных
func SaveRefreshToken(user_id, hashedRefreshToken string) error {
	// Подключение к базе данных
	db, err := Initialize()
	if err != nil {
		return errors.New("error saving to database")
	}
	defer db.Close()

	// Если такой user_id уже есть, то обновляем токен
	_, err = db.Exec(`
    	INSERT INTO user_tokens (user_id, token)
    	VALUES ($1, $2)
    	ON CONFLICT (user_id) 
    	DO UPDATE SET token = EXCLUDED.token
	`, user_id, hashedRefreshToken)
	if err != nil {
		return errors.New("error saving to database")
	}

	return nil
}

// Валидация Refresh токена
func ValidateRefreshToken(user_id, refreshToken string) error {
	// Подключение к базе данных
	db, err := Initialize()
	if err != nil {
		return errors.New("error saving to database")
	}
	defer db.Close()

	var hashedToken string

	// Запрос к базе данных
	err = db.QueryRow("SELECT token FROM user_tokens WHERE user_id = $1", user_id).Scan(&hashedToken)
	if err != nil {
		if err == sql.ErrNoRows {
			return errors.New("no token found")
		}
		return errors.New("error querying token")
	}

	// Сравниваем токены
	if err := bcrypt.CompareHashAndPassword([]byte(hashedToken), []byte(refreshToken)); err != nil {
		return errors.New("invalid refresh token")
	}

	return nil
}
