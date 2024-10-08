# Тестовое задание на позицию Junior Backend Developer

**Используемые технологии:**

- Go
- JWT
- PostgreSQL

**Задание:**

Написать часть сервиса аутентификации.

Два REST маршрута:

- Первый маршрут выдает пару Access, Refresh токенов для пользователя с идентификатором (GUID) указанным в параметре запроса
- Второй маршрут выполняет Refresh операцию на пару Access, Refresh токенов

**Требования:**

Access токен тип JWT, алгоритм SHA512, хранить в базе строго запрещено.

Refresh токен тип произвольный, формат передачи base64, хранится в базе исключительно в виде bcrypt хеша, должен быть защищен от изменения на стороне клиента и попыток повторного использования.

Access, Refresh токены обоюдно связаны, Refresh операцию для Access токена можно выполнить только тем Refresh токеном который был выдан вместе с ним.

Payload токенов должен содержать сведения об ip адресе клиента, которому он был выдан. В случае, если ip адрес изменился, при рефреш операции нужно послать email warning на почту юзера (для упрощения можно использовать моковые данные).
## Запуск в Docker-Compose
Команда для сборки и запуска из директории приложения:
```bash
docker-compose up --build
```
## Получение Access и Refresh токенов
```bash
curl -X GET http://localhost:8080/token?user_id=GUID
```
Данный запрос в ответ получает Access и Refresh токены. Необходимо отправить GUID пользователя.
## Обновление токенов
```bash
curl -X POST http://localhost:8080/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "access_token": "",
    "refresh_token": ""
  }'
```
Данный запрос обновляет токены. Происходит проверка валидности токенов и в случае успеха обновленные токены возващаются пользователю.
## База данных
При сборке, таблицы импортируются из папки init-scripts. Идёт использование функциональности docker-entrypoint-initdb.d. Эта директория в контейнере PostgreSQL предназначена для скриптов инициализации базы данных.

./.database/postgres/data - по этому пути от корневого каталога проекта будет располагаться том для хранения данных Postgres (персистентность).
