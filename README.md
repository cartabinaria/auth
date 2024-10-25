# `auth`

Progetto che permette agli studenti di accedere ai servizi di CartaBinaria
collegando il proprio account Github.

## Usage

Run tool with:

```shell
go run cmd/auth.go
```

Generate swagger.json with:

```shell
swag init -g cmd/auth.go
swag fmt
```

To login, in your browser go to:

```
http://localhost:3000/login?redirect_uri=http://localhost:3000/whoami
```

A cookie named `auth` should be set, and then to logout:

```
http://localhost:3000/logout?redirect_uri=http://localhost:3000/whoami
```
