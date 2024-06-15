package auth

type User struct {
	Username  string `json:"username"`
	AvatarUrl string `json:"avatarUrl"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	Admin     bool   `json:"admin"`
}
