package auth

type Role string

const (
	RoleAdmin  Role = "admin"
	RoleMember Role = "member"
	RoleUser   Role = "user"
)

type User struct {
	ID        uint   `json:"id"`
	Username  string `json:"username"`
	AvatarUrl string `json:"avatarUrl"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	Role      Role   `json:"role"`
}
