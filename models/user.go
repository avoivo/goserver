package models

// User model
type User struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	IsAdmin  bool   `json:"isAdmin"`
	IsActive bool   `json:"isActive"`
}
