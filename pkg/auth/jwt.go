/*
JWT Authentication Module - HUMAN WRITTEN

This module handles all authentication and authorization for the e-commerce platform.
It is maintained exclusively by the security team and undergoes regular security audits.

SECURITY NOTICE: This file is in a restricted zone. AI-assisted modifications are
NOT permitted without explicit security team approval.

Last Security Audit: 2024-01-12
Audit Firm: CyberSecure Partners
*/

package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var (
	// In production, load from secure secrets manager
	jwtSecretKey     = []byte("your-256-bit-secret-key-here-min-32-chars!")
	refreshSecretKey = []byte("your-refresh-secret-key-also-min-32-chars!")

	tokenExpiry   = 15 * time.Minute
	refreshExpiry = 7 * 24 * time.Hour
)

// Claims represents the JWT claims structure
type Claims struct {
	UserID string   `json:"user_id"`
	Email  string   `json:"email"`
	Roles  []string `json:"roles"`
	jwt.RegisteredClaims
}

// User represents a user in the system
type User struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	Roles        []string  `json:"roles"`
	CreatedAt    time.Time `json:"created_at"`
	LastLogin    time.Time `json:"last_login"`
}

// TokenPair contains access and refresh tokens
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

var (
	users     = make(map[string]*User)
	usersByID = make(map[string]*User)
	mu        sync.RWMutex
)

func init() {
	// Seed demo user
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("demo123"), bcrypt.DefaultCost)
	demoUser := &User{
		ID:           "user-demo-001",
		Email:        "demo@example.com",
		PasswordHash: string(hashedPassword),
		Roles:        []string{"user"},
		CreatedAt:    time.Now(),
	}
	users[demoUser.Email] = demoUser
	usersByID[demoUser.ID] = demoUser
}

// Login authenticates a user and returns a token pair
func Login(c *gin.Context) {
	var req struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	mu.RLock()
	user, exists := users[req.Email]
	mu.RUnlock()

	if !exists {
		// Use constant-time comparison to prevent timing attacks
		bcrypt.CompareHashAndPassword([]byte("$2a$10$dummy"), []byte(req.Password))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Generate token pair
	tokens, err := generateTokenPair(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate tokens"})
		return
	}

	// Update last login
	mu.Lock()
	user.LastLogin = time.Now()
	mu.Unlock()

	c.JSON(http.StatusOK, gin.H{
		"message": "Login successful",
		"tokens":  tokens,
		"user": gin.H{
			"id":    user.ID,
			"email": user.Email,
			"roles": user.Roles,
		},
	})
}

// RefreshToken generates a new access token using a valid refresh token
func RefreshToken(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Refresh token required"})
		return
	}

	// Parse and validate refresh token
	token, err := jwt.ParseWithClaims(req.RefreshToken, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return refreshSecretKey, nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
		return
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
		return
	}

	// Get user and generate new tokens
	mu.RLock()
	user, exists := usersByID[claims.UserID]
	mu.RUnlock()

	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	tokens, err := generateTokenPair(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate tokens"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"tokens": tokens})
}

// VerifyToken validates an access token
func VerifyToken(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
		return
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization format"})
		return
	}

	tokenString := parts[1]
	claims, err := validateAccessToken(tokenString)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"valid":   true,
		"user_id": claims.UserID,
		"email":   claims.Email,
		"roles":   claims.Roles,
		"expires": claims.ExpiresAt.Time,
	})
}

// generateTokenPair creates new access and refresh tokens
func generateTokenPair(user *User) (*TokenPair, error) {
	now := time.Now()

	// Access token
	accessClaims := &Claims{
		UserID: user.ID,
		Email:  user.Email,
		Roles:  user.Roles,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(tokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    "ecommerce-platform",
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessString, err := accessToken.SignedString(jwtSecretKey)
	if err != nil {
		return nil, err
	}

	// Refresh token
	refreshClaims := &Claims{
		UserID: user.ID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(refreshExpiry)),
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    "ecommerce-platform",
		},
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshString, err := refreshToken.SignedString(refreshSecretKey)
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessString,
		RefreshToken: refreshString,
		ExpiresIn:    int64(tokenExpiry.Seconds()),
	}, nil
}

// validateAccessToken parses and validates an access token
func validateAccessToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return jwtSecretKey, nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	return claims, nil
}

// GenerateSecureToken creates a cryptographically secure random token
func GenerateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}
