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
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// Token configuration
const (
	tokenIssuer        = "ecommerce-platform"
	accessTokenExpiry  = 15 * time.Minute
	refreshTokenExpiry = 7 * 24 * time.Hour
	bcryptCost         = bcrypt.DefaultCost
)

// RSA key size for token signing
const rsaKeyBits = 2048

var (
	// In production, load PEM-encoded keys from secure secrets manager.
	// These ephemeral keys are generated at startup for demo purposes only.
	accessPrivateKey  *rsa.PrivateKey
	refreshPrivateKey *rsa.PrivateKey
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
	TokenType    string `json:"token_type"`
}

// UserStore manages user persistence with thread-safe access
type UserStore struct {
	mu        sync.RWMutex
	byEmail   map[string]*User
	byID      map[string]*User
}

// TokenService handles all JWT operations using RS256 (RSA + SHA-256)
type TokenService struct {
	accessKey     *rsa.PrivateKey
	refreshKey    *rsa.PrivateKey
	accessExpiry  time.Duration
	refreshExpiry time.Duration
	issuer        string
}

// AuthHandler ties together user storage and token operations
type AuthHandler struct {
	users  *UserStore
	tokens *TokenService
}

// NewUserStore creates an initialized UserStore
func NewUserStore() *UserStore {
	return &UserStore{
		byEmail: make(map[string]*User),
		byID:    make(map[string]*User),
	}
}

// Add registers a user in both lookup maps
func (s *UserStore) Add(u *User) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byEmail[u.Email] = u
	s.byID[u.ID] = u
}

// FindByEmail looks up a user by email
func (s *UserStore) FindByEmail(email string) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.byEmail[email]
	return u, ok
}

// FindByID looks up a user by ID
func (s *UserStore) FindByID(id string) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.byID[id]
	return u, ok
}

// UpdateLastLogin records the current time as the user's last login
func (s *UserStore) UpdateLastLogin(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.byID[id]; ok {
		u.LastLogin = time.Now()
	}
}

// NewTokenService creates a TokenService with the given RSA key pairs and durations
func NewTokenService(accessKey, refreshKey *rsa.PrivateKey, accessExp, refreshExp time.Duration, issuer string) *TokenService {
	return &TokenService{
		accessKey:     accessKey,
		refreshKey:    refreshKey,
		accessExpiry:  accessExp,
		refreshExpiry: refreshExp,
		issuer:        issuer,
	}
}

// Issue creates a new access/refresh token pair for the given user
func (ts *TokenService) Issue(user *User) (*TokenPair, error) {
	now := time.Now()

	accessString, err := ts.signToken(user, ts.accessKey, now, ts.accessExpiry, true)
	if err != nil {
		return nil, fmt.Errorf("signing access token: %w", err)
	}

	refreshString, err := ts.signToken(user, ts.refreshKey, now, ts.refreshExpiry, false)
	if err != nil {
		return nil, fmt.Errorf("signing refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessString,
		RefreshToken: refreshString,
		ExpiresIn:    int64(ts.accessExpiry.Seconds()),
		TokenType:    "Bearer",
	}, nil
}

// signToken builds and signs a single JWT using RS256
func (ts *TokenService) signToken(user *User, key *rsa.PrivateKey, now time.Time, expiry time.Duration, includeProfile bool) (string, error) {
	claims := &Claims{
		UserID: user.ID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(expiry)),
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    ts.issuer,
		},
	}
	if includeProfile {
		claims.Email = user.Email
		claims.Roles = user.Roles
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(key)
}

// ValidateAccess parses and validates an access token string
func (ts *TokenService) ValidateAccess(tokenString string) (*Claims, error) {
	return ts.parseToken(tokenString, &ts.accessKey.PublicKey)
}

// ValidateRefresh parses and validates a refresh token string
func (ts *TokenService) ValidateRefresh(tokenString string) (*Claims, error) {
	return ts.parseToken(tokenString, &ts.refreshKey.PublicKey)
}

// parseToken is the shared RS256 parsing logic for both token types
func (ts *TokenService) parseToken(tokenString string, key *rsa.PublicKey) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return key, nil
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

// PublicAccessKey returns the public key for external access token verification
func (ts *TokenService) PublicAccessKey() *rsa.PublicKey {
	return &ts.accessKey.PublicKey
}

// --- Package-level default instance (keeps existing routes working) ---

var defaultHandler *AuthHandler

func init() {
	// Generate ephemeral RSA key pairs for demo.
	// In production, load PEM-encoded keys from a secrets manager.
	var err error
	accessPrivateKey, err = rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		panic(fmt.Sprintf("failed to generate access RSA key: %v", err))
	}
	refreshPrivateKey, err = rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		panic(fmt.Sprintf("failed to generate refresh RSA key: %v", err))
	}

	store := NewUserStore()
	svc := NewTokenService(accessPrivateKey, refreshPrivateKey, accessTokenExpiry, refreshTokenExpiry, tokenIssuer)

	// Seed demo user
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("demo123"), bcryptCost)
	store.Add(&User{
		ID:           "user-demo-001",
		Email:        "demo@example.com",
		PasswordHash: string(hashedPassword),
		Roles:        []string{"user"},
		CreatedAt:    time.Now(),
	})

	defaultHandler = &AuthHandler{users: store, tokens: svc}
}

// --- HTTP Handlers ---

// Login authenticates a user and returns a token pair
func Login(c *gin.Context) { defaultHandler.HandleLogin(c) }

// RefreshToken generates a new token pair using a valid refresh token
func RefreshToken(c *gin.Context) { defaultHandler.HandleRefresh(c) }

// VerifyToken validates an access token from the Authorization header
func VerifyToken(c *gin.Context) { defaultHandler.HandleVerify(c) }

// HandleLogin authenticates credentials and issues tokens
func (h *AuthHandler) HandleLogin(c *gin.Context) {
	var req struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	user, exists := h.users.FindByEmail(req.Email)
	if !exists {
		// Constant-time comparison to prevent timing attacks
		bcrypt.CompareHashAndPassword([]byte("$2a$10$dummy"), []byte(req.Password))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	tokens, err := h.tokens.Issue(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate tokens"})
		return
	}

	h.users.UpdateLastLogin(user.ID)

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

// HandleRefresh validates a refresh token and issues a new token pair
func (h *AuthHandler) HandleRefresh(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Refresh token required"})
		return
	}

	claims, err := h.tokens.ValidateRefresh(req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
		return
	}

	user, exists := h.users.FindByID(claims.UserID)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	tokens, err := h.tokens.Issue(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate tokens"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"tokens": tokens})
}

// HandleVerify validates an access token and returns the embedded claims
func (h *AuthHandler) HandleVerify(c *gin.Context) {
	tokenString, err := extractBearerToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	claims, err := h.tokens.ValidateAccess(tokenString)
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

// extractBearerToken pulls the token string from the Authorization header
func extractBearerToken(c *gin.Context) (string, error) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return "", errors.New("Authorization header required")
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", errors.New("Invalid authorization format")
	}
	return parts[1], nil
}

// GenerateSecureToken creates a cryptographically secure random token
func GenerateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}
