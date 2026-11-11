package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/nhridoy/shetu-server/internal/config"
	"github.com/nhridoy/shetu-server/internal/models"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"gorm.io/gorm"
)

func generatePKCE() (verifier string, challenge string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])
	return
}

func getOAuthConfig(provider string, cfg *config.Config) (*oauth2.Config, error) {
	switch provider {
	case "google":
		if cfg.OAuthGoogleID == "" || cfg.OAuthGoogleSecret == "" {
			return nil, fmt.Errorf("google oauth is not configured on this server")
		}
		return &oauth2.Config{
			ClientID:     cfg.OAuthGoogleID,
			ClientSecret: cfg.OAuthGoogleSecret,
			Endpoint:     google.Endpoint,
			RedirectURL:  cfg.OAuthRedirectBase + "/api/v1/auth/oauth/callback/" + provider,
			Scopes:       []string{"openid", "email", "profile"},
		}, nil
	case "github":
		if cfg.OAuthGitHubID == "" || cfg.OAuthGitHubSecret == "" {
			return nil, fmt.Errorf("github oauth is not configured on this server")
		}
		return &oauth2.Config{
			ClientID:     cfg.OAuthGitHubID,
			ClientSecret: cfg.OAuthGitHubSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://github.com/login/oauth/authorize",
				TokenURL: "https://github.com/login/oauth/access_token",
			},
			RedirectURL: cfg.OAuthRedirectBase + "/api/v1/auth/oauth/callback/" + provider,
			Scopes:      []string{"user:email"},
		}, nil
	default:
		return nil, fmt.Errorf("unknown provider: %s", provider)
	}
}

func isAllowedAppCallback(uri string, cfg *config.Config) bool {
	return slices.Contains(cfg.OAuthRedirectURIs, uri)
}

// oauthTargetURL builds the final redirect back into the client. Every
// destination carries a `dest` query param consumed by the loopback
// listener / deep link handler: setup | success | error.
func oauthTargetURL(state *models.OAuthState, cfg *config.Config, dest string, params url.Values) string {
	base := cfg.AppScheme + "://auth/" + dest
	if state != nil && state.RedirectURI != "" {
		base = state.RedirectURI
	}

	q := url.Values{}
	for k, vals := range params {
		for _, v := range vals {
			q.Add(k, v)
		}
	}
	q.Set("dest", dest)
	return base + "?" + q.Encode()
}

type userInfo struct {
	Email       string
	Name        string
	AvatarURL   string
	ProviderSub string
}

func fetchGoogleUserInfo(token *oauth2.Token) (*userInfo, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("google userinfo returned %d", resp.StatusCode)
	}

	var raw struct {
		Email   string `json:"email"`
		Name    string `json:"name"`
		Picture string `json:"picture"`
		ID      string `json:"id"`
	}
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	return &userInfo{
		Email:       raw.Email,
		Name:        raw.Name,
		AvatarURL:   raw.Picture,
		ProviderSub: raw.ID,
	}, nil
}

type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

func fetchGitHubEmails(client *http.Client, token *oauth2.Token, apiBase string) (string, error) {
	req, err := http.NewRequest("GET", apiBase+"/user/emails", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github emails returned %d", resp.StatusCode)
	}

	var emails []githubEmail
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &emails); err != nil {
		return "", err
	}

	// Prefer primary; fall back to any verified, then any at all.
	for _, e := range emails {
		if e.Primary && e.Verified && e.Email != "" {
			return e.Email, nil
		}
	}
	for _, e := range emails {
		if e.Verified && e.Email != "" {
			return e.Email, nil
		}
	}
	for _, e := range emails {
		if e.Email != "" {
			return e.Email, nil
		}
	}
	return "", fmt.Errorf("github user has no email")
}

func fetchGitHubUserInfo(token *oauth2.Token, apiBase string) (*userInfo, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", apiBase+"/user", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github user returned %d", resp.StatusCode)
	}

	var raw struct {
		Name      string `json:"name"`
		Email     string `json:"email"`
		AvatarURL string `json:"avatar_url"`
		ID        int64  `json:"id"`
	}
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}

	email := raw.Email
	if email == "" {
		// Hidden-email accounts: /user returns null, but /user/emails
		// still lists the primary address. Without this, two such
		// accounts violate the unique email index and break signup.
		email, err = fetchGitHubEmails(client, token, apiBase)
		if err != nil {
			return nil, err
		}
	}

	return &userInfo{
		Email:       email,
		Name:        raw.Name,
		AvatarURL:   raw.AvatarURL,
		ProviderSub: fmt.Sprintf("%d", raw.ID),
	}, nil
}

var (
	errOAuthLinkFailed       = errors.New("oauth link failed")
	errOAuthUserCreateFailed = errors.New("oauth user create failed")
	errOAuthVaultSeedFailed  = errors.New("oauth vault seed failed")
)

// linkOrCreateOAuthUser links an existing account to an OAuth provider or
// creates a new user when no matching account exists, and returns it. OAuth
// users are exempt from email verification: the provider has already
// confirmed the address, so EmailVerifiedAt is set on both paths. The
// returned error distinguishes the failure stage so the handler can pick the
// right redirect reason.
func linkOrCreateOAuthUser(db *gorm.DB, provider string, ui *userInfo) (models.User, error) {
	providerSub := ui.ProviderSub
	var user models.User
	found := db.Where("auth_provider = ? AND provider_sub = ?", provider, providerSub).First(&user).Error == nil

	if !found {
		if db.Where("email = ?", ui.Email).First(&user).Error == nil {
			user.AuthProvider = provider
			user.ProviderSub = &providerSub
			now := time.Now()
			user.EmailVerifiedAt = &now
			if err := db.Save(&user).Error; err != nil {
				return user, errOAuthLinkFailed
			}
		} else {
			now := time.Now()
			user = models.User{
				ID:              uuid.New(),
				Email:           ui.Email,
				FullName:        ui.Name,
				AuthProvider:    provider,
				ProviderSub:     &providerSub,
				EmailVerifiedAt: &now,
				Initialized:     false,
				CreatedAt:       now,
				UpdatedAt:       now,
			}
			if err := db.Create(&user).Error; err != nil {
				return user, errOAuthUserCreateFailed
			}
			if err := models.SeedPersonalVault(db, user.ID); err != nil {
				return user, errOAuthVaultSeedFailed
			}
		}
	}
	return user, nil
}

func HandleOAuthStart(db *gorm.DB, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		provider := c.Param("provider")
		oauthCfg, err := getOAuthConfig(provider, cfg)
		if err != nil {
			if strings.Contains(err.Error(), "not configured") {
				Error(c, http.StatusBadRequest, "PROVIDER_NOT_CONFIGURED", err.Error())
				return
			}
			Error(c, http.StatusBadRequest, "INVALID_PROVIDER", "unsupported OAuth provider")
			return
		}

		appCallback := c.Query("app_callback")
		if appCallback != "" && !isAllowedAppCallback(appCallback, cfg) {
			Error(c, http.StatusBadRequest, "INVALID_CALLBACK", "unregistered redirect URI")
			return
		}

		verifier, challenge, err := generatePKCE()
		if err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to generate PKCE")
			return
		}

		state, err := randBytes(32)
		if err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to generate OAuth state")
			return
		}
		deviceID := c.Query("device_id")
		if deviceID == "" {
			deviceID = "default"
		}

		oauthState := models.OAuthState{
			State:        state,
			Provider:     provider,
			CodeVerifier: verifier,
			DeviceID:     deviceID,
			RedirectURI:  appCallback,
			ExpiresAt:    time.Now().Add(10 * time.Minute),
		}
		if err := db.Create(&oauthState).Error; err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to store OAuth state")
			return
		}

		authURL := oauthCfg.AuthCodeURL(state,
			oauth2.SetAuthURLParam("code_challenge", challenge),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		)

		if c.Query("format") == "json" {
			Success(c, http.StatusOK, gin.H{"auth_url": authURL})
			return
		}

		c.Redirect(http.StatusFound, authURL)
	}
}

func HandleOAuthCallback(db *gorm.DB, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		provider := c.Param("provider")
		code := c.Query("code")
		state := c.Query("state")

		var oauthState models.OAuthState
		stateFound := false
		if state != "" {
			stateFound = db.Where("state = ?", state).First(&oauthState).Error == nil
		}

		// Provider-side error or a malformed callback (e.g. the user pressed
		// Cancel on the consent page and the provider redirected with
		// error=access_denied). When the state row is known it is routed back
		// to the waiting client — the loopback listener — so the app shows the
		// failure immediately instead of hanging until the timeout.
		if code == "" {
			message := "provider_error"
			if providerErr := c.Query("error"); providerErr != "" {
				message = providerErr
			}
			if stateFound {
				now := time.Now()
				db.Model(&oauthState).Update("used_at", &now)
				c.Redirect(http.StatusFound, oauthTargetURL(&oauthState, cfg, "error", url.Values{"message": []string{message}}))
			} else {
				c.Redirect(http.StatusFound, oauthTargetURL(nil, cfg, "error", url.Values{"message": []string{"missing_code_or_state"}}))
			}
			return
		}

		if state == "" {
			c.Redirect(http.StatusFound, oauthTargetURL(nil, cfg, "error", url.Values{"message": []string{"missing_code_or_state"}}))
			return
		}

		if !stateFound {
			c.Redirect(http.StatusFound, oauthTargetURL(nil, cfg, "error", url.Values{"message": []string{"invalid_state"}}))
			return
		}

		if oauthState.UsedAt != nil {
			c.Redirect(http.StatusFound, oauthTargetURL(&oauthState, cfg, "error", url.Values{"message": []string{"state_already_used"}}))
			return
		}

		if time.Now().After(oauthState.ExpiresAt) {
			c.Redirect(http.StatusFound, oauthTargetURL(&oauthState, cfg, "error", url.Values{"message": []string{"state_expired"}}))
			return
		}

		now := time.Now()
		db.Model(&oauthState).Update("used_at", &now)

		oauthCfg, err := getOAuthConfig(provider, cfg)
		if err != nil {
			c.Redirect(http.StatusFound, oauthTargetURL(&oauthState, cfg, "error", url.Values{"message": []string{"invalid_provider"}}))
			return
		}

		token, err := oauthCfg.Exchange(c.Request.Context(), code,
			oauth2.SetAuthURLParam("code_verifier", oauthState.CodeVerifier),
		)
		if err != nil {
			c.Redirect(http.StatusFound, oauthTargetURL(&oauthState, cfg, "error", url.Values{"message": []string{"token_exchange_failed"}}))
			return
		}

		var ui *userInfo
		switch provider {
		case "google":
			ui, err = fetchGoogleUserInfo(token)
		case "github":
			ui, err = fetchGitHubUserInfo(token, "https://api.github.com")
		default:
			c.Redirect(http.StatusFound, oauthTargetURL(&oauthState, cfg, "error", url.Values{"message": []string{"unsupported_provider"}}))
			return
		}
		if err != nil {
			c.Redirect(http.StatusFound, oauthTargetURL(&oauthState, cfg, "error", url.Values{"message": []string{"userinfo_failed"}}))
			return
		}

		user, err := linkOrCreateOAuthUser(db, provider, ui)
		if err != nil {
			message := "link_failed"
			switch {
			case errors.Is(err, errOAuthUserCreateFailed):
				message = "create_user_failed"
			case errors.Is(err, errOAuthVaultSeedFailed):
				message = "vault_seed_failed"
			}
			c.Redirect(http.StatusFound, oauthTargetURL(&oauthState, cfg, "error", url.Values{"message": []string{message}}))
			return
		}

		if !user.Initialized {
			setupCode, err := randBytes(32)
			if err != nil {
				c.Redirect(http.StatusFound, oauthTargetURL(&oauthState, cfg, "error", url.Values{"message": []string{"setup_code_failed"}}))
				return
			}
			setupCodeHash := hashToken(setupCode)
			ac := models.AuthCode{
				CodeHash:  setupCodeHash,
				Purpose:   "oauth_setup",
				UserID:    user.ID,
				DeviceID:  oauthState.DeviceID,
				ExpiresAt: time.Now().Add(15 * time.Minute),
			}
			if err := db.Create(&ac).Error; err != nil {
				c.Redirect(http.StatusFound, oauthTargetURL(&oauthState, cfg, "error", url.Values{"message": []string{"setup_code_failed"}}))
				return
			}
			c.Redirect(http.StatusFound, oauthTargetURL(&oauthState, cfg, "setup", url.Values{
				"setup_code": []string{setupCode},
				"user_id":    []string{user.ID.String()},
			}))
			return
		}

		rt, err := createRefreshToken(db, user.ID, oauthState.DeviceID, cfg)
		if err != nil {
			c.Redirect(http.StatusFound, oauthTargetURL(&oauthState, cfg, "error", url.Values{"message": []string{"token_generation_failed"}}))
			return
		}

		at, err := GenerateAccessToken(user.ID, oauthState.DeviceID, cfg)
		if err != nil {
			c.Redirect(http.StatusFound, oauthTargetURL(&oauthState, cfg, "error", url.Values{"message": []string{"token_generation_failed"}}))
			return
		}

		c.Redirect(http.StatusFound, oauthTargetURL(&oauthState, cfg, "success", url.Values{
			"access_token":  []string{at},
			"refresh_token": []string{rt},
			"user_id":       []string{user.ID.String()},
		}))
	}
}

type oauthExchangeRequest struct {
	SetupCode string `json:"setup_code" binding:"required"`
	UserID    string `json:"user_id" binding:"required"`
}

func HandleOAuthExchange(db *gorm.DB, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req oauthExchangeRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "setup_code and user_id are required")
			return
		}

		userID, err := uuid.Parse(req.UserID)
		if err != nil {
			Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "invalid user_id")
			return
		}

		codeHash := hashToken(req.SetupCode)

		var ac models.AuthCode
		if db.Where("code_hash = ? AND purpose = ?", codeHash, "oauth_setup").First(&ac).Error != nil {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid or expired setup code")
			return
		}

		if ac.UsedAt != nil {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "setup code already used")
			return
		}

		if time.Now().After(ac.ExpiresAt) {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "setup code expired")
			return
		}

		if ac.UserID != userID {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "setup code does not match user")
			return
		}

		now := time.Now()
		db.Model(&ac).Update("used_at", &now)

		var user models.User
		if db.Where("id = ?", userID).First(&user).Error != nil {
			Error(c, http.StatusNotFound, "NOT_FOUND", "user not found")
			return
		}

		rt, err := createRefreshToken(db, userID, ac.DeviceID, cfg)
		if err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create refresh token")
			return
		}

		at, err := GenerateAccessToken(userID, ac.DeviceID, cfg)
		if err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to generate tokens")
			return
		}

		Success(c, http.StatusOK, gin.H{
			"access_token":  at,
			"refresh_token": rt,
			"user":          user,
			"initialized":   user.Initialized,
		})
	}
}

type oauthSetupRequest struct {
	SetupToken   string         `json:"setup_token" binding:"required"`
	AuthVerifier string         `json:"auth_verifier" binding:"required"`
	RecoveryCode string         `json:"recovery_code"`
	PublicKey    string         `json:"public_key"`
	Keyring      keyringPayload `json:"keyring"`
	KDF          kdfParams      `json:"kdf"`
	ServerSalt   string         `json:"server_salt" binding:"required"`
	SaltCL       string         `json:"salt_cl" binding:"required"`
}

func HandleOAuthSetup(db *gorm.DB, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req oauthSetupRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "setup_token, auth_verifier, server_salt, and salt_cl are required")
			return
		}

		codeHash := hashToken(req.SetupToken)

		var ac models.AuthCode
		if db.Where("code_hash = ? AND purpose = ?", codeHash, "oauth_setup").First(&ac).Error != nil {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid or expired setup token")
			return
		}

		if ac.UsedAt != nil {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "setup token already used")
			return
		}

		if time.Now().After(ac.ExpiresAt) {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "setup token expired")
			return
		}

		var user models.User
		if db.Where("id = ?", ac.UserID).First(&user).Error != nil {
			Error(c, http.StatusNotFound, "NOT_FOUND", "user not found")
			return
		}

		if user.Initialized {
			Error(c, http.StatusConflict, "ALREADY_INITIALIZED", "user already initialized")
			return
		}

		if !validKDF(req.KDF) {
			Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "invalid kdf parameters")
			return
		}

		var recoveryHash *string
		if req.RecoveryCode != "" {
			codeBytes, err := base64.RawStdEncoding.DecodeString(req.RecoveryCode)
			if err != nil {
				Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "invalid recovery_code encoding")
				return
			}
			codeHashb := sha256.Sum256(codeBytes)
			hash := base64.RawStdEncoding.EncodeToString(codeHashb[:])
			recoveryHash = &hash
		}

		var publicKey *string
		if req.PublicKey != "" {
			publicKey = &req.PublicKey
		}

		now := time.Now()
		db.Model(&ac).Update("used_at", &now)

		user.AuthVerifier = &req.AuthVerifier
		user.AuthSalt = &req.ServerSalt
		user.SaltCL = &req.SaltCL
		user.KDFM = req.KDF.M
		user.KDFT = req.KDF.T
		user.KDFP = req.KDF.P
		user.PublicKey = publicKey
		user.RecoveryHash = recoveryHash
		user.Initialized = true
		user.UpdatedAt = now
		if err := db.Save(&user).Error; err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to update user")
			return
		}

		clearLoginNonces(db, user.Email)

		if err := seedKeyring(db, user.ID, req.Keyring); err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to store keyring")
			return
		}

		rt, err := createRefreshToken(db, user.ID, ac.DeviceID, cfg)
		if err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create refresh token")
			return
		}

		at, err := GenerateAccessToken(user.ID, ac.DeviceID, cfg)
		if err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to generate tokens")
			return
		}

		Success(c, http.StatusOK, gin.H{
			"access_token":  at,
			"refresh_token": rt,
			"user":          user,
		})
	}
}

// HandleKeyring returns the wrapped keyring + salt for an already-authenticated
// device, so unlock can re-derive the KEK without a login proof.
func HandleKeyring(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, exists := c.Get("user_id")
		if !exists {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "missing user context")
			return
		}

		var user models.User
		if db.Where("id = ?", userID).First(&user).Error != nil {
			Error(c, http.StatusNotFound, "NOT_FOUND", "user not found")
			return
		}

		keyring := fetchKeyring(db, user.ID)
		Success(c, http.StatusOK, gin.H{
			"keyring": keyring,
			"salt_cl": deref(user.SaltCL),
		})
	}
}
