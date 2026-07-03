package httpapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/subtle"
	"strings"
	"time"

	"budol/gmr-vault/internal/config"
	"budol/gmr-vault/internal/store"
	"budol/gmr-vault/internal/vaultcrypto"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
)

const apiKeyHeader = "X-GMR-Vault-Key"

type Server struct {
	cfg   config.Config
	store store.Store
}

func New(cfg config.Config, vaultStore store.Store) *fiber.App {
	server := Server{cfg: cfg, store: vaultStore}
	app := fiber.New(fiber.Config{
		AppName:      "GMR Vault",
		ErrorHandler: errorHandler,
	})
	app.Use(recover.New())
	app.Use(cors.New(cors.Config{
		AllowOriginsFunc: func(origin string) bool {
			return allowedOrigin(cfg.AllowedOrigins, origin)
		},
		AllowHeaders:     "Authorization, Content-Type, X-GMR-Vault-Key",
		AllowMethods:     "GET,POST,OPTIONS",
		AllowCredentials: true,
	}))

	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"ok": true, "service": "gmr-vault"})
	})

	v1 := app.Group("/v1", server.requireInternalAuth)
	v1.Post("/wallets", server.createWallet)
	v1.Get("/wallets", server.listWallets)
	v1.Get("/wallets/:id", server.getWallet)
	v1.Get("/audit-logs", server.auditLogs)
	v1.Post("/sign-message", server.signMessage)
	v1.Post("/sign-digest", server.signDigest)
	v1.Post("/sign-typed-data", server.signTypedData)
	v1.Post("/sign-transaction", server.signTransaction)

	return app
}

func (s Server) requireInternalAuth(c *fiber.Ctx) error {
	key := strings.TrimSpace(c.Get(apiKeyHeader))
	if key == "" {
		auth := strings.TrimSpace(c.Get("Authorization"))
		if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
			key = strings.TrimSpace(auth[7:])
		}
	}
	if subtle.ConstantTimeCompare([]byte(key), []byte(s.cfg.InternalAPIKey)) != 1 {
		return fiber.NewError(fiber.StatusUnauthorized, "invalid vault api key")
	}
	return c.Next()
}

func (s Server) createWallet(c *fiber.Ctx) error {
	var request struct {
		ProjectID  string `json:"projectId"`
		WalletType string `json:"walletType"`
		Metadata   string `json:"metadata"`
	}
	if err := c.BodyParser(&request); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	generated, err := vaultcrypto.Generate(s.cfg.MasterKey)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "failed to generate wallet")
	}
	wallet, err := s.store.CreateWallet(c.Context(), store.WalletInput{
		ProjectID:           request.ProjectID,
		WalletType:          request.WalletType,
		Address:             generated.Address,
		EncryptedPrivateKey: generated.EncryptedPrivateKey,
		KeyVersion:          generated.KeyVersion,
		Metadata:            request.Metadata,
	})
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	s.audit(c, wallet.ProjectID, wallet.ID, wallet.Address, "wallet.create", "success", "")
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"wallet": wallet})
}

func (s Server) listWallets(c *fiber.Ctx) error {
	projectID := strings.TrimSpace(c.Query("projectId"))
	if projectID == "" {
		return fiber.NewError(fiber.StatusBadRequest, "projectId is required")
	}
	wallets, err := s.store.ListWallets(c.Context(), projectID, queryLimit(c))
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "failed to list wallets")
	}
	return c.JSON(fiber.Map{"wallets": wallets})
}

func (s Server) getWallet(c *fiber.Ctx) error {
	wallet, ok, err := s.store.GetWalletSecret(c.Context(), c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "failed to load wallet")
	}
	if !ok {
		return fiber.NewError(fiber.StatusNotFound, "wallet not found")
	}
	return c.JSON(fiber.Map{"wallet": wallet.Wallet})
}

func (s Server) auditLogs(c *fiber.Ctx) error {
	logs, err := s.store.ListAuditLogs(c.Context(), c.Query("projectId"), c.Query("walletId"), queryLimit(c))
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "failed to list audit logs")
	}
	return c.JSON(fiber.Map{"auditLogs": logs})
}

func (s Server) signMessage(c *fiber.Ctx) error {
	var request struct {
		WalletID  string `json:"walletId"`
		ProjectID string `json:"projectId"`
		Address   string `json:"address"`
		Message   string `json:"message"`
		Format    string `json:"format"`
	}
	if err := c.BodyParser(&request); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	wallet, privateKey, err := s.loadSigningKey(c.Context(), request.WalletID, request.ProjectID, request.Address)
	if err != nil {
		return err
	}
	message := []byte(request.Message)
	if strings.EqualFold(strings.TrimSpace(request.Format), "hex") {
		decoded, err := hexutil.Decode(request.Message)
		if err != nil {
			s.audit(c, wallet.ProjectID, wallet.ID, wallet.Address, "sign.message", "failed", "invalid hex message")
			return fiber.NewError(fiber.StatusBadRequest, "invalid hex message")
		}
		message = decoded
	}
	signature, err := vaultcrypto.SignMessage(privateKey, message)
	if err != nil {
		s.audit(c, wallet.ProjectID, wallet.ID, wallet.Address, "sign.message", "failed", err.Error())
		return fiber.NewError(fiber.StatusInternalServerError, "failed to sign message")
	}
	s.audit(c, wallet.ProjectID, wallet.ID, wallet.Address, "sign.message", "success", "")
	return c.JSON(fiber.Map{"wallet": wallet.Wallet, "signature": signature})
}

func (s Server) signDigest(c *fiber.Ctx) error {
	var request struct {
		WalletID  string `json:"walletId"`
		ProjectID string `json:"projectId"`
		Address   string `json:"address"`
		Digest    string `json:"digest"`
	}
	if err := c.BodyParser(&request); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	wallet, privateKey, err := s.loadSigningKey(c.Context(), request.WalletID, request.ProjectID, request.Address)
	if err != nil {
		return err
	}
	digest, err := hexutil.Decode(request.Digest)
	if err != nil || len(digest) != 32 {
		s.audit(c, wallet.ProjectID, wallet.ID, wallet.Address, "sign.digest", "failed", "invalid digest")
		return fiber.NewError(fiber.StatusBadRequest, "digest must be 32-byte hex")
	}
	signature, err := vaultcrypto.SignDigest(privateKey, digest)
	if err != nil {
		s.audit(c, wallet.ProjectID, wallet.ID, wallet.Address, "sign.digest", "failed", err.Error())
		return fiber.NewError(fiber.StatusInternalServerError, "failed to sign digest")
	}
	s.audit(c, wallet.ProjectID, wallet.ID, wallet.Address, "sign.digest", "success", "")
	return c.JSON(fiber.Map{"wallet": wallet.Wallet, "signature": signature})
}

func (s Server) signTypedData(c *fiber.Ctx) error {
	var request struct {
		WalletID  string             `json:"walletId"`
		ProjectID string             `json:"projectId"`
		Address   string             `json:"address"`
		TypedData apitypes.TypedData `json:"typedData"`
	}
	if err := c.BodyParser(&request); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	wallet, privateKey, err := s.loadSigningKey(c.Context(), request.WalletID, request.ProjectID, request.Address)
	if err != nil {
		return err
	}
	signature, err := vaultcrypto.SignTypedData(privateKey, request.TypedData)
	if err != nil {
		s.audit(c, wallet.ProjectID, wallet.ID, wallet.Address, "sign.typed_data", "failed", err.Error())
		return fiber.NewError(fiber.StatusBadRequest, "failed to sign typed data")
	}
	s.audit(c, wallet.ProjectID, wallet.ID, wallet.Address, "sign.typed_data", "success", "")
	return c.JSON(fiber.Map{"wallet": wallet.Wallet, "signature": signature})
}

func (s Server) signTransaction(c *fiber.Ctx) error {
	var request struct {
		WalletID    string                       `json:"walletId"`
		ProjectID   string                       `json:"projectId"`
		Address     string                       `json:"address"`
		Transaction vaultcrypto.TransactionInput `json:"transaction"`
	}
	if err := c.BodyParser(&request); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	wallet, privateKey, err := s.loadSigningKey(c.Context(), request.WalletID, request.ProjectID, request.Address)
	if err != nil {
		return err
	}
	signed, err := vaultcrypto.SignTransaction(privateKey, request.Transaction)
	if err != nil {
		s.audit(c, wallet.ProjectID, wallet.ID, wallet.Address, "sign.transaction", "failed", err.Error())
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	s.audit(c, wallet.ProjectID, wallet.ID, wallet.Address, "sign.transaction", "success", "")
	return c.JSON(fiber.Map{"wallet": wallet.Wallet, "signedTransaction": signed})
}

func (s Server) loadSigningKey(ctx context.Context, walletID string, projectID string, address string) (store.WalletSecret, *ecdsa.PrivateKey, error) {
	var wallet store.WalletSecret
	var ok bool
	var err error
	if strings.TrimSpace(walletID) != "" {
		wallet, ok, err = s.store.GetWalletSecret(ctx, walletID)
	} else {
		if strings.TrimSpace(projectID) == "" || strings.TrimSpace(address) == "" {
			return store.WalletSecret{}, nil, fiber.NewError(fiber.StatusBadRequest, "walletId or projectId/address is required")
		}
		if !common.IsHexAddress(address) {
			return store.WalletSecret{}, nil, fiber.NewError(fiber.StatusBadRequest, "valid address is required")
		}
		wallet, ok, err = s.store.GetWalletSecretByAddress(ctx, projectID, address)
	}
	if err != nil {
		return store.WalletSecret{}, nil, fiber.NewError(fiber.StatusInternalServerError, "failed to load wallet")
	}
	if !ok {
		return store.WalletSecret{}, nil, fiber.NewError(fiber.StatusNotFound, "wallet not found")
	}
	privateKey, err := vaultcrypto.PrivateKeyFromEncrypted(wallet.EncryptedPrivateKey, s.cfg.MasterKey)
	if err != nil {
		return store.WalletSecret{}, nil, fiber.NewError(fiber.StatusInternalServerError, "failed to unlock wallet")
	}
	return wallet, privateKey, nil
}

func (s Server) audit(c *fiber.Ctx, projectID string, walletID string, address string, action string, status string, message string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = s.store.CreateAuditLog(ctx, store.AuditInput{
		ProjectID: projectID,
		WalletID:  walletID,
		Address:   address,
		Action:    action,
		Status:    status,
		Error:     message,
		IPAddress: c.IP(),
		UserAgent: string(c.Context().UserAgent()),
	})
}

func queryLimit(c *fiber.Ctx) int {
	limit := c.QueryInt("limit", 50)
	if limit <= 0 || limit > 250 {
		return 50
	}
	return limit
}

func allowedOrigin(allowed []string, origin string) bool {
	if len(allowed) == 0 || strings.TrimSpace(origin) == "" {
		return true
	}
	for _, value := range allowed {
		if strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(origin)) {
			return true
		}
	}
	return false
}

func errorHandler(c *fiber.Ctx, err error) error {
	code := fiber.StatusInternalServerError
	message := "internal server error"
	if fiberErr, ok := err.(*fiber.Error); ok {
		code = fiberErr.Code
		message = fiberErr.Message
	}
	return c.Status(code).JSON(fiber.Map{"error": message})
}
