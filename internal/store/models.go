package store

import "context"

type WalletInput struct {
	ProjectID           string
	WalletType          string
	Address             string
	EncryptedPrivateKey string
	KeyVersion          string
	Metadata            string
}

type Wallet struct {
	ID         string `json:"id"`
	ProjectID  string `json:"projectId"`
	Address    string `json:"address"`
	WalletType string `json:"walletType"`
	Status     string `json:"status"`
	KeyVersion string `json:"keyVersion"`
	Metadata   string `json:"metadata,omitempty"`
	CreatedAt  string `json:"createdAt"`
	UpdatedAt  string `json:"updatedAt"`
}

type WalletSecret struct {
	Wallet
	EncryptedPrivateKey string `json:"-"`
}

type AuditInput struct {
	ProjectID string
	WalletID  string
	Address   string
	Action    string
	Status    string
	Error     string
	IPAddress string
	UserAgent string
}

type AuditLog struct {
	ID        string `json:"id"`
	ProjectID string `json:"projectId"`
	WalletID  string `json:"walletId"`
	Address   string `json:"address"`
	Action    string `json:"action"`
	Status    string `json:"status"`
	Error     string `json:"error,omitempty"`
	IPAddress string `json:"ipAddress,omitempty"`
	UserAgent string `json:"userAgent,omitempty"`
	CreatedAt string `json:"createdAt"`
}

type Store interface {
	Close(ctx context.Context) error
	CreateWallet(ctx context.Context, input WalletInput) (Wallet, error)
	GetWalletSecret(ctx context.Context, walletID string) (WalletSecret, bool, error)
	GetWalletSecretByAddress(ctx context.Context, projectID string, address string) (WalletSecret, bool, error)
	ListWallets(ctx context.Context, projectID string, limit int) ([]Wallet, error)
	CreateAuditLog(ctx context.Context, input AuditInput) error
	ListAuditLogs(ctx context.Context, projectID string, walletID string, limit int) ([]AuditLog, error)
}
