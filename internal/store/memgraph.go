package store

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type MemgraphStore struct {
	driver neo4j.DriverWithContext
}

func NewMemgraphStore(ctx context.Context, uri string, username string, password string) (*MemgraphStore, error) {
	auth := neo4j.NoAuth()
	if username != "" {
		auth = neo4j.BasicAuth(username, password, "")
	}
	driver, err := neo4j.NewDriverWithContext(uri, auth)
	if err != nil {
		return nil, err
	}
	if err := driver.VerifyConnectivity(ctx); err != nil {
		_ = driver.Close(ctx)
		return nil, err
	}
	return &MemgraphStore{driver: driver}, nil
}

func (s *MemgraphStore) Close(ctx context.Context) error {
	return s.driver.Close(ctx)
}

func (s *MemgraphStore) CreateWallet(ctx context.Context, input WalletInput) (Wallet, error) {
	projectID := strings.TrimSpace(input.ProjectID)
	address := strings.ToLower(strings.TrimSpace(input.Address))
	walletType := strings.TrimSpace(input.WalletType)
	if projectID == "" {
		return Wallet{}, errors.New("projectId is required")
	}
	if address == "" {
		return Wallet{}, errors.New("address is required")
	}
	if walletType == "" {
		walletType = "server"
	}
	now := time.Now().UTC().Format(time.RFC3339)
	session := s.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)
	result, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		rows, err := tx.Run(ctx, `
MERGE (p:GMRVaultProject {id: $projectID})
ON CREATE SET p.createdAt = $now
SET p.updatedAt = $now
CREATE (w:GMRVaultWallet {
  id: $id,
  projectId: $projectID,
  address: $address,
  walletType: $walletType,
  encryptedPrivateKey: $encryptedPrivateKey,
  keyVersion: $keyVersion,
  metadata: $metadata,
  status: "active",
  createdAt: $now,
  updatedAt: $now
})
MERGE (p)-[:HAS_VAULT_WALLET]->(w)
RETURN w.id AS id, w.projectId AS projectId, w.address AS address, w.walletType AS walletType,
  w.status AS status, w.keyVersion AS keyVersion, coalesce(w.metadata, "") AS metadata,
  w.createdAt AS createdAt, w.updatedAt AS updatedAt
`, map[string]any{
			"id":                  uuid.NewString(),
			"projectID":           projectID,
			"address":             address,
			"walletType":          walletType,
			"encryptedPrivateKey": strings.TrimSpace(input.EncryptedPrivateKey),
			"keyVersion":          firstNonEmpty(input.KeyVersion, "v1"),
			"metadata":            strings.TrimSpace(input.Metadata),
			"now":                 now,
		})
		if err != nil {
			return nil, err
		}
		if rows.Next(ctx) {
			return walletFromRecord(rows.Record()), nil
		}
		return nil, rows.Err()
	})
	if err != nil {
		return Wallet{}, err
	}
	return result.(Wallet), nil
}

func (s *MemgraphStore) GetWalletSecret(ctx context.Context, walletID string) (WalletSecret, bool, error) {
	session := s.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)
	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		rows, err := tx.Run(ctx, `
MATCH (w:GMRVaultWallet {id: $walletID})
WHERE coalesce(w.status, "active") = "active"
RETURN w.id AS id, w.projectId AS projectId, w.address AS address, w.walletType AS walletType,
  w.status AS status, w.keyVersion AS keyVersion, coalesce(w.metadata, "") AS metadata,
  w.createdAt AS createdAt, w.updatedAt AS updatedAt, w.encryptedPrivateKey AS encryptedPrivateKey
`, map[string]any{"walletID": strings.TrimSpace(walletID)})
		if err != nil {
			return nil, err
		}
		if rows.Next(ctx) {
			return walletSecretFromRecord(rows.Record()), nil
		}
		return nil, rows.Err()
	})
	if err != nil {
		return WalletSecret{}, false, err
	}
	if result == nil {
		return WalletSecret{}, false, nil
	}
	return result.(WalletSecret), true, nil
}

func (s *MemgraphStore) GetWalletSecretByAddress(ctx context.Context, projectID string, address string) (WalletSecret, bool, error) {
	session := s.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)
	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		rows, err := tx.Run(ctx, `
MATCH (:GMRVaultProject {id: $projectID})-[:HAS_VAULT_WALLET]->(w:GMRVaultWallet {address: $address})
WHERE coalesce(w.status, "active") = "active"
RETURN w.id AS id, w.projectId AS projectId, w.address AS address, w.walletType AS walletType,
  w.status AS status, w.keyVersion AS keyVersion, coalesce(w.metadata, "") AS metadata,
  w.createdAt AS createdAt, w.updatedAt AS updatedAt, w.encryptedPrivateKey AS encryptedPrivateKey
`, map[string]any{"projectID": strings.TrimSpace(projectID), "address": strings.ToLower(strings.TrimSpace(address))})
		if err != nil {
			return nil, err
		}
		if rows.Next(ctx) {
			return walletSecretFromRecord(rows.Record()), nil
		}
		return nil, rows.Err()
	})
	if err != nil {
		return WalletSecret{}, false, err
	}
	if result == nil {
		return WalletSecret{}, false, nil
	}
	return result.(WalletSecret), true, nil
}

func (s *MemgraphStore) ListWallets(ctx context.Context, projectID string, limit int) ([]Wallet, error) {
	if limit <= 0 || limit > 250 {
		limit = 50
	}
	session := s.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)
	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		rows, err := tx.Run(ctx, `
MATCH (:GMRVaultProject {id: $projectID})-[:HAS_VAULT_WALLET]->(w:GMRVaultWallet)
WHERE coalesce(w.status, "active") = "active"
RETURN w.id AS id, w.projectId AS projectId, w.address AS address, w.walletType AS walletType,
  w.status AS status, w.keyVersion AS keyVersion, coalesce(w.metadata, "") AS metadata,
  w.createdAt AS createdAt, w.updatedAt AS updatedAt
ORDER BY w.createdAt DESC
LIMIT $limit
`, map[string]any{"projectID": strings.TrimSpace(projectID), "limit": int64(limit)})
		if err != nil {
			return nil, err
		}
		wallets := []Wallet{}
		for rows.Next(ctx) {
			wallets = append(wallets, walletFromRecord(rows.Record()))
		}
		return wallets, rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return result.([]Wallet), nil
}

func (s *MemgraphStore) CreateAuditLog(ctx context.Context, input AuditInput) error {
	now := time.Now().UTC().Format(time.RFC3339)
	session := s.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)
	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		_, err := tx.Run(ctx, `
CREATE (a:GMRVaultAuditLog {
  id: $id,
  projectId: $projectID,
  walletId: $walletID,
  address: $address,
  action: $action,
  status: $status,
  error: $error,
  ipAddress: $ipAddress,
  userAgent: $userAgent,
  createdAt: $now
})
`, map[string]any{
			"id":        uuid.NewString(),
			"projectID": strings.TrimSpace(input.ProjectID),
			"walletID":  strings.TrimSpace(input.WalletID),
			"address":   strings.ToLower(strings.TrimSpace(input.Address)),
			"action":    strings.TrimSpace(input.Action),
			"status":    firstNonEmpty(input.Status, "success"),
			"error":     strings.TrimSpace(input.Error),
			"ipAddress": strings.TrimSpace(input.IPAddress),
			"userAgent": strings.TrimSpace(input.UserAgent),
			"now":       now,
		})
		return nil, err
	})
	return err
}

func (s *MemgraphStore) ListAuditLogs(ctx context.Context, projectID string, walletID string, limit int) ([]AuditLog, error) {
	if limit <= 0 || limit > 250 {
		limit = 50
	}
	session := s.driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)
	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		rows, err := tx.Run(ctx, `
MATCH (a:GMRVaultAuditLog)
WHERE ($projectID = "" OR a.projectId = $projectID)
  AND ($walletID = "" OR a.walletId = $walletID)
RETURN a.id AS id, coalesce(a.projectId, "") AS projectId, coalesce(a.walletId, "") AS walletId,
  coalesce(a.address, "") AS address, coalesce(a.action, "") AS action, coalesce(a.status, "") AS status,
  coalesce(a.error, "") AS error, coalesce(a.ipAddress, "") AS ipAddress, coalesce(a.userAgent, "") AS userAgent,
  a.createdAt AS createdAt
ORDER BY a.createdAt DESC
LIMIT $limit
`, map[string]any{"projectID": strings.TrimSpace(projectID), "walletID": strings.TrimSpace(walletID), "limit": int64(limit)})
		if err != nil {
			return nil, err
		}
		logs := []AuditLog{}
		for rows.Next(ctx) {
			logs = append(logs, auditLogFromRecord(rows.Record()))
		}
		return logs, rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return result.([]AuditLog), nil
}

func walletFromRecord(record *neo4j.Record) Wallet {
	return Wallet{
		ID:         stringValue(record, "id"),
		ProjectID:  stringValue(record, "projectId"),
		Address:    stringValue(record, "address"),
		WalletType: stringValue(record, "walletType"),
		Status:     stringValue(record, "status"),
		KeyVersion: stringValue(record, "keyVersion"),
		Metadata:   stringValue(record, "metadata"),
		CreatedAt:  stringValue(record, "createdAt"),
		UpdatedAt:  stringValue(record, "updatedAt"),
	}
}

func walletSecretFromRecord(record *neo4j.Record) WalletSecret {
	return WalletSecret{
		Wallet:              walletFromRecord(record),
		EncryptedPrivateKey: stringValue(record, "encryptedPrivateKey"),
	}
}

func auditLogFromRecord(record *neo4j.Record) AuditLog {
	return AuditLog{
		ID:        stringValue(record, "id"),
		ProjectID: stringValue(record, "projectId"),
		WalletID:  stringValue(record, "walletId"),
		Address:   stringValue(record, "address"),
		Action:    stringValue(record, "action"),
		Status:    stringValue(record, "status"),
		Error:     stringValue(record, "error"),
		IPAddress: stringValue(record, "ipAddress"),
		UserAgent: stringValue(record, "userAgent"),
		CreatedAt: stringValue(record, "createdAt"),
	}
}

func stringValue(record *neo4j.Record, key string) string {
	value, ok := record.Get(key)
	if !ok || value == nil {
		return ""
	}
	if str, ok := value.(string); ok {
		return str
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
