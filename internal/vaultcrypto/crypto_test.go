package vaultcrypto

import (
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

func TestGenerateEncryptDecryptAndSignMessage(t *testing.T) {
	masterKey := "test-master-key-32-bytes-minimum-value"
	wallet, err := Generate(masterKey)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if !strings.HasPrefix(wallet.EncryptedPrivateKey, "gmr-vault:v1:") {
		t.Fatalf("expected vault encrypted key prefix, got %q", wallet.EncryptedPrivateKey)
	}
	privateKey, err := PrivateKeyFromEncrypted(wallet.EncryptedPrivateKey, masterKey)
	if err != nil {
		t.Fatalf("PrivateKeyFromEncrypted() error = %v", err)
	}
	address := crypto.PubkeyToAddress(privateKey.PublicKey).Hex()
	if !strings.EqualFold(address, wallet.Address) {
		t.Fatalf("decrypted address mismatch: got %s want %s", address, wallet.Address)
	}
	signature, err := SignMessage(privateKey, []byte("hello"))
	if err != nil {
		t.Fatalf("SignMessage() error = %v", err)
	}
	if !strings.HasPrefix(signature, "0x") || len(signature) != 132 {
		t.Fatalf("unexpected signature shape: %s", signature)
	}
}
