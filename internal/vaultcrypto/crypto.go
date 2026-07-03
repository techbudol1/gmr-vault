package vaultcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

type GeneratedWallet struct {
	Address             string
	EncryptedPrivateKey string
	KeyVersion          string
}

func Generate(masterKey string) (GeneratedWallet, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return GeneratedWallet{}, err
	}
	privateKeyBytes := crypto.FromECDSA(privateKey)
	encrypted, err := Encrypt(privateKeyBytes, masterKey)
	if err != nil {
		return GeneratedWallet{}, err
	}
	return GeneratedWallet{
		Address:             crypto.PubkeyToAddress(privateKey.PublicKey).Hex(),
		EncryptedPrivateKey: encrypted,
		KeyVersion:          "v1",
	}, nil
}

func Encrypt(plaintext []byte, masterKey string) (string, error) {
	if len(masterKey) < 32 {
		return "", errors.New("vault master key must be at least 32 characters")
	}
	keyHash := sha256.Sum256([]byte(masterKey))
	block, err := aes.NewCipher(keyHash[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return "gmr-vault:v1:" + base64.RawStdEncoding.EncodeToString(nonce) + ":" + base64.RawStdEncoding.EncodeToString(ciphertext), nil
}

func PrivateKeyFromEncrypted(encrypted string, masterKey string) (*ecdsa.PrivateKey, error) {
	if len(masterKey) < 32 {
		return nil, errors.New("vault master key must be at least 32 characters")
	}
	parts := strings.Split(strings.TrimSpace(encrypted), ":")
	if len(parts) != 4 || parts[0] != "gmr-vault" || parts[1] != "v1" {
		return nil, errors.New("unsupported encrypted wallet format")
	}
	nonce, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return nil, err
	}
	keyHash := sha256.Sum256([]byte(masterKey))
	block, err := aes.NewCipher(keyHash[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return crypto.ToECDSA(plaintext)
}

func SignMessage(privateKey *ecdsa.PrivateKey, message []byte) (string, error) {
	hash := accountsTextHash(message)
	signature, err := crypto.Sign(hash, privateKey)
	if err != nil {
		return "", err
	}
	signature[64] += 27
	return hexutil.Encode(signature), nil
}

func SignDigest(privateKey *ecdsa.PrivateKey, digest []byte) (string, error) {
	if len(digest) != 32 {
		return "", errors.New("digest must be 32 bytes")
	}
	signature, err := crypto.Sign(digest, privateKey)
	if err != nil {
		return "", err
	}
	signature[64] += 27
	return hexutil.Encode(signature), nil
}

func SignTypedData(privateKey *ecdsa.PrivateKey, typedData apitypes.TypedData) (string, error) {
	domainSeparator, err := typedData.HashStruct("EIP712Domain", typedData.Domain.Map())
	if err != nil {
		return "", err
	}
	typedHash, err := typedData.HashStruct(typedData.PrimaryType, typedData.Message)
	if err != nil {
		return "", err
	}
	rawData := []byte{0x19, 0x01}
	rawData = append(rawData, domainSeparator...)
	rawData = append(rawData, typedHash...)
	digest := crypto.Keccak256(rawData)
	return SignDigest(privateKey, digest)
}

type TransactionInput struct {
	ChainID              string `json:"chainId"`
	Nonce                uint64 `json:"nonce"`
	To                   string `json:"to"`
	Value                string `json:"value"`
	Data                 string `json:"data"`
	GasLimit             uint64 `json:"gasLimit"`
	GasPrice             string `json:"gasPrice"`
	MaxFeePerGas         string `json:"maxFeePerGas"`
	MaxPriorityFeePerGas string `json:"maxPriorityFeePerGas"`
}

type SignedTransaction struct {
	RawTransaction  string `json:"rawTransaction"`
	TransactionHash string `json:"transactionHash"`
	From            string `json:"from"`
}

func SignTransaction(privateKey *ecdsa.PrivateKey, input TransactionInput) (SignedTransaction, error) {
	chainID, err := parsePositiveBig(input.ChainID)
	if err != nil {
		return SignedTransaction{}, errors.New("valid chainId is required")
	}
	value := parseBigOrZero(input.Value)
	data, err := hexutil.Decode(emptyHex(input.Data))
	if err != nil {
		return SignedTransaction{}, err
	}
	var tx *types.Transaction
	if strings.TrimSpace(input.MaxFeePerGas) != "" || strings.TrimSpace(input.MaxPriorityFeePerGas) != "" {
		maxFee := parseBigOrZero(input.MaxFeePerGas)
		maxPriority := parseBigOrZero(input.MaxPriorityFeePerGas)
		tx = types.NewTx(&types.DynamicFeeTx{
			ChainID:   chainID,
			Nonce:     input.Nonce,
			GasTipCap: maxPriority,
			GasFeeCap: maxFee,
			Gas:       input.GasLimit,
			To:        optionalTo(input.To),
			Value:     value,
			Data:      data,
		})
	} else {
		tx = types.NewTx(&types.LegacyTx{
			Nonce:    input.Nonce,
			GasPrice: parseBigOrZero(input.GasPrice),
			Gas:      input.GasLimit,
			To:       optionalTo(input.To),
			Value:    value,
			Data:     data,
		})
	}
	signed, err := types.SignTx(tx, types.LatestSignerForChainID(chainID), privateKey)
	if err != nil {
		return SignedTransaction{}, err
	}
	raw, err := signed.MarshalBinary()
	if err != nil {
		return SignedTransaction{}, err
	}
	return SignedTransaction{
		RawTransaction:  hexutil.Encode(raw),
		TransactionHash: signed.Hash().Hex(),
		From:            crypto.PubkeyToAddress(privateKey.PublicKey).Hex(),
	}, nil
}

func accountsTextHash(data []byte) []byte {
	prefix := []byte("\x19Ethereum Signed Message:\n" + new(big.Int).SetInt64(int64(len(data))).String())
	return crypto.Keccak256(append(prefix, data...))
}

func parsePositiveBig(value string) (*big.Int, error) {
	parsed := parseBigOrZero(value)
	if parsed.Sign() <= 0 {
		return nil, errors.New("value must be positive")
	}
	return parsed, nil
}

func parseBigOrZero(value string) *big.Int {
	value = strings.TrimSpace(value)
	if value == "" {
		return big.NewInt(0)
	}
	if strings.HasPrefix(value, "0x") {
		parsed, ok := new(big.Int).SetString(value[2:], 16)
		if ok {
			return parsed
		}
		return big.NewInt(0)
	}
	parsed, ok := new(big.Int).SetString(value, 10)
	if ok {
		return parsed
	}
	return big.NewInt(0)
}

func optionalTo(value string) *common.Address {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	address := common.HexToAddress(value)
	return &address
}

func emptyHex(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "0x"
	}
	if strings.HasPrefix(value, "0x") {
		return value
	}
	_, err := hex.DecodeString(value)
	if err != nil {
		return "0x"
	}
	return "0x" + value
}
