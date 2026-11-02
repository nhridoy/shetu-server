package sync

import (
	"encoding/base64"
	"encoding/json"
	"maps"
	"testing"

	"github.com/google/uuid"
)

func encryptedData(table string) string {
	value, _ := json.Marshal(map[string]any{
		"v":     1,
		"alg":   "xchacha20poly1305",
		"nonce": base64.StdEncoding.EncodeToString(make([]byte, 24)),
		"ct":    base64.StdEncoding.EncodeToString(make([]byte, 32)),
		"aad":   base64.StdEncoding.EncodeToString([]byte(table)),
	})
	return string(value)
}

func TestValidateRecordRejectsPlaintextAndUnexpectedFields(t *testing.T) {
	vaultID := uuid.New().String()
	recordID := uuid.New().String()
	deviceID := uuid.New().String()
	operationID := uuid.New().String()
	base := map[string]any{
		"id": recordID, "vault_id": vaultID, "revision": 1,
		"created_at": "2026-09-27T10:20:30.000Z",
		"updated_at": "2026-09-27T10:20:30.000Z",
		"edited_at":  "2026-09-27T10:20:30.000Z",
		"device_id":  deviceID, "operation_id": operationID,
		"name": "Example", "sort_order": 0,
		"data": encryptedData("hosts"),
	}
	if err := validateRecord("hosts", base, vaultID, deviceID, operationID); err != nil {
		t.Fatalf("valid encrypted host rejected: %v", err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"plaintext password": func(v map[string]any) { v["password"] = "secret" },
		"plaintext data":     func(v map[string]any) { v["data"] = `{"password":"secret"}` },
		"wrong aad":          func(v map[string]any) { v["data"] = encryptedData("keys") },
		"foreign vault":      func(v map[string]any) { v["vault_id"] = uuid.New().String() },
		"spoofed device":     func(v map[string]any) { v["device_id"] = uuid.New().String() },
		"noncanonical time":  func(v map[string]any) { v["edited_at"] = "2026-09-27T16:20:30+06:00" },
	} {
		t.Run(name, func(t *testing.T) {
			value := make(map[string]any, len(base))
			maps.Copy(value, base)
			mutate(value)
			if err := validateRecord("hosts", value, vaultID, deviceID, operationID); err == nil {
				t.Fatal("invalid sync record accepted")
			}
		})
	}
}

func TestValidateRecordAcceptsActualUnpaddedCiphertext(t *testing.T) {
	vaultID, deviceID, operationID := uuid.New().String(), uuid.New().String(), uuid.New().String()
	payload, _ := json.Marshal(map[string]any{
		"v": 1, "alg": "xchacha20poly1305",
		"nonce": base64.RawStdEncoding.EncodeToString(make([]byte, 24)),
		"ct":    base64.RawStdEncoding.EncodeToString(make([]byte, 32)),
		"aad":   base64.RawStdEncoding.EncodeToString([]byte("hosts")),
	})
	row := map[string]any{
		"id": uuid.New().String(), "vault_id": vaultID, "revision": 1,
		"created_at": "2026-09-27T10:20:30.000Z", "updated_at": "2026-09-27T10:20:30.000Z",
		"edited_at": "2026-09-27T10:20:30.000Z", "device_id": deviceID,
		"operation_id": operationID, "name": "Host", "sort_order": 0, "data": string(payload),
	}
	if err := validateRecord("hosts", row, vaultID, deviceID, operationID); err != nil {
		t.Fatal(err)
	}
}
