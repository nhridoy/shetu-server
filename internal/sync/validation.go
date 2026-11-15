package sync

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

const timestampLayout = "2006-01-02T15:04:05.000Z"
const maxRecordBytes = 1 << 20

var commonFields = []string{
	"id", "vault_id", "revision", "created_at", "updated_at", "deleted_at",
	"edited_at", "device_id", "operation_id", "sort_order", "data", "name",
}

var tableFields = map[string][]string{
	"vaults":                {"owner_id", "kind", "is_default"},
	"groups":                {"parent_id"},
	"hosts":                 {"os", "auth_type", "tags", "color", "group_id", "key_id"},
	"keys":                  {"description", "key_type", "fingerprint", "public_key"},
	"snippets":              {"description", "tags"},
	"identities":            {},
	"workspaces":            {},
	"presets":               {},
	"port_forwards":         {"host_id", "mode"},
	"session_history":       {},
	"session_output_chunks": {},
	"session_preferences":   {},
}

func canonicalTimestamp(value any) bool {
	s, ok := value.(string)
	if !ok || len(s) != len(timestampLayout) {
		return false
	}
	parsed, err := time.Parse(timestampLayout, s)
	return err == nil && parsed.UTC().Format(timestampLayout) == s
}

func requiredUUID(record map[string]any, field, expected string) error {
	value, ok := record[field].(string)
	if !ok {
		return fmt.Errorf("%s must be a UUID", field)
	}
	if _, err := uuid.Parse(value); err != nil {
		return fmt.Errorf("%s must be a UUID", field)
	}
	if expected != "" && value != expected {
		return fmt.Errorf("%s does not match request", field)
	}
	return nil
}

func decodeBase64(value string) ([]byte, error) {
	decoded, err := base64.RawStdEncoding.DecodeString(value)
	if err == nil {
		return decoded, nil
	}
	return base64.StdEncoding.DecodeString(value)
}

func validateCiphertext(table string, value any) error {
	s, ok := value.(string)
	if !ok || len(s) == 0 || len(s) > maxRecordBytes {
		return errors.New("data must be bounded ciphertext")
	}
	// A default vault may have no sensitive payload yet. All other records must
	// carry an AEAD envelope, not a plaintext JSON object.
	if table == "vaults" && s == "{}" {
		return nil
	}
	var payload struct {
		Version    int    `json:"v"`
		Alg        string `json:"alg"`
		Nonce      string `json:"nonce"`
		CT         string `json:"ct"`
		AAD        string `json:"aad"`
		VaultID    string `json:"vault_id"`
		Epoch      int    `json:"epoch"`
		RecordType string `json:"record_type"`
	}
	if err := json.Unmarshal([]byte(s), &payload); err != nil {
		return errors.New("invalid ciphertext envelope")
	}
	if payload.Alg != "xchacha20poly1305" {
		return errors.New("unsupported ciphertext envelope")
	}
	if payload.Version == 1 {
		if payload.AAD != base64.RawStdEncoding.EncodeToString([]byte(table)) && payload.AAD != base64.StdEncoding.EncodeToString([]byte(table)) {
			return errors.New("unsupported ciphertext envelope")
		}
	} else if payload.Version == 2 {
		if payload.RecordType != table || payload.Epoch < 1 {
			return errors.New("invalid team ciphertext context")
		}
		if _, err := uuid.Parse(payload.VaultID); err != nil {
			return errors.New("invalid team ciphertext vault")
		}
	} else {
		return errors.New("unsupported ciphertext envelope")
	}
	nonce, err := decodeBase64(payload.Nonce)
	if err != nil || len(nonce) != 24 {
		return errors.New("invalid ciphertext nonce")
	}
	ct, err := decodeBase64(payload.CT)
	if err != nil || len(ct) < 16 {
		return errors.New("invalid ciphertext body")
	}
	return nil
}

// validateRecord limits plaintext metadata to the fields explicitly approved
// for synchronization. The server validates AEAD shape/AAD, never decrypts it.
func validateRecord(table string, record map[string]any, vaultID, deviceID, operationID string) error {
	extra, known := tableFields[table]
	if !known {
		return errors.New("unknown sync table")
	}
	encoded, err := json.Marshal(record)
	if err != nil || len(encoded) > maxRecordBytes {
		return errors.New("record exceeds size limit")
	}
	allowed := make(map[string]bool, len(commonFields)+len(extra))
	for _, field := range commonFields {
		allowed[field] = true
	}
	for _, field := range extra {
		allowed[field] = true
	}
	for field := range record {
		if !allowed[field] {
			return fmt.Errorf("unexpected plaintext field %q", field)
		}
	}
	if fixed, ok := map[string]string{
		"session_history":       "Session",
		"session_output_chunks": "Output chunk",
		"session_preferences":   "Session preferences",
	}[table]; ok && record["name"] != fixed {
		return errors.New("history name must be non-identifying")
	}
	if err := requiredUUID(record, "id", ""); err != nil {
		return err
	}
	if table == "vaults" {
		if record["id"] != vaultID {
			return errors.New("vault record ID does not match request")
		}
		if value, ok := record["vault_id"].(string); ok && value != "" {
			return errors.New("vault record must have empty vault_id")
		}
	} else if err := requiredUUID(record, "vault_id", vaultID); err != nil {
		return err
	}
	if err := requiredUUID(record, "device_id", deviceID); err != nil {
		return err
	}
	if err := requiredUUID(record, "operation_id", operationID); err != nil {
		return err
	}
	for _, field := range []string{"created_at", "updated_at", "edited_at"} {
		if !canonicalTimestamp(record[field]) {
			return fmt.Errorf("%s must be canonical UTC milliseconds", field)
		}
	}
	if value, exists := record["deleted_at"]; exists && value != nil && !canonicalTimestamp(value) {
		return errors.New("deleted_at must be canonical UTC milliseconds")
	}
	if err := validateCiphertext(table, record["data"]); err != nil {
		return err
	}
	if data, ok := record["data"].(string); ok && data != "{}" {
		var context struct {
			Version int    `json:"v"`
			VaultID string `json:"vault_id"`
		}
		if err := json.Unmarshal([]byte(data), &context); err != nil {
			return errors.New("invalid ciphertext envelope")
		}
		if context.Version == 2 && context.VaultID != vaultID {
			return errors.New("team ciphertext vault mismatch")
		}
	}
	return nil
}
