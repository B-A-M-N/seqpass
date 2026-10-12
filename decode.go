package secretbridge

import (
	"encoding/json"
	"fmt"
)

func decodeCatalog(data interface{}) ([]CatalogEntry, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	var entries []CatalogEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func decodeOpID(data interface{}) (string, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", err
	}
	if m["op_id"] == "" {
		return "", fmt.Errorf("no op_id in response")
	}
	return m["op_id"], nil
}
