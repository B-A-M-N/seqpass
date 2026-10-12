package metadata

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// Receipt is a durable, sanitized operation result. Only closed,
// operation-specific DTOs are persisted: never raw HTTP responses or
// credential material. Bounded at 64 KiB.
type Receipt struct {
	OpID        string    `json:"op_id"`
	OpType      string    `json:"op_type"`
	Status      string    `json:"status"`
	ResultType  string    `json:"result_type"`
	Result      string    `json:"result"`
	CompletedAt time.Time `json:"completed_at"`
}

const maxReceiptBytes = 64 * 1024

func (d *DB) SaveReceipt(opID, opType, resultType string, result interface{}) error {
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	if len(raw) > maxReceiptBytes {
		return errors.New("receipt too large")
	}
	_, err = d.db.Exec(`
		INSERT INTO op_receipts (op_id, op_type, status, result_type, result_json, completed_at)
		VALUES (?, ?, 'completed', ?, ?, ?)
		ON CONFLICT(op_id) DO UPDATE SET status='completed', result_type=?, result_json=?, completed_at=?
	`, opID, opType, resultType, string(raw), time.Now(), resultType, string(raw), time.Now())
	return err
}

func (d *DB) GetReceipt(opID string) (*Receipt, error) {
	r := &Receipt{}
	err := d.db.QueryRow(`
		SELECT op_id, op_type, status, result_type, result_json, completed_at
		FROM op_receipts WHERE op_id = ?
	`, opID).Scan(&r.OpID, &r.OpType, &r.Status, &r.ResultType, &r.Result, &r.CompletedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return r, err
}
