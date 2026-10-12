package metadata

import (
	"time"

	"github.com/secretbridge/secretbridge/internal/types"
)

func (d *DB) WriteAuditLog(al *types.AuditLog) error {
	if al.ID == "" {
		al.ID = generateID()
	}
	if al.CreatedAt.IsZero() {
		al.CreatedAt = time.Now()
	}

	_, err := d.db.Exec(`
		INSERT INTO audit_logs (id, operation_id, action, actor, target, outcome, metadata, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, al.ID, al.OperationID, al.Action, al.Actor, al.Target, al.Outcome, al.Metadata, al.CreatedAt)
	return err
}

func (d *DB) ListAuditLogs(limit int) ([]*types.AuditLog, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := d.db.Query(`
		SELECT id, operation_id, action, actor, target, outcome, metadata, created_at
		FROM audit_logs ORDER BY created_at DESC LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []*types.AuditLog
	for rows.Next() {
		al := &types.AuditLog{}
		if err := rows.Scan(&al.ID, &al.OperationID, &al.Action, &al.Actor, &al.Target, &al.Outcome, &al.Metadata, &al.CreatedAt); err != nil {
			return nil, err
		}
		logs = append(logs, al)
	}
	return logs, nil
}
