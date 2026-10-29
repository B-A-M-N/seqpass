//go:build !linux

package transfer

import "fmt"

func (j *OperationJournal) lockOperation(string) (func(), error) {
	return nil, fmt.Errorf("recipient operation locking requires Linux")
}
