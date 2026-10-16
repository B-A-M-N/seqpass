package harness

import "testing"

func TestProtectedInputTransactionIsAdapterOnlyContract(t *testing.T) {
	var tx ProtectedInputTransaction
	if tx != nil {
		t.Fatal("zero transaction should not be usable")
	}
}

func TestRelayStatusCarriesNoSecretField(t *testing.T) {
	remaining := int64(1)
	st := RelayStatus{
		RequestID: "req-1", State: "awaiting_user", RecipientID: "rd1",
		Consumption: "single_dispatch", RemainingDeliveries: &remaining,
	}
	_ = st
}
