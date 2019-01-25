package stratumsdk_test

import (
	"testing"

	"github.com/evzpav/stratum-sdk-go/stratumsdk"
)

func TestOperationFees(t *testing.T) {
	client := stratumsdk.Initial(apiUser, apiSecret, true)
	feePayload := new(stratumsdk.FeePayload)
	_, apiErr, err := client.Operations().Fees(feePayload)
	if err != nil {
		t.Errorf("sdk error: TestOperationFees() -> %s ", err.Error())
	}
	if apiErr != nil {
		t.Errorf("apiError: TestOperationFees() -> %s ", apiErr.Data)
	}
}

func TestOperationList(t *testing.T) {
	client := stratumsdk.Initial(apiUser, apiSecret, true)
	operationPayload := new(stratumsdk.OperationPayload)
	_, apiErr, err := client.Operations().List(operationPayload)
	if err != nil {
		t.Errorf("sdk error: TestOperationList() -> %s ", err.Error())
	}
	if apiErr != nil {
		t.Errorf("apiError: TestOperationList() -> %s ", apiErr.Data)
	}
}

func TestOperationGet(t *testing.T) {
	client := stratumsdk.Initial(apiUser, apiSecret, true)
	operationPayload := new(stratumsdk.OperationPayload)
	_, apiErr, err := client.Operations().Get(operationPayload)
	if err != nil {
		t.Errorf("sdk error: TestOperationGet() -> %s ", err.Error())
	}
	if apiErr != nil {
		t.Errorf("apiError: TestOperationGet() -> %s ", apiErr.Data)
	}
}
