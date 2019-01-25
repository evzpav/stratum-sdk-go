package stratumsdk_test

import (
	"testing"

	"github.com/evzpav/stratum-sdk-go/stratumsdk"
)

const (
	apiUser   = "apiUser"
	apiSecret = "apiSecret"
)

func TestPing(t *testing.T) {
	client := stratumsdk.Initial(apiUser, apiSecret, true)
	pingResult, apiErr, err := client.Test().Ping()
	if err != nil {
		t.Errorf("sdk error: TestPing() -> %s ", err.Error())
	}
	if apiErr != nil {
		t.Errorf("apiError: TestPing() -> %s ", apiErr.Data)
	}
	if pingResult.Ping != "pong" {
		t.Errorf("ping call not result in pong")
	}

}

func TestSig(t *testing.T) {
	client := stratumsdk.Initial(apiUser, apiSecret, true)
	apiErr, err := client.Test().Sig()
	if err != nil {
		t.Errorf("sdk error: TestSig() -> %s ", err.Error())
	}
	if apiErr != nil {
		t.Errorf("apiError: TestSig() -> %s ", apiErr.Data)
	}
}

func TestTime(t *testing.T) {
	client := stratumsdk.Initial(apiUser, apiSecret, true)
	timeResult, apiErr, err := client.Test().Time()
	if err != nil {
		t.Errorf("sdk error: TestTime() -> %s ", err.Error())
	}
	if apiErr != nil {
		t.Errorf("apiError: TestTime() -> %s ", apiErr.Data)
	}
	if timeResult.Time != float64(timeResult.Time) {
		t.Errorf("time call not result in pong")
	}

}
