package stratumsdk_test

import (
	"testing"

	"github.com/evzpav/stratum-sdk-go/stratumsdk"
)

const (
	walletIdTest      = 40
	WalletGroupIdTest = 5
)

func TestWalletCreate(t *testing.T) {
	client := stratumsdk.Initial(apiUser, apiSecret, true)
	walletCreatePayload := &stratumsdk.WalletPayload{
		WalletGroupId: WalletGroupIdTest,
		WalletLabel:   "99xtest",
		Currency:      "BTC",
		WalletType:    "checking",
	}
	wallet, apiErr, err := client.Wallets().Create(walletCreatePayload)

	if err != nil {
		t.Errorf("sdk error: TestWalletCreate() -> %s ", err.Error())
	}
	if apiErr != nil {
		t.Errorf("apiError: TestWalletCreate() -> %s ", apiErr.Data)
	}
	if wallet.WalletGroupId != WalletGroupIdTest {
		t.Errorf("WalletGroupEid is different")
	}

	if wallet.WalletLabel != "99xtest" {
		t.Errorf("WalletGroupLabel is different")
	}
	if wallet.Currency != "BTC" {
		t.Errorf("Currency is different")
	}

}

func TestWalletCreateFailCurrency(t *testing.T) {
	client := stratumsdk.Initial(apiUser, apiSecret, true)
	walletCreatePayload := &stratumsdk.WalletPayload{
		WalletGroupId: WalletGroupIdTest,
		WalletLabel:   "99xtest",
		Currency:      "BTCcccccc",
		WalletType:    "checking",
	}
	_, apiErr, err := client.Wallets().Create(walletCreatePayload)
	if err != nil {
		t.Errorf("sdk error: TestWalletCreateFailCurrency() -> %s ", err.Error())
	}

	if apiErr == nil {
		t.Errorf("apiError: test with dont exists currency fail")
	}
}

func TestWalletCreateFailGroup(t *testing.T) {
	client := stratumsdk.Initial(apiUser, apiSecret, true)
	walletCreatePayload := &stratumsdk.WalletPayload{
		WalletGroupId: 100000000,
		WalletLabel:   "99xtest",
		Currency:      "BTCcccccc",
		WalletType:    "checking",
	}
	_, apiErr, err := client.Wallets().Create(walletCreatePayload)
	if err != nil {
		t.Errorf("sdk error: TestWalletCreateFailGroup() -> %s ", err.Error())
	}
	if apiErr == nil {
		t.Errorf("apiError: test with dont exists WalletGroupId fail")
	}
}

func TestWalletList(t *testing.T) {
	client := stratumsdk.Initial(apiUser, apiSecret, true)
	walletsListPayload := new(stratumsdk.WalletsListPayload)
	_, apiErr, err := client.Wallets().List(walletsListPayload)
	if err != nil {
		t.Errorf("sdk error: TestWalletList() -> %s ", err.Error())
	}
	if apiErr != nil {
		t.Errorf("apiError: TestWalletList() -> %s ", apiErr.Data)
	}
}

func TestWalletPayloadList(t *testing.T) {
	client := stratumsdk.Initial(apiUser, apiSecret, true)
	walletsListPayload := &stratumsdk.WalletsListPayload{
		WalletGroupId: WalletGroupIdTest,
	}
	walletList, apiErr, err := client.Wallets().List(walletsListPayload)
	if err != nil {
		t.Errorf("sdk error: TestWalletPayloadList() -> %s ", err.Error())
	}
	if apiErr != nil {
		t.Errorf("apiError: TestWalletPayloadList() -> %s ", apiErr.Data)
	}
	if len(*walletList) == 0 {
		t.Errorf("count: TestWalletPayloadList() ->  walletList not found wallets ")
	}
}

func TestWalletGet(t *testing.T) {
	client := stratumsdk.Initial(apiUser, apiSecret, true)
	walletPayload := &stratumsdk.WalletPayload{
		WalletId: walletIdTest,
	}
	wallet, apiErr, err := client.Wallets().Get(walletPayload)
	if err != nil {
		t.Errorf("sdk error: TestWalletGet() -> %s ", err.Error())
	}
	if apiErr != nil {
		t.Errorf("apiError: TestWalletGet() -> %s ", apiErr.Data)
	}
	if wallet.WalletId != walletIdTest {
		t.Errorf("WalletGroupId is different")
	}
}
