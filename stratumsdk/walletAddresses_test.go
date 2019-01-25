package stratumsdk_test

import (
	"testing"

	"github.com/evzpav/stratum-sdk-go/stratumsdk"
)

const (
	walletIdTestAddress = 40
	WalletAddressTest   = "2Mv3iP7e717vnXeQCJDHKzt8QRaL6KokHFv"
)

func TestWalletAddressAssign(t *testing.T) {
	client := stratumsdk.Initial(apiUser, apiSecret, true)
	walletAddressesPayload := &stratumsdk.WalletAddressesPayload{
		WalletAddressEid:   200,
		WalletAddressLabel: "99xtest",
		WalletId:           walletIdTestAddress,
	}
	walletAddress, apiErr, err := client.WalletsAddresses().Assign(walletAddressesPayload)
	if err != nil {
		t.Errorf("sdk error: TestWalletAddressAssign() -> %s ", err.Error())
	}
	if apiErr != nil {
		t.Errorf("apiError: TestWalletAddressAssign() -> %s ", apiErr.Data)
	}
	t.Errorf("walletAddress : %#v", walletAddress)

}

func TestWalletAddressGet(t *testing.T) {
	client := stratumsdk.Initial(apiUser, apiSecret, true)
	walletAddressesPayload := &stratumsdk.WalletAddressesPayload{
		WalletAddress: WalletAddressTest,
		Currency:      "BTC",
	}
	walletAddress, apiErr, err := client.WalletsAddresses().Get(walletAddressesPayload)
	if err != nil {
		t.Errorf("sdk error: TestWalletAddressGet() -> %s ", err.Error())
	}
	if apiErr != nil {
		t.Errorf("apiError: TestWalletAddressGet() -> %s ", apiErr.Data)
	}
	//t.Errorf("%#v", walletGroup)
	if walletAddress.WalletAddress != WalletAddressTest {
		t.Errorf("WalletAddress is different")
	}
}

func TestWalletAddressList(t *testing.T) {
	client := stratumsdk.Initial(apiUser, apiSecret, true)
	walletsAddressesListPayload := new(stratumsdk.WalletsAddressesListPayload)
	_, apiErr, err := client.WalletsAddresses().List(walletsAddressesListPayload)
	if err != nil {
		t.Errorf("sdk error: TestWalletAddressList() -> %s ", err.Error())
	}
	if apiErr != nil {
		t.Errorf("apiError: TestWalletAddressList() -> %s ", apiErr.Data)
	}

	t.Errorf("%s", "")
}

func TestWalletAddressPayloadList(t *testing.T) {
	client := stratumsdk.Initial(apiUser, apiSecret, true)
	walletsAddressesListPayload := &stratumsdk.WalletsAddressesListPayload{
		WalletId: walletIdTestAddress,
	}
	_, apiErr, err := client.WalletsAddresses().List(walletsAddressesListPayload)
	if err != nil {
		t.Errorf("sdk error: TestWalletAddressPayloadList() -> %s ", err.Error())
	}
	if apiErr != nil {
		t.Errorf("apiError: TestWalletAddressPayloadList() -> %s ", apiErr.Data)
	}

}
