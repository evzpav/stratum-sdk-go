package stratumsdk_test

import (
	"testing"

	"github.com/evzpav/stratum-sdk-go/stratumsdk"
)

func TestWalletGroupCreate(t *testing.T) {
	client := stratumsdk.Initial(apiUser, apiSecret, true)
	wallgroupCreatePayload := &stratumsdk.WalletGroupPayload{
		WalletGroupLabel: "99xtest",
		WalletGroupEid:   200,
	}
	walletGroup, apiErr, err := client.WalletGroup().Create(wallgroupCreatePayload)
	if err != nil {
		t.Errorf("sdk error: TestWalletGroupCreate() -> %s ", err.Error())
	}
	if apiErr != nil {
		t.Errorf("apiError: TestWalletGroupCreate() -> %s ", apiErr.Data)
	}
	if walletGroup.WalletGroupEid != 200 {
		t.Errorf("WalletGroupEid is different")
	}

	if walletGroup.WalletGroupLabel != "99xtest" {
		t.Errorf("WalletGroupLabel is different")
	}

}

func TestWalletGroupList(t *testing.T) {
	client := stratumsdk.Initial(apiUser, apiSecret, true)
	walletGroupPayload := new(stratumsdk.WalletGroupPayload)
	_, apiErr, err := client.WalletGroup().List(walletGroupPayload)
	if err != nil {
		t.Errorf("sdk error: TestWalletGroupList() -> %s ", err.Error())
	}
	if apiErr != nil {
		t.Errorf("apiError: TestWalletGroupList() -> %s ", apiErr.Data)
	}
}

func TestWalletGroupPayloadList(t *testing.T) {
	client := stratumsdk.Initial(apiUser, apiSecret, true)
	var count = 1
	walletGroupPayload := &stratumsdk.WalletGroupPayload{
		WalletGroupEid: 200,
	}
	walletGroupList, apiErr, err := client.WalletGroup().List(walletGroupPayload)
	if err != nil {
		t.Errorf("sdk error: TestWalletGroupPayloadList() -> %s ", err.Error())
	}
	if apiErr != nil {
		t.Errorf("apiError: TestWalletGroupPayloadList() -> %s ", apiErr.Data)
	}
	if len(*walletGroupList) > count {
		t.Errorf("count: TestWalletGroupPayloadList() ->  walletGroupList is bigger than %d ", count)
	}
}

func TestWalletGroupGet(t *testing.T) {
	client := stratumsdk.Initial(apiUser, apiSecret, true)
	walletGroupPayload := &stratumsdk.WalletGroupPayload{
		WalletGroupId: 21,
	}
	walletGroup, apiErr, err := client.WalletGroup().Get(walletGroupPayload)
	if err != nil {
		t.Errorf("sdk error: TestWalletGroupGet() -> %s ", err.Error())
	}
	if apiErr != nil {
		t.Errorf("apiError: TestWalletGroupGet() -> %s ", apiErr.Data)
	}
	//t.Errorf("%#v", walletGroup)
	if walletGroup.WalletGroupId != 21 {
		t.Errorf("WalletGroupId is different")
	}
}
