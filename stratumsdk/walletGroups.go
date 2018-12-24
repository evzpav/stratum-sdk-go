package stratumsdk

import (
	"github.com/pquerna/ffjson/ffjson"
)

type WalletGroupPayload struct {
	WalletGroupEid   int    `json:"wallet_group_eid,ommitempty"`
	WalletGroupId    int    `json:"wallet_group_id,ommitempty"`
	WalletGroupLabel string `json:"wallet_group_label,ommitempty"`
}

type WalletGroupData struct {
	WalletGroupEid   int    `json:"wallet_group_eid"`
	WalletGroupId    int    `json:"wallet_group_id"`
	WalletGroupLabel string `json:"wallet_group_label"`
}

type WalletGroup struct {
	client *ApiClient
}

type WalletGroupListResult struct {
	Data []WalletGroupData `json:"data"`
}

type WalletGroupResult struct {
	Data WalletGroupData `json:"data"`
}

func (c *ApiClient) WalletGroup() *WalletGroup {
	return &WalletGroup{client: c}
}

func (w *WalletGroup) List(payload *WalletGroupPayload) (*[]WalletGroupData, *ApiError, error) {
	result := new(WalletGroupListResult)
	payloadJSON, err := ffjson.Marshal(payload)
	if err != nil {
		return nil, nil, err
	}
	apiErr, err := w.client.call("walletGroups", "list", payloadJSON, result)
	if err != nil {
		return nil, nil, err
	}
	return &result.Data, apiErr, nil
}

func (w *WalletGroup) Create(payload *WalletGroupPayload) (*WalletGroupData, *ApiError, error) {
	result := new(WalletGroupResult)
	payloadJSON, err := ffjson.Marshal(payload)
	if err != nil {
		return nil, nil, err
	}
	apiErr, err := w.client.call("walletGroups", "create", payloadJSON, result)
	if err != nil {
		return nil, nil, err
	}
	return &result.Data, apiErr, nil

}

func (w *WalletGroup) Get(payload *WalletGroupPayload) (*WalletGroupData, *ApiError, error) {
	result := new(WalletGroupResult)
	payloadJSON, err := ffjson.Marshal(payload)
	if err != nil {
		return nil, nil, err
	}
	apiErr, err := w.client.call("walletGroups", "get", payloadJSON, result)
	if err != nil {
		return nil, nil, err
	}
	return &result.Data, apiErr, nil

}
