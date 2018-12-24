package stratumsdk

import (
	"github.com/pquerna/ffjson/ffjson"
)

type WalletData struct {
	WalletId           int     `json:"wallet_id"`
	WalletEid          int     `json:"wallet_eid"`
	WalletLabel        string  `json:"wallet_label"`
	WalletBalance      float64 `json:"wallet_balance"`
	WalletGroupId      int     `json:"wallet_group_id"`
	WalletGroupLabel   string  `json:"wallet_group_label"`
	WalletGroupEid     int     `json:"wallet_group_eid"`
	WalletType         string  `json:"wallet_type"`
	CurrencyName       string  `json:"currency_name"`
	Currency           string  `json:"currency"`
	CurrencyType       string  `json:"currency_type,omitempty"`
	CurrencyUnit       string  `json:"currency_unit"`
	CurrencyUnitSymbol string  `json:"currency_unit_symbol"`
	CurrencyUnitDigits int     `json:"currency_unit_digits"`
}

type WalletsListPayload struct {
	WalletEid        int     `json:"wallet_eid"`
	WalletBalanceMin float64 `json:"wallet_balance_min"`
	WalletBalanceMax float64 `json:"wallet_balance_max"`
	WalletGroupEid   int     `json:"wallet_group_eid"`
	WalletGroupId    int     `json:"wallet_group_id"`
	WalletType       string  `json:"wallet_type"`
	Currency         string  `json:"currency"`
	CurrencyType     string  `json:"currency_type"`
}

type WalletPayload struct {
	Currency      string `json:"currency"`
	WalletEid     int    `json:"wallet_eid"`
	WalletGroupId int    `json:"wallet_group_id"`
	WalletLabel   string `json:"wallet_label"`
	WalletType    string `json:"wallet_type"`
	WalletId      int    `json:"wallet_id"`
}

// Success reply from a list action
type WalletsListResult struct {
	Data []WalletData `json:"data"`
}
type WalletResult struct {
	Data WalletData `json:"data"`
}

type Wallets struct {
	client *ApiClient
}

// attach module to apiclient
func (c *ApiClient) Wallets() *Wallets {
	return &Wallets{client: c}
}

// List - is a list wallets in your user
func (w *Wallets) List(payload *WalletsListPayload) (*[]WalletData, *ApiError, error) {
	result := new(WalletsListResult)
	payloadJSON, err := ffjson.Marshal(payload)
	if err != nil {
		return nil, nil, err
	}
	apiErr, err := w.client.call("wallets", "list", payloadJSON, result)
	if err != nil {
		return nil, nil, err
	}
	return &result.Data, apiErr, nil
}

func (w *Wallets) Create(payload *WalletPayload) (*WalletData, *ApiError, error) {
	result := new(WalletResult)
	payloadJSON, err := ffjson.Marshal(payload)
	if err != nil {
		return nil, nil, err
	}
	apiErr, err := w.client.call("wallets", "create", payloadJSON, result)
	if err != nil {
		return nil, nil, err
	}
	return &result.Data, apiErr, nil

}

func (w *Wallets) Get(payload *WalletPayload) (*WalletData, *ApiError, error) {
	result := new(WalletResult)
	payloadJSON, err := ffjson.Marshal(payload)
	if err != nil {
		return nil, nil, err
	}
	apiErr, err := w.client.call("wallets", "get", payloadJSON, result)
	if err != nil {
		return nil, nil, err
	}
	return &result.Data, apiErr, nil

}
