package stratumsdk

import "github.com/pquerna/ffjson/ffjson"

// Withdraws strcture for consumer widthdraws
type Withdraws struct {
	client *ApiClient
}

type WithdrawsData struct {
	DestAddress     string  `json:"dest_address"`
	OperationAmount float64 `json:"operation_amount"`
	OperationDesc   string  `json:"operation_desc"`
	OperationEid    int     `json:"operation_eid"`
	OperationOtp    string  `json:"operation_otp"`
	WalletId        int     `json:"wallet_id"`
}
type WithdrawsPayload struct {
	DestAddress     string  `json:"dest_address"`
	OperationAmount float64 `json:"operation_amount"`
	OperationDesc   string  `json:"operation_desc"`
	OperationEid    int     `json:"operation_eid"`
	OperationOtp    string  `json:"operation_otp"`
	WalletId        int     `json:"wallet_id"`
}

type WithdrawsResult struct {
	Data WithdrawsData `json:"data"`
}

func (c *ApiClient) Withdraws() *Withdraws {
	return &Withdraws{client: c}
}

func (w *Withdraws) Crypto(payload *WithdrawsPayload) (*WithdrawsData, *ApiError, error) {
	result := new(WithdrawsResult)
	payloadJSON, err := ffjson.Marshal(payload)
	if err != nil {
		return nil, nil, err
	}
	apiErr, err := w.client.call("withdraws", "crypto", payloadJSON, &result)
	if err != nil {
		return nil, nil, err
	}
	return &result.Data, apiErr, nil
}
