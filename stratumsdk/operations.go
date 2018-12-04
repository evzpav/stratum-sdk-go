package stratumsdk

import (
	"encoding/json"
	"fmt"
)

type Operations struct {
	client *ApiClient
}

type FeeData struct {
	Currency      string  `json:"currency"`
	DestType      string  `json:"dest_type"`
	OperationType string  `json:"operation_type"`
	OperationFee  float64 `json:"operation_fee"`
}

type OperationData struct {
	OperationId          int     `json:"Operation_id"`
	WalletId             int     `json:"Wallet_id"`
	OperationAmount      float64 `json:"Operation_amount"`
	OperationTamount     float64 `json:"Operation_tamount"`
	OperationFee         float64 `json:"Operation_fee"`
	OperationDesc        string  `json:"Operation_desc"`
	OperationEid         int     `json:"Operation_eid"`
	OperationEtxid       string  `json:"Operation_etxid"`
	OperationTs          int     `json:"Operation_ts"`
	OperationUpdTs       int     `json:"Operation_upd_ts"`
	OperationConf        int     `json:"Operation_conf"`
	OperationConfreq     int     `json:"Operation_confreq"`
	DestTypeData         string  `json:"dest_type_data"`
	OperationInfo        string  `json:"Operation_info"`
	CurrencyUsdtrate     int     `json:"Currency_usdtrate"`
	OperationStatus      string  `json:"Operation_status"`  //"in:new,processing,done,failed"
	OperationType        string  `json:"Operation_type"`    //"in:deposit,withdraw,transfer"
	WalletEid            int     `json:"Wallet_eid"`
	WalletGroupId        int     `json:"Wallet_group_id"`
	WalletGroupEid       int     `json:"Wallet_group_eid"`
	WalletLabel          string  `json:"Wallet_label"`
	WalletType           string  `json:"Wallet_type"`
	Currency             string  `json:"Currency"`
	CurrencyUnit         string  `json:"Currency_unit"`
	CurrencyType         string  `json:"Currency_type"`
	DestType             string  `json:"dest_type"`        //"in:in,out,intra"
	DirectionType        string  `json:"direction_type"`
}

type DestinationData struct {
	WalletAddress string `json:"wallet_address"`
}
type OperationPayload struct {
	DestType           string `json:"dest_type,omitempty"`             // types: in,out,intra
	DirectionType      string `json:"direction_type,omitempty"`        // types in,out,intra
	OperationEid       int    `json:"operation_eid,omitempty"`
	OperationStatus    string `json:"operation_status,omitempty"`      // new,processing,done,failed
	OperationTsFrom    int    `json:"operation_ts_from,omitempty"`     // doubt ask for Sven
	OperationTsTo      int    `json:"operation_ts_to,omitempty"`       // doubt ask for Sven
	OperationType      string `json:"operation_type,omitempty"`        // types: deposit,withdraw,transfer"
	OperationUpdTsFrom int    `json:"operation_upd_ts_from,omitempty"` // doubt ask for Sven
	OperationUpdTsTo   int    `json:"operation_upd_ts_to,omitempty"`   // doubt ask for Sven
	WalletEid          int    `json:"wallet_eid,omitempty"`
	WalletGroupEid     int    `json:"wallet_group_eid,omitempty"`
	WalletId           int    `json:"wallet_id,omitempty"`
	Currency           string  `json:"Currency"`
}

type OperationResult struct {
	Data OperationData `json:"data"`
}

type OperationListResult struct {
	Data []OperationData `json:"data"`
}

type FeePayload struct {
	Currency      string `json:"currency"`
	DestType      string `json:"dest_type"`
	OperationType string `json:"operation_type"`
}

type FeeResult struct {
	Data []FeeData `json:"data"`
}

func (c *ApiClient) Operations() *Operations {
	return &Operations{client: c}
}

// Fees - get fees
func (o *Operations) Fees(payload *FeePayload) (*[]FeeData, *ApiError, error) {
	result := new(FeeResult)
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, err
	}
	apiErr, err := o.client.call("operations", "fees", payloadJSON, &result)
	if err != nil {
		return nil, nil, err
	}
	return &result.Data, apiErr, nil

}

// List - list operations in account
func (o *Operations) List(payload *OperationPayload) (*[]OperationData, *ApiError, error) {
	result := new(OperationListResult)
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, err
	}
	fmt.Printf("%s", payloadJSON)
	apiErr, err := o.client.call("operations", "list", payloadJSON, &result)
	if err != nil {
		return nil, nil, err
	}

	return &result.Data, apiErr, nil

}

// Get - get operation in account
func (o *Operations) Get(payload *OperationPayload) (*OperationData, *ApiError, error) {
	result := new(OperationResult)
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, err
	}
	fmt.Printf("%s", payloadJSON)
	apiErr, err := o.client.call("operations", "get", payloadJSON, &result)
	if err != nil {
		return nil, nil, err
	}
	return &result.Data, apiErr, nil

}
