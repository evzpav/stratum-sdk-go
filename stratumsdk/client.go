package stratumsdk

import (
	"github.com/pquerna/ffjson/ffjson"
	"github.com/rafaeltokyo/stratum-sdk-go/stratumclient"
)

const (
	StatusOK   = stratumclient.StatusOK
	StatusFAIL = stratumclient.StatusFAIL
)

type ApiError struct {
	stratumclient.Result
}

type ApiClient struct {
	conn *stratumclient.StratumClient
}

const (
	envProduction = "https://stratum.global/api/"
	envSandbox    = "https://dev.stratum.global/api/"
)

//Initial - create a initial instance the sdk
func Initial(apiUser string, apiKey string, sandbox bool) *ApiClient {
	client := &ApiClient{
		conn: stratumclient.New(apiUser, apiKey),
	}
	if sandbox {
		client.conn.SetEndpoint(envSandbox)
	} else {
		client.conn.SetEndpoint(envProduction)
	}
	return client
}

// call a ApiClient request
func (c *ApiClient) call(module string, action string, payload []byte, target interface{}) (*ApiError, error) {
	apiErr := new(ApiError)

	apires, err := c.conn.CallRestApi(module, action, payload, false)
	if err != nil {
		return nil, err
	}

	//fmt.Printf("%s", apires.Raw)
	if err = ffjson.Unmarshal(apires.Raw, apiErr); err != nil {
		return nil, err
	}
	if apiErr.Status != StatusOK {
		return apiErr, nil
	}
	if target == nil {
		return nil, nil
	}
	if err = ffjson.Unmarshal(apires.Raw, target); err != nil {
		return nil, err
	}
	return nil, nil
}
