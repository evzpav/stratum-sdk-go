package stratumsdk

import "github.com/evzpav/stratum-sdk-go/stratumclient"

// Test api resource Client
type Test struct {
	Client *ApiClient
}

type PingData struct {
	Ping string `json:"ping"`
}

type PingResult struct {
	stratumclient.ResultHeader
	Data PingData `json"ping"`
}

type TimeData struct {
	Time float64 `json:"time"`
}

type TimeResult struct {
	stratumclient.ResultHeader
	Data TimeData `json"time"`
}

func (c *ApiClient) Test() *Test {
	return &Test{Client: c}
}

//Ping a func returns pong
func (t *Test) Ping() (*PingData, *ApiError, error) {
	pingResult := new(PingResult)
	apiErr, err := t.Client.call("test", "ping", []byte("{}"), &pingResult)
	if err != nil {
		return &pingResult.Data, nil, err
	}
	return &pingResult.Data, apiErr, nil

}

//Sig is a func test signature implementation
func (t *Test) Sig() (*ApiError, error) {
	apiErr, err := t.Client.call("test", "sig", []byte("{}"), nil)
	if err != nil {
		return nil, err
	}
	return apiErr, nil

}

// Time is a func get detail a timestamp stratum
func (t *Test) Time() (*TimeData, *ApiError, error) {
	timeResult := new(TimeResult)
	apiErr, err := t.Client.call("test", "time", []byte("{}"), &timeResult)
	if err != nil {
		return &timeResult.Data, nil, err
	}
	return &timeResult.Data, apiErr, nil

}
