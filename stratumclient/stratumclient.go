package stratumclient

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"time"

	"github.com/pquerna/ffjson/ffjson"
)

const (
	StatusOK   = "ok"
	StatusFAIL = "failed"
)

type StratumClient struct {
	apiKey              string
	apiKeySecret        string
	endpoint            string
	netTransportTimeout time.Duration
	netClientTimeout    time.Duration
}

type ResultHeader struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Code    string `json:"code"`
}

type Result struct {
	ResultHeader
	Data interface{} `json:"data"`
	Raw  []byte
}

func New(user string, secret string) *StratumClient {
	return &StratumClient{
		apiKey:              user,
		apiKeySecret:        secret,
		endpoint:            "https://stratum.global/api/",
		netTransportTimeout: 5 * time.Second,
		netClientTimeout:    10 * time.Second,
	}
}

func (c *StratumClient) SetEndpoint(endpoint string) {
	c.endpoint = endpoint
}

func (c *StratumClient) SetNetTransportTimeout(timeout int) {
	c.netTransportTimeout = time.Second * time.Duration(timeout)
}

func (c *StratumClient) SetNetClientTimeout(timeout int) {
	c.netClientTimeout = time.Second * time.Duration(timeout)
}
func (c *StratumClient) CallRestApi(mod string, action string, payload []byte, decode bool) (Result, error) {
	// create data package
	mytime := time.Now().Unix()
	sdata := url.Values{
		"api_ts":   {strconv.FormatInt(mytime, 10)},
		"api_user": {c.apiKey},
		"payload":  {string(payload)},
	}
	apiSig := makeSig([]byte(c.apiKeySecret), makeSigMsg(sdata))
	sdata.Add("api_sig", apiSig)

	// holt the returl
	var answer Result

	// create http client, unlimited timeouts are not an option !!
	var netTransport = &http.Transport{
		Dial:                (&net.Dialer{Timeout: c.netTransportTimeout}).Dial,
		TLSHandshakeTimeout: c.netTransportTimeout,
	}
	var netClient = &http.Client{Timeout: c.netClientTimeout, Transport: netTransport}

	// send and decode output
	url := concat(c.endpoint, mod, "/", action)
	res, err := netClient.PostForm(url, sdata)
	if err != nil {
		answer.Status = StatusFAIL
		answer.Message = "Call failed"
		answer.Data = err.Error()
		return answer, err
	}
	defer res.Body.Close()
	body, _ := ioutil.ReadAll(res.Body)
	if decode {
		if err := ffjson.NewDecoder().Decode(body, &answer); err != nil {
			answer.Status = StatusFAIL
			answer.Message = "Decoding json failed"
			answer.Data = err.Error()
			return answer, err
		}
	} else {
		if err != nil {
			answer.Status = StatusFAIL
			answer.Message = "Decoding body failed"
			answer.Data = err.Error()
			return answer, err
		}
		answer.Status = StatusOK
		answer.Message = "Request ok"
		answer.Raw = body
	}
	return answer, nil
}

// join strings together, _much_ faster then +
func concat(astring ...string) string {
	var b bytes.Buffer
	for i := 0; i < len(astring); i++ {
		b.WriteString(astring[i])
	}
	return b.String()
}

// create signagture
func makeSig(key []byte, msg string) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(msg))
	return hex.EncodeToString(h.Sum(nil))
}

// create message to sign from form values
func makeSigMsg(data url.Values) string {
	var keys []string
	for key := range data {
		if key != "api_sig" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	var testStr string
	for _, key := range keys {
		testStr += key + "=" + data.Get(key) + "&"
	}
	return testStr[:len(testStr)-1]
}
