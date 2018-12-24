

![Stratum.hk](stratum_go.png "Stratum.hk")

stratum-sdk-go is a sdk for use operation in Stratum.hk cryptocurrency transactions


## How to install:
``` bash
go get github.com/pquerna/ffjson
go get github.com/rafaeltokyo/stratum-sdk-go
```

## How to use

1. **apiUser** (sent by the team Stratum)
2. **apiSecret** (sent by the team Stratum)
3. **sandbox** ( if true in developer mode)

```go
var sandbox = true
client := stratumsdk.Initial("apiUser","apiSecret", sandbox)
```

## Example Bitcoin Wallet and Address

```go
var sandbox = true
client := stratumsdk.Initial("apiUser","apiSecret", sandbox)
walletCreatePayload := &stratumsdk.WalletData{
		WalletGroupId: 10,
		WalletLabel:   "99xtest",
		Currency:      "BTC",
		WalletType:    "checking",
        WalletEid      100,
}

wallet, apiErr, err := client.Wallets().Create(walletCreatePayload)

if err != nil {
	fmt.Printf("sdk error:  %s ", err.Error())
}
if apiErr != nil {
	fmt.Printf("apiError: %s ", apiErr.Data)
}

walletAddressesPayload := &stratumsdk.WalletAddressesPayload{
		WalletAddressEid:   200,
		WalletAddressLabel: "99xtest",
		WalletId:           wallet.WalletId,
}
walletAddress, apiErr, err := client.WalletsAddresses().Assign(walletAddressesPayload)

if err != nil {
	fmt.Printf("sdk error:  %s ", err.Error())
}
if apiErr != nil {
	fmt.Printf("apiError: %s ", apiErr.Data)
}
fmt.Printf("my btc address",walletAddress.WalletAddress)


```



## WalletGroup

[Create a new WalletGroup](https://github.com/rafaeltokyo/stratum-sdk-go/blob/master/docs/walletGroup/WalletGroup%20Create.md) <br />
[Get WalletGroup List](https://github.com/rafaeltokyo/stratum-sdk-go/blob/master/docs/walletGroup/WalletGroup%20List.md)<br />
[Get WalletGroup Detail](https://github.com/rafaeltokyo/stratum-sdk-go/blob/master/docs/walletGroup/WalletGroup%20Get.md)<br />

## Wallet

[Create a new Wallet](https://github.com/rafaeltokyo/stratum-sdk-go/blob/master/docs/wallet/Wallet%20Create.md) <br />
[Get Wallet List](https://github.com/rafaeltokyo/stratum-sdk-go/blob/master/docs/wallet/Wallet%20Get.md)<br />
[Get Wallet Detail](https://github.com/rafaeltokyo/stratum-sdk-go/blob/master/docs/wallet/Wallet%20List.md)<br />

## WalletAddress

[Assign WalletAddress](https://github.com/rafaeltokyo/stratum-sdk-go/blob/master/docs/walletAddress/WalletAddress%20Assign.md) <br />
[Get Wallet List](https://github.com/rafaeltokyo/stratum-sdk-go/blob/master/docs/walletAddress/WalletAddress%20List.md)<br />
[Get Wallet Detail](https://github.com/rafaeltokyo/stratum-sdk-go/blob/master/docs/walletAddress/WalletAddress%20List.md)<br />

## Operations

[Operations list](https://github.com/rafaeltokyo/stratum-sdk-go/blob/master/docs/operations/Operation%20List.md) <br />
[Operations Fee](https://github.com/rafaeltokyo/stratum-sdk-go/blob/master/docs/operations/Operation%20fee.md)<br />
