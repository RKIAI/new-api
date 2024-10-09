package controller

import (
	"fmt"
	"github.com/Calcium-Ion/go-epay/epay"
	"github.com/gin-gonic/gin"
	"github.com/samber/lo"
	"log"
	"net/url"
	"one-api/common"
	"one-api/constant"
	"one-api/model"
	"one-api/service"
	"strconv"
	"sync"
	"time"
)

type EpayRequest struct {
	Amount        int    `json:"amount"`
	PaymentMethod string `json:"payment_method"`
	TopUpCode     string `json:"top_up_code"`
}

type AmountRequest struct {
	Amount    int    `json:"amount"`
	TopUpCode string `json:"top_up_code"`
}

func GetEpayClient() *epay.Client {
	if constant.PayAddress == "" || constant.EpayId == "" || constant.EpayKey == "" {
		return nil
	}
	withUrl, err := epay.NewClient(&epay.Config{
		PartnerID: constant.EpayId,
		Key:       constant.EpayKey,
	}, constant.PayAddress)
	if err != nil {
		return nil
	}
	return withUrl
}

func getPayMoney(amount float64, group string) float64 {
	if !common.DisplayInCurrencyEnabled {
		amount = amount / common.QuotaPerUnit
	}
	// 别问为什么用float64，问就是这么点钱没必要
	topupGroupRatio := common.GetTopupGroupRatio(group)
	if topupGroupRatio == 0 {
		topupGroupRatio = 1
	}
	payMoney := amount * constant.Price * topupGroupRatio
	return payMoney
}

func getMinTopup() int {
	minTopup := constant.MinTopUp
	if !common.DisplayInCurrencyEnabled {
		minTopup = minTopup * int(common.QuotaPerUnit)
	}
	return minTopup
}

func RequestEpay(c *gin.Context) {
	var req EpayRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		c.JSON(200, gin.H{"message": "error", "data": "Parameter error"})
		return
	}
	if req.Amount < getMinTopup() {
		c.JSON(200, gin.H{"message": "error", "data": fmt.Sprintf("The recharge amount cannot be less than %d", getMinTopup())})
		return
	}

	id := c.GetInt("id")
	group, err := model.CacheGetUserGroup(id)
	if err != nil {
		c.JSON(200, gin.H{"message": "error", "data": "Failed to obtain user group"})
		return
	}
	payMoney := getPayMoney(float64(req.Amount), group)
	if payMoney < 0.01 {
		c.JSON(200, gin.H{"message": "error", "data": "Recharge amount is too low"})
		return
	}

	var payType epay.PurchaseType
	if req.PaymentMethod == "zfb" {
		payType = epay.Alipay
	}
	if req.PaymentMethod == "wx" {
		req.PaymentMethod = "wxpay"
		payType = epay.WechatPay
	}
	callBackAddress := service.GetCallbackAddress()
	returnUrl, _ := url.Parse(constant.ServerAddress + "/log")
	notifyUrl, _ := url.Parse(callBackAddress + "/api/user/epay/notify")
	tradeNo := fmt.Sprintf("%s%d", common.GetRandomString(6), time.Now().Unix())
	tradeNo = fmt.Sprintf("USR%dNO%s", id, tradeNo)
	client := GetEpayClient()
	if client == nil {
		c.JSON(200, gin.H{"message": "error", "data": "The current administrator has not configured payment information"})
		return
	}
	uri, params, err := client.Purchase(&epay.PurchaseArgs{
		Type:           payType,
		ServiceTradeNo: tradeNo,
		Name:           fmt.Sprintf("TUC%d", req.Amount),
		Money:          strconv.FormatFloat(payMoney, 'f', 2, 64),
		Device:         epay.PC,
		NotifyUrl:      notifyUrl,
		ReturnUrl:      returnUrl,
	})
	if err != nil {
		c.JSON(200, gin.H{"message": "error", "data": "Payment failed"})
		return
	}
	amount := req.Amount
	if !common.DisplayInCurrencyEnabled {
		amount = amount / int(common.QuotaPerUnit)
	}
	topUp := &model.TopUp{
		UserId:     id,
		Amount:     amount,
		Money:      payMoney,
		TradeNo:    tradeNo,
		CreateTime: time.Now().Unix(),
		Status:     "pending",
	}
	err = topUp.Insert()
	if err != nil {
		c.JSON(200, gin.H{"message": "error", "data": "Failed to create order"})
		return
	}
	c.JSON(200, gin.H{"message": "success", "data": params, "url": uri})
}

// tradeNo lock
var orderLocks sync.Map
var createLock sync.Mutex

// LockOrder 尝试对给定订单号加锁
func LockOrder(tradeNo string) {
	lock, ok := orderLocks.Load(tradeNo)
	if !ok {
		createLock.Lock()
		defer createLock.Unlock()
		lock, ok = orderLocks.Load(tradeNo)
		if !ok {
			lock = new(sync.Mutex)
			orderLocks.Store(tradeNo, lock)
		}
	}
	lock.(*sync.Mutex).Lock()
}

// UnlockOrder 释放给定订单号的锁
func UnlockOrder(tradeNo string) {
	lock, ok := orderLocks.Load(tradeNo)
	if ok {
		lock.(*sync.Mutex).Unlock()
	}
}

func EpayNotify(c *gin.Context) {
	params := lo.Reduce(lo.Keys(c.Request.URL.Query()), func(r map[string]string, t string, i int) map[string]string {
		r[t] = c.Request.URL.Query().Get(t)
		return r
	}, map[string]string{})
	client := GetEpayClient()
	if client == nil {
		log.Println("EasyPay callback failed. Configuration information not found.")
		_, err := c.Writer.Write([]byte("fail"))
		if err != nil {
			log.Println("EasyPay callback writing failed")
			return
		}
	}
	verifyInfo, err := client.Verify(params)
	if err == nil && verifyInfo.VerifyStatus {
		_, err := c.Writer.Write([]byte("success"))
		if err != nil {
			log.Println("EasyPay callback writing failed")
		}
	} else {
		_, err := c.Writer.Write([]byte("fail"))
		if err != nil {
			log.Println("EasyPay callback writing failed")
		}
		log.Println("EasyPay callback signature verification failed")
		return
	}

	if verifyInfo.TradeStatus == epay.StatusTradeSuccess {
		log.Println(verifyInfo)
		LockOrder(verifyInfo.ServiceTradeNo)
		defer UnlockOrder(verifyInfo.ServiceTradeNo)
		topUp := model.GetTopUpByTradeNo(verifyInfo.ServiceTradeNo)
		if topUp == nil {
			log.Printf("Yifuzhi callback order not found: %v", verifyInfo)
			return
		}
		if topUp.Status == "pending" {
			topUp.Status = "success"
			err := topUp.Update()
			if err != nil {
				log.Printf("EasyPay callback to update order failed: %v", topUp)
				return
			}
			//user, _ := model.GetUserById(topUp.UserId, false)
			//user.Quota += topUp.Amount * 500000
			err = model.IncreaseUserQuota(topUp.UserId, topUp.Amount*int(common.QuotaPerUnit))
			if err != nil {
				log.Printf("Yifu payment callback failed to update user: %v", topUp)
				return
			}
			log.Printf("Yifu Pay callback to update user successfully %v", topUp)
			model.RecordLog(topUp.UserId, model.LogTypeTopup, fmt.Sprintf("Online recharge is successful, recharge amount: %v, payment amount:%f", common.LogQuota(topUp.Amount*int(common.QuotaPerUnit)), topUp.Money))
		}
	} else {
		log.Printf("Yifuzhi abnormal callback: %v", verifyInfo)
	}
}

func RequestAmount(c *gin.Context) {
	var req AmountRequest
	err := c.ShouldBindJSON(&req)
	if err != nil {
		c.JSON(200, gin.H{"message": "error", "data": "Parameter error"})
		return
	}

	if req.Amount < getMinTopup() {
		c.JSON(200, gin.H{"message": "error", "data": fmt.Sprintf("The recharge amount cannot be less than %d", getMinTopup())})
		return
	}
	id := c.GetInt("id")
	group, err := model.CacheGetUserGroup(id)
	if err != nil {
		c.JSON(200, gin.H{"message": "error", "data": "Failed to obtain user group"})
		return
	}
	payMoney := getPayMoney(float64(req.Amount), group)
	if payMoney <= 0.01 {
		c.JSON(200, gin.H{"message": "error", "data": "Recharge amount is too low"})
		return
	}
	c.JSON(200, gin.H{"message": "success", "data": strconv.FormatFloat(payMoney, 'f', 2, 64)})
}
