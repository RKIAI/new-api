package controller

import (
	"encoding/json"
	"fmt"
	"net/http"
	"one-api/common"
	"one-api/constant"
	"one-api/model"
	"strings"

	"github.com/gin-gonic/gin"
)

func TestStatus(c *gin.Context) {
	err := model.PingDB()
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"success": false,
			"message": "Database connection failed",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Server is running",
	})
	return
}

func GetStatus(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
		"data": gin.H{
			"version":                  common.Version,
			"start_time":               common.StartTime,
			"email_verification":       common.EmailVerificationEnabled,
			"github_oauth":             common.GitHubOAuthEnabled,
			"github_client_id":         common.GitHubClientId,
			"telegram_oauth":           common.TelegramOAuthEnabled,
			"telegram_bot_name":        common.TelegramBotName,
			"system_name":              common.SystemName,
			"logo":                     common.Logo,
			"footer_html":              common.Footer,
			"wechat_qrcode":            common.WeChatAccountQRCodeImageURL,
			"wechat_login":             common.WeChatAuthEnabled,
			"server_address":           constant.ServerAddress,
			"price":                    constant.Price,
			"min_topup":                constant.MinTopUp,
			"turnstile_check":          common.TurnstileCheckEnabled,
			"turnstile_site_key":       common.TurnstileSiteKey,
			"top_up_link":              common.TopUpLink,
			"chat_link":                common.ChatLink,
			"chat_link2":               common.ChatLink2,
			"quota_per_unit":           common.QuotaPerUnit,
			"display_in_currency":      common.DisplayInCurrencyEnabled,
			"enable_batch_update":      common.BatchUpdateEnabled,
			"enable_drawing":           common.DrawingEnabled,
			"enable_task":              common.TaskEnabled,
			"enable_data_export":       common.DataExportEnabled,
			"data_export_default_time": common.DataExportDefaultTime,
			"default_collapse_sidebar": common.DefaultCollapseSidebar,
			"enable_online_topup":      constant.PayAddress != "" && constant.EpayId != "" && constant.EpayKey != "",
			"mj_notify_enabled":        constant.MjNotifyEnabled,
		},
	})
	return
}

func GetNotice(c *gin.Context) {
	common.OptionMapRWMutex.RLock()
	defer common.OptionMapRWMutex.RUnlock()
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
		"data":    common.OptionMap["Notice"],
	})
	return
}

func GetAbout(c *gin.Context) {
	common.OptionMapRWMutex.RLock()
	defer common.OptionMapRWMutex.RUnlock()
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
		"data":    common.OptionMap["About"],
	})
	return
}

func GetMidjourney(c *gin.Context) {
	common.OptionMapRWMutex.RLock()
	defer common.OptionMapRWMutex.RUnlock()
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
		"data":    common.OptionMap["Midjourney"],
	})
	return
}

func GetHomePageContent(c *gin.Context) {
	common.OptionMapRWMutex.RLock()
	defer common.OptionMapRWMutex.RUnlock()
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
		"data":    common.OptionMap["HomePageContent"],
	})
	return
}

func SendEmailVerification(c *gin.Context) {
	email := c.Query("email")
	if err := common.Validate.Var(email, "required,email"); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "Invalid parameters",
		})
		return
	}
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "Invalid email address",
		})
		return
	}
	localPart := parts[0]
	domainPart := parts[1]
	if common.EmailDomainRestrictionEnabled {
		allowed := false
		for _, domain := range common.EmailDomainWhitelist {
			if domainPart == domain {
				allowed = true
				break
			}
		}
		if !allowed {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"message": "The administrator has enabled the email domain name whitelist, and your email address is not allowed due to special symbols or it's not in the whitelist.",
			})
			return
		}
	}
	if common.EmailAliasRestrictionEnabled {
		containsSpecialSymbols := strings.Contains(localPart, "+") || strings.Contains(localPart, ".")
		if containsSpecialSymbols {
			c.JSON(http.StatusOK, gin.H{
				"success": false,
				"message": "Your administrator has enabled email alias restrictions and your email address was rejected because it contains special symbols.",
			})
			return
		}
	}

	if model.IsEmailAlreadyTaken(email) {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "Email address is already taken",
		})
		return
	}
	code := common.GenerateVerificationCode(6)
	common.RegisterVerificationCodeWithKey(email, code, common.EmailVerificationPurpose)
	subject := fmt.Sprintf("%sEmail verification email", common.SystemName)
	content := fmt.Sprintf("<p>Hello, you are verifying your %s email address.</p>"+
		"<p>Your verification code is:<strong>%s</strong></p>"+
		"<p>The verification code is valid for %d minutes. If it is not your own operation, please ignore it.</p>", common.SystemName, code, common.VerificationValidMinutes)
	err := common.SendEmail(subject, email, content)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
	})
	return
}

func SendPasswordResetEmail(c *gin.Context) {
	email := c.Query("email")
	if err := common.Validate.Var(email, "required,email"); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "Invalid parameters",
		})
		return
	}
	if !model.IsEmailAlreadyTaken(email) {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "This email address is not registered",
		})
		return
	}
	code := common.GenerateVerificationCode(0)
	common.RegisterVerificationCodeWithKey(email, code, common.PasswordResetPurpose)
	link := fmt.Sprintf("%s/user/reset?email=%s&token=%s", constant.ServerAddress, email, code)
	subject := fmt.Sprintf("%s Password Reset", common.SystemName)
	content := fmt.Sprintf("<p>Hello, you are resetting your %s password.</p>"+
		"<p>Click <a href='%s'>Here</a> Perform a password reset。</p>"+
		"<p>If the link does not work, please try clicking the link below or copy it into your browser:<br> %s </p>"+
		"<p>The reset link is valid for %d minutes. Please ignore it if it is not your own operation.</p>", common.SystemName, link, link, common.VerificationValidMinutes)
	err := common.SendEmail(subject, email, content)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
	})
	return
}

type PasswordResetRequest struct {
	Email string `json:"email"`
	Token string `json:"token"`
}

func ResetPassword(c *gin.Context) {
	var req PasswordResetRequest
	err := json.NewDecoder(c.Request.Body).Decode(&req)
	if req.Email == "" || req.Token == "" {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "Invalid parameters",
		})
		return
	}
	if !common.VerifyCodeWithKey(req.Email, req.Token, common.PasswordResetPurpose) {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "The reset link is invalid or expired",
		})
		return
	}
	password := common.GenerateVerificationCode(12)
	err = model.ResetUserPasswordByEmail(req.Email, password)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}
	common.DeleteKey(req.Email, common.PasswordResetPurpose)
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
		"data":    password,
	})
	return
}
