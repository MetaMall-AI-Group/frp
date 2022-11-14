package auth

import (
	"fmt"

	"github.com/fatedier/frp/pkg/msg"
	"github.com/gbrlsnchs/jwt/v3"
)

type ServerJwtConfig struct {
	JwtKey string `ini:"jwt_key" json:"jwt_key"`
}

type ClientJwtConfig struct {
	Token string `ini:"token" json:"token"`
}

func getDefaultClientJwtConf() ClientJwtConfig {
	return ClientJwtConfig{
		Token: "",
	}
}

func getDefaultServerJwtConf() ServerJwtConfig {
	return ServerJwtConfig{
		JwtKey: "",
	}
}

type JwtAuthSetterVerifier struct {
	BaseConfig

	key   string
	token string
}

func NewServerJwtAuth(baseCfg BaseConfig, cfg ServerJwtConfig) *JwtAuthSetterVerifier {
	return &JwtAuthSetterVerifier{
		BaseConfig: baseCfg,
		key:        cfg.JwtKey,
	}
}

func NewClientJwtAuth(baseCfg BaseConfig, cfg ClientJwtConfig) *JwtAuthSetterVerifier {
	return &JwtAuthSetterVerifier{
		BaseConfig: baseCfg,
		token:      cfg.Token,
	}
}

func (auth *JwtAuthSetterVerifier) SetLogin(loginMsg *msg.Login) (err error) {
	loginMsg.PrivilegeKey = auth.token
	return nil
}

func (auth *JwtAuthSetterVerifier) SetPing(pingMsg *msg.Ping) error {
	if !auth.AuthenticateHeartBeats {
		return nil
	}
	pingMsg.PrivilegeKey = auth.token
	return nil
}

func (auth *JwtAuthSetterVerifier) SetNewWorkConn(newWorkConnMsg *msg.NewWorkConn) error {

	if !auth.AuthenticateNewWorkConns {
		return nil
	}
	newWorkConnMsg.PrivilegeKey = auth.token
	return nil
}

func (auth *JwtAuthSetterVerifier) validate(tokenString string) bool {
	hs := jwt.NewHS256([]byte(auth.key))
	payload := &jwt.Payload{}
	_, err := jwt.Verify([]byte(tokenString), hs, payload)
	return err == nil
}

func (auth *JwtAuthSetterVerifier) VerifyLogin(loginMsg *msg.Login) error {

	if !auth.validate(loginMsg.PrivilegeKey) {
		return fmt.Errorf("token in login doesn't match token from configuration")
	}
	return nil
}

func (auth *JwtAuthSetterVerifier) VerifyPing(pingMsg *msg.Ping) error {
	if !auth.AuthenticateHeartBeats {
		return nil
	}

	if !auth.validate(pingMsg.PrivilegeKey) {
		return fmt.Errorf("token in login doesn't match token from configuration")
	}
	return nil
}

func (auth *JwtAuthSetterVerifier) VerifyNewWorkConn(newWorkConnMsg *msg.NewWorkConn) error {
	if !auth.AuthenticateNewWorkConns {
		return nil
	}

	if !auth.validate(newWorkConnMsg.PrivilegeKey) {
		return fmt.Errorf("token in login doesn't match token from configuration")
	}
	return nil
}
