package common

import (
	"encoding/json"
)

var UserUsableGroups = map[string]string{
	"default": "Default Group",
	"vip":     "Vip Group",
}

func UserUsableGroups2JSONString() string {
	jsonBytes, err := json.Marshal(UserUsableGroups)
	if err != nil {
		SysError("error marshalling user groups: " + err.Error())
	}
	return string(jsonBytes)
}

func UpdateUserUsableGroupsByJSONString(jsonStr string) error {
	UserUsableGroups = make(map[string]string)
	return json.Unmarshal([]byte(jsonStr), &UserUsableGroups)
}
