package main

import (
	"fmt"
	"k8sEPDS/cmd"
	"k8sEPDS/conf"
	"k8sEPDS/models"

	"github.com/spf13/viper"
)

func main() {
	cmd.Main()
}
func init() {
	viper.SetConfigFile(".\\conf\\conf.yaml")
	if err := viper.ReadInConfig(); err != nil {
		fmt.Printf("读取配置文件失败: %s\n", err)
		return
	}

	var k8sConfig models.K8sEPDSConfig
	if err := viper.UnmarshalKey("k8s.0",&k8sConfig.K8s);err!=nil{
		fmt.Printf("解析 K8s 配置失败: %s\n", err)
		return
	}
	conf.Config.K8s	= k8sConfig.K8s
	if err := viper.UnmarshalKey("ssh.0", &k8sConfig.SSH); err != nil {
		fmt.Printf("解析 SSH 配置失败: %s\n", err)
		return
	}
	conf.Config.SSH = k8sConfig.SSH
}
