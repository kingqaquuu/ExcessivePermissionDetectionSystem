/*
 * @Description:
 * @Author: kingqaquuu
 * @Date: 2025-01-21 16:27:21
 * @LastEditTime: 2025-01-24 21:44:29
 * @LastEditors: kingqaquuu
 */
package conf

import (
	"fmt"
	"io"
	"k8sEPDS/models"
	"strconv"
)

var Config models.K8sEPDSConfig

// updateStringField 更新字符串类型的配置字段
// 参数:
//   - prompt: 提示信息
//   - currentValue: 当前值
//
// 返回:
//   - string: 更新后的值，如果用户未输入则返回当前值
func updateStringField(prompt string, currentValue string) string {
	var input string
	fmt.Printf("%s (当前值: %s): ", prompt, currentValue)
	if _, err := fmt.Scanln(&input); err != nil && err != io.EOF {
		return currentValue
	}
	if input != "" {
		return input
	}
	return currentValue
}

// updateIntField 更新整数类型的配置字段
// 参数:
//   - prompt: 提示信息
//   - currentValue: 当前值
//
// 返回:
//   - int: 更新后的值，如果用户输入无效则返回当前值
func updateIntField(prompt string, currentValue int) int {
	var input string
	fmt.Printf("%s (当前值: %d): ", prompt, currentValue)
	if _, err := fmt.Scanln(&input); err != nil && err != io.EOF {
		return currentValue
	}
	if input != "" {
		if val, err := strconv.Atoi(input); err == nil {
			return val
		}
		fmt.Println("输入的不是有效的数字，保持原值")
	}
	return currentValue
}

// UpdateConfig 更新系统配置信息
// 交互式更新 K8s 和 SSH 的配置项
// 包括 API 服务器地址、代理地址、认证信息和 SSH 连接信息
func UpdateConfig() {
	// 更新基本配置
	fmt.Println("\n=== K8S 配置更新 ===")
	Config.K8s.ApiServer = updateStringField("Kubernetes API Server地址", Config.K8s.ApiServer)
	Config.K8s.ProxyAddress = updateStringField("Kubernetes 代理地址", Config.K8s.ProxyAddress)
	Config.K8s.TokenFile = updateStringField("Token文件路径", Config.K8s.TokenFile)
	Config.K8s.Kubeconfig = updateStringField("Kubeconfig文件路径", Config.K8s.Kubeconfig)
	Config.K8s.AdminCert = updateStringField("管理员证书路径", Config.K8s.AdminCert)
	Config.K8s.AdminCertKey = updateStringField("管理员证书密钥路径", Config.K8s.AdminCertKey)
	// 更新SSH配置
	fmt.Println("\n=== SSH 配置更新 ===")
	Config.SSH.Host = updateStringField("SSH 主机地址", Config.SSH.Host)
	Config.SSH.Username = updateStringField("SSH 用户名", Config.SSH.Username)
	Config.SSH.Password = updateStringField("SSH 密码", Config.SSH.Password)
	Config.SSH.Port = updateIntField("SSH 端口", Config.SSH.Port)
	Config.SSH.PrivateKeyFile = updateStringField("SSH 私钥地址", Config.SSH.PrivateKeyFile)
	Config.SSH.Nodename = updateStringField("目标主机节点名称", Config.SSH.Nodename)
	// 验证配置
	if err := validateConfig(Config); err != nil {
		fmt.Printf("配置验证失败: %v\n", err)
	}
}

// validateConfig 验证配置信息的有效性
// 参数:
//   - config: K8sEPDSConfig 类型的配置对象
//
// 返回:
//   - error: 如果配置无效返回错误信息，否则返回 nil
func validateConfig(config models.K8sEPDSConfig) error {
	if config.K8s.ApiServer == "" {
		return fmt.Errorf("API Server 地址不能为空")
	}

	if config.SSH.Port <= 0 || config.SSH.Port > 65535 {
		return fmt.Errorf("SSH 端口号无效 (1-65535)")
	}

	if config.SSH.Host == "" {
		return fmt.Errorf("SSH 主机地址不能为空")
	}

	return nil
}

// GetConfig 打印当前配置信息
// 显示所有 K8s 和 SSH 相关的配置项当前值
func GetConfig() {
	fmt.Println("\n=== Kubernetes 配置 ===")
	printConfigItem("API Server", Config.K8s.ApiServer)
	printConfigItem("代理地址", Config.K8s.ProxyAddress)
	printConfigItem("Token 文件地址", Config.K8s.TokenFile)
	printConfigItem("Kubeconfig", Config.K8s.Kubeconfig)
	printConfigItem("管理员证书地址", Config.K8s.AdminCert)
	printConfigItem("证书密钥地址", Config.K8s.AdminCertKey)

	fmt.Println("\n=== SSH 配置 ===")
	printConfigItem("主机地址", Config.SSH.Host)
	printConfigItem("端口", strconv.Itoa(Config.SSH.Port))
	printConfigItem("用户名", Config.SSH.Username)
	printConfigItem("密码", maskPassword(Config.SSH.Password))
	printConfigItem("私钥文件地址", Config.SSH.PrivateKeyFile)
	printConfigItem("节点名称", Config.SSH.Nodename)
}

// printConfigItem 打印配置项
func printConfigItem(name, value string) {
    fmt.Printf("%-15s: %s\n", name, value)
}

// maskPassword 对密码进行掩码处理
func maskPassword(password string) string {
    if password == "" {
        return ""
    }
    return "********"
}