/*
 * @Description:
 * @Author: kingqaquuu
 * @Date: 2025-01-21 16:30:34
 * @LastEditTime: 2025-01-25 13:06:12
 * @LastEditors: kingqaquuu
 */
package utils

import (
	"fmt"
	"k8sEPDS/models"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Contains 检查切片中是否包含指定元素
// 参数:
//   - arr: 待检查的字符串切片
//   - target: 目标字符串
//
// 返回:
//   - bool: 如果包含返回true，否则返回false

func Contains(arr []string, target string) bool {
	if len(arr) == 0 || target == "" {
		return false
	}

	for _, s := range arr {
		if s == target {
			return true
		}
	}
	return false
}

// CheckRestrict 检查访问限制类型
// 参数:
//   - k: 键值
//   - rawType: 原始类型
//   - criticalSA: 关键ServiceAccount配置
//
// 返回:
//   - string: 处理后的限制类型
func CheckRestrict(k string, rawType string, criticalSA *models.CriticalSA) string {

	result := rawType
	if strings.Contains(k, "(") {
		result = rawType + k[strings.Index(k, "("):]
	} else if strings.Contains(k, "[") {
		result = rawType + k[strings.Index(k, "["):]
	} else {
		criticalSA.Level = "cluster"
	}
	//Update
	if strings.Contains(k, "(") {
		criticalSA.ResourceName = strings.Trim(k[strings.Index(k, "("):], "()")
	}
	if strings.Contains(k, "[") {
		criticalSA.Namespace = strings.Trim(k[strings.Index(k, "["):], "[]")
	}
	return result
}


// ReadRemoteFile 读取远程文件内容
// 参数:
//   - config: SSH连接配置
//   - filePath: 要读取的文件路径
//
// 返回:
//   - string: 文件内容
//   - error: 错误信息
func ReadRemoteFile(config models.SSHConfig, filePath string) (string, error) {
	// SSH configuration information of the remote host
	sshConfig := &ssh.ClientConfig{
		User:            config.Username,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// 设置认证方式
    auth, err := getAuthMethod(config)
    if err != nil {
        return "", fmt.Errorf("认证设置失败: %w", err)
    }
    sshConfig.Auth = []ssh.AuthMethod{auth}

	// 连接远程主机
    client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", config.Host, config.Port), sshConfig)
    if err != nil {
        return "", fmt.Errorf("连接失败: %w", err)
    }
    defer client.Close()


	// 创建会话
    session, err := client.NewSession()
    if err != nil {
        return "", fmt.Errorf("创建会话失败: %w", err)
    }
    defer session.Close()

	// 执行命令读取文件
    output, err := session.CombinedOutput("cat " + filePath)
    if err != nil {
        return "", fmt.Errorf("执行命令失败: %w", err)
    }

    return string(output), nil
}


// getAuthMethod 获取SSH认证方法
func getAuthMethod(config models.SSHConfig) (ssh.AuthMethod, error) {
    if config.PrivateKeyFile != "" {
        privateKeyBytes, err := os.ReadFile(config.PrivateKeyFile)
        if err != nil {
            return nil, fmt.Errorf("读取私钥文件失败: %w", err)
        }
        privateKey, err := ssh.ParsePrivateKey(privateKeyBytes)
        if err != nil {
            return nil, fmt.Errorf("解析私钥失败: %w", err)
        }
        return ssh.PublicKeys(privateKey), nil
    }
    return ssh.Password(config.Password), nil
}