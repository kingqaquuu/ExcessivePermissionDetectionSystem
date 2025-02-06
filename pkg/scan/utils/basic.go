package utils

import (
	"fmt"
	"k8sEPDS/models"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Contains 判断目标字符串 target 是否存在于字符串数组 arr 中
// 返回值:
//   true  - 如果 target 存在于 arr 中
//   false - 如果 target 不存在于 arr 中
func Contains(arr []string, target string) bool {
	for _, s := range arr {
		if s == target {
			return true
		}
	}
	return false
}

// CheckRestrict 根据传入的字符串 k 判断资源的约束信息，并更新 criticalSA 中相关字段。
// 参数:
//   k           - 包含资源约束信息的字符串，如 "resource(resourceName)" 或 "resource[namespace]"
//   rawType     - 原始类型字符串，用于拼接约束信息，返回结果中将包含该约束后缀
//   criticalSA  - 指向 models.CriticalSA 对象的指针，用于更新 Level、ResourceName 和 Namespace 字段
// 返回值:
//   拼接后的约束类型字符串
func CheckRestrict(k string, rawType string, criticalSA *models.CriticalSA) string {
	result := rawType
	// 尝试查找 "(" 字符，表示资源名称约束
	if idx := strings.Index(k, "("); idx != -1 {
        result = rawType + k[idx:]
        // 将括号中的内容提取出来，更新 ResourceName 字段
        criticalSA.ResourceName = strings.Trim(k[idx:], "()")
    } else if idx := strings.Index(k, "["); idx != -1 {
        // 查找 "[" 字符，表示命名空间约束
        result = rawType + k[idx:]
        // 将中括号中的内容提取出来，更新 Namespace 字段
        criticalSA.Namespace = strings.Trim(k[idx:], "[]")
    } else {
        // 如果 k 中既不包含 "(" 也不包含 "["，则认为资源级别为集群级别
        criticalSA.Level = "cluster"
    }
    return result
}

// ReadRemoteFile 通过 SSH 连接远程主机，读取指定文件内容并返回。  
// 参数:
//   host           - 远程主机地址
//   port           - SSH 端口号
//   username       - SSH 登录用户名
//   password       - 密码（当 privateKeyFile 为空时使用）
//   privateKeyFile - 私钥文件路径（非空时使用私钥认证）
//   filePath       - 要读取的远程文件路径
// 返回值:
//   string - 文件内容
//   error  - 可能产生的错误
func ReadRemoteFile(host string, port int, username, password, privateKeyFile string, filePath string) (string, error) {
	// 设置 SSH 配置
	sshConfig := &ssh.ClientConfig{
		User:            username,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	// 如果提供了私钥文件，则使用私钥认证；否则使用密码认证
	if privateKeyFile != "" {
		// 读取私钥文件内容
		privateKeyBytes, err := os.ReadFile(privateKeyFile)
		if err != nil {
			return "", fmt.Errorf("读取私钥文件失败: %w", err)
		}
		// 解析私钥
        privateKey, err := ssh.ParsePrivateKey(privateKeyBytes)
        if err != nil {
            return "", fmt.Errorf("解析私钥失败: %w", err)
        }
		sshConfig.Auth = []ssh.AuthMethod{ssh.PublicKeys(privateKey)}

	} else {
		sshConfig.Auth = []ssh.AuthMethod{ssh.Password(password)}
	}

	// 构建远程地址
    addr := fmt.Sprintf("%s:%d", host, port)
	// 建立 SSH 连接
    client, err := ssh.Dial("tcp", addr, sshConfig)
    if err != nil {
        return "", fmt.Errorf("连接 %s 失败: %w", addr, err)
    }
    defer client.Close()

	// 创建新 SSH 会话
    session, err := client.NewSession()
    if err != nil {
        return "", fmt.Errorf("创建 SSH 会话失败: %w", err)
    }
    defer session.Close()

	// 构建命令，执行 cat 命令读取文件内容
    cmd := fmt.Sprintf("cat %s", filePath)
    output, err := session.CombinedOutput(cmd)
    if err != nil {
        return "", fmt.Errorf("执行命令 %q 失败: %w", cmd, err)
    }

	// Return file content
	return string(output), nil
}
