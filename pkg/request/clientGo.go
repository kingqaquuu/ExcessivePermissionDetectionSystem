/*
 * @Description:
 * @Author: kingqaquuu
 * @Date: 2025-01-21 16:32:26
 * @LastEditTime: 2025-02-06 20:14:11
 * @LastEditors: kingqaquuu
 */
package request

import (
	"fmt"
	"k8sEPDS/conf"
	"net/http"
	"net/url"
	"os"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// GetClientSet 根据传入的 token（若为空则从配置文件中读取）创建并返回一个 Kubernetes Clientset。
// 如果无法创建，则返回 error。
func GetClientSet(token string) (*kubernetes.Clientset, error) {
	config := &rest.Config{}
	// 当 token 为空时，从配置文件中读取 token 文件内容
	if token == "" {
		rawToken, err := os.ReadFile(conf.Config.K8s.TokenFile)
		if err != nil {
			return nil, fmt.Errorf("读取 token 文件失败: %w", err)
		}
		token = string(rawToken)
		// 如果 token 仍为空，则采用证书认证方式
		if token == "" {
			config.TLSClientConfig.CertFile = conf.Config.K8s.AdminCert
			config.TLSClientConfig.KeyFile = conf.Config.K8s.AdminCertKey
		}
	}
	// 如果配置了代理地址，则设置代理
	if conf.Config.K8s.ProxyAddress != "" {
		proxyURL, err := url.Parse(conf.Config.K8s.ProxyAddress)
		if err != nil {
			return nil, fmt.Errorf("解析代理地址失败: %w", err)
		}
		config.Proxy = http.ProxyURL(proxyURL)
	}
	// 生产环境下请勿开启非安全模式(Insecure)，此处为简化使用
    config.TLSClientConfig.Insecure = true
	// 当 token 不为空时，设置 BearerToken
    if token != "" {
        config.BearerToken = token
    }
	// 设置 API Server 地址
    config.Host = "https://" + conf.Config.K8s.ApiServer
	// 创建 Kubernetes ClientSet
    clientset, err := kubernetes.NewForConfig(config)
    if err != nil {
        return nil, fmt.Errorf("创建 kubernetes client 失败: %w", err)
    }
    return clientset, nil
}
