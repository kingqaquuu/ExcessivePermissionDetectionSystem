/*
 * @Description:
 * @Author: kingqaquuu
 * @Date: 2025-01-21 16:32:26
 * @LastEditTime: 2025-01-25 12:35:36
 * @LastEditors: kingqaquuu
 */
package request

import (
	"fmt"
	"k8sEPDS/conf"
	"net/http"
	"net/url"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// GetClientSet 创建Kubernetes客户端实例
// 参数:
//   - token: 认证令牌，可选
//
// 返回:
//   - *kubernetes.Clientset: Kubernetes客户端实例
//   - error: 错误信息
func GetClientSet(token string) (*kubernetes.Clientset, error) {
	// 使用request包中已有的认证逻辑
	opts := NewK8sRequestOption()
	if err := setupAuthentication(opts); err != nil {
		return nil, fmt.Errorf("认证设置失败: %w", err)
	}

	config := &rest.Config{
		Host: fmt.Sprintf("https://%s", conf.Config.K8s.ApiServer),
	}

	// 设置认证信息
	if token != "" {
		config.BearerToken = token
	} else {
		if opts.Token != "" {
			config.BearerToken = opts.Token
		} else if opts.Cert != "" && opts.Key != "" {
			config.TLSClientConfig.CertFile = opts.Cert
			config.TLSClientConfig.KeyFile = opts.Key
		}
	}
	// 设置代理
	if conf.Config.K8s.ProxyAddress != "" {
		proxyURL, err := url.Parse(conf.Config.K8s.ProxyAddress)
		if err != nil {
			return nil, fmt.Errorf("代理地址解析失败: %w", err)
		}
		config.Proxy = func(_ *http.Request) (*url.URL, error) {
			return proxyURL, nil
		}
	}

	// TLS配置
	config.TLSClientConfig.Insecure = true
	
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
        return nil, fmt.Errorf("创建客户端失败: %w", err)
    }
	return clientset, nil
}
