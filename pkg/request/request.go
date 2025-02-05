/*
 * @Description:
 * @Author: kingqaquuu
 * @Date: 2025-01-21 16:32:29
 * @LastEditTime: 2025-01-25 00:32:05
 * @LastEditors: kingqaquuu
 */
package request

import (
	"crypto/tls"
	"fmt"
	"io"
	"k8sEPDS/conf"
	"net/http"
	"os"
	"strings"
	"time"
)

type K8sRequestOption struct {
	Token      string            // Token认证信息
	Cert       string            // 客户端证书
	Key        string            // 客户端密钥
	Server     string            // API服务器地址
	Api        string            // API路径
	Method     string            // HTTP方法
	PostData   string            // POST请求数据
	Header     map[string]string // 自定义请求头
	Timeout    time.Duration     // 请求超时时间
	RetryTimes int               // 重试次数
}

// NewK8sRequestOption 创建请求选项实例
func NewK8sRequestOption() *K8sRequestOption {
	return &K8sRequestOption{
		Server:     conf.Config.K8s.ApiServer,
		Method:     http.MethodGet,
		Header:     make(map[string]string),
		Timeout:    10 * time.Second,
		RetryTimes: 3,
	}
}

// ApiRequest 发送API请求
func ApiRequest(opts K8sRequestOption) (string, error) {
	if err := validateOptions(&opts); err != nil {
		return "", fmt.Errorf("验证请求选项失败: %w", err)
	}

	client, err := createHTTPClient(&opts)
	if err != nil {
		return "", fmt.Errorf("创建HTTP客户端失败: %w", err)
	}

	return executeRequest(client, opts)
}

// validateOptions 验证请求选项
func validateOptions(opts *K8sRequestOption) error {
	if opts.Server == "" {
		opts.Server = conf.Config.K8s.ApiServer
	}
	if opts.Server == "" {
		return fmt.Errorf("服务器地址未设置")
	}
	opts.Method = strings.ToUpper(opts.Method)
	if !isValidMethod(opts.Method) {
		return fmt.Errorf("不支持的HTTP方法: %s", opts.Method)
	}
	return nil
}

// setupAuthentication 设置认证信息
func setupAuthentication(opts *K8sRequestOption) error {
	// 1. 优先使用opts.Token
	if opts.Token != "" {
		return nil
	}

	// 2. 尝试从token文件读取
	if conf.Config.K8s.TokenFile != "" {
		tokenBytes, err := os.ReadFile(conf.Config.K8s.TokenFile)
		if err == nil && len(tokenBytes) > 0 {
			opts.Token = string(tokenBytes)
			return nil
		}
	}

	// 3. 使用证书认证
	if opts.Cert == "" {
		opts.Cert = conf.Config.K8s.AdminCert
		opts.Key = conf.Config.K8s.AdminCertKey
	}

	if opts.Cert == "" || opts.Key == "" {
		return fmt.Errorf("未配置有效的认证信息")
	}

	return nil
}

// createHTTPClient 创建HTTP客户端
func createHTTPClient(opts *K8sRequestOption) (*http.Client, error) {
	if err := setupAuthentication(opts); err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	// 如果使用证书认证
	if opts.Token == "" {
		cert, err := tls.LoadX509KeyPair(opts.Cert, opts.Key)
		if err != nil {
			return nil, fmt.Errorf("加载证书失败: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   opts.Timeout,
	}, nil
}

// executeRequest 执行HTTP请求
func executeRequest(client *http.Client, opts K8sRequestOption) (string, error) {
	url := fmt.Sprintf("https://%s%s", opts.Server, opts.Api)

	var lastErr error
	for i := 0; i <= opts.RetryTimes; i++ {
		resp, err := sendRequest(client, url, opts)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		time.Sleep(time.Second * time.Duration(i+1))
	}

	return "", fmt.Errorf("请求失败(重试%d次): %w", opts.RetryTimes, lastErr)
}

// sendRequest 发送单次请求
func sendRequest(client *http.Client, url string, opts K8sRequestOption) (string, error) {
	req, err := http.NewRequest(opts.Method, url, strings.NewReader(opts.PostData))
	if err != nil {
		return "", err
	}

	// 设置Token认证
	if opts.Token != "" {
		req.Header.Set("Authorization", "Bearer "+opts.Token)
	}
	// 设置其他请求头
	for key, value := range opts.Header {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	return string(body), nil
}

// isValidMethod 验证HTTP方法是否有效
func isValidMethod(method string) bool {
	validMethods := map[string]bool{
		http.MethodGet:    true,
		http.MethodPost:   true,
		http.MethodPut:    true,
		http.MethodDelete: true,
		http.MethodPatch:  true,
	}
	return validMethods[method]
}
