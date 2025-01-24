/*
 * @Description:
 * @Author: kingqaquuu
 * @Date: 2025-01-21 16:32:26
 * @LastEditTime: 2025-01-21 16:32:41
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

func GetClientSet(token string) *kubernetes.Clientset {
	config := &rest.Config{}
	if token == "" {
		rawToken, _ := os.ReadFile(conf.Config.K8s.TokenFile)
		token = string(rawToken)
		if token == "" {
			config.TLSClientConfig.CertFile = conf.Config.K8s.AdminCert
			config.TLSClientConfig.KeyFile = conf.Config.K8s.AdminCertKey
		}
	}
	if conf.Config.K8s.ProxyAddress != "" {
		proxyURL := conf.Config.K8s.ProxyAddress
		proxy := func(_ *http.Request) (*url.URL, error) {
			return url.Parse(proxyURL)
		}
		config.WrapTransport = func(rt http.RoundTripper) http.RoundTripper {
			return &http.Transport{
				Proxy: proxy,
				// Other configurations can be made as needed.
			}
		}
	}
	config.TLSClientConfig.Insecure = true
	if token != "" {
		config.BearerToken = token
	}
	config.Host = "https://" + conf.Config.K8s.ApiServer
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		fmt.Printf("Error creating kubernetes client: %v\n", err)
	}
	return clientset
}
