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
	"io/ioutil"
	"k8sEPDS/conf"
	"net/http"
	"net/url"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func GetClientSet(token string) *kubernetes.Clientset {
	config := &rest.Config{}
	if token == "" {
		rawToken, _ := ioutil.ReadFile(conf.TokenFile)
		token = string(rawToken)
		if token == "" {
			config.TLSClientConfig.CertFile = conf.AdminCert
			config.TLSClientConfig.KeyFile = conf.AdminCertKey
		}
	}
	if conf.ProxyAddress != "" {
		proxyURL := conf.ProxyAddress
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
	config.Host = "https://" + conf.ApiServer //"https://192.168.183.130:6443"
	// config = &rest.Config{
	// 	BearerToken: token,
	// 	Host:        "https://" + conf.ApiServer, //"https://192.168.183.130:6443"
	// 	TLSClientConfig: rest.TLSClientConfig{
	// 		Insecure: true,
	// 		// CAData: []byte(""), If Insecure: true is not enabled, CAData is required.
	// 	},
	// }
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		fmt.Printf("Error creating kubernetes client: %v\n", err)
	}
	return clientset
}
