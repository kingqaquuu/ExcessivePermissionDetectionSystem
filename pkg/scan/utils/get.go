package utils

import (
	"fmt"
	apis "k8sEPDS/models"
	"k8sEPDS/pkg/request"
	"strings"

	"github.com/tidwall/gjson"
)

// k8sRequest 封装Kubernetes API请求
func k8sRequest(api string) ([]gjson.Result, error) {
    opts := request.K8sRequestOption{
        Api:    api,
        Method: "GET",
    }
    resp, err := request.ApiRequest(opts)
    if err != nil {
        return nil, fmt.Errorf("API请求失败: %w", err)
    }
    return gjson.Get(resp, "items").Array(), nil
}

// parseKubePod 解析Pod数据
func parseKubePod(pod gjson.Result) apis.Pod {
    newPod := apis.Pod{
        Namespace:      pod.Get("metadata.namespace").String(),
        Name:           pod.Get("metadata.name").String(),
        Uid:            pod.Get("metadata.uid").String(),
        NodeName:       pod.Get("spec.nodeName").String(),
        ServiceAccount: pod.Get("spec.serviceAccountName").String(),
    }

    // 设置Token挂载状态
    if tokenMounted := pod.Get("spec.automountServiceAccountToken"); tokenMounted.Exists() {
        newPod.TokenMounted = tokenMounted.Bool()
    } else {
        newPod.TokenMounted = true
    }

    // 设置控制器信息
    if owners := pod.Get("metadata.ownerReferences"); owners.Exists() {
        newPod.ControllBy = make([]string, 0)
        for _, owner := range owners.Array() {
            newPod.ControllBy = append(newPod.ControllBy, owner.Get("kind").String())
        }
    }

    return newPod
}


// GetPods 获取所有Pod信息
// 返回:
//   - []apis.Pod: Pod列表
//   - error: 错误信息
func GetPods() ([]apis.Pod, error) {
	pods, err := k8sRequest("/api/v1/pods")
    if err != nil {
        return nil, err
    }

    podList := make([]apis.Pod, 0, len(pods))

	for _, pod := range pods {
		newPod := parseKubePod(pod)
		podList = append(podList, newPod)
	}
	return podList, nil
}

// parseRoleBinding 解析RoleBinding数据
func parseRoleBinding(binding gjson.Result, namespace string) apis.RoleBinding {
    newBinding := apis.RoleBinding{
        Namespace: namespace,
        Name:      binding.Get("metadata.name").String(),
        RoleRef:   binding.Get("roleRef.name").String(),
    }

    if subjects := binding.Get("subjects"); subjects.Exists() {
        for _, sa := range subjects.Array() {
            if sa.Get("kind").String() == "ServiceAccount" {
                subject := fmt.Sprintf("%s/%s", sa.Get("namespace").String(), sa.Get("name").String())
                newBinding.Subject = append(newBinding.Subject, subject)
            }
        }
    }

    return newBinding
}


// GetClusterRoleBindings 获取所有ClusterRoleBinding
// 返回:
//   - []apis.RoleBinding: ClusterRoleBinding列表
func GetClusterRoleBindings() ([]apis.RoleBinding,error) {
	bindings, err := k8sRequest("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings")
    if err != nil {
        return nil, err
    }

	bindingList := make([]apis.RoleBinding, 0, len(bindings))
    for _, binding := range bindings {
        newBinding := parseRoleBinding(binding, binding.Get("metadata.namespace").String())
        bindingList = append(bindingList, newBinding)
    }
    return bindingList, nil
}

func GetRolesBindings() ([]apis.RoleBinding, error) {
	bindings, err := k8sRequest("/apis/rbac.authorization.k8s.io/v1/rolebindings")
    if err != nil {
        return nil, err
    }

    bindingList := make([]apis.RoleBinding, 0, len(bindings))
    for _, binding := range bindings {
        newBinding := parseRoleBinding(binding, binding.Get("metadata.namespace").String())
        bindingList = append(bindingList, newBinding)
    }
    return bindingList, nil
}

// GetRulesFromRole 获取Role的规则
// 参数:
//   - role: role的名称 (格式: namespace/name 或 name)
//
// 返回:
//   - []apis.Rule: 规则列表
func GetRulesFromRole(role string) ([]apis.Rule, error) {
    api := buildRoleAPI(role)
    opts := request.K8sRequestOption{
        Api:    api,
        Method: "GET",
    }

    resp, err := request.ApiRequest(opts)
    if err != nil {
        return nil, fmt.Errorf("获取Role规则失败: %w", err)
    }

    return parseRules(gjson.Get(resp, "rules").Array()), nil
}


// buildRoleAPI 构建Role API路径
func buildRoleAPI(role string) string {
    baseAPI := "/apis/rbac.authorization.k8s.io/v1"
    if strings.Contains(role, "/") {
        parts := strings.SplitN(role, "/", 2)
        return fmt.Sprintf("%s/namespaces/%s/roles/%s", baseAPI, parts[0], parts[1])
    }
    return fmt.Sprintf("%s/clusterroles/%s", baseAPI, role)
}


// parseRules 解析规则数据
func parseRules(rules []gjson.Result) []apis.Rule {
    ruleList := make([]apis.Rule, 0, len(rules))
    for _, rule := range rules {
        newRule := apis.Rule{
            Resourcs: make([]string, 0),
            Verbs:    make([]string, 0),
        }

        // 解析资源
        for _, res := range rule.Get("resources").Array() {
            if resourceNames := rule.Get("resourceNames"); resourceNames.Exists() {
                for _, resName := range resourceNames.Array() {
                    resource := fmt.Sprintf("%s(%s)", res.String(), resName.String())
                    newRule.Resourcs = append(newRule.Resourcs, resource)
                }
            } else {
                newRule.Resourcs = append(newRule.Resourcs, res.String())
            }
        }

        // 解析动作
        for _, verb := range rule.Get("verbs").Array() {
            newRule.Verbs = append(newRule.Verbs, verb.String())
        }

        ruleList = append(ruleList, newRule)
    }
    return ruleList
}