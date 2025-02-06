package utils

import (
	"context"
	apis "k8sEPDS/models"
	"k8sEPDS/pkg/request"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

// GetPods 使用 client-go 获取集群中所有 Pod，并转换为自定义结构 apis.Pod
// 返回值:
//    []apis.Pod - 转换后的 Pod 列表
//    error      - 获取过程中产生的错误
func GetPods()([]apis.Pod, error){
	// 获取 Kubernetes ClientSet 对象
	clientset,err := request.GetClientSet("")
    if err != nil {
        // 获取 Kubernetes ClientSet 对象失败，返回 nil
        return nil,err
    }
	// 使用 client-go 列出所有命名空间中的 Pod
	pods, err := clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	// 预分配 slice 容量
	podList := make([]apis.Pod, 0, len(pods.Items))
	// 遍历每个 Pod 并转换为自定义的 apis.Pod 结构
	for _, pod := range pods.Items {
		newPod := apis.Pod{
			Namespace:      pod.Namespace,
			Name:           pod.Name,
			Uid:            string(pod.UID),
			NodeName:       pod.Spec.NodeName,
			ServiceAccount: pod.Spec.ServiceAccountName,
		}
		// 如果未显式设置，默认 TokenMounted 为 true
		if pod.Spec.AutomountServiceAccountToken != nil {
			newPod.TokenMounted = *pod.Spec.AutomountServiceAccountToken
		} else {
			newPod.TokenMounted = true
		}
		// 根据 OwnerReferences 直接分配切片容量
		if len(pod.OwnerReferences) > 0 {
			newPod.ControllBy = make([]string, 0)
			for _, owner := range pod.OwnerReferences {
				newPod.ControllBy = append(newPod.ControllBy, owner.Kind)
			}
		}
		podList = append(podList, newPod)
	}
	return podList, nil
}

// GetClusterRoleBindings 使用 client-go 获取所有 ClusterRoleBindings，并转换为 apis.RoleBinding 结构
// 返回值:
//    []apis.RoleBinding - 转换后的 ClusterRoleBindings 列表
//    error              - 获取过程中产生的错误
func GetClusterRoleBindings() ([]apis.RoleBinding, error){
	// 从 request 包中获取 Kubernetes ClientSet
	clientset,err := request.GetClientSet("")
    if err != nil {
        // 获取 Kubernetes ClientSet 对象失败，返回 nil
        return nil,err
    }
	// 使用 client-go 列出所有 ClusterRoleBindings
	crbList, err := clientset.RbacV1().ClusterRoleBindings().List(context.TODO(), metav1.ListOptions{})
    if err != nil {
        return nil, err
    }
	// 根据获取到的条数预分配 slice 空间
	clusterRoleBindingList := make([]apis.RoleBinding, 0, len(crbList.Items))
	// 遍历每个 ClusterRoleBinding 并转换为自定义结构 apis.RoleBinding
	for _, crb:=range crbList.Items{
		newClusterRoleBinding := apis.RoleBinding{
			Namespace: "",          // ClusterRoleBinding 是集群级别对象，无命名空间
            Name:      crb.Name,      // 绑定名称
            RoleRef:   crb.RoleRef.Name, // 关联的角色名称
		}
		// 遍历 crb 中所有的 Subject
		for _, subject := range crb.Subjects {
			// 仅处理 Kind 为 ServiceAccount 的 Subject
            if subject.Kind != "ServiceAccount" {
                continue
            }
			// 将 Subject 的命名空间和名称拼接（格式：namespace/name）并添加到列表中
            newClusterRoleBinding.Subject = append(newClusterRoleBinding.Subject, subject.Namespace+"/"+subject.Name)
        }
		// 将转换后的 RoleBinding 添加到结果列表中
		clusterRoleBindingList = append(clusterRoleBindingList, newClusterRoleBinding)
	}
	return clusterRoleBindingList, nil
}

// GetRolesBindings 使用 client-go 获取所有命名空间中的 RoleBindings，并转换为自定义结构 apis.RoleBinding
// 返回值:
//    []apis.RoleBinding - 转换后的 RoleBinding 列表
//    error              - 获取过程中产生的错误
func GetRolesBindings() ([]apis.RoleBinding, error) {
	// 从 request 包中获取 Kubernetes ClientSet
	clientset,err := request.GetClientSet("")
    if err != nil {
        // 获取 Kubernetes ClientSet 对象失败，返回 nil
        return nil,err
    }
	// 使用 client-go 列出所有命名空间中的 RoleBindings
    rbList, err := clientset.RbacV1().RoleBindings("").List(context.TODO(), metav1.ListOptions{})
    if err != nil {
        return nil, err
    }
	// 根据获取到的条数预分配 slice 空间
    roleBindingList := make([]apis.RoleBinding, 0, len(rbList.Items))
    // 遍历 RoleBindings 列表，并将其转换为自定义结构 apis.RoleBinding
	for _, rb := range rbList.Items {
        newRB := apis.RoleBinding{
            Namespace: rb.Namespace, // RoleBinding 所属的命名空间
            Name:      rb.Name,      // RoleBinding 名称
        }
        // 如果 RoleRef 的 Kind 为 "Role"，则 RoleRef 包含命名空间前缀
        if rb.RoleRef.Kind == "Role" {
            newRB.RoleRef = rb.Namespace + "/" + rb.RoleRef.Name
        } else {
            newRB.RoleRef = rb.RoleRef.Name
        }
        // 遍历所有 Subject，只处理 Kind 为 "ServiceAccount" 的记录
        for _, subject := range rb.Subjects {
            if subject.Kind != "ServiceAccount" {
                continue
            }
            newRB.Subject = append(newRB.Subject, subject.Namespace+"/"+subject.Name)
        }
        roleBindingList = append(roleBindingList, newRB)
    }
    return roleBindingList, nil
}

// GetRulesFromRole 根据传入的 role 字符串（格式："namespace/role" 或 "clusterrole"），
// 使用 client-go 获取对应的 Role 或 ClusterRole 对象，并转换为自定义结构 apis.Rule 列表。
// 返回值:
//    []apis.Rule - 转换后的规则列表
//    error       - 获取过程中可能产生的错误
func GetRulesFromRole(role string) ([]apis.Rule,error){
	// 获取 Kubernetes ClientSet 对象
	clientset,err := request.GetClientSet("")
    if err != nil {
        // 获取 Kubernetes ClientSet 对象失败，返回 nil
        return nil,err
    }
	var rules []rbacv1.PolicyRule
	// 如果 role 中包含 "/"，则认为该 Role 为 namespaced 类型
    if strings.Contains(role, "/") {
        // 将 role 分割成 namespace 和 role 名称
        parts := strings.SplitN(role, "/", 2)
        namespace := parts[0]
        name := parts[1]
        // 使用 client-go 获取指定命名空间内的 Role 对象
        r, err := clientset.RbacV1().Roles(namespace).Get(context.TODO(), name, metav1.GetOptions{})
        if err != nil {
            // 获取 Role 对象失败，返回 nil
            return nil,err
        }
        rules = r.Rules
    } else {
        // 否则，role 为 clusterRole
        cr, err := clientset.RbacV1().ClusterRoles().Get(context.TODO(), role, metav1.GetOptions{})
        if err != nil {
            // 获取 ClusterRole 对象失败，返回 nil
            return nil,err
        }
        rules = cr.Rules
    }
	// 根据获取到的规则数量预分配转换后的规则 slice
    ruleList := make([]apis.Rule, 0, len(rules))
    // 遍历每个 PolicyRule，将其转换为自定义结构 apis.Rule
    for _, rule := range rules {
        newRule := apis.Rule{
            Resourcs: make([]string, 0),
            Verbs:    make([]string, 0),
        }
        // 遍历 PolicyRule 中定义的资源
        for _, res := range rule.Resources {
            // 如果 PolicyRule 中包含 ResourceNames，则为每个资源名称拼接格式：resource(resourceName)
            if len(rule.ResourceNames) > 0 {
                for _, resName := range rule.ResourceNames {
                    newRule.Resourcs = append(newRule.Resourcs, res+"("+resName+")")
                }
            } else {
                // 否则直接添加资源名称
                newRule.Resourcs = append(newRule.Resourcs, res)
            }
        }
        // 遍历 PolicyRule 中定义的 verbs，直接添加
        for _, verb := range rule.Verbs {
            newRule.Verbs = append(newRule.Verbs, verb)
        }
        // 将转换后的规则加入到 ruleList 中
        ruleList = append(ruleList, newRule)
    }

    // 返回转换后的规则列表
    return ruleList,nil
}