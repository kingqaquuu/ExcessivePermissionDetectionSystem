package scan

import (
	"fmt"
	"k8sEPDS/models"
	"k8sEPDS/pkg/scan/utils"
	"strings"
)

// GetSA 获取并标记已经挂载的 ServiceAccount。
// 参数:
//    sas - key 为 "namespace/ServiceAccount" 的 SA 映射
// 返回值:
//    标记后的 SA 映射及可能的错误
func GetSA(sas map[string]*models.SA) (map[string]*models.SA) {
	result := sas
	pods, err := utils.GetPods()
	if err != nil {
		fmt.Println("[GetPods] 失败: ", err.Error())
		return result
	}
	for _, pod := range pods {
		key := strings.Join([]string{pod.Namespace, pod.ServiceAccount}, "/")
		if sa, exists := result[key]; exists {
			sa.IsMounted = true
			sa.SAPod = pod
		}
	}
	return result
}

// counters 封装各类计数器，减少重复变量
type counters struct {
    clusterRoleBind1 int
    clusterRoleBind2 int
    roleBind1        int
    roleBind2        int
    clusterRoleEsc   int
    roleEsc          int
}
// GetCriticalSA 过滤出高权限的 ServiceAccount，并标记是否在受控节点。
// 参数:
//   SAs           - 标记后的 ServiceAccount 映射
//   ControledNode - 受控节点名称
// 返回值:
//   CriticalSA 列表
func  GetCriticalSA(SAs map[string]*models.SA, ControledNode string) []models.CriticalSA {
	result := []models.CriticalSA{}
	for _, sa := range SAs {
		cnt := counters{}
		criticalSA := models.CriticalSA{
			SA0:    *sa,
			InNode: sa.SAPod.NodeName == ControledNode,
			Level:  "namespace",
			Type:   []string{},
		}
		// 收集角色名称
        for roleName := range sa.Roles {
            criticalSA.Roles = append(criticalSA.Roles, roleName)
        }
		// 遍历各角色及其权限规则
		for _, role := range sa.Roles {
			for resource, permissions := range role {
				// get secrets
				if utils.Contains(permissions, "get") || utils.Contains(permissions, "*") {
					if strings.Contains(resource, "secrets") || strings.Contains(resource, "*") {
						criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(resource, "getsecrets", &criticalSA))
					}
				}
				// watch secrets
				if utils.Contains(permissions, "watch") || utils.Contains(permissions, "*") {
					if strings.Contains(resource, "secrets") || strings.Contains(resource, "*") {
						criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(resource, "watchsecrets", &criticalSA))
					}
				}
				// patch 权限处理
				if utils.Contains(permissions, "patch") || utils.Contains(permissions, "*") {
					// 节点直接添加
					if resource == "nodes" || resource == "*" {
						criticalSA.Type = append(criticalSA.Type, "patchnodes")
					}
					// clusterroles
					if strings.Contains(resource, "clusterroles") || strings.Contains(resource, "*") {
						cnt.clusterRoleEsc++
						if cnt.clusterRoleEsc == 2 {
							criticalSA.Type = append(criticalSA.Type, "patchclusterroles")
						}
					}
					// roles
					if strings.Contains(resource, "roles") || strings.Contains(resource, "*") {
						cnt.roleEsc++
						if cnt.roleEsc == 2 {
							criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(resource, "patchroles", &criticalSA))
						}
					}
					// clusterrolebindings
					if strings.Contains(resource, "clusterrolebindings") || strings.Contains(resource, "*") {
						cnt.clusterRoleBind2++
						if cnt.clusterRoleBind2 == 2 {
							criticalSA.Type = append(criticalSA.Type, "patchclusterrolebindings")
						}
					}
					// rolebindings
					if strings.Contains(resource, "rolebindings") || strings.Contains(resource, "*") {
                        cnt.roleBind2++
                        if cnt.roleBind2 == 2 {
                            criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(resource, "patchrolebindings", &criticalSA))
                        }
                    }
					// 其他 patch 操作直接添加
					if strings.Contains(resource, "pods") || strings.Contains(resource, "*") {
                        criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(resource, "patchpods", &criticalSA))
                    }
					if strings.Contains(resource, "daemonsets") || strings.Contains(resource, "*") {
                        criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(resource, "patchdaemonsets", &criticalSA))
                    }
					if strings.Contains(resource, "deployments") || strings.Contains(resource, "*") {
                        criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(resource, "patchdeployments", &criticalSA))
                    }
					if strings.Contains(resource, "statefulsets") || strings.Contains(resource, "*") {
                        criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(resource, "patchstatefulsets", &criticalSA))
                    }
					if strings.Contains(resource, "replicasets") || strings.Contains(resource, "*") {
                        criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(resource, "patchreplicasets", &criticalSA))
                    }
					if strings.Contains(resource, "cronjobs") || strings.Contains(resource, "*") {
                        criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(resource, "patchcronjobs", &criticalSA))
                    } else if strings.Contains(resource, "jobs") || strings.Contains(resource, "*") {
                        criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(resource, "patchjobs", &criticalSA))
                    }
					if strings.Contains(resource, "replicationcontrollers") || strings.Contains(resource, "*") {
                        criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(resource, "patchreplicationcontrollers", &criticalSA))
                    }
					if strings.Contains(resource, "mutatingwebhookconfigurations") || resource == "*" {
						criticalSA.Type = append(criticalSA.Type, "patchmutatingwebhookconfigurations")
					}
					if strings.Contains(resource, "permissionsalidatingwebhookconfigurations") || resource == "*" {
						criticalSA.Type = append(criticalSA.Type, "patchpermissionsalidatingwebhookconfigurations")
					}
				}
				// create 权限处理
				if utils.Contains(permissions, "create") || utils.Contains(permissions, "*") {
					if strings.Contains(resource, "secrets") || strings.Contains(resource, "*") {
                        criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(resource, "createsecrets", &criticalSA))
                    }
					if strings.Contains(resource, "clusterrolebindings") || strings.Contains(resource, "*") {
                        cnt.clusterRoleBind1++
                        if cnt.clusterRoleBind1 == 2 {
                            criticalSA.Type = append(criticalSA.Type, "createclusterrolebindings")
                        }
                    }
					if strings.Contains(resource, "rolebindings") || strings.Contains(resource, "*") {
                        cnt.roleBind1++
                        if cnt.roleBind1 == 2 {
                            criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(resource, "createrolebindings", &criticalSA))
                        }
                    }
					if strings.Contains(resource, "serviceaccounts/token") || strings.Contains(resource, "*") {
                        criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(resource, "createtokens", &criticalSA))
                    }
					if strings.Contains(resource, "pods") || strings.Contains(resource, "*") {
                        criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(resource, "createpods", &criticalSA))
                    }
					if strings.Contains(resource, "pods/exec") || strings.Contains(resource, "*") {
                        criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(resource, "execpods", &criticalSA))
                    }
					if strings.Contains(resource, "pods/ephemeralcontainers") || strings.Contains(resource, "*") {
                        criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(resource, "execpods2", &criticalSA))
                    }
					if strings.Contains(resource, "daemonsets") || strings.Contains(resource, "*") {
                        criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(resource, "createdaemonsets", &criticalSA))
                    }
					if strings.Contains(resource, "deployments") || strings.Contains(resource, "*") {
                        criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(resource, "createdeployments", &criticalSA))
                    }
					if strings.Contains(resource, "statefulsets") || strings.Contains(resource, "*") {
                        criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(resource, "createstatefulsets", &criticalSA))
                    }
					if strings.Contains(resource, "replicasets") || strings.Contains(resource, "*") {
                        criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(resource, "createreplicasets", &criticalSA))
                    }
					if strings.Contains(resource, "cronjobs") || strings.Contains(resource, "*") {
                        criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(resource, "createcronjobs", &criticalSA))
                    } else if strings.Contains(resource, "jobs") || strings.Contains(resource, "*") {
                        criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(resource, "createjobs", &criticalSA))
                    }
					if strings.Contains(resource, "replicationcontrollers") || strings.Contains(resource, "*") {
                        criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(resource, "createreplicationcontrollers", &criticalSA))
                    }
					if strings.Contains(resource, "mutatingwebhookconfigurations") || strings.Contains(resource, "*") {
                        criticalSA.Type = append(criticalSA.Type, "createmutatingwebhookconfigurations")
                    }
                    if strings.Contains(resource, "validatingwebhookconfigurations") || strings.Contains(resource, "*") {
                        criticalSA.Type = append(criticalSA.Type, "createvalidatingwebhookconfigurations")
                    }
                    if strings.Contains(resource, "nodes") || strings.Contains(resource, "*") {
                        criticalSA.Type = append(criticalSA.Type, "createnodes")
                    }
				}
				// bind 权限处理
				if utils.Contains(permissions, "bind") || utils.Contains(permissions, "*") {
					if strings.Contains(resource, "clusterroles") || strings.Contains(resource, "*") {
                        cnt.clusterRoleBind1++
                        cnt.clusterRoleBind2++
                        if cnt.clusterRoleBind1 == 2 {
                            criticalSA.Type = append(criticalSA.Type, "createclusterrolebindings")
                        }
                        if cnt.clusterRoleBind2 == 2 {
                            criticalSA.Type = append(criticalSA.Type, "patchclusterrolebindings")
                        }
                    }
					if strings.Contains(resource, "roles") || strings.Contains(resource, "*") {
                        cnt.roleBind1++
                        cnt.roleBind2++
                        if cnt.roleBind1 == 2 {
                            criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(resource, "createrolebindings", &criticalSA))
                        }
                        if cnt.roleBind2 == 2 {
                            criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(resource, "patchrolebindings", &criticalSA))
                        }
                    }
				}
				// delete 权限处理
				if utils.Contains(permissions, "delete") || utils.Contains(permissions, "*") {
					if strings.Contains(resource, "pods") || strings.Contains(resource, "*") {
                        criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(resource, "deletepods", &criticalSA))
                    }
					if strings.Contains(resource, "nodes") || strings.Contains(resource, "*") {
                        criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(resource, "deletenodes", &criticalSA))
                    }
					if strings.Contains(resource, "validatingwebhookconfigurations") || strings.Contains(resource, "*") {
                        criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(resource, "deletevalidatingwebhookconfigurations", &criticalSA))
                    }
				}
				// escalate 权限处理
				if utils.Contains(permissions, "escalate") || utils.Contains(permissions, "*") {
					if strings.Contains(resource, "clusterroles") || strings.Contains(resource, "*") {
						cnt.clusterRoleEsc++
                        if cnt.clusterRoleEsc == 2 {
                            criticalSA.Type = append(criticalSA.Type, "patchclusterroles")
                        }
                    }
					if strings.Contains(resource, "roles") || strings.Contains(resource, "*") {
                        cnt.roleEsc++
                        if cnt.roleEsc == 2 {
                            criticalSA.Type = append(criticalSA.Type, utils.CheckRestrict(resource, "patchroles", &criticalSA))
                        }
                    }
				}
				// impersonate权限处理
				if utils.Contains(permissions, "impersonate") {
					criticalSA.Type = append(criticalSA.Type, "impersonate")
				}
				// update权限处理
				if utils.Contains(permissions, "update") {
                    criticalSA.Type = append(criticalSA.Type, "update"+resource)
                }
			}
		}
		// 仅保留存在权限操作的记录
		if len(criticalSA.Type) != 0 {
			result = append(result, criticalSA)
		}
	}
	return result
}

// updateSABinding 更新 SA 的 RoleBindings 和 权限信息
// 参数:
//   sa         - ServiceAccount 名称
//   binding    - 当前绑定对象（ClusterRoleBinding 或 RoleBinding）
//   rules      - 当前绑定关联的规则列表
//   ns         - 当 ns 非空时，说明处理 RoleBinding，需要将资源名称带上命名空间信息
//   SaBindingMap - 存储每个 SA 对资源的权限映射
//   result     - 存储转换后的 SA 对象
func updateSABinding(sa string, bindingName string, roleRef string, rules []models.Rule, ns string, SaBindingMap map[string]map[string][]string, result map[string]*models.SA) {
    // 初始化 SaBindingMap 对当前 SA 的数据
    if _, ok := SaBindingMap[sa]; !ok {
        SaBindingMap[sa] = make(map[string][]string)
    }
    // 初始化 result 中当前 SA 的数据
    if _, ok := result[sa]; !ok {
        result[sa] = &models.SA{
            Name:         sa,
            RoleBindings: []string{},
            Roles:        map[string]map[string][]string{},
        }
    }
    // 添加 RoleBinding 名称
    result[sa].RoleBindings = append(result[sa].RoleBindings, bindingName)
    // 遍历规则，将资源、权限更新到 SA 对象中
    for _, rule := range rules {
        for _, res := range rule.Resourcs {
            // 对于 RoleBinding，增加命名空间信息
            resourceStr := res
            if ns != "" {
                resourceStr = res + "[" + ns + "]"
            }
            // 初始化角色对应的资源映射
            if _, ok := result[sa].Roles[roleRef]; !ok {
                result[sa].Roles[roleRef] = make(map[string][]string)
            }
            // 添加每个 verb 到角色绑定中
            for _, verb := range rule.Verbs {
                result[sa].Roles[roleRef][resourceStr] = append(result[sa].Roles[roleRef][resourceStr], verb)
                SaBindingMap[sa][resourceStr] = append(SaBindingMap[sa][resourceStr], verb)
            }
        }
    }
    // 更新权限映射
    result[sa].Permission = SaBindingMap[sa]
}


// GetSaBinding 使用 client-go 获取所有 RoleBinding 和 ClusterRoleBinding 信息，
// 构建每个 ServiceAccount (SA) 的权限映射，并返回转换后的 SA 数据。
// 返回值:
//    map[string]*models.SA - 键为 SA 名称，值为对应的 SA 信息（包括 RoleBindings、Roles 和 Permission 映射）
func GetSaBinding() map[string]*models.SA {
    // SaBindingMap 存储每个 SA 对各资源的权限映射，键为资源字符串，值为权限的切片
    SaBindingMap := map[string]map[string][]string{}
    // result 存储转换后的 SA 对象，键为 SA 名称
    result := make(map[string]*models.SA)

    // 获取所有 ClusterRoleBindings (集群范围的角色绑定)
    clusterrolebindingList, err := utils.GetClusterRoleBindings()
    if err != nil {
        fmt.Println("[GetClusterRoleBindings] 失败: ", err.Error())
        return result
    }
    // 获取所有命名空间内的 RoleBindings
    rolebindingList, err := utils.GetRolesBindings()
    if err != nil {
        fmt.Println("[GetRolesBindings] 失败: ", err.Error())
        return result
    }

    // 处理 ClusterRoleBindings（集群级别的角色绑定，其资源无需命名空间前缀，因此 ns 参数为空）
    for _, crb := range clusterrolebindingList {
        // 根据绑定中的 RoleRef 获取角色规则
        rules, err := utils.GetRulesFromRole(crb.RoleRef)
        if err != nil {
            fmt.Println("[GetRulesFromRole] 失败: ", err.Error())
            // 出现错误时跳过处理当前绑定，继续处理下一个绑定
            continue
        }
        // 遍历该绑定中的每个 ServiceAccount
        for _, sa := range crb.Subject {
            // 更新 SA 对象的 RoleBindings 和权限信息
            updateSABinding(sa, crb.Name, crb.RoleRef, rules, "", SaBindingMap, result)
        }
    }

    // 处理命名空间内的 RoleBindings
    for _, rb := range rolebindingList {
        // 获取当前 RoleBinding 的角色规则
        rules, err := utils.GetRulesFromRole(rb.RoleRef)
        if err != nil {
            fmt.Println("[GetRulesFromRole] 失败: ", err.Error())
            // 如果获取角色规则失败则跳过当前绑定
            continue
        }
        // 遍历 RoleBinding 中所有的 ServiceAccount
        for _, sa := range rb.Subject {
            // 传入 rb.Namespace 以便为资源名称添加命名空间信息
            updateSABinding(sa, rb.Name, rb.RoleRef, rules, rb.Namespace, SaBindingMap, result)
        }
    }

    // 返回构建好的 SA 权限映射结果
    return result
}

// GetCriticalSAToken 通过 SSH 连接远程主机，获取 CriticalSA 的 token。
// 参数:
//   sa  - 包含 Pod 信息的 models.CriticalSA 对象
//   ssh - SSH 连接配置
// 返回值:
//   string - 从远程主机读取的 token 内容
//   error  - 可能产生的错误
func GetCriticalSAToken(sa models.CriticalSA, ssh models.SSHConfig) (string, error) {
	filePath := fmt.Sprintf("/var/lib/kubelet/pods/%s/volumes/kubernetes.io*/*/token", sa.SA0.SAPod.Uid)
	// 通过 SSH 读取远程文件内容
	token, err := utils.ReadRemoteFile(ssh.Host, ssh.Port, ssh.Username, ssh.Password, ssh.PrivateKeyFile, filePath)
    // 直接返回 token 和错误信息
    return token, err
}
