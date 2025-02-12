package cmd

import (
	"fmt"
	"k8sEPDS/conf"
	"k8sEPDS/models"
	exp "k8sEPDS/pkg/exploit"
	"k8sEPDS/pkg/scan"
	"reflect"
	"sort"
	"strings"
)

var (
	ssh          models.SSHConfig
	criticalSAs  []models.CriticalSA
	saBindingMap map[string]*models.SA
)

// SA_sort 用于封装排序和调度信息
type SA_sort struct {
    Level        string                   // 用于排序的关键字（如 any, restrict）
    dispatchFunc string                   // 调用的函数键
    SA           models.CriticalSAWrapper // 实际 SA 信息
}

func Main() {
	ssh = conf.Config.SSH
	operation := ""
	for {
		fmt.Println("可用命令:")
		fmt.Println("  scan        - 扫描权限")
		fmt.Println("  exp         - 利用漏洞")
		fmt.Println("  resetconfig - 重置配置")
		fmt.Println("  help        - 显示帮助")
		fmt.Println("  exit        - 退出程序")
		fmt.Print("请输入命令:")
		fmt.Scan(&operation)
		switch operation {
		case "scan":
			{
				saBindingMap = scan.GetSaBinding()
				criticalSAs = scan.GetCriticalSA(scan.GetSA(saBindingMap), ssh.Nodename)

				fmt.Println()
				for _, criticalSA := range criticalSAs {
					if !criticalSA.SA0.IsMounted {
						continue
					}
					fmt.Println("[app]:", criticalSA.SA0.SAPod.Namespace)
					fmt.Println("[component]:", criticalSA.SA0.SAPod.Name)
					fmt.Println("[ServiceAccount]:", criticalSA.SA0.Name)
					fmt.Println("[permission]:", criticalSA.Type)
					fmt.Println("[node]:", criticalSA.SA0.SAPod.NodeName)
					fmt.Println("[roles/clusterRoles]:", criticalSA.Roles)
					fmt.Println("[roleBindings]:", criticalSA.SA0.RoleBindings)
					fmt.Println("-------------------------------------------")
					fmt.Println()
				}
			}
		case "exp":
			{
				exploit(classify(), ssh.Nodename, false)
			}
		case "resetconfig":
			{
				conf.GetConfig()
				conf.UpdateConfig()
				ssh = conf.Config.SSH
			}
		case "help":
			{
				fmt.Println("可用命令:")
				fmt.Println("  scan        - 扫描关键ServiceAccount")
				fmt.Println("  exp         - 利用关键SA的关键权限进行攻击")
				fmt.Println("  resetconfig - 重新加载配置")
				fmt.Println("  help        - 显示帮助信息")
				fmt.Println("  exit        - 退出程序")
			}
		case "exit":
			{
				fmt.Println("退出程序。")
                return
			}
		default:
            fmt.Println("无效的命令，请使用 help 查看可用命令")
		}
	}

}

func classify() map[string][]SA_sort {
	result := make(map[string][]SA_sort, 0)
	kind := map[string]string{
		"impersonate":               	"anyescalate",
		"createclusterrolebindings": 	"anyescalate",
		"patchclusterroles":         	"anyescalate",
		"createtokens":              	"anyescalate",
		"createpods":                	"anyescalate",
		"createpodcontrollers":      	"anyescalate",
		"patchpodcontrollers":       	"anyescalate",
		"createwebhookconfig":       	"anyescalate",
		"patchwebhookconfig":        	"anyescalate",
		"createrolebindings":        	"restrictescalate",
		"patchclusterrolebindings":  	"restrictescalate",
		"patchrolebindings":         	"restrictescalate",
		"patchroles":                	"restrictescalate",
		"createsecrets":             	"restrictescalate",
		"getsecrets":               	"restrictescalate",
		"listsecrets":					"restrictescalate",
		"execpods":                  	"restrictescalate",
		"ephemeralcontainerspods":	 	"restrictescalate",
		"patchpods":                 	"restrictescalate",
		"watchsecrets":              	"restrictescalate",
		"updatesecrets": 			 	"restrictescalate",
		"updatepods": 					"restrictescalate",
		"patchnodes":                	"anyhijack",
		"patchnodestatus":				"anyhijack",
		"deletenodes":               	"anyhijack",
		"deletecollections": 			"anyhijack",
		"deletevalidatingwebhookconfigurations":"anyhijack",
		"deletepods":                	"restricthijack",
		"createpodeviction":         	"restricthijack",
	}
	replacements := map[string]string{
		"daemonsets":                      "podcontrollers",
		"deployments":                     "podcontrollers",
		"statefulsets":                    "podcontrollers",
		"replicasets":                     "podcontrollers",
		"jobs":                            "podcontrollers",
		"cronjobs":                        "podcontrollers",
		"replicationcontrollers":          "podcontrollers",
		"mutatingwebhookconfigurations":   "webhookconfig",
		"validatingwebhookconfigurations": "webhookconfig",
	}
	if len(saBindingMap) == 0 {
		saBindingMap = scan.GetSaBinding()
	}
	if len(criticalSAs) == 0 {
		criticalSAs = scan.GetCriticalSA(scan.GetSA(saBindingMap), ssh.Nodename)
	}
	criticalSAsWrappers := []models.CriticalSAWrapper{}
	for _, criticalSA := range criticalSAs {
		for _, criticalSAType := range criticalSA.Type {
			criticalSAsWrapper := models.CriticalSAWrapper{
				Crisa: criticalSA,
				Type:  criticalSAType,
			}
			criticalSAsWrappers = append(criticalSAsWrappers, criticalSAsWrapper)
		}
	}

	for _, criticalSA := range criticalSAsWrappers {
		if !criticalSA.Crisa.InNode || !criticalSA.Crisa.SA0.IsMounted {
			continue
		}
		kindType := criticalSA.Type //reduce the rawType
		if strings.Contains(criticalSA.Type, "(") {
			kindType = kindType[:strings.Index(kindType, "(")]
		} else if strings.Contains(criticalSA.Type, "[") {
			kindType = kindType[:strings.Index(kindType, "[")]
		}
		dispatchfunc := kindType
		for old, new := range replacements {
			dispatchfunc = strings.Replace(dispatchfunc, old, new, -1)
		}
		newResult := SA_sort{Level: kind[dispatchfunc] + "-" + criticalSA.Type, SA: criticalSA, dispatchFunc: dispatchfunc}
		tmpType := ""
		if strings.Contains(kind[dispatchfunc], "escalate") {
			tmpType = "escalate"
		} else if strings.Contains(kind[dispatchfunc], "hijack") {
			tmpType = "hijack"
		} else if strings.Contains(kind[dispatchfunc], "dos") {
			tmpType = "dos"
		}
		if criticalSA.Crisa.Level == "namespace" && !strings.Contains(criticalSA.Type, "kube-system") {
			newResult = SA_sort{Level: "restrict" + tmpType + "-" + criticalSA.Type, SA: criticalSA, dispatchFunc: dispatchfunc}
		}
		result[tmpType] = append(result[tmpType], newResult)
	}
	for k := range result {
		sort.Slice(result[k], func(i, j int) bool {
			return result[k][i].Level < result[k][j].Level
		})
	}

	return result
}

func exploit(payloads map[string][]SA_sort, ControledNode string, hijacked bool) {
	// 优先处理权限升级中包含 "any" 的选项
	anyescalateMap := make(map[int]SA_sort)
	cnt := 0
	for _, sa := range payloads["escalate"] {
		if strings.Contains(sa.Level, "any") {
			if cnt == 0 {
				fmt.Println("[√] 发现可用于权限升级的权限，详情如下：")
				fmt.Println("---------------------------")
			}
			fmt.Println(cnt, sa.SA.Type, " 使用的 ServiceAccount：", sa.SA.Crisa.SA0.Name)
            anyescalateMap[cnt] = sa
			cnt++
		}
	}
	if len(anyescalateMap) != 0 {
		var choice int
		fmt.Println("---------------------------")
		fmt.Print("[输入] 请选择一种权限升级方式（输入 -1 取消）：")
		fmt.Scan(&choice)
		if choice == -1{
			return
		}
		fmt.Println("[提示] 即将执行：账户", anyescalateMap[choice].SA.Crisa.SA0.Name, "（权限："+anyescalateMap[choice].SA.Type+"） 的权限升级")
		dispatch(anyescalateMap[choice].SA.Crisa, anyescalateMap[choice].dispatchFunc)
		return
	}
	// 若已尝试过劫持分支
	if hijacked {
		if len(payloads["escalate"]) == 0 {
			fmt.Println("[错误] 未检测到可用的权限升级方法")
            return
		}
		fmt.Println("[警告] 仍无法任意升级权限")
        fmt.Println("[提示] 以下列出部分可尝试的权限升级方式：")
        fmt.Println("---------------------------")
		escalateMap := make(map[int]SA_sort)
		cnt := 0
		for _, sa := range payloads["escalate"] {
			fmt.Println(cnt, sa.SA.Type, sa.SA.Crisa.SA0.Name)
			escalateMap[cnt] = sa
			cnt++
		}
		fmt.Println("---------------------------")
        fmt.Print("[输入] 请选择一种权限升级方式：")
		var choice int
		fmt.Scan(&choice)
		fmt.Println("[提示] 即将执行：账户", escalateMap[choice].SA.Crisa.SA0.Name, "（权限："+escalateMap[choice].SA.Type+"） 的权限升级")
        dispatch(escalateMap[choice].SA.Crisa, escalateMap[choice].dispatchFunc)
	}
	// 若还未检测过劫持，则尝试检测劫持相关权限后再次进行权限升级
	if !hijacked {
		fmt.Println("[提示] 无法任意升级权限")
        fmt.Println("[提示] 准备用于检测组件劫持相关权限")
        hijack(payloads)
		exploit(payloads, ControledNode, true)
	}
}

func hijack(payloads map[string][]SA_sort) bool {
	if len(payloads["hijack"]) == 0 {
		fmt.Println("[错误] 未检测到与组件劫持相关的权限")
        return false
	}
	anyhijackMap := make(map[int]SA_sort)
	cnt1 := 0
	for _, sa := range payloads["hijack"] {
		if strings.Contains(sa.Level, "any") {
			if cnt1 == 0 {
				fmt.Println("[√] 发现可劫持任意组件的权限，详情如下：")
                fmt.Println("---------------------------")
            }
			fmt.Println(cnt1, sa.SA.Type, " 使用的 ServiceAccount：", sa.SA.Crisa.SA0.Name)
            anyhijackMap[cnt1] = sa
            cnt1++
		}
	}
	if len(anyhijackMap) != 0 {
		var choice int
		fmt.Println("---------------------------")
		fmt.Print("[输入] 请选择一种劫持方式：")
        fmt.Scan(&choice)
        fmt.Println("[提示] 即将执行：账户", anyhijackMap[choice].SA.Crisa.SA0.Name, "（权限："+anyhijackMap[choice].SA.Type+"） 的组件劫持")
        dispatch(anyhijackMap[choice].SA.Crisa, anyhijackMap[choice].dispatchFunc)
        return true
	}
	fmt.Println("[提示] 仅检测到部分组件可被劫持")
    fmt.Println("[提示] 以下列出可劫持的组件：")
    fmt.Println("---------------------------")
	hijackMap := make(map[int]SA_sort)
	cnt2 := 0
	for _, sa := range payloads["hijack"] {
        fmt.Println(cnt2, sa.SA.Type, " 使用的 ServiceAccount：", sa.SA.Crisa.SA0.Name)
        hijackMap[cnt2] = sa
        cnt2++
    }
	fmt.Println("---------------------------")
    fmt.Print("[输入] 请选择一种劫持方式：")
	var choice int
	fmt.Scan(&choice)
	fmt.Println("[提示] 即将执行：账户", hijackMap[choice].SA.Crisa.SA0.Name, "（权限："+hijackMap[choice].SA.Type+"） 的组件劫持")
    dispatch(hijackMap[choice].SA.Crisa, hijackMap[choice].dispatchFunc)
    return true
}

func dispatch(sa models.CriticalSA, dispatchFunc string) {
	funcMap := map[string]interface{}{
		"createsecrets":exp.Createsecrets,
		"createpods": exp.Createpods, 
		"createtokens": exp.Createtokens, 
		"createclusterrolebindings": exp.Createclusterrolebindings, 
		"createrolebindings": exp.Createrolebindings, 
		"createpodeviction": exp.Createpodeviction, 
		"createpodcontrollers": exp.Createpodcontrollers, 
		"createwebhookconfig": exp.Createwebhookconfig,
		"deletepods": exp.Deletepods, 
		"deletenodes": exp.Deletenodes,
		"deletevalidatingwebhookconfigurations":exp.Deletevalidatingwebhookconfigurations,
		"deletecollections": exp.Deletecollections,
		"getsecrets": exp.Getsecrets, 
		"listsecrets":exp.Listsecrets,
		"patchclusterroles": exp.Patchclusterroles, 
		"patchroles": exp.Patchroles, 
		"patchclusterrolebindings": exp.Patchclusterrolebindings, 
		"patchrolebindings": exp.Patchrolebindings, 
		"patchnodes": exp.Patchnodes, 
		"patchnodestatus": exp.Patchnodestatus,
		"patchpods": exp.Patchpods,
		"patchpodcontrollers": exp.Patchpodcontrollers,
		"patchwebhookconfig": exp.Patchwebhookconfig, 
		"watchsecrets": exp.WatchSecrets, 
		"impersonate": exp.Impersonate, 
		"execpods": exp.Execpods, 
		"ephemeralcontainerspods": exp.Ephemeralcontainerspods, 
		"updatesecrets": exp.UpdateSecrets,
		"updatepods": exp.UpdatePods,
		
	}
	funcValue := reflect.ValueOf(funcMap[dispatchFunc])
	args := []reflect.Value{reflect.ValueOf([]models.CriticalSA{sa}), reflect.ValueOf(ssh)}
	//fmt.Println("[msg] About to be called:", strings.Title(sa.Type))
	funcValue.Call(args)
}


