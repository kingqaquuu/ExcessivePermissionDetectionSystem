/*
 * @Description:
 * @Author: kingqaquuu
 * @Date: 2025-01-21 16:27:48
 * @LastEditTime: 2025-01-23 12:21:05
 * @LastEditors: kingqaquuu
 */
package models

type Pod struct {
	Namespace      string   // Pod所在的命名空间
	Name           string   // Pod的名称
	Uid            string   // Pod的唯一标识符
	NodeName       string   // Pod运行的节点名称
	ServiceAccount string   // 关联的ServiceAccount名称
	ControllBy     []string // Pod的控制器类型(如Deployment/DaemonSet等)
	TokenMounted   bool     // 是否挂载了Token
}

/*
ServiceAccount
*/
type SA struct {
	IsMounted    bool                           // 是否被Pod挂载使用
	Name         string                         // ServiceAccount完整名称(格式:namespace/name)
	SAPod        Pod                            // 使用该SA的Pod信息
	Permission   map[string][]string            // 权限映射(资源类型->操作列表)
	Roles        map[string]map[string][]string // 角色映射(类型->角色名称->权限列表)
	RoleBindings []string                       // 关联的RoleBinding列表
}

/*
关键ServiceAccount
*/
type CriticalSA struct {
	InNode       bool     // 对应的Pod是否在指定节点上(是否在node1节点上运行)
	Type         []string // 具有的高危权限类型(如["hostPath","privileged"]等)
	Level        string   // 权限范围(cluster表示集群级别,namespace表示命名空间级别)
	SA0          SA       // 主要关注的ServiceAccount信息(完整的SA对象)
	Namespace    string   // 命名空间(SA所在的命名空间)
	ResourceName string   // 资源名称(关联的资源对象名称)
	Roles        []string // 角色列表(该SA绑定的所有角色名称)
}
type CriticalSAWrapper struct {
	Crisa CriticalSA // 包装的危险SA对象(完整的CriticalSA信息)
	Type  string     // 危险类型(标识这个SA具体的危险类型)
}
type RoleBinding struct {
	Namespace string   // 角色绑定所在的命名空间
	Name      string   // 角色绑定的名称
	RoleRef   string   // 引用的角色名称(指向具体的Role或ClusterRole)
	Subject   []string // 主体列表(被绑定的对象,如ServiceAccount名称列表)
}

type Rule struct {
	Resourcs []string // 资源列表(可以操作的Kubernetes资源,如pods、deployments等)
	Verbs    []string // 操作列表(允许的操作,如get、list、create等)
}

type SAtoken struct {
	SaName         string `json:"name"`  // ServiceAccount的名称
	PermissionType string `json:"type"`  // 权限类型(如cluster、namespace级别)
	Token          string `json:"token"` // ServiceAccount的认证令牌
}

type CriticalSASet struct {
	TokenSet []string // 关键ServiceAccount的Token集合
}

type SSHConfig struct {
	Host           string // SSH连接的目标IP地址
	Port           int    // SSH连接端口
	Username       string // SSH登录用户名
	Password       string // SSH登录密码
	PrivateKeyFile string // SSH私钥文件路径
	Nodename       string // 目标节点名称
}

type K8SConfig struct {
	ApiServer    string //K8s Api服务器地址
	ProxyAddress string //代理 如果没有留空
	TokenFile    string //token文件存放位置
	Kubeconfig   string
	AdminCert    string //证书
	AdminCertKey string
}

type K8sEPDSConfig struct {
	K8s K8SConfig
	SSH SSHConfig
}
