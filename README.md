# ExcessivePermissionDetectionSystem
K8s过度权限漏洞检测系统，为kingqaquuu毕设所设计

# 能够检测的过度权限

| 权限                                  | 说明                                   | 可能的影响                                           |
| ------------------------------------- | -------------------------------------- | ---------------------------------------------------- |
| getsecrets                            | 读取 Secrets                           | 泄露敏感数据（如凭据、Token）                        |
| watchsecrets                          | 监听 Secrets 变化                      | 可能长期监控到敏感信息的变化                         |
| listsecrets                           | 列出所有 Secrets                       | 批量泄露敏感信息                                     |
| **patch**                             | 部分更新资源                           | 可能被滥用修改关键配置，如 `ClusterRole`、`Pod`      |
| patchnodes                            | 更新 `nodes`                           | 可能导致节点配置被修改，影响调度和资源分配           |
| patchclusterroles                     | 更新 `clusterroles`                    | 可能导致权限提升                                     |
| patchroles                            | 更新 `roles`                           | 可能使普通用户获得更高权限                           |
| patchclusterrolebindings              | 更新 `clusterrolebindings`             | 可能导致权限继承问题                                 |
| patchrolebindings                     | 更新 `rolebindings`                    | 可能导致特定用户获得未授权权限                       |
| patchpods                             | 更新 `pods`                            | 可能修改 `Pod` 规格，影响应用运行                    |
| patchdaemonsets                       | 更新 `daemonsets`                      | 可能导致全局 `DaemonSet` 行为异常                    |
| patchdeployments                      | 更新 `deployments`                     | 可能影响 `Deployment` 变更，引发服务问题             |
| patchstatefulsets                     | 更新 `statefulsets`                    | 可能影响 `StatefulSet` 的一致性                      |
| patchreplicasets                      | 更新 `replicasets`                     | 可能导致副本异常                                     |
| patchcronjobs                         | 更新 `cronjobs`                        | 可能影响定时任务执行                                 |
| patchjobs                             | 更新 `jobs`                            | 可能影响一次性任务执行                               |
| patchreplicationcontrollers           | 更新 `replicationcontrollers`          | 可能影响副本控制                                     |
| patchmutatingwebhookconfigurations    | 更新 `mutatingwebhookconfigurations`   | 可能影响 Webhook 配置，带来安全风险                  |
| patchvalidatingwebhookconfigurations  | 更新 `validatingwebhookconfigurations` | 可能导致未授权的请求绕过安全验证                     |
| **create**                            | 创建新资源                             | 可能导致未授权的资源创建，如 `ServiceAccount`、`Pod` |
| createsecrets                         | 创建 `secrets`                         | 可能被滥用存储敏感数据                               |
| createclusterrolebindings             | 创建 `clusterrolebindings`             | 可能导致权限提升                                     |
| createrolebindings                    | 创建 `rolebindings`                    | 可能导致未授权的角色绑定                             |
| createtokens                          | 创建 `serviceaccounts/token`           | 可能创建高权限 `ServiceAccount` 令牌                 |
| createpods                            | 创建 `pods`                            | 可能导致未授权 `Pod` 运行                            |
| execpods                              | 执行 `pods/exec`                       | 可能导致远程代码执行                                 |
| ephemeralcontainerspods               | 创建 `pods/ephemeralcontainers`        | 可能导致攻击者在 `Pod` 内部运行任意代码              |
| createdaemonsets                      | 创建 `daemonsets`                      | 可能影响所有节点，带来全局风险                       |
| createdeployments                     | 创建 `deployments`                     | 可能影响应用部署                                     |
| createstatefulsets                    | 创建 `statefulsets`                    | 可能影响 `StatefulSet` 数据一致性                    |
| createreplicasets                     | 创建 `replicasets`                     | 可能导致副本异常                                     |
| createcronjobs                        | 创建 `cronjobs`                        | 可能导致计划任务执行未授权操作                       |
| createjobs                            | 创建 `jobs`                            | 可能影响任务调度                                     |
| createreplicationcontrollers          | 创建 `replicationcontrollers`          | 可能影响副本控制                                     |
| createmutatingwebhookconfigurations   | 创建 `mutatingwebhookconfigurations`   | 可能导致拦截请求，修改流量，带来安全风险             |
| createvalidatingwebhookconfigurations | 创建 `validatingwebhookconfigurations` | 可能导致绕过安全策略                                 |
| createnodes                           | 创建 `nodes`                           | 可能导致未授权的节点加入集群                         |
| **delete**                            | 删除资源                               | 可能导致业务中断，如 `Pod`、`Node` 被删除            |
| deletepods                            | 删除 `pods`                            | 可能导致应用终止                                     |
| deletenodes                           | 删除 `nodes`                           | 可能导致整个集群失稳                                 |
| deletevalidatingwebhookconfigurations | 删除 `validatingwebhookconfigurations` | 可能导致安全策略丢失                                 |
| **deletecollection**                  | 批量删除资源                           | 大规模删除资源，可能导致系统崩溃                     |
| **escalate**                          | 提升权限                               | 可能导致权限提升，如修改 `ClusterRole`               |
| patchclusterroles                     | 提升 `clusterroles`                    | 可能导致权限过大                                     |
| patchroles                            | 提升 `roles`                           | 可能导致权限管理混乱                                 |
| **impersonate**                       | 伪装其他用户                           | 可能导致攻击者获取更高权限                           |
| **update**                            | 更新资源                               | 修改资源内容，可能导致配置更改                       |
| update                                | 更新指定 `resource`，如 `updatepods`   | 可能影响应用运行                                     |
| **bind**                              | 绑定角色权限                           | 可能使低权限用户获得更高权限                         |
| createclusterrolebindings             | 绑定 `clusterrolebindings`             | 可能导致未授权权限提升                               |
| createrolebindings                    | 绑定 `rolebindings`                    | 可能导致普通用户获取管理员权限                       |
| **approve**                           | 批准操作，如证书签发                   | 可能导致未经授权的证书被签发，影响安全性             |

这样，每个权限下的具体资源都列出来了，你可以更清楚地看到不同权限的详细影响。这样是否符合你的需求？如果有需要调整或补充的，请告诉我！ 😊
