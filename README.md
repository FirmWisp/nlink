# nlink — Linux 进程/端口隐藏技术研究

本项目是针对 Linux 内核进程、文件、网络rootkit技术的研究性实现，分别基于 eBPF、LKM 两种主流方案进行对比研究。


> **声明：本项目仅用于学习和安全研究，请勿用于非法用途。**

## 参考

- 参考项目：voidlink
- 参考项目：[ebpfkit](https://github.com/Gui774ume/ebpfkit)、[bad-bpf](https://github.com/pathtofile/bad-bpf)、[ebpfRootkit](https://github.com/haolipeng/ebpfRootkit)

---

## 背景

在 Linux 安全研究领域，Rootkit 技术长期以来是攻防研究的核心课题之一。传统 Rootkit 以内核模块（LKM）为主要载体，通过直接修改内核数据结构或劫持系统调用表来实现隐藏。随着内核安全防护机制的演进（如 `CONFIG_MODULE_SIG`、`Secure Boot`、`DKOM` 检测等），LKM 类 Rootkit 的部署门槛持续提高。

与此同时，eBPF（Extended Berkeley Packet Filter）作为内核提供的安全沙箱执行环境，因其无需加载内核模块、动态可附加、受 verifier 严格审查等特性，近年来被广泛用于可观测性、网络过滤等领域。然而，相同的能力也使其成为新型隐蔽技术的研究对象——攻击者可以利用合法的 eBPF 接口在无需 rootkit 驻留的前提下实现隐藏效果，极大增加了检测难度。

---


### eBPF 与 LKM 的能力对比

| 维度                   | LKM Rootkit                            | eBPF Rootkit                             |
| ---------------------- | -------------------------------------- | ---------------------------------------- |
| **内核版本依赖** | 强，需适配内核符号                     | 弱，CO-RE 一次编译多版本运行             |
| **加载权限**     | `CAP_SYS_MODULE`                     | `CAP_BPF` + `CAP_SYS_ADMIN`          |
| **持久化**       | 可写入`/etc/modules`                 | 随加载进程退出自动卸载（无持久化）       |
| **检测难度**     | `lsmod` / `cat /proc/modules` 可见 | 通过`bpftool prog list` 可见           |
| **绕过安全机制** | 受 Secure Boot / 模块签名限制          | 受`CONFIG_BPF_JIT_ALWAYS_ON` 等限制    |
| **用户空间写入** | 任意写                                 | 仅通过`bpf_probe_write_user`（有限制） |
| **灵活性**       | 极高（直接操作内核数据结构）           | 受 verifier 约束，能力受限               |

---

### 检测思路

