# 5GRAKA — 5G AKA 协议 ProVerif 形式化安全验证

基于 **ProVerif** 对 5G 网络认证与密钥协商协议（**5G AKA**，3GPP TS 33.501）进行形式化建模与安全性质自动验证。

本目录包含同一协议模型的 5 个变体文件，分别针对不同的安全性质（弱一致性 / 非单射一致性 / 单射一致性 / 保密性 / 失同步攻击场景）进行验证。

---

## 1. 目录结构

| 文件 | 大小 | 验证重点 |
|---|---|---|
| `5GRAKA.pv` | 7.7 KB | 综合模型：弱一致性(6) + 单射一致性 UE→HN(1) + 保密性 K/SUPI/sec(3)；含重同步 AUTS 处理 |
| `5GRAKA_I.pv` | 7.1 KB | 单射一致性专项：UE / SN / HN 两两之间的 6 条单射一致性查询 |
| `5GRAKA_NI.pv` | 5.5 KB | 非单射一致性专项：UE-HN（IDSN）、SN-HN（SUPI）2 条查询 |
| `5GRAKA_wa.pv` | 5.3 KB | 弱一致性专项：begin/end 事件 6 条查询 |
| `5G_RAKA.pv` | 8.1 KB | 完整模型：双用户（目标 UEA + 非目标 UEB）+ 失同步/失败场景，12 条查询 |
| `_analysis/` | — | ProVerif 运行输出（含各查询的完整攻击轨迹），由 `proverif` 复现生成 |

---

## 2. 环境要求

- **ProVerif 2.05**（`proverif.exe`，位于上级目录 `..\proverif.exe`），支持 Windows / Linux / macOS 命令行运行。
- 无需额外依赖库，模型使用 ProVerif 内置的 applied pi 演算语法。

## 3. 快速开始

```bash
# 语法解析检查（不执行分析）
proverif -parse-only 5GRAKA.pv

# 运行完整验证（输出查询结果与攻击轨迹）
proverif 5G_RAKA.pv

# 将结果保存到文件
proverif 5GRAKA_I.pv > result_I.txt 2>&1
```

> 说明：`-parse-only` 仅检查语法，不检查语义；完整运行才会报告每条查询的验证结果（`RESULT ... is true/false`）及反例轨迹。

---

## 4. 协议模型

### 4.1 参与角色

| 角色 | 对应网元 | 职责 |
|---|---|---|
| `process_UE` | 用户设备 | 生成 SUCI、验证网络挑战（MAC/SQN）、生成 RES、派生 KSEAF、重同步 AUTS |
| `process_SN` / `process_SEAF` | 服务网络（SEAF） | 转发 SUCI 与认证向量、计算并附加 MAC_SN、校验 HXRES 后转发 RES、获取 KSEAF |
| `process_HN` | 归属网络（AUSF/ARPF） | 解出 SUPI/RUE、生成挑战 AUTN、验证 RES/XRES、派生并下发 KSEAF、校验 AUTS |

### 4.2 信道

| 信道 | 属性 | 用途 |
|---|---|---|
| `c` | 公开 | 广播归属网络公钥 `pkHN` |
| `c_ue_sn` | 公开（攻击者可控） | UE 与 SN 之间的所有认证消息 |
| `c_sn_hn` | 私有 | SN 与 HN 之间的认证向量与密钥传输 |

### 4.3 密码原语建模

| 原语 | 用途 |
|---|---|
| `Encap / Ksession / first / second / MAC` | ECIES 式 SUCI 加密（封装 + 会话密钥派生 + MAC 标签） |
| `f1 / f2 / f5` | 5G AKA 加密函数：MAC-A / RES·XRES / AK |
| `f1' / f5'` | 重同步流程（AUTS）专用函数 |
| `KDF` | 派生锚点密钥 `KSEAF = KDF(K, RHN, RUE, IDSN)` |
| `h` | 哈希：`MAC_SN`、`HXRES` |
| `xor` | SQN 掩藏（`CONC = SQN ⊕ AK`） |
| `senc / sdec` | 会话秘密 `sec` 的对称加密传输 |

### 4.4 认证消息流程

```
UE                          SN(SEAF)                      HN
 │  ① (SUCI, IDHN)              │                            │
 ├─────────────────────────────►│  ② (SUCI, IDHN, IDSN)      │
 │                              ├───────────────────────────►│
 │                              │  ③ (RUE, RHN, AUTN, HXRES, KSEAF)
 │                              │◄───────────────────────────┤
 │  ④ (RHN, AUTN, MAC_SN)       │                            │
 │◄─────────────────────────────┤                            │
 │  ⑤ RES                       │                            │
 ├─────────────────────────────►│  ⑥ RES（校验 h(RHN,RES)=HXRES 后转发）
 │                              ├───────────────────────────►│
 │                              │  ⑦ (XSUPI, KSEAF)（校验 RES=XRES 后下发）
 │                              │◄───────────────────────────┤
 │  ⑧ senc(sec, KSEAF)          │                            │
 │◄─────────────────────────────┤                            │
```

失败路径：UE 校验 MAC 失败发送 `MAC_failure`；SQN 失同步时发送 `(Sync_failure, AUTS)`，HN 用 `f1'/f5'` 校验 AUTS。

---

## 5. 各模型文件说明

### 5.1 `5GRAKA.pv` — 综合模型

- **启用的查询**：弱一致性 6 条；单射一致性 `inj-event(UE_end) ⇒ inj-event(HN_end)`（KSEAF）；保密性 `attacker(K)`、`attacker(SUPI)`、`attacker(sec)`。


### 5.2 `5GRAKA_I.pv` — 单射一致性专项

- 6 条单射一致性查询（UE↔SN、UE↔HN、SN↔HN 三个方向各一对 begin/end 事件，参数为 KSEAF 及标识符）。
- 不含保密性、弱一致性查询，不含重同步路径。

### 5.3 `5GRAKA_NI.pv` — 非单射一致性专项

- `event(UE_HN_idsn(idsn)) ⇒ event(HN_UE_idsn(idsn))`（UE 与 HN 就 IDSN 的一致）；
- `event(SN__HN_supi(supi)) ⇒ event(HN_SN_supi(supi))`（SN 与 HN 就 SUPI 的一致）。

### 5.4 `5GRAKA_wa.pv` — 弱一致性专项

- 6 条弱一致性查询（UE / SN / HN 的 begin/end 事件对）。

### 5.5 `5G_RAKA.pv` — 完整模型（双用户 + 失同步场景）

- 两个用户：目标用户 `UEA`（长期密钥 `KA`）、非目标用户 `UEB`（长期密钥 `KB`），HN 仅服务 `SUPIA`。
- 查询组合：弱一致性 6 条 + 非单射一致性 2 条 + 单射一致性 3 条 + 特殊查询 1 条：
  `event(UEA_send_Sync_Failure(x,y)) && event(UEB_send_MAC_Failure(z)) ⇒ false`（目标用户发送同步失败与非目标用户发送 MAC 失败不可共现）。
- 完整实现失败/失同步路径与 AUTS 重同步校验。

---


### 复现

```bash
cd 5GRAKA
proverif 5GRAKA.pv    
proverif 5GRAKA_I.pv   
proverif 5GRAKA_NI.pv 
proverif 5GRAKA_wa.pv   
proverif 5G_RAKA.pv   
```

---

