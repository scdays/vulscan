# SOC 与 TVM 平台定制化联动方案 V1.1

> **方案版本**：V1.1  
> **编制日期**：2026-05-17  
> **编制依据**：
> - 《基础电信企业网络安全漏洞管理平台接口规范（2025年版）》
> - 《基础电信企业网络安全漏洞管理平台测试规范（2025年版）》
> - TVM 二次开发接口文档（v2.8）
> **变更说明**：补齐排查→验证→修复→备案四阶段接口参数；明确 `vulID` / `vulInfoID` 双标识及 `vulInfoStat` / `lvRsn` 语义；对齐部侧 A.8、A.23 码表。

---

## 一、系统架构（简述）

在 SOC 与 TVM 之间增加 **SOC-TVM 接入层**，负责协议转换、任务映射、结果标准化、异步回调及部侧 `vulInfoLst` 结构组装。

```
SOC ──REST/Kafka──▶ 接入层 ──TVM原生API──▶ TVM
         ◀──回调/推送──              ◀──扫描结果──
```

| 模块 | 职责 |
|------|------|
| 任务管理 | `socTaskId` ↔ TVM `taskId` 映射 |
| 数据同步 | 漏洞结果推送 Kafka / SFTP / HTTP |
| 状态写回 | 验证/修复/备案与部侧码表一致 |
| 部侧对接 | 组装 `vulInfoLst`、工单 orderSubType |

---

## 二、核心数据模型

### 2.1 两个不同字段标识（部侧表34 `vulInfoLst`）

| 字段 | 层级 | 含义 | 填写方 |
|------|------|------|--------|
| **`vulID`** | 产品漏洞 | 漏洞编号，部侧核准 | 部侧/基线库 |
| **`vulInfoID`** | 系统漏洞实例 | 系统漏洞 ID（资产上的具体漏洞） | 发现者（企业侧） |

嵌套结构：

```text
vulInfoLst
  └─ comVulLst（vulNum 次，vulID 与 pwDictInstID 二选一）
       └─ InstVulLst（assetNum 次）
            ├─ vulInfoID
            ├─ vulInfoStat
            ├─ lvRsn
            └─ 资产/网络/组件字段…
```

**SOC 接入层约定**：对外 API 以 **`vulInfoID`** 为主键；TVM `vulnDisposalId` 仅作内部映射。

### 2.2 系统漏洞状态 `vulInfoStat`（附录 A.8）

| 状态码 | 说明 | 生命周期阶段 |
|--------|------|-------------|
| 0 | 潜在预警 | 预警 |
| 1 | 初始发现 | 识别 |
| 2 | 已验证有效 | 识别 |
| **3** | **已验证误报** | 修复 |
| 5 | 已修复 | 修复 |
| 6 | 核验修复 | 修复 |
| 7 | 核验未修复 | 识别 |
| 8 | 验证失败 | 识别 |
| 9 | 修复失败 | 识别 |
| 10 | 核验失败 | 识别 |

工单参数 `srcVulInfoStat` / `dstVulInfoStat` 为**工单筛选/目标状态**，不是实例持久字段的第二套状态码。

### 2.3 未修复原因 `lvRsn`（附录 A.23）

| 编码 | 说明 |
|------|------|
| 101 | 无修复方案 |
| 102 | 修复方案无效 |
| 103 | 修复成本过高 |
| 104 | 优先级未达基线 |
| 105 | 白名单 |
| 107 | 非对外暴露资产 |
| 108 | VPT 无危害 |
| 109 | 接受风险 |
| 999 | 其他 |

规范要求：**仅对「未修复状态」补充 `lvRsn`**（表34 字段10）。

### 2.4 其他字段口径

| 字段 | 规范取值 |
|------|----------|
| `isAccess` | **0**=内网，**1**=互联网 |
| `remedTime` | 修复阶段必填，`"数值+单位"`（日/周/月） |
| `vulAddrType` | 1=IPv4, 2=IPv6, 3=HTTP, 4=N/A, 5=其他 |

---

## 三、阶段与部侧指令对照（附录 A.3）

| SOC 阶段 | 部侧 orderSubType | 说明 |
|----------|-------------------|------|
| 排查 | 31 请求 / 41 回传 | 系统漏洞排查工单 |
| **验证** | **32 请求 / 42 回传** | 系统漏洞验证工单 |
| **修复** | **33 请求 / 43 回传** | 系统漏洞修复工单 |
| 核验（可选） | 34 请求 / 44 回传 | 系统漏洞核验工单 |
| 排查处置（通用） | 3 请求 / 4 回传 | 系统漏洞排查处置工单 |
| 跨级扫描 | 1061/1062/1063 | 排查/验证/核验任务 |

### 3.1 状态推进规则

```text
排查完成     → vulInfoStat = 1（初始发现）
验证有效     → vulInfoStat = 2
验证误报     → vulInfoStat = 3（禁止修复/备案）
修复完成     → vulInfoStat = 5，lvRsn 清空
不可修复备案 → 保持未修复态（1/2/7）+ 填写 lvRsn
核验通过     → vulInfoStat = 6
核验未通过   → vulInfoStat = 7
```

**未修复状态**（可填写 `lvRsn`）：`1`、`2`、`7`（不含 `3` 误报、`5`/`6` 已修复）。

---

## 四、SOC 接入层接口定义

### 4.1 排查阶段

#### `POST /api/soc/task/create`

| 参数 | 类型 | 必填 | 说明 |
|------|------|:---:|------|
| socTaskId | string | ✓ | SOC 幂等键 |
| targets | string[] | ✓ | 扫描目标 |
| targetType | int | ✓ | 1=IPv4, 2=IPv6, 3=URL |
| vulnType | int | ✓ | 1=系统漏洞, 2=Web漏洞 |
| taskName | string | ✓ | 任务名称 |
| callbackUrl | string | ✓ | 完成回调 URL |
| scanTemplateId | int | ○ | TVM 扫描模板 |
| priority | int | ○ | 1低/2中/3高 |
| scheduleTime | datetime | ○ | 定时执行 |
| options.portScope | string | ○ | 端口范围 |
| options.isLiveProbe | bool | ○ | 存活探测 |
| options.pswdGuessEnabled | bool | ○ | 弱口令检测 |

**响应 `data`**：`socTaskId`, `taskId`, `status`（ACCEPTED/QUEUED/REJECTED）, `createdAt`

**落库**：生成 `vulInfoID`，`vulInfoStat=1`。

#### `GET /api/soc/task/progress`

| 参数 | 必填 |
|------|:---:|
| socTaskId 或 taskId | 二选一 |

**响应 `data.status`**：PENDING / RUNNING / FINISHED / FAILED

#### `POST /api/soc/vuln/list`

| 参数 | 类型 | 必填 |
|------|------|:---:|
| socTaskId | string | ✓ |
| vulInfoStatList | int[] | ○ |
| vulnLevelList | int[] | ○ |
| page | int | ✓ |
| size | int | ✓（≤1000） |

**列表项必返**：`vulInfoID`, `vulID`, `vulInfoStat`, `lvRsn`, `vulName`, `vulLevel`, `orgVulId`, `vulNetAddr`, `vulPort`, `vulSvc`, `isAccess`, `transferTime`, `vulnDisposalId`（TVM 映射）

---

### 4.2 验证阶段

> 对应部侧：**系统漏洞验证工单（32/42）**  
> 验证成功回传：可排查型指令列表至少 1 条系统漏洞，状态为「已验证有效」。

#### `POST /api/soc/vuln/verify-status`

**请求示例**

```json
{
  "socTaskId": "SOC-2026-0001",
  "vulInfoID": "ENT-VUL-0001",
  "vulnType": 1,
  "verifyResult": "FALSE_POSITIVE",
  "verifyMethod": 1021,
  "evidence": "人工复核记录编号-20260515-01",
  "operator": "sec@corp.com",
  "verifyTime": "2026-05-15T16:30:00Z",
  "remark": "确认为误报"
}
```

| 参数 | 必填 | 规则 |
|------|:---:|------|
| socTaskId | ✓ | |
| vulInfoID | ✓ | 系统漏洞 ID |
| vulnType | ✓ | |
| verifyResult | ✓ | `VALID` → **2**；`FALSE_POSITIVE` → **3** |
| verifyMethod | ○ | A.10 处置方式 |
| operator | ✓ | |
| verifyTime | ○ | 写入 `transferTime` |

**前置**：`vulInfoStat ∈ {0, 1}` 或允许从 `1` 重验  
**后置**：`vulInfoStat=3` 时拒绝后续修复/备案接口

#### `POST /api/soc/vuln/verify-status/batch`

| 参数 | 必填 |
|------|:---:|
| socTaskId | ✓ |
| items[].vulInfoID | ✓ |
| items[].verifyResult | ✓ |
| operator | ✓ |

---

### 4.3 修复阶段（仅标记已修复）

> 对应部侧：**系统漏洞修复工单（33/43）** + 修复台账 `remedInfo`

#### `POST /api/soc/vuln/mark-fixed`

**请求示例**

```json
{
  "socTaskId": "SOC-2026-0001",
  "vulInfoID": "ENT-VUL-0001",
  "vulnType": 1,
  "method": 1050,
  "remedDesc": "安装官方补丁并重启服务",
  "fixLnk": "https://vendor.example.com/patch",
  "defDev": "N/A",
  "remedTime": "3日",
  "operator": "ops@corp.com",
  "fixedAt": "2026-05-16T10:00:00Z",
  "remark": "修复完成"
}
```

| 参数 | 必填 | 部侧要求 |
|------|:---:|----------|
| vulInfoID | ✓ | |
| method | ✓ | A.10：1050 补丁 / 1051 等效防护 / 1052 阻断等 |
| remedDesc | ✓ | 修复完成上报必填 |
| fixLnk | 条件 | method=1050 时必填 |
| defDev | 条件 | 1051/1052 时必填 |
| remedTime | ✓ | `"数值+单位"` |
| operator / fixedAt | ✓ | |

**前置**：`vulInfoStat ∈ {1, 2, 7}` 且 `≠ 3`  
**后置**：`vulInfoStat := 5`，`lvRsn` 清空

---

### 4.4 备案阶段（不可修复）

> 部侧无独立「备案状态码」；对**未修复**漏洞在 `vulInfoLst` 中填写 **`lvRsn`**。

#### `POST /api/soc/vuln/record-unfixable`

**请求示例**

```json
{
  "socTaskId": "SOC-2026-0001",
  "vulInfoID": "ENT-VUL-0002",
  "vulnType": 1,
  "lvRsn": 109,
  "archiveReason": "业务连续性限制，评估后接受风险",
  "operator": "owner@corp.com",
  "approvedBy": "manager@corp.com",
  "recordAt": "2026-05-16T11:00:00Z"
}
```

| 参数 | 必填 | 说明 |
|------|:---:|------|
| vulInfoID | ✓ | |
| lvRsn | ✓ | 101–109 或 999 |
| archiveReason | ✓ | 企业内部备案说明（扩展） |
| operator | ✓ | |
| approvedBy | ○ | 审批人 |

**前置**：`vulInfoStat` 为未修复态（1/2/7），且 `≠ 3/5/6`  
**后置**：`vulInfoStat` **不变**；写入 `lvRsn`；可选 `archiveFlag=1`, `archiveId`

---

### 4.5 通用查询与回调

#### `POST /api/soc/vuln/detail`

| 参数 | 必填 |
|------|:---:|
| vulInfoID | ✓ |
| socTaskId | ○ |

返回表34 完整字段（含 `remed`、`fixLnk`、`vulInstCpe` 等）。

#### 异步回调 `POST {callbackUrl}`

```json
{
  "eventType": "TASK_COMPLETED",
  "socTaskId": "SOC-2026-0001",
  "taskId": "TVM-111",
  "status": "COMPLETED",
  "completedAt": "2026-05-15T16:00:00Z",
  "summary": { "totalVuln": 25, "verified": 20, "falsePositive": 5 }
}
```

签名字段：`X-Callback-Signature`, `X-Callback-Timestamp`（5 分钟有效）。

---

## 五、TVM 原生接口映射

| SOC 动作 | TVM 接口 |
|----------|----------|
| 创建任务 | POST `/task/create`（先 GET `/device/list`） |
| 查询进度 | GET `/task/progress` |
| 漏洞列表 | POST `/vuln/disposal/list` |
| 漏洞详情 | GET `/vuln/disposal/detail` |
| 状态处置 | POST `/vuln/disposal/disposal` |
| 修复核验 | POST `/vuln/disposal/verify` |

接入层负责 TVM 字段 → `vulInfoLst` 字段映射（见下表）。

| TVM 字段 | 部侧/标准化字段 |
|----------|----------------|
| vulDisposalId | （内部映射，非 vulInfoID） |
| cveId | orgVulId |
| assetKey | vulNetAddr |
| port | vulPort |
| service | vulSvc |
| vulSolution | remed |

---

## 六、统一错误码（建议）

| errCode | 含义 |
|---------|------|
| 0 | 成功 |
| 40001 | 参数校验失败 |
| 40002 | 状态机不允许（如误报后修复） |
| 40003 | vulInfoID 不存在 |
| 40004 | lvRsn 编码非法 |
| 40901 | 幂等重复请求 |
| 50001 | TVM 调用失败 |

---

## 七、接口开发清单

**SOC 侧（接入层对外）**

- [ ] `POST /api/soc/task/create`
- [ ] `GET /api/soc/task/progress`
- [ ] `POST /api/soc/vuln/list`
- [ ] `POST /api/soc/vuln/detail`
- [ ] `POST /api/soc/vuln/verify-status`
- [ ] `POST /api/soc/vuln/verify-status/batch`
- [ ] `POST /api/soc/vuln/mark-fixed`
- [ ] `POST /api/soc/vuln/record-unfixable`

**废弃**：`POST /api/soc/vuln/update-status`（混合语义，拆分为上述专用接口）

---

## 八、验收与测试检查表

依据《测试规范（2025）》检测要点，SOC-TVM 联动应满足：

### 8.1 接口连通性（检测要点-02 / -03）

| 编号 | 检查项 | 通过标准 |
|------|--------|----------|
| T-02 | 指令交互接口 | 能按规范解析 orderSubType 3/4/31–44 等并回传 |
| T-03 | 数据传输接口 | 常态化上报 `vulInfoLst` 字段类型/长度/必选符合表34 |

### 8.2 误报验证（检测要点-06）

| 编号 | 检查项 | 通过标准 |
|------|--------|----------|
| T-06-1 | 验证有效 | `verify-status` 将 `vulInfoStat` 置 **2** |
| T-06-2 | 验证误报 | `verify-status` 将 `vulInfoStat` 置 **3**，且不可进入修复 |
| T-06-3 | 部侧回传 | 验证工单 42 回传 `vulInfoLst` 含正确 `vulInfoID`+`vulInfoStat` |

### 8.3 处置修复（检测要点-07）

| 编号 | 检查项 | 通过标准 |
|------|--------|----------|
| T-07-1 | 已修复 | `mark-fixed` 置 **5**，含 `remedTime` |
| T-07-2 | 修复字段 | method=1050 时 `fixLnk` 非空；修复台账含 `remedDesc` |
| T-07-3 | 修复日志 | 可提取修复过程日志与 `remedInfo` 一致 |

### 8.4 修复核验（检测要点-08）

| 编号 | 检查项 | 通过标准 |
|------|--------|----------|
| T-08-1 | 核验闭环 | TVM verify 后状态 **6** 或 **7** |
| T-08-2 | 跨级任务 | 支持 1063 核验任务映射 |

### 8.5 备案 / 未修复原因

| 编号 | 检查项 | 通过标准 |
|------|--------|----------|
| T-AR-1 | 不可修复 | `record-unfixable` 填写 **lvRsn**（101–999） |
| T-AR-2 | 状态保持 | 备案后 `vulInfoStat` 仍为未修复态，非 5 |
| T-AR-3 | 误报隔离 | `vulInfoStat=3` 时 `lvRsn` 接口返回 40002 |

### 8.6 数据质量（检测要点-13 / -15）

| 编号 | 检查项 | 通过标准 |
|------|--------|----------|
| T-13 | 及时性 | 排查漏洞在常态化周期内完成上报 |
| T-15 | 真实性 | 上报 `vulInfoStat` 与 SOC/TVM 实测一致 |
| T-15-2 | 双标识 | 每条实例均有 `vulInfoID`；产品层 `vulID` 不缺失 |

### 8.7 建议自动化用例

```text
1. 创建任务 → 列表 vulInfoStat=1
2. verify-status(FALSE_POSITIVE) → stat=3 → mark-fixed 应失败
3. 新漏洞 verify-status(VALID) → stat=2
4. mark-fixed → stat=5, lvRsn=null
5. 另一漏洞 record-unfixable(lvRsn=109) → stat 仍为 2, lvRsn=109
6. 幂等：重复 mark-fixed 返回 40901 或相同结果
```

---

## 九、修订记录

| 版本 | 日期 | 说明 |
|------|------|------|
| V1.0 | 2026-05-15 | 初稿（排查为主） |
| V1.1 | 2026-05-17 | 对齐工信部 2025 接口/测试规范；新增验证阶段；拆分修复/备案接口；校正码表 |

---

*配套参考文档（仓库根目录）：*

- `基础电信企业网络安全漏洞管理平台接口规范(2025年版).docx`
- `基础电信企业网络安全漏洞管理平台测试规范(2025年版).docx`
- `基础电信企业网络安全漏洞管理平台建设指南(2025年版).docx`
