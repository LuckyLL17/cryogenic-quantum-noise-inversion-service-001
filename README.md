# 低温量子器件实验数据校准与噪声谱反演服务

纯后端 Node.js + TypeScript 服务，不依赖数据库、Docker 或第三方运行时。服务从多通道 ADC/IQ 采样、实验时钟、仪器配置和校准版本中重建实验窗口，完成时钟同步、IQ 校准、窗口化、功率谱/互谱计算、相干性分析、噪声类型判别和 T1/T2/Ramsey 等衰减参数拟合。

## 运行

```bash
npm test
npm start
```

默认监听 `127.0.0.1:4387`。证据落盘目录可用 `AUDIT_STORE_DIR` 覆盖（默认 `.audit-store/`）。

## 分析接口（响应格式保持不变）

- `GET /health`
- `POST /v1/analyses`：提交分析任务，返回任务 ID
- `GET /v1/analyses/:id`：读取任务状态或结果
- `POST /v1/analyses/:id/cancel`：取消排队或运行中的任务
- `POST /v1/experiments/preview`：同步、校准并快速预览派生指标

旧响应体不变；成功或失败的分析现在都会封存一条不可变证据，其 ID 通过响应头
`x-audit-record-id: <recordId>` 返回，任务查询同样带该响应头。

## 可审计回放

每次预览和异步分析都封存一条证据记录（哈希链 + 原子两阶段写）：

- **不可变完整输入**：原始采样、校准表、分析选项全部保存，而非仅一个摘要值；
- **校准引用**：每个校准版本除 `profileId` 外还绑定完整内容的 SHA-256；
- **规则版本**：封存 `ALGORITHM_VERSION` 与逐规则模块的版本清单；
- **结果摘要**：保存去随机 ID 的完整确定性结果与标量摘要；
- **防篡改链**：记录摘要覆盖上一条记录摘要，逐条链接。

接口：

- `POST /v1/audit/records/:id/replay`：重放指定历史记录并报告差异
- `GET /v1/audit/records/:id`：读取一条证据（含 `recordState`）
- `GET /v1/audit/records?kind=&jobId=&experimentId=`：列出证据摘要
- `GET /v1/audit/health`：封存计数与崩溃恢复/隔离详情

### 重放如何判定「是否真正可复现」

重放**始终从证据内封存的输入启动**，调用方无法替换输入；默认使用记录内嵌的校准
（`calibration.mode = "sealed"`），**绝不偷偷改用当前校准**。也可显式要求
`{"calibration":{"mode":"registry","profiles":[...]}}`，此时先比对再计算，缺失或变更
会被单独报告，而不是被静默替换。重放只新增 `replays/<id>.json`，不修改任何原记录。

报告三层信息可独立确认：

1. `evidence`：记录完整性（`sealed/tampered/orphaned/unsealed`）、哈希链、输入摘要
   自洽、封存版本、是否跨进程会话（`restarted`）；
2. `status` 与 `conditions`：机器可区分的条件码组合；
3. `diff`：`exact` / `within-tolerance` / `different`，含逐字段路径、旧值、新值与误差。

| 场景 | 条件码 | status |
| --- | --- | --- |
| 逐位复现 | `REPLAYED_EXACT` | `reproduced`（`reproducible=true`） |
| 仅浮点误差且在容差内 | `NUMERICAL_DRIFT` | `numerical-drift`（`reproducible=false`） |
| 结果结构性/超容差分歧 | `RESULT_DIVERGED` | `diverged` |
| 算法整体版本升级 | `ALGORITHM_UPGRADED`（附 `versions`） | 按 diff 结果 |
| 仅规则模块版本变化 | `RULE_VERSION_CHANGED`（附 `changedModules`） | 按 diff 结果 |
| 历史校准当前缺失 | `CALIBRATION_MISSING` | `unreplayable` |
| 同版本校准内容变更 | `CALIBRATION_CHANGED` | 按 diff 结果 |
| 封存中途崩溃的部分写入 | `RECORD_UNSEALED` | `unreplayable` |
| 记录文件/索引孤儿 | `RECORD_ORPHANED` | `unreplayable` |
| 证据被篡改（摘要不符） | `RECORD_TAMPERED` | `unreplayable` |
| 进程重启后重放 | `evidence.restarted=true`（仍可 `reproduced`） | 按 diff 结果 |
| 并发重放同一记录 | `CONCURRENT_REPLAY`，仅计算一次、判定一致 | 按 diff 结果 |
| 原始就是失败结果 | `OUTCOME_FAILED`，按错误码一致性判定 | `reproduced`/`diverged` |
| 记录不存在 | `RECORD_NOT_FOUND`（HTTP 404） | `not-found` |

容差可在重放请求中声明：`{"tolerance":{"absolute":1e-12,"relative":1e-9}}`（默认值）。
容差内的浮点叶子差异是 `within-tolerance`（`reproducible` 仍为 `false`——只有逐位
`exact` 才算严格可复现）；任何结构差异（字段缺失、数组长度变化、类型变化）一律
`different`，不会被容差掩盖。

### 存储布局与崩溃恢复

```
.audit-store/
  index.log            每条封存一行，sequence + prev 摘要哈希链
  records/<id>.json    staging 临时文件 + rename 原子封存
  staging/<id>.json    崩溃中断留下的部分写入（启动时隔离为 unsealed）
  replays/<id>.json    每次重放一份独立报告（只增不改）
```

重启时重放索引链：撕裂的索引行（`tornIndexEntries`）、有索引无文件、摘要不符
（`tampered`）、有文件无索引（`orphaned`）、staging 残留（`unsealed`）都会出现在
`/v1/audit/health` 的 `recovery` 中，并在对应重放里得到可区分结论，而不是被静默修复。
