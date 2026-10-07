# Auditable, Replayable Noise Analysis

实验团队对照历史噪声分析与新算法、新校准版本的可审计回放能力。

预览（preview）与异步分析（async analysis）在执行时保存**不可变的完整输入、校准引用、规则版本和结果摘要**；之后可以指定任意历史记录进行**忠实重放（faithful replay）**并得到可区分的差异报告，同时完整保留旧响应格式。

- 零依赖，Node.js ≥ 20
- `npm test` 运行 55 个测试
- `npm run demo` 运行端到端演示

---

## 1. 旧响应格式保持不变

分析接口的原有字段语义完全不变，只**新增**一个 `audit` 字段：

```js
const preview = await service.preview(request);
// {
//   inputDigest:          'b21abea8…',      // 旧：仅输入哈希
//   calibrationVersions:  { primary:'v2025-09' }, // 旧
//   ruleVersion:          '2.0.0',          // 旧
//   result:               { metrics, flags },     // 旧
//   audit: { recordId, rule:{specSha256,implDigest}, calibrations:[…], inputRef, engine } // 新
// }
```

异步接口同样保留 `jobId / status / inputDigest / calibrationVersions / ruleVersion`，仅新增 `audit`。

## 2. 保存了什么证据

每条记录落盘为只增目录 `records/<recordId>/`：

| 文件 | 内容 |
|---|---|
| `input.json` | **完整输入快照**（不只是 inputDigest），SHA-256 写入 meta 与首条事件 |
| `meta.json` | 不可变清单：输入引用、校准引用（id+版本+**内容哈希**）、规则引用（集合+版本+spec 哈希+**实现源码哈希**）、引擎描述 |
| `events.log` | **哈希链式** JSONL 事件日志：`RECORD_CREATED → JOB_ENQUEUED → JOB_STARTED → RESULT_PERSISTED / ANALYSIS_FAILED`，每条包含 `seq / prevSha / sha` |
| `result.json` | 结果摘要 + 摘要哈希；终态事件锚定同一哈希 |

冻结区（记录之外、内容寻址）：

- `calibrations/<sha>.json` —— 当时校准的**完整冻结副本**
- `rules/<specSha>.json` + `rules/impl-<implDigest>.js` —— 规则 spec 与**实现源码**的冻结副本

所有文件均为 **tmp + fsync + rename 原子写入**；并发追加由每记录互斥锁保护，链式哈希检测重排、截断和篡改。

## 3. 忠实回放

```js
const report = await replayer.replay(recordId, {
  // mode: 'FAITHFUL'（默认）或 'CURRENT_REFERENCE'
  // compareWithCurrent: true,      // 附加"用今天的默认值会怎样"的对照
  // allowEngineVersionMismatch: false,
  // tolerance: { absTol, relTol, ulpTol },
});
```

忠实回放的铁律：

1. **绝不修改原记录**——回放报告写入独立的 `replays/<replayId>.json`，记录目录逐字节不变（有测试断言）。
2. **只使用记录钉住的校准版本与规则版本**；注册表的"当前版本"永不被偷偷替换。
3. 注册表里历史版本已不存在或实现已被重建时，从冻结区**重编译冻结源码**执行；当前算法升级只作为证据中的 `upgradeAvailable`，或通过显式 `compareWithCurrent` / `CURRENT_REFERENCE` 模式对照，结论与忠实判定分开报告。

调用方从三段内容确认一次重放是否真正可复现：

- **`evidence`**：输入/校准/规则引用、链校验结果、会话 id（是否跨进程重启）、引擎比对、校准注册表比对、并发计数；
- **`state`**：记录生命周期状态、是否使用了冻结实现、注册表漂移、升级可用性；
- **`diff`**：EXACT / WITHIN_TOLERANCE / MISMATCH / STRUCTURAL_MISMATCH，含逐字段绝对误差、相对误差、ULP 距离。

顶层给出 `status`、粗粒度 `verdict` 和布尔 `reproducible`。

## 4. 可区分的结果状态码

| 场景 | status |
|---|---|
| 逐位复现 | `REPRODUCIBLE` |
| 浮点微差在容差内（abs/rel/ULP 三条件） | `REPRODUCIBLE_WITH_TOLERANCE` |
| 证据完好但计算结果不同 | `DIVERGED` |
| 输出结构不同（如 v1→v2 新增字段） | 差异报告 `STRUCTURAL_MISMATCH`；显式对照模式为 `CURRENT_REFERENCE_MATCH/MISMATCH`（verdict=`INFORMATIONAL`） |
| 进程重启导致作业未终结（ENQUEUED/RUNNING），重开时追加 `RECOVERED_AFTER_RESTART` | `REPLAY_BLOCKED_RECORD_INTERRUPTED` |
| 原子写残留 `.tmp` 碎片 / 事件行撕裂 | `REPLAY_BLOCKED_RECORD_PARTIAL` |
| 元数据/事件链/输入快照损坏或被换、spec 被换 | `REPLAY_BLOCKED_RECORD_CORRUPT` / `REPLAY_BLOCKED_RULE_SPEC_DRIFT` |
| 结果摘要被改（与链上摘要不符） | `REPLAY_BLOCKED_RECORD_TAMPERED` |
| 完整输入快照丢失 | `REPLAY_BLOCKED_INPUT_MISSING` |
| 冻结校准副本丢失 / 内容损坏 | `REPLAY_BLOCKED_CALIBRATION_MISSING` / `…_SNAPSHOT_CORRUPT` |
| 注册表中同 id@version 绑定已漂移 | 证据标记 `registryStatus:'DRIFTED'`，**冻结副本照常复现** |
| 规则版本连同冻结源码均不可得 | `REPLAY_BLOCKED_RULE_VERSION_UNAVAILABLE` |
| 引擎族/版本不一致 | `REPLAY_BLOCKED_ENGINE_MISMATCH`（族不同必阻塞；版本不同需显式放行） |
| 冻结实现重放时运行出错 | `REPLAY_BLOCKED_EXECUTION_ERROR` |
| 同一记录并发回放 | 全部允许；报告 `evidence.concurrency.peakConcurrentReplaysOfSameRecord` |

补充防线：

- 同一 `calibrationId@version` 用不同内容再次注册会直接抛 `CalibrationConflictError`（版本字符串不可能静默指向两份校准）。
- 引擎证据包含 `engineFamily / version / node / platform / arch / stdlibDigest`；数值运行时（求和原语等）的实现摘要不同会被记录为警告，最终由容差差异决定结论，浮点误差既不会被当成"复现"也不会被夸大为算法分歧。

## 5. 典型用法

```js
const store = await new AuditStore({ root: '/data/audit' }).open(); // 重开即恢复
const service  = new AnalysisService({ store, calibrations, rules });
const replayer = new Replayer({ store, calibrations, rules });

const { audit } = await service.preview(request);

const r = await replayer.replay(audit.recordId, { compareWithCurrent: true });
if (r.reproducible) {
  // r.status === 'REPRODUCIBLE' 或 'REPRODUCIBLE_WITH_TOLERANCE'
} else if (r.verdict === 'BLOCKED') {
  // r.status 精确给出阻塞原因（校准缺失/中断/篡改/部分写/…）
}
// r.currentReference 是"用当前默认校准+当前规则"的独立对照
```

## 6. 目录结构

```
src/
  statuses.js              全部状态码/生命周期/事件类型
  util/hash.js             规范化 JSON、内容哈希、原子写
  util/diff.js             容差/ULP 结构化差异
  util/locks.js            进程内互斥 + 跨进程目录锁
  registries/calibration.js  只增校准注册表（冲突即拒绝，可持久化）
  registries/rules.js        版本化规则注册表 + 冻结源码编译
  analysis/noiseRules.js     v1/v2 内置噪声算法（纯函数，可冻结重编译）
  analysis/engine.js         执行与引擎证据
  analysis/service.js        预览/异步分析编排（旧格式 + audit）
  audit/store.js             只增证据存储、链式事件、崩溃恢复
  replay/replayer.js         分类、忠实重放、当前值对照
test/                        node:test 测试套件（55）
examples/demo.js             九类场景端到端演示
```
