// Package freshness 实现可持久化的 TUF 新鲜度与回滚审计账本。
//
// 本包只依赖 Go 标准库，不能 import metadata 或 metadata/config，以避免与
// metadata 包形成循环依赖。updater 负责传入元数据字节的指纹、调用时受信集合
// 的版本变化以及原始错误；Classify 只读取错误并把原错误保留在 Verdict.Err。
//
// # Code 与 metadata.Err* 的对应表
//
// 由于不能直接 import metadata，Classify 通过错误的稳定具体类型名和 Unwrap
// 链识别下列错误；错误所有权、errors.Is 关系以及 Refresh 的返回文案均不变。
//
//	Code                    metadata 错误或判定条件
//	CodeAccept              err == nil，且 RefTime 不晚于 Expires
//	CodeEqual               *metadata.ErrEqualVersionNumber
//	CodeEqualDivergent      版本相同，但 Prev.Meta 与 Seen.Meta 不一致
//	CodeRollback            版本或 Meta 版本回退，包括 root 请求版本与内容版本不符
//	CodeMetaRemoval         Prev.Meta 中的条目在 Seen.Meta 中缺失
//	CodeExpired             *metadata.ErrExpiredMetadata，或 RefTime.After(Expires)
//	CodeVersionMismatch     非回退性质的 *metadata.ErrBadVersionNumber
//	CodeSignature           *metadata.ErrUnsignedMetadata
//	CodeHashMismatch        *metadata.ErrLengthOrHashMismatch 等长度/哈希错误
//	CodeRejected            其他 *metadata.ErrRepository 或未分类拒绝
//	CodeTrustReset          新 root 被接受并推进后，清理 timestamp/snapshot 记忆
//	CodeWarning             非致命的账本或审计告警
//
// 时间边界遵循 TUF 的 referenceTime.After(Expires) 规则：RefTime 恰好等于
// Expires 时未过期；RefTime 为 Expires 后一纳秒时过期。本包不调用 time.Now。
//
// # 降级规则
//
//  1. 账本文件不存在时视为空账本，Degraded 为 false，不影响 Refresh。
//  2. JSON 损坏或字段类型不符时清空为初始账本，追加 Msg 固定为
//     "ledger unreadable" 的 Warning（Err 保留解析错误），Degraded 变为 true；
//     本进程之后的 Flush 均返回 ErrDegradedReadOnly，且不覆盖磁盘旧文件。
//  3. schemaVersion 大于 SupportedSchemaVersion（当前为 1）时进入只读模式，
//     Warning 只记录一次，Flush 返回 ErrSchemaTooNew，绝不把文件重写为低版本。
//  4. 非空文件缺少 schemaVersion 或 schemaVersion 为 0 时按第 2 条损坏规则处理，
//     不静默补写当前版本号。
package freshness
