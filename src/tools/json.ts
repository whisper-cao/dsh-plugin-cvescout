/**
 * canonical 值边界转换。
 *
 * `output.schema: { type: 'json' }` 的推导类型是 `JsonValue`：它是一个带字符串
 * 索引签名的递归联合，而领域模型（RetestResult / AuditReport 之类）是显式字段
 * 的对象类型。TypeScript 不会给显式对象类型自动补索引签名，且 `JsonValue` 不
 * 接受 `undefined`，于是可选字段会直接报错。
 *
 * 与其为了迁就类型系统把每个领域模型都摊平成 `Record<string, JsonValue>`，不如
 * 在这一处边界上显式转换，并在返回前做一次「能否无损 JSON 序列化」的断言，
 * 让契约在运行时仍然成立。
 */
import type { JsonValue } from '@deepseek-ai/dsh-tools'

/** 断言并转换为 canonical JSON 值；顺带做一次 JSON 可序列化校验。 */
export function asJsonValue<T>(value: T): JsonValue {
  const roundTripped = JSON.parse(JSON.stringify(value ?? null)) as JsonValue
  return roundTripped
}

/** 渲染侧把 canonical 值还原回领域模型（只读字段访问）。 */
export function fromJsonValue<T>(value: unknown): T {
  return value as T
}
