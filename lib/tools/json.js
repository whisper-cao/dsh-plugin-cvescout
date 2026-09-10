/** 断言并转换为 canonical JSON 值；顺带做一次 JSON 可序列化校验。 */
export function asJsonValue(value) {
    const roundTripped = JSON.parse(JSON.stringify(value ?? null));
    return roundTripped;
}
/** 渲染侧把 canonical 值还原回领域模型（只读字段访问）。 */
export function fromJsonValue(value) {
    return value;
}
