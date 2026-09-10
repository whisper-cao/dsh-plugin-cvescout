/**
 * 插件内部共享的数据模型。
 *
 * 这些结构同时是各工具的 canonical JSON 值，会被回放、被 Code/PTC 模式
 * 程序化读取，因此字段名保持 camelCase、不携带任何内部引用。
 *
 * 全部使用 `type` 别名而非 `interface`：`tool` 的 `output.schema` 若声明为
 * `{ type: 'json' }`，其推导类型是 `JsonValue`（带索引签名），而 TypeScript
 * 只给对象字面量类型别名隐式索引签名。用别名可以省掉边界处的强制转换。
 */
export {};
