import { resolveTargetInput } from "./url.js";
/**
 * 把工具入参里的目标解析成绝对 URL。
 *
 * 用户/模型给的往往是裸域名（`portal.example.com`）或配置里的系统别名，所有工具都必须
 * 在**安全护栏校验之前**调用它，否则合法目标会因为解析失败被误判成越权。
 */
export function resolveTarget(runtime, raw) {
    return resolveTargetInput(raw, {
        defaultScheme: runtime.cfg.defaultScheme,
        aliases: runtime.cfg.targetAliases,
    });
}
