import { Config, resolveConfig } from "./config.js";
import { IntelCache, resolveCachePath } from "./core/cache.js";
import { IntelJudge } from "./core/judge.js";
import { SafetyGuard } from "./core/safety.js";
import { registerPromptSection } from "./prompt.js";
import { TOOL_NAMES, registerAllTools } from "./tools/index.js";
/** 插件名。 */
export const name = 'cvescout';
/** 依赖工具注册表：Cordis 会等 ctx.tools 就绪后再调用 apply。 */
export const inject = ['tools'];
/** 导出配置 schema，cordis.yml 中的 config 由它校验并补默认值。 */
export { Config };
/** 构造运行期依赖集合。 */
export function createRuntime(config) {
    const cfg = resolveConfig(config);
    return {
        cfg,
        safety: new SafetyGuard(cfg),
        cache: new IntelCache(resolveCachePath(cfg), cfg.cacheTtlHours),
        judge: new IntelJudge(),
    };
}
export function apply(ctx, config) {
    const runtime = createRuntime(config);
    registerAllTools(ctx, runtime);
    // 常驻系统提示词指引：把「什么话术该走本插件」教给模型，仅靠工具描述不够可靠。
    registerPromptSection(ctx, runtime);
    const scope = runtime.cfg.allowedDomains.length > 0
        ? `授权域名 ${runtime.cfg.allowedDomains.join(', ')}`
        : '未设置授权域名白名单（不限制目标，仅建议离线验证时使用）';
    const aliasCount = Object.keys(runtime.cfg.targetAliases).length;
    console.log(`[cvescout] 已注册 ${TOOL_NAMES.length} 个工具 + 1 段系统提示词指引；${scope}；` +
        `别名 ${aliasCount} 条；默认 ${runtime.cfg.defaultScheme}` +
        `${runtime.cfg.allowSchemeFallback ? '（连接失败自动换协议）' : ''}；` +
        `限速 ${runtime.cfg.maxRequestsPerMinute}/min、总量 ${runtime.cfg.maxTotalRequests}；` +
        `情报缓存 ${runtime.cache.path}`);
}
