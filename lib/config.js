/**
 * 插件配置。
 *
 * Harness 约定：凡是不同部署可能需要取不同值的参数，都必须走配置字段，
 * 不能硬编码。配置在 cordis.yml 中传入，由 Schemastery 校验并填充默认值；
 * `resolveConfig` 再做一次防御性补全，保证单独调用本模块时也能工作。
 */
import Schema from '@deepseek-ai/schemastery';
/** 默认载荷黑名单：命中即拦截。 */
export const DEFAULT_BLOCKED_PATTERNS = [
    'rm\\s+-rf',
    'del\\s+/[sSfq]',
    'DROP\\s+TABLE',
    'DELETE\\s+FROM',
    'UPDATE\\s+\\w+\\s+SET',
    'INSERT\\s+INTO',
    'TRUNCATE\\s+TABLE',
    'mkfs',
    'format\\s+[a-zA-Z]:',
    'shutdown',
    'reboot',
    ':\\(\\)\\s*\\{',
];
/** 默认额外探测的被动路径。 */
export const DEFAULT_PASSIVE_PATHS = ['/robots.txt', '/.well-known/security.txt'];
export const Config = Schema.object({
    allowedDomains: Schema.array(Schema.string()).default([]),
    targetAliases: Schema.dict(Schema.string()).default({}),
    defaultScheme: Schema.union(['https', 'http']).default('https'),
    allowSchemeFallback: Schema.boolean().default(true),
    maxRequestsPerMinute: Schema.number().default(30),
    maxTotalRequests: Schema.number().default(200),
    timeoutMs: Schema.number().default(10000),
    maxResponseBytes: Schema.number().default(20000),
    userAgent: Schema.string().default('CVEScout-DSH/0.1 (non-intrusive-verification)'),
    cachePath: Schema.string().default(''),
    cacheTtlHours: Schema.number().default(24),
    nvdApiKey: Schema.string().default(''),
    githubToken: Schema.string().default(''),
    allowNonIdempotentProbe: Schema.boolean().default(false),
    blockedPayloadPatterns: Schema.array(Schema.string()).default([...DEFAULT_BLOCKED_PATTERNS]),
    reportDir: Schema.string().default(''),
    probeAllowedMethods: Schema.boolean().default(true),
    errorPageProbe: Schema.boolean().default(true),
    passiveProbePaths: Schema.array(Schema.string()).default([...DEFAULT_PASSIVE_PATHS]),
});
function numberOr(value, fallback) {
    return typeof value === 'number' && Number.isFinite(value) ? value : fallback;
}
function booleanOr(value, fallback) {
    return typeof value === 'boolean' ? value : fallback;
}
function stringOr(value, fallback) {
    return typeof value === 'string' ? value : fallback;
}
function stringArrayOr(value, fallback) {
    if (!Array.isArray(value))
        return [...fallback];
    const items = value.map((item) => String(item)).filter((item) => item.length > 0);
    return items.length > 0 ? items : [...fallback];
}
function stringRecordOr(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value))
        return {};
    const result = {};
    for (const [key, item] of Object.entries(value)) {
        const trimmed = key.trim();
        if (trimmed && item !== null && item !== undefined && String(item).trim()) {
            result[trimmed] = String(item).trim();
        }
    }
    return result;
}
/**
 * 防御性配置补全：Cordis 正常会按导出 schema 填默认值，这里保证即便直接
 * 构造 runtime（单测、脚本化调用）也不会拿到 undefined 字段。
 */
export function resolveConfig(input) {
    const raw = (input ?? {});
    const scheme = stringOr(raw.defaultScheme, 'https').toLowerCase();
    return {
        allowedDomains: Array.isArray(raw.allowedDomains)
            ? raw.allowedDomains.map((item) => String(item).trim()).filter((item) => item.length > 0)
            : [],
        targetAliases: stringRecordOr(raw.targetAliases),
        defaultScheme: scheme === 'http' ? 'http' : 'https',
        allowSchemeFallback: booleanOr(raw.allowSchemeFallback, true),
        maxRequestsPerMinute: numberOr(raw.maxRequestsPerMinute, 30),
        maxTotalRequests: numberOr(raw.maxTotalRequests, 200),
        timeoutMs: numberOr(raw.timeoutMs, 10000),
        maxResponseBytes: numberOr(raw.maxResponseBytes, 20000),
        userAgent: stringOr(raw.userAgent, 'CVEScout-DSH/0.1 (non-intrusive-verification)'),
        cachePath: stringOr(raw.cachePath, ''),
        cacheTtlHours: numberOr(raw.cacheTtlHours, 24),
        nvdApiKey: stringOr(raw.nvdApiKey, ''),
        githubToken: stringOr(raw.githubToken, ''),
        allowNonIdempotentProbe: booleanOr(raw.allowNonIdempotentProbe, false),
        blockedPayloadPatterns: stringArrayOr(raw.blockedPayloadPatterns, DEFAULT_BLOCKED_PATTERNS),
        reportDir: stringOr(raw.reportDir, ''),
        probeAllowedMethods: booleanOr(raw.probeAllowedMethods, true),
        errorPageProbe: booleanOr(raw.errorPageProbe, true),
        passiveProbePaths: stringArrayOr(raw.passiveProbePaths, DEFAULT_PASSIVE_PATHS),
    };
}
