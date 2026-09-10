/**
 * 插件配置。
 *
 * Harness 约定：凡是不同部署可能需要取不同值的参数，都必须走配置字段，
 * 不能硬编码。配置在 cordis.yml 中传入，由 Schemastery 校验并填充默认值；
 * `resolveConfig` 再做一次防御性补全，保证单独调用本模块时也能工作。
 */
import Schema from '@deepseek-ai/schemastery'

/** 默认载荷黑名单：命中即拦截。 */
export const DEFAULT_BLOCKED_PATTERNS: readonly string[] = [
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
]

/** 默认额外探测的被动路径。 */
export const DEFAULT_PASSIVE_PATHS: readonly string[] = ['/robots.txt', '/.well-known/security.txt']

export interface CvescoutConfig {
  /** 授权目标域名白名单。为空数组表示不做域名限制（仅建议在离线/隔离环境使用）。 */
  allowedDomains: string[]
  /**
   * 目标别名表：用户口中的系统名 / 简称 → 域名或 URL。
   * 用于把「帮我看看内部管理系统有没有 CVE-2021-44228」这类说法落到具体目标上。
   */
  targetAliases: Record<string, string>
  /** 用户只给域名没给协议时补的协议。 */
  defaultScheme: 'https' | 'http'
  /**
   * 首次请求在连接/TLS 层失败时，是否自动换一次协议重试（仅限被动方法）。
   * 内网站点常有只开 http 或只开 https 的情况，开启可显著减少「目标不可达」的假失败。
   */
  allowSchemeFallback: boolean
  /** 滑动窗口速率限制：每分钟最大探测请求数。 */
  maxRequestsPerMinute: number
  /** 单次插件生命周期内最大探测请求数。 */
  maxTotalRequests: number
  /** 单次 HTTP 请求超时（毫秒）。 */
  timeoutMs: number
  /** 响应体截断上限（字节），避免把大页面塞进上下文。 */
  maxResponseBytes: number
  /** 探测请求使用的 User-Agent。 */
  userAgent: string
  /** 情报缓存文件路径。留空则使用 ~/.cvescout/intel-cache.json。 */
  cachePath: string
  /** 情报缓存有效期（小时）。 */
  cacheTtlHours: number
  /** NVD API Key（可选）。带 Key 时限速从 5 次/30 秒提升到 50 次/30 秒。 */
  nvdApiKey: string
  /** GitHub Token（可选）。用于 PoC 搜索，未填则回退到环境变量 GITHUB_TOKEN。 */
  githubToken: string
  /**
   * 是否允许非幂等探测（POST/PUT/PATCH/DELETE）。
   * 默认 false，仅放行 GET/HEAD/OPTIONS 等被动探测。
   */
  allowNonIdempotentProbe: boolean
  /** 载荷黑名单正则。命中即拦截，防止把破坏性载荷递给目标。 */
  blockedPayloadPatterns: string[]
  /** 复测报告落盘目录。留空则使用 ~/.cvescout/reports。 */
  reportDir: string
  /** 指纹识别时是否发 OPTIONS 读取 Allow 头（被动探测，用于判断写入路径是否可达）。 */
  probeAllowedMethods: boolean
  /** 指纹识别时是否用随机路径采一次 404 错误页特征（SPA 兜底 / 框架默认错误页）。 */
  errorPageProbe: boolean
  /** 指纹识别时额外探测的被动路径（只取 200 响应，不写入任何内容）。 */
  passiveProbePaths: string[]
}

export const Config: Schema<CvescoutConfig> = Schema.object({
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
})

function numberOr(value: unknown, fallback: number): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback
}

function booleanOr(value: unknown, fallback: boolean): boolean {
  return typeof value === 'boolean' ? value : fallback
}

function stringOr(value: unknown, fallback: string): string {
  return typeof value === 'string' ? value : fallback
}

function stringArrayOr(value: unknown, fallback: readonly string[]): string[] {
  if (!Array.isArray(value)) return [...fallback]
  const items = value.map((item) => String(item)).filter((item) => item.length > 0)
  return items.length > 0 ? items : [...fallback]
}

function stringRecordOr(value: unknown): Record<string, string> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {}
  const result: Record<string, string> = {}
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    const trimmed = key.trim()
    if (trimmed && item !== null && item !== undefined && String(item).trim()) {
      result[trimmed] = String(item).trim()
    }
  }
  return result
}

/**
 * 防御性配置补全：Cordis 正常会按导出 schema 填默认值，这里保证即便直接
 * 构造 runtime（单测、脚本化调用）也不会拿到 undefined 字段。
 */
export function resolveConfig(input?: Partial<CvescoutConfig> | null): CvescoutConfig {
  const raw = (input ?? {}) as Partial<CvescoutConfig>
  const scheme = stringOr(raw.defaultScheme, 'https').toLowerCase()
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
  }
}
