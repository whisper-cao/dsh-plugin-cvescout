/**
 * 安全护栏。
 *
 * 所有对外请求在真正触达目标之前都必须过这一层。检查维度（顺序固定）：
 *
 *   1. 破坏性工具名单（纵深防御，Harness 自身工具不在此列）
 *   2. 载荷黑名单正则
 *   3. 授权域名白名单
 *   4. 速率限制（60s 滑动窗口）
 *   5. 总请求数上限
 *   6. 审计日志（含参数脱敏）
 *
 * 域名匹配刻意不用 `domain in url` 这类子串判断——那会让 `target.com`
 * 被 `target.com.evil.com` 命中。这里解析 URL 主机名后做精确/后缀匹配。
 */
import type { CvescoutConfig } from '../config.ts'
import { hostOf } from './url.ts'

/** 破坏性工具名单：这些名字在我们的工具集里本就不存在，作为纵深防御保留。 */
export const BLOCKED_TOOL_NAMES: readonly string[] = [
  'write_file',
  'delete_file',
  'exec_command',
  'shell_exec',
]

const SENSITIVE_KEY_PATTERN = /password|passwd|token|api[_-]?key|secret|cookie|authorization|credential/i
const MAX_AUDIT_ENTRIES = 500

export interface SafetyDecision {
  allowed: boolean
  reason: string
  /**
   * 拒绝类别。
   *
   * 区分它的原因是：并行探测时这两类拒绝该有不同处置——
   * `scope` 是「目标未授权」，必须硬失败并向上冒泡（不能被降级成「不可达」）；
   * `rate-limit` / `total-limit` 只是本地配额，应当如实记进 probeErrors
   * 并保留已采到的部分情报，而不是丢掉整次扫描。
   */
  kind: SafetyDecisionKind
}

export type SafetyDecisionKind =
  | 'ok'
  | 'blocked-tool'
  | 'blocked-pattern'
  | 'scope'
  | 'rate-limit'
  | 'total-limit'

/** 安全护栏拒绝调用时抛出的专用错误，便于调用方与网络错误区分开。 */
export class SafetyBlockedError extends Error {
  readonly toolName: string
  readonly kind: SafetyDecisionKind

  constructor(toolName: string, reason: string, kind: SafetyDecisionKind = 'scope') {
    super(`安全护栏拦截 [${toolName}]: ${reason}`)
    this.name = 'SafetyBlockedError'
    this.toolName = toolName
    this.kind = kind
  }

  /** 是否为「目标未授权」——这类拒绝必须硬失败，不允许被静默降级。 */
  get isScopeViolation(): boolean {
    return this.kind === 'scope'
  }
}

export interface AuditEntry {
  index: number
  timestamp: string
  tool: string
  params: unknown
  allowed: boolean
  reason: string
}

export interface AuditReport {
  totalCalls: number
  blockedCalls: number
  allowedCalls: number
  blockRate: string
  totalRequests: number
  requestsLastMinute: number
  limits: {
    maxRequestsPerMinute: number
    maxTotalRequests: number
    allowedDomains: string[]
  }
  log: AuditEntry[]
}

export class SafetyGuard {
  private readonly cfg: CvescoutConfig
  private readonly auditLog: AuditEntry[] = []
  private readonly timestamps: number[] = []
  private totalRequests = 0
  private counter = 0

  constructor(cfg: CvescoutConfig) {
    this.cfg = cfg
  }

  /** 同步校验一次工具调用；通过后才计入速率与总量配额。 */
  check(toolName: string, params: unknown): SafetyDecision {
    const decision = this.evaluate(toolName, params)
    if (!decision.allowed) {
      this.record(toolName, params, false, decision.reason)
      return decision
    }
    this.totalRequests += 1
    this.timestamps.push(Date.now())
    this.record(toolName, params, true, '')
    return decision
  }

  /**
   * 校验失败时抛 SafetyBlockedError，便于在非工具上下文中使用
   * （例如批量流水线内部）。调用方若在 try/catch 里吞异常，必须显式
   * 放行这个错误类型，否则会把「未授权」误报成「不可达」。
   */
  assertAllowed(toolName: string, params: unknown): void {
    const decision = this.check(toolName, params)
    if (!decision.allowed) {
      throw new SafetyBlockedError(toolName, decision.reason, decision.kind)
    }
  }

  private evaluate(toolName: string, params: unknown): SafetyDecision {
    if (BLOCKED_TOOL_NAMES.includes(toolName)) {
      return {
        allowed: false,
        kind: 'blocked-tool',
        reason: `工具 ${toolName} 属破坏性操作，已被拦截`,
      }
    }

    const payloadHit = this.matchBlockedPattern(params)
    if (payloadHit) {
      return { allowed: false, kind: 'blocked-pattern', reason: `参数包含禁止模式: ${payloadHit}` }
    }

    const scopeHit = this.matchScopeViolation(params)
    if (scopeHit) {
      return { allowed: false, kind: 'scope', reason: this.scopeHint(scopeHit) }
    }

    const now = Date.now()
    while (this.timestamps.length > 0 && now - this.timestamps[0] >= 60_000) {
      this.timestamps.shift()
    }
    if (this.timestamps.length >= this.cfg.maxRequestsPerMinute) {
      return {
        allowed: false,
        kind: 'rate-limit',
        reason: `超过速率限制 (${this.cfg.maxRequestsPerMinute}/min)`,
      }
    }
    if (this.totalRequests >= this.cfg.maxTotalRequests) {
      return {
        allowed: false,
        kind: 'total-limit',
        reason: `超过总请求数限制 (${this.cfg.maxTotalRequests})`,
      }
    }

    return { allowed: true, kind: 'ok', reason: 'ok' }
  }

  private matchBlockedPattern(params: unknown): string | null {
    const serialized = safeStringify(params).toLowerCase()
    for (const pattern of this.cfg.blockedPayloadPatterns) {
      try {
        if (new RegExp(pattern, 'i').test(serialized)) return pattern
      } catch {
        // 配置里的非法正则不应让整条链路崩掉，忽略即可（配置加载时已有拼写校验空间）。
      }
    }
    return null
  }

  private matchScopeViolation(params: unknown): string | null {
    if (this.cfg.allowedDomains.length === 0) return null
    for (const candidate of collectUrlLikeValues(params)) {
      if (!this.isDomainAllowed(candidate)) return candidate
    }
    return null
  }

  /**
   * 目标主机是否落在授权白名单内（精确匹配或子域后缀匹配）。
   *
   * 接受裸域名输入（`portal.example.com`、`127.0.0.1:5000`）：调用方可能还没做地址
   * 归一化就来校验，这里不能因为解析失败就把合法目标判成越权。
   */
  isDomainAllowed(rawUrl: string): boolean {
    if (this.cfg.allowedDomains.length === 0) return true
    const host = hostOf(rawUrl, this.cfg.defaultScheme)
    if (!host) return false
    return this.cfg.allowedDomains.some((domain) => {
      const normalized = String(domain)
        .trim()
        .toLowerCase()
        .replace(/^https?:\/\//, '')
        .replace(/^\./, '')
        .split('/')[0]
        .split(':')[0]
      if (!normalized) return false
      return host === normalized || host.endsWith(`.${normalized}`)
    })
  }

  /** 授权范围的人类可读描述，供拦截信息与 target_scope 工具共用。 */
  describeScope(): string {
    if (this.cfg.allowedDomains.length === 0) {
      return '未配置授权域名白名单（当前不限制目标，仅建议离线/隔离环境这样用）'
    }
    return `当前授权域名：${this.cfg.allowedDomains.join('、')}`
  }

  /** 目标不在授权范围时的可执行提示。 */
  scopeHint(target: string): string {
    return (
      `目标 ${target} 不在授权范围内。${this.describeScope()}。` +
      '请把该域名加入 cordis.yml 的 allowedDomains（或用 targetAliases 给系统名配别名）后重试；' +
      '在获得授权前不要尝试绕过校验。'
    )
  }

  private record(toolName: string, params: unknown, allowed: boolean, reason: string): void {
    this.counter += 1
    this.auditLog.push({
      index: this.counter,
      timestamp: new Date().toISOString(),
      tool: toolName,
      params: sanitize(params),
      allowed,
      reason,
    })
    if (this.auditLog.length > MAX_AUDIT_ENTRIES) {
      this.auditLog.splice(0, this.auditLog.length - MAX_AUDIT_ENTRIES)
    }
  }

  /** 生成审计报告。 */
  report(limit = 50): AuditReport {
    const blocked = this.auditLog.filter((entry) => !entry.allowed).length
    const total = this.auditLog.length
    const now = Date.now()
    const lastMinute = this.timestamps.filter((ts) => now - ts < 60_000).length
    return {
      totalCalls: total,
      blockedCalls: blocked,
      allowedCalls: total - blocked,
      blockRate: total > 0 ? `${((blocked / total) * 100).toFixed(1)}%` : '0%',
      totalRequests: this.totalRequests,
      requestsLastMinute: lastMinute,
      limits: {
        maxRequestsPerMinute: this.cfg.maxRequestsPerMinute,
        maxTotalRequests: this.cfg.maxTotalRequests,
        allowedDomains: [...this.cfg.allowedDomains],
      },
      log: this.auditLog.slice(-Math.max(1, limit)).reverse(),
    }
  }

  /** 清空审计与计数（用于批量任务之间复位）。 */
  reset(): void {
    this.auditLog.length = 0
    this.timestamps.length = 0
    this.totalRequests = 0
    this.counter = 0
  }

  get usedRequests(): number {
    return this.totalRequests
  }
}

function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value) ?? String(value)
  } catch {
    return String(value)
  }
}

function sanitize(params: unknown): unknown {
  if (params === null || typeof params !== 'object') return params
  if (Array.isArray(params)) return params.map((item) => sanitize(item))
  const out: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(params as Record<string, unknown>)) {
    out[key] = SENSITIVE_KEY_PATTERN.test(key) ? '***REDACTED***' : sanitize(value)
  }
  return out
}

/** 递归收集参数里所有像 URL 的字符串，用于授权范围检查。 */
function collectUrlLikeValues(value: unknown, depth = 0): string[] {
  if (depth > 6 || value === null || value === undefined) return []
  if (typeof value === 'string') {
    return /^https?:\/\//i.test(value.trim()) ? [value.trim()] : []
  }
  if (Array.isArray(value)) {
    return value.flatMap((item) => collectUrlLikeValues(item, depth + 1))
  }
  if (typeof value === 'object') {
    return Object.values(value as Record<string, unknown>).flatMap((item) =>
      collectUrlLikeValues(item, depth + 1),
    )
  }
  return []
}
