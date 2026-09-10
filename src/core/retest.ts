/**
 * 复测流水线。
 *
 * 确定性流水线（不依赖 LLM 判断）：
 *
 *   情报（缓存或新侦察） → CVE 情报 → 情报判读 → 被动探测取证 → 判定
 *                                              ↘ 可选：非破坏性复现 → 升级为 VULNERABLE
 *
 * 判定纪律：不做主动利用、不投递攻击载荷，因此除非拿到非破坏性复现的正向
 * 证据，一律不给 VULNERABLE，而是给 UNCERTAIN 并说明还差什么。
 */
import { mkdir, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import type { CvescoutRuntime } from './runtime.ts'
import { resolveTarget } from './runtime.ts'
import { normalizeKey, resolveReportDir } from './cache.ts'
import { request } from './http.ts'
import { formatRange } from './judge.ts'
import { executeRepro } from './pentest.ts'
import { fingerprintTarget, type FingerprintResult } from '../sources/fingerprint.ts'
import { lookupCve, normalizeCveId } from '../sources/nvd.ts'
import { searchPoc } from '../sources/poc.ts'
import type {
  BatchRetestResult,
  PocEntry,
  PocResult,
  ProbeEvidence,
  ReproDoc,
  RetestResult,
  TargetIntel,
} from '../types.ts'

/** 写入报告时保留的响应头白名单（不含任何凭据值）。 */
const INTERESTING_HEADERS = [
  'server',
  'x-powered-by',
  'x-application-context',
  'x-generator',
  'via',
  'x-frame-options',
  'strict-transport-security',
]

export type RetestOptions = {
  /** 忽略缓存，强制重新侦察。 */
  forceRecon?: boolean
  /** 非破坏性复现文档；命中同一 CVE 时执行并可把结论升级为 VULNERABLE。 */
  reproDoc?: ReproDoc | null
  /** PoC 搜索返回条数上限。 */
  maxPocResults?: number
  /** 批量报告落盘目录，留空则用配置默认值。 */
  reportDir?: string
  /** 是否把报告写入磁盘。 */
  saveReport?: boolean
}

/** 把指纹结果转成情报模型。 */
export function intelFromFingerprint(targetUrl: string, fingerprint: FingerprintResult): TargetIntel {
  return {
    targetUrl,
    server: fingerprint.server,
    framework: fingerprint.framework,
    techStack: fingerprint.techStack,
    wafDetected: fingerprint.wafDetected,
    wafVendor: fingerprint.wafVendor,
    lastScanned: new Date().toISOString(),
    scanStatus: fingerprint.error ? 'failed' : fingerprint.probeErrors.length > 0 ? 'partial' : 'complete',
    scanDurationMs: fingerprint.scanDurationMs,
    allowedMethods: fingerprint.allowedMethods,
    errorPageSignature: fingerprint.errorPageSignature,
  }
}

/** 取情报：缓存优先，未命中或强制刷新时重新侦察。 */
export async function ensureIntel(
  runtime: CvescoutRuntime,
  targetUrl: string,
  forceRecon: boolean,
  signal?: AbortSignal,
): Promise<{ intel: TargetIntel; cacheHit: boolean; fresh: FingerprintResult | null }> {
  if (!forceRecon) {
    const cached = await runtime.cache.get(normalizeKey(targetUrl))
    if (cached) return { intel: cached, cacheHit: true, fresh: null }
  }

  const fresh = await fingerprintTarget(runtime, targetUrl, signal)
  const intel = intelFromFingerprint(targetUrl, fresh)
  if (!fresh.error) {
    await runtime.cache.set(intel)
  }
  return { intel, cacheHit: false, fresh }
}

/** 收集被动探测证据。本次已侦察过就直接复用，避免重复请求。 */
export async function collectEvidence(
  runtime: CvescoutRuntime,
  targetUrl: string,
  fresh: FingerprintResult | null,
  intel: TargetIntel,
  signal?: AbortSignal,
): Promise<ProbeEvidence[]> {
  if (fresh) {
    return [
      {
        url: targetUrl,
        method: 'GET',
        statusCode: fresh.statusCode ?? 0,
        server: fresh.server,
        poweredBy: null,
        allowedMethods: fresh.allowedMethods,
        interestingHeaders: {},
        note: '复用本次指纹侦察结果，未发额外请求',
      },
    ]
  }

  try {
    runtime.safety.assertAllowed('cve_retest', { url: targetUrl })
    const response = await request(runtime.cfg, { url: targetUrl, method: 'GET' }, signal)
    return [
      {
        url: targetUrl,
        method: 'GET',
        statusCode: response.statusCode,
        server: response.headers.server ?? null,
        poweredBy: response.headers['x-powered-by'] ?? null,
        allowedMethods: intel.allowedMethods,
        interestingHeaders: pickInteresting(response.headers),
        note: '情报来自缓存，仅做一次存活与响应头确认',
      },
    ]
  } catch (error) {
    return [
      {
        url: targetUrl,
        method: 'GET',
        statusCode: 0,
        server: intel.server,
        poweredBy: null,
        allowedMethods: intel.allowedMethods,
        interestingHeaders: {},
        note: `存活确认失败: ${(error as Error).message}`,
      },
    ]
  }
}

function pickInteresting(headers: Record<string, string>): Record<string, string> {
  const picked: Record<string, string> = {}
  for (const name of INTERESTING_HEADERS) {
    const value = headers[name]
    if (value) picked[name] = value
  }
  // 只记 Cookie 名，不记值，避免把会话标识写进报告。
  const cookies = headers['set-cookie']
  if (cookies) {
    picked['set-cookie-names'] = cookies
      .split(/,(?=[^;]+=)/)
      .map((item) => item.split('=')[0].trim())
      .filter(Boolean)
      .join(', ')
  }
  return picked
}

/** 单个 CVE 复测。 */
export async function retestOne(
  runtime: CvescoutRuntime,
  targetUrl: string,
  cveIdRaw: string,
  options: RetestOptions = {},
  signal?: AbortSignal,
): Promise<RetestResult> {
  const cveId = normalizeCveId(cveIdRaw)
  // 用户可能只给域名或系统别名：先归一化，后续护栏与缓存键都基于它。
  const target = resolveTarget(runtime, targetUrl)
  const { intel, cacheHit, fresh } = await ensureIntel(runtime, target, options.forceRecon === true, signal)
  const cve = await lookupCve(runtime.cfg, cveId, signal)
  const judgment = runtime.judge.judge(cve, intel)

  const limitations: string[] = []
  let poc: PocResult = { cveId, pocCount: 0, pocs: [] }
  let evidence: ProbeEvidence[] = []

  let verdict: RetestResult['verdict']
  let confidence: number
  let reason: string
  let reproducibility: RetestResult['reproducibility']

  if (cve.error) {
    verdict = 'UNCERTAIN'
    confidence = 0.1
    reproducibility = 'low'
    reason = `CVE 情报不可用：${cve.error}`
    limitations.push('缺少 CVE 受影响范围，无法做任何版本比对')
  } else if (judgment.applicable === 'no') {
    verdict = 'NOT_VULNERABLE'
    confidence = 0.95
    reproducibility = 'low'
    reason = judgment.reason
    limitations.push('结论基于组件版本比对；若目标存在多个同类组件实例，需确认版本取样点是否为实际生效实例')
  } else {
    poc = await searchPoc(runtime.cfg, cveId, signal, options.maxPocResults ?? 5)
    evidence = await collectEvidence(runtime, target, fresh, intel, signal)

    if (judgment.applicable === 'yes') {
      verdict = 'UNCERTAIN'
      confidence = poc.pocCount > 0 ? 0.7 : 0.6
      reproducibility = poc.pocCount > 0 ? 'high' : 'medium'
      reason = `${judgment.reason}；${
        poc.pocCount > 0
          ? `存在 ${poc.pocCount} 个公开 PoC，需按复现文档做非破坏性实证`
          : '未找到公开 PoC，需人工核查触发前提（默认配置是否可达）'
      }`
      if (poc.pocCount === 0) {
        limitations.push('无公开 PoC，仅凭版本区间推断，无法排除前置条件不满足的情况')
      }
    } else {
      verdict = 'UNCERTAIN'
      confidence = 0.3
      reproducibility = 'low'
      reason = judgment.reason
      limitations.push('未识别到 CVE 涉及组件，可能是指纹覆盖不足或目标为 SPA/动态渲染，需人工核查')
    }
  }

  if (cacheHit) {
    limitations.push(`情报来自缓存（TTL ${runtime.cfg.cacheTtlHours}h），未重新侦察，如需刷新请置 forceRecon=true`)
  }
  if (intel.wafDetected) {
    limitations.push(`目标前置 ${intel.wafVendor ?? 'WAF/网关'}，被动探测结果可能被拦截或改写`)
  }
  limitations.push('本插件不投递攻击载荷、不做真实内容写入；VULNERABLE 只在拿到非破坏性复现正向证据时给出')

  // 可选：执行非破坏性复现，成功则升级结论。
  let pentest: RetestResult['pentest'] = null
  const reproDoc = options.reproDoc ?? null
  if (reproDoc && normalizeCveId(reproDoc.cveId) === cveId && reproDoc.steps.length > 0) {
    const report = await executeRepro(runtime, target, reproDoc, signal)
    pentest = {
      executed: true,
      success: report.overallSuccess,
      stepsTotal: report.stepsTotal,
      stepsSuccess: report.stepsSuccess,
      stepsSkipped: report.stepsSkipped,
      summary: report.summary,
      reasons: report.recommendations,
    }
    if (report.overallSuccess) {
      verdict = 'VULNERABLE'
      confidence = 0.9
      reproducibility = 'high'
      reason = `${reason}；非破坏性复现取得正向证据（${report.stepsSuccess}/${report.stepsTotal} 步成功）`
    } else {
      limitations.push('复现步骤未取得正向证据，不能据此排除漏洞，需人工复核步骤与前置条件')
    }
  }

  return {
    cveId,
    targetUrl: target,
    verdict,
    applicable: judgment.applicable,
    confidence,
    reason,
    reproducibility,
    component: judgment.matchedComponent
      ? { name: judgment.matchedComponent, version: judgment.targetVersion }
      : null,
    affectedRange: judgment.range,
    cvss: { score: cve.cvssScore, severity: cve.severity },
    poc: { count: poc.pocCount, top: poc.pocs.slice(0, 5) },
    intel: {
      cacheHit,
      lastScanned: intel.lastScanned,
      server: intel.server,
      waf: intel.wafDetected ? (intel.wafVendor ?? 'detected') : null,
    },
    evidence,
    pentest,
    limitations,
    generatedAt: new Date().toISOString(),
  }
}

/** 批量复测。 */
export async function retestBatch(
  runtime: CvescoutRuntime,
  targetUrl: string,
  cveIds: string[],
  options: RetestOptions = {},
  signal?: AbortSignal,
): Promise<BatchRetestResult> {
  const unique = Array.from(new Set(cveIds.map((item) => normalizeCveId(item)).filter(Boolean)))
  const target = resolveTarget(runtime, targetUrl)
  const results: RetestResult[] = []

  for (const cveId of unique) {
    if (signal?.aborted) break
    results.push(
      await retestOne(
        runtime,
        target,
        cveId,
        { ...options, saveReport: false, reproDoc: options.reproDoc ?? null },
        signal,
      ),
    )
  }

  const stats = {
    vulnerable: results.filter((item) => item.verdict === 'VULNERABLE').length,
    notVulnerable: results.filter((item) => item.verdict === 'NOT_VULNERABLE').length,
    uncertain: results.filter((item) => item.verdict === 'UNCERTAIN').length,
    probed: results.filter((item) => item.evidence.length > 0).length,
    skippedByIntel: results.filter((item) => item.applicable === 'no').length,
  }

  const batch: BatchRetestResult = {
    targetUrl: target,
    total: results.length,
    stats,
    results,
    report: '',
    reportPath: null,
    reportJsonPath: null,
    generatedAt: new Date().toISOString(),
  }
  batch.report = renderBatchReport(batch)

  if (options.saveReport) {
    const dir = options.reportDir?.trim() || resolveReportDir(runtime.cfg)
    const stamp = new Date().toISOString().replace(/[:.]/g, '-')
    const host = safeHostName(targetUrl)
    const base = join(dir, `${host}-${stamp}`)
    await mkdir(dir, { recursive: true })
    await writeFile(`${base}.md`, batch.report, 'utf8')
    await writeFile(
      `${base}.json`,
      JSON.stringify({ ...batch, report: undefined }, null, 2),
      'utf8',
    )
    batch.reportPath = `${base}.md`
    batch.reportJsonPath = `${base}.json`
  }

  return batch
}

/** 生成 Markdown 汇总报告。 */
export function renderBatchReport(batch: BatchRetestResult): string {
  const lines: string[] = []
  lines.push('# CVE 批量复测汇总报告')
  lines.push('')
  lines.push(`- 目标: ${batch.targetUrl}`)
  lines.push(`- 复测 CVE 数量: ${batch.total}`)
  lines.push(`- 生成时间: ${batch.generatedAt}`)
  lines.push('')
  lines.push('## 统计')
  lines.push('')
  lines.push(`- 存在漏洞（有正向证据）: ${batch.stats.vulnerable}`)
  lines.push(`- 不受影响（可排除）: ${batch.stats.notVulnerable}`)
  lines.push(`- 需人工确认: ${batch.stats.uncertain}`)
  lines.push(`- 被动探测取证: ${batch.stats.probed}`)
  lines.push(`- 情报预判排除: ${batch.stats.skippedByIntel}`)
  lines.push('')

  const groups: Array<{ title: string; filter: (item: RetestResult) => boolean }> = [
    { title: '存在漏洞的 CVE', filter: (item) => item.verdict === 'VULNERABLE' },
    { title: '不受影响的 CVE', filter: (item) => item.verdict === 'NOT_VULNERABLE' },
    { title: '需要人工确认的 CVE', filter: (item) => item.verdict === 'UNCERTAIN' },
  ]

  for (const group of groups) {
    const items = batch.results.filter(group.filter)
    lines.push(`## ${group.title}`)
    lines.push('')
    if (items.length === 0) {
      lines.push('无')
      lines.push('')
      continue
    }
    for (const item of items) {
      const cvss = item.cvss.score !== null ? ` | CVSS ${item.cvss.score}` : ''
      lines.push(`### ${item.cveId}（置信度 ${item.confidence}${cvss}）`)
      lines.push('')
      lines.push(`- 结论依据: ${item.reason}`)
      if (item.component) {
        lines.push(`- 命中组件: ${item.component.name} ${item.component.version ?? '(版本未知)'}`)
      }
      if (item.affectedRange) {
        lines.push(`- 受影响区间: ${formatRange(item.affectedRange)}`)
      }
      if (item.poc.count > 0) {
        lines.push(`- 公开 PoC: ${item.poc.count} 个，例如 ${item.poc.top[0]?.url ?? '-'}`)
      }
      if (item.pentest?.executed) {
        lines.push(`- 非破坏性复现: ${item.pentest.success ? '成功' : '未取得正向证据'}（${item.pentest.stepsSuccess}/${item.pentest.stepsTotal} 步）`)
      }
      if (item.limitations.length > 0) {
        lines.push(`- 限制: ${item.limitations.join('；')}`)
      }
      lines.push('')
    }
  }

  lines.push('---')
  lines.push('')
  lines.push('本报告由 CVEScout DeepSeek Harness 插件生成：仅使用被动探测与非破坏性复现，未向目标投递攻击载荷。')
  return lines.join('\n')
}

function safeHostName(targetUrl: string): string {
  try {
    return new URL(targetUrl).hostname.replace(/[^a-zA-Z0-9.-]/g, '_')
  } catch {
    return targetUrl.replace(/[^a-zA-Z0-9.-]/g, '_').slice(0, 60)
  }
}

/** 从复测结果里挑选要展示的 PoC 链接（供工具渲染复用）。 */
export function topPocLinks(result: RetestResult, limit = 3): PocEntry[] {
  return result.poc.top.slice(0, limit)
}
