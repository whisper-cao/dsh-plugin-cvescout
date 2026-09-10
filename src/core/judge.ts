/**
 * 情报判读引擎。
 *
 * 职责：拿到目标指纹情报和 CVE 受影响范围后，先做一次「能不能直接排除」的
 * 静态判断，尽量不做无意义的主动探测。
 *
 * 两处刻意的实现选择：
 *  - 组件名匹配用归一化 + 别名表，能对上 http_server ↔ Apache、
 *    spring-boot ↔ Spring Boot 这类写法差异；短名只允许精确匹配，避免
 *    `nx`（Siemens NX）被 `nginx` 包含这类误判。
 *  - 版本比较用不依赖第三方库的 best-effort 比较器（支持 1.2.83 > 1.2.8、
 *    1.2.0-rc1 < 1.2.0 这类情况），命中不确定区间时不会硬给结论。
 *  - 在版本判读之上叠加**协议前置条件**：一批 CVE 必须启用 HTTP/2 才能触发，
 *    实测确认目标不提供 HTTP/2 时可直接排除（见 applyProtocolPrecondition）。
 */
import type { AffectedProduct, CveInfo, Judgment, TargetIntel, VersionRange } from '../types.ts'

/** 版本号切段：先按分隔符切，再在段内切出数字/字母块。 */
function segments(version: string): Array<Array<number | string>> {
  const cleaned = String(version ?? '').trim().replace(/^[vV]/, '')
  if (!cleaned) return []
  return cleaned
    .split(/[.\-_+~:]/)
    .filter((segment) => segment.length > 0)
    .map((segment) => {
      const chunks: Array<number | string> = []
      const re = /(\d+)|([A-Za-z]+)/g
      let match: RegExpExecArray | null
      while ((match = re.exec(segment)) !== null) {
        chunks.push(match[1] !== undefined ? Number(match[1]) : match[2].toLowerCase())
      }
      return chunks
    })
}

function compareChunk(a: number | string | undefined, b: number | string | undefined): number {
  if (a === undefined && b === undefined) return 0
  if (a === undefined) return typeof b === 'number' ? -1 : 1
  if (b === undefined) return typeof a === 'number' ? 1 : -1
  if (typeof a === 'number' && typeof b === 'number') return a === b ? 0 : a > b ? 1 : -1
  if (typeof a === 'string' && typeof b === 'string') {
    if (a === b) return 0
    return a > b ? 1 : -1
  }
  // 数字块 > 字母块：1.2.0 > 1.2.0-rc1，符合常见语义化版本直觉。
  return typeof a === 'number' ? 1 : -1
}

/** best-effort 版本比较。返回 -1 / 0 / 1。无法比较时按字符串比较兜底。 */
export function compareVersions(a: string, b: string): number {
  const sa = segments(a)
  const sb = segments(b)
  if (sa.length === 0 || sb.length === 0) {
    return a === b ? 0 : a > b ? 1 : -1
  }
  const length = Math.max(sa.length, sb.length)
  for (let i = 0; i < length; i += 1) {
    const ca = sa[i] ?? []
    const cb = sb[i] ?? []
    const chunkLength = Math.max(ca.length, cb.length)
    for (let j = 0; j < chunkLength; j += 1) {
      const result = compareChunk(ca[j], cb[j])
      if (result !== 0) return result
    }
  }
  return 0
}

/** 判断版本是否落在受影响区间内。区间信息缺失的一侧视为无穷。 */
export function isVersionInRange(version: string, range: VersionRange): boolean {
  if (range.start) {
    const lower = compareVersions(version, range.start)
    if (lower < 0) return false
  }
  if (range.end) {
    const upper = compareVersions(version, range.end)
    if (range.endInclusive ? upper > 0 : upper >= 0) return false
  }
  return true
}

/** 归一化组件名：去掉大小写、分隔符与常见后缀噪声。 */
export function normalizeComponentName(name: string): string {
  return String(name ?? '')
    .toLowerCase()
    .replace(/^cpe:2\.3:[aho*]:[^:]*:/, '')
    .replace(/\.(js|py|java|net|rb|php|go)$/, '')
    .replace(/[^a-z0-9]/g, '')
}

/** 组件名别名表：CPE 里的写法 → 指纹里常见的写法。 */
const COMPONENT_ALIASES: Record<string, string[]> = {
  httpserver: ['apache', 'httpd', 'apachehttpserver'],
  apache: ['apache', 'httpd', 'httpserver'],
  nginx: ['nginx'],
  tomcat: ['tomcat', 'apachetomcat', 'coyote'],
  springboot: ['springboot', 'spring'],
  springframework: ['spring', 'springframework'],
  fastjson: ['fastjson'],
  jackson: ['jackson', 'jacksondatabind'],
  log4j: ['log4j', 'log4j2'],
  struts: ['struts', 'struts2'],
  mchangecommonsjava: ['mchangecommonsjava', 'mchange'],
}

/** 子串匹配的最小长度：短名（如 CPE 里的 nx / ip / vm）极易误命中，必须排除。 */
const MIN_SUBSTRING_LENGTH = 5

/** 在情报里查找与 CPE 组件名对应的条目。 */
export function findIntelComponent(
  intel: TargetIntel,
  componentName: string,
): { name: string; version: string | null } | null {
  const normalized = normalizeComponentName(componentName)
  if (!normalized) return null
  const candidates = new Set<string>([normalized, ...(COMPONENT_ALIASES[normalized] ?? [])])

  for (const component of intel.techStack) {
    const stackName = normalizeComponentName(component.name)
    if (!stackName) continue
    for (const candidate of candidates) {
      if (matchesName(stackName, candidate)) {
        return { name: component.name, version: component.version ?? null }
      }
    }
  }

  const haystacks = [intel.server, intel.framework].filter((value): value is string => Boolean(value))
  for (const haystack of haystacks) {
    const normalizedHaystack = normalizeComponentName(haystack)
    for (const candidate of candidates) {
      if (candidate.length >= MIN_SUBSTRING_LENGTH && normalizedHaystack.includes(candidate)) {
        const versionMatch = haystack.match(/(\d+(?:\.\d+)+)/)
        return { name: componentName, version: versionMatch ? versionMatch[1] : null }
      }
    }
  }

  return null
}

/**
 * 组件名匹配规则：先精确，再允许长名子串。
 *
 * 这里刻意不做「短名子串」匹配——CPE 里 `nx`（Siemens NX）会被 `nginx` 包含，
 * 早先的宽松匹配会把 log4j 的 CVE 判到 nginx 目标上。
 */
function matchesName(stackName: string, candidate: string): boolean {
  if (stackName === candidate) return true
  const shortest = Math.min(stackName.length, candidate.length)
  if (shortest < MIN_SUBSTRING_LENGTH) return false
  return stackName.includes(candidate) || candidate.includes(stackName)
}

export class IntelJudge {
  /**
   * 预判 CVE 对目标是否适用。
   *
   * `skipRecon: true` 表示证据已经足够（例如版本明确不在受影响区间），
   * 调用方可以直接给 NOT_VULNERABLE，无需再做主动探测。
   */
  judge(cveInfo: CveInfo, intel: TargetIntel): Judgment {
    return applyProtocolPrecondition(cveInfo, intel, this.judgeByVersion(cveInfo, intel))
  }

  /** 纯版本区间判读。协议前置条件由 {@link applyProtocolPrecondition} 叠加。 */
  private judgeByVersion(cveInfo: CveInfo, intel: TargetIntel): Judgment {
    const cveId = cveInfo.cveId
    const products = cveInfo.affectedProducts ?? []

    if (products.length === 0) {
      return {
        cveId,
        applicable: 'uncertain',
        reason: cveInfo.error
          ? `CVE 情报不可用（${cveInfo.error}），无法判读`
          : 'CVE 信息中缺少受影响产品数据',
        skipRecon: false,
        matchedComponent: null,
        targetVersion: null,
        range: null,
      }
    }

    const notes: string[] = []
    for (const product of products) {
      const matched = findIntelComponent(intel, product.component)
      if (!matched) continue

      const range: VersionRange = {
        start: product.versionStart,
        end: product.versionEnd,
        endInclusive: product.versionEndInclusive,
      }

      if (!matched.version) {
        notes.push(`目标存在 ${matched.name} 但未能取到版本号，无法与 ${product.component} 区间比对`)
        continue
      }

      if (isVersionInRange(matched.version, range)) {
        return {
          cveId,
          applicable: 'yes',
          reason: `目标运行 ${matched.name} ${matched.version}，落在受影响区间 ${formatRange(range)} 内`,
          skipRecon: false,
          matchedComponent: matched.name,
          targetVersion: matched.version,
          range,
        }
      }

      return {
        cveId,
        applicable: 'no',
        reason: `目标运行 ${matched.name} ${matched.version}，不在受影响区间 ${formatRange(range)} 内`,
        skipRecon: true,
        matchedComponent: matched.name,
        targetVersion: matched.version,
        range,
        exclusionBasis: 'version',
      }
    }

    return {
      cveId,
      applicable: 'uncertain',
      reason:
        notes.length > 0
          ? notes.join('；')
          : `目标指纹中未识别到 CVE 涉及组件（${distinctComponents(products).slice(0, 4).join(', ')}），需人工核查`,
      skipRecon: false,
      matchedComponent: null,
      targetVersion: null,
      range: null,
    }
  }

  /** 批量判读。 */
  batchJudge(cveList: CveInfo[], intel: TargetIntel): {
    judgments: Judgment[]
    summary: { total: number; applicable: number; notApplicable: number; uncertain: number; canSkipRecon: number }
  } {
    const judgments = cveList.map((cve) => this.judge(cve, intel))
    return {
      judgments,
      summary: {
        total: judgments.length,
        applicable: judgments.filter((item) => item.applicable === 'yes').length,
        notApplicable: judgments.filter((item) => item.applicable === 'no').length,
        uncertain: judgments.filter((item) => item.applicable === 'uncertain').length,
        canSkipRecon: judgments.filter((item) => item.skipRecon).length,
      },
    }
  }
}

/** 生成人类可读的区间描述。 */
export function formatRange(range: VersionRange): string {
  const start = range.start ? `>= ${range.start}` : '任意低版本'
  const end = range.end ? `${range.endInclusive ? '<= ' : '< '}${range.end}` : '任意高版本'
  return `${start} 且 ${end}`
}

/** 去重后的受影响组件名。 */
function distinctComponents(products: AffectedProduct[]): string[] {
  return Array.from(new Set(products.map((item) => item.component)))
}

// ---------------------------------------------------------------------------
// 协议前置条件判读
// ---------------------------------------------------------------------------

/**
 * 已知「必须启用 HTTP/2 才能触发」的高关注 CVE。
 *
 * 这类漏洞的触发面完全落在 HTTP/2 帧层（Rapid Reset、CONTINUATION flood、
 * 各类 h2 DoS），所以一旦实测确认目标**不提供 HTTP/2 over TLS**，就可以直接
 * 排除，不必再纠结版本区间。名单只收录公开资料明确限定 HTTP/2 的条目。
 */
const HTTP2_REQUIRED_CVES: ReadonlySet<string> = new Set([
  // HTTP/2 Rapid Reset
  'CVE-2023-44487',
  // Apache httpd：HTTP/2 DoS 与 CONTINUATION flood
  'CVE-2023-43622',
  'CVE-2024-27316',
  // Apache Tomcat：HTTP/2 请求处理 DoS
  'CVE-2024-24549',
  // Node.js：HTTP/2 CONTINUATION DoS
  'CVE-2024-27983',
  // 2019 年 HTTP/2 DoS 系列（"The Nine"）
  'CVE-2019-9511',
  'CVE-2019-9512',
  'CVE-2019-9513',
  'CVE-2019-9514',
  'CVE-2019-9515',
  'CVE-2019-9516',
  'CVE-2019-9517',
  'CVE-2019-9518',
])

/** 描述里提到 HTTP/2 相关术语。 */
const HTTP2_DESCRIPTION_PATTERN = /HTTP\/2|HTTP2|\bh2c?\b|HPACK|CONTINUATION/i
/** 描述里提到拒绝服务 / 资源耗尽语义。 */
const DOS_DESCRIPTION_PATTERN =
  /denial of service|resource exhaustion|memory exhaustion|cpu exhaustion|rapid reset|\bDoS\b|拒绝服务|资源耗尽/i

/** 判断该 CVE 是否以「启用 HTTP/2」为触发前提。 */
export function requiresHttp2(cveInfo: CveInfo): { required: boolean; basis: string | null } {
  if (HTTP2_REQUIRED_CVES.has(String(cveInfo.cveId).toUpperCase())) {
    return { required: true, basis: '该 CVE 属公开资料明确限定 HTTP/2 的条目' }
  }
  const text = `${cveInfo.description ?? ''} ${(cveInfo.references ?? []).join(' ')}`
  if (HTTP2_DESCRIPTION_PATTERN.test(text) && DOS_DESCRIPTION_PATTERN.test(text)) {
    return { required: true, basis: '描述同时提到 HTTP/2 与拒绝服务/资源耗尽' }
  }
  return { required: false, basis: null }
}

export type ProtocolPrecondition = {
  status: 'not-required' | 'satisfied' | 'violated' | 'unknown'
  detail: string
}

/**
 * 评估 HTTP/2 前置条件。
 *
 * `violated` 只在**实测确认**不支持 HTTP/2 时给出；探测失败或情报来自旧缓存
 * （没有 `tls` 字段）时一律 unknown——绝不把「不知道」当成「不支持」。
 */
export function assessHttp2Precondition(
  cveInfo: CveInfo,
  intel: TargetIntel,
): ProtocolPrecondition {
  const { required, basis } = requiresHttp2(cveInfo)
  if (!required) return { status: 'not-required', detail: '' }

  const tls = intel.tls ?? null
  const hints = intel.protocolHints ?? null

  // Alt-Svc 广告了 h2 说明服务端确实提供 HTTP/2，即使握手被中间设备改写也算满足。
  if (hints?.http2Advertised) {
    return { status: 'satisfied', detail: `响应头 Alt-Svc 广告了 h2（${basis}）` }
  }

  if (tls && tls.ok) {
    return {
      status: tls.http2 ? 'satisfied' : 'violated',
      detail: `${tls.http2Evidence}（${basis}）`,
    }
  }

  const reason = tls?.error ?? '未做 TLS 探测（目标非 https 或探测已关闭）'
  return { status: 'unknown', detail: `协议能力未知：${reason}（${basis}）` }
}

/**
 * 把协议前置条件叠加到版本判读结果上。
 *
 * 只收紧、不放松：
 *  - 前置条件被实测证伪 → 不管版本是否命中区间，一律 `applicable: 'no'` 且跳过取证。
 *    这把原本只能给 `UNCERTAIN` 的「版本命中但无法实证」变成确定性的排除。
 *  - 前置条件满足 → 保留版本结论，仅在版本未给结论时补上协议事实。
 *  - 未知 → 不动结论，只在版本不是「已排除」时把不确定性写进理由。
 */
function applyProtocolPrecondition(
  cveInfo: CveInfo,
  intel: TargetIntel,
  base: Judgment,
): Judgment {
  const precondition = assessHttp2Precondition(cveInfo, intel)
  if (precondition.status === 'not-required') return base

  if (precondition.status === 'violated') {
    return {
      ...base,
      applicable: 'no',
      skipRecon: true,
      exclusionBasis: 'protocol',
      reason: `目标不满足该 CVE 的协议前置条件：${precondition.detail}`,
    }
  }

  if (precondition.status === 'satisfied') {
    if (base.applicable === 'no') return base
    return { ...base, reason: `${base.reason}；协议前置条件已满足（${precondition.detail}）` }
  }

  // unknown：版本已经能排除时不必再堆协议噪声。
  if (base.applicable === 'no') return base
  return { ...base, reason: `${base.reason}；${precondition.detail}` }
}
