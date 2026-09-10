/**
 * 目标技术栈指纹识别。
 *
 * 设计要点：
 *  - 除 header / body 外增加 cookie 来源，能识别 JSESSIONID（Java 容器）、
 *    Spring Boot 默认错误页、Next.js 等只看响应头看不出来的栈；
 *  - 覆盖常见 Java 生态指纹（Tomcat / Spring Boot / Jetty / Undertow）；
 *  - **协议能力**：做一次裸 TLS 握手判定 HTTP/2 over TLS 是否可用，并读 `Alt-Svc`
 *    广告，这两条是「仅 HTTP/2 可触发」类 CVE 的排除依据；
 *  - **并行执行**：根请求之后 OPTIONS / 错误页 / 各被动路径 / TLS 握手彼此独立，
 *    全部并发（并发上限走配置）。原先串行时每个额外探测都要多等一个往返。
 *  - 每个探测动作都要过安全护栏，探测路径与是否做 OPTIONS/错误页/TLS 探测都走配置。
 */
import type { ProtocolHints, TechComponent, TlsIntel } from '../types.ts'
import { request } from '../core/http.ts'
import { SafetyBlockedError } from '../core/safety.ts'
import { resolveTarget } from '../core/runtime.ts'
import type { CvescoutRuntime } from '../core/runtime.ts'
import { emptyTlsIntel, probeTls } from '../core/tls.ts'

export interface FingerprintResult {
  targetUrl: string
  statusCode: number | null
  server: string | null
  framework: string | null
  title: string | null
  techStack: TechComponent[]
  wafDetected: boolean
  wafVendor: string | null
  allowedMethods: string[]
  errorPageSignature: string | null
  robots: string | null
  securityTxt: string | null
  /** TLS / ALPN 探测结果；目标非 https 或探测被关闭时为 null。 */
  tls: TlsIntel | null
  /** HTTP 层协议线索（Alt-Svc / Via）。 */
  protocolHints: ProtocolHints | null
  scanDurationMs: number
  probeErrors: string[]
  error?: string
}

type RuleSource = 'header' | 'body' | 'cookie'

interface FingerprintRule {
  name: string
  category: string
  pattern: string
  from: RuleSource
  /** 取 header 时指定 header 名，留空表示匹配全部响应头拼接串。 */
  header?: string
  confidence: number
  /** 命中后是否直接判定为 WAF。 */
  waf?: boolean
}

/** 指纹规则表。 */
export const FINGERPRINT_RULES: readonly FingerprintRule[] = [
  // ---- 服务器 / 容器 ----
  { name: 'Apache', category: 'server', pattern: 'Apache/([\\d.]+)', from: 'header', header: 'server', confidence: 0.9 },
  { name: 'Nginx', category: 'server', pattern: 'nginx/([\\d.]+)', from: 'header', header: 'server', confidence: 0.9 },
  { name: 'Nginx', category: 'server', pattern: '^nginx$', from: 'header', header: 'server', confidence: 0.7 },
  { name: 'Microsoft-IIS', category: 'server', pattern: 'Microsoft-IIS/([\\d.]+)', from: 'header', header: 'server', confidence: 0.9 },
  { name: 'LiteSpeed', category: 'server', pattern: 'LiteSpeed', from: 'header', header: 'server', confidence: 0.85 },
  { name: 'OpenResty', category: 'server', pattern: 'openresty/([\\d.]+)', from: 'header', header: 'server', confidence: 0.9 },
  { name: 'Tengine', category: 'server', pattern: 'Tengine', from: 'header', header: 'server', confidence: 0.85 },
  { name: 'Apache Tomcat', category: 'server', pattern: 'Apache-Coyote/([\\d.]+)|Tomcat/([\\d.]+)', from: 'header', header: 'server', confidence: 0.85 },
  { name: 'Jetty', category: 'server', pattern: 'Jetty\\(([\\d.]+)', from: 'header', header: 'server', confidence: 0.85 },
  { name: 'Gunicorn', category: 'server', pattern: 'gunicorn/([\\d.]+)', from: 'header', header: 'server', confidence: 0.85 },
  { name: 'Uvicorn', category: 'server', pattern: 'uvicorn', from: 'header', header: 'server', confidence: 0.8 },
  { name: 'Werkzeug', category: 'server', pattern: 'Werkzeug/([\\d.]+)', from: 'header', header: 'server', confidence: 0.85 },
  { name: 'Undertow', category: 'server', pattern: 'undertow', from: 'header', header: 'server', confidence: 0.8 },
  { name: 'cloudflare', category: 'server', pattern: 'cloudflare', from: 'header', header: 'server', confidence: 0.8 },
  { name: 'Caddy', category: 'server', pattern: 'Caddy', from: 'header', header: 'server', confidence: 0.8 },
  { name: 'Envoy', category: 'server', pattern: 'envoy', from: 'header', header: 'server', confidence: 0.8 },
  { name: 'HAProxy', category: 'server', pattern: 'HAProxy', from: 'header', header: 'server', confidence: 0.75 },
  { name: 'Traefik', category: 'server', pattern: 'Traefik', from: 'header', header: 'server', confidence: 0.8 },
  { name: 'Kestrel', category: 'server', pattern: 'Kestrel', from: 'header', header: 'server', confidence: 0.8 },
  { name: 'Cowboy', category: 'server', pattern: 'Cowboy', from: 'header', header: 'server', confidence: 0.75 },
  { name: 'lighttpd', category: 'server', pattern: 'lighttpd/([\\d.]+)', from: 'header', header: 'server', confidence: 0.85 },
  { name: 'WildFly', category: 'server', pattern: 'WildFly|JBoss', from: 'header', header: 'server', confidence: 0.8 },
  { name: 'Zyxel', category: 'server', pattern: 'Zyxel|zyxel', from: 'header', header: 'server', confidence: 0.7 },

  // ---- 语言 / 框架 ----
  { name: 'PHP', category: 'framework', pattern: 'PHP/([\\d.]+)', from: 'header', header: 'x-powered-by', confidence: 0.9 },
  { name: 'Express.js', category: 'framework', pattern: 'Express', from: 'header', header: 'x-powered-by', confidence: 0.85 },
  { name: 'ASP.NET', category: 'framework', pattern: 'ASP\\.NET', from: 'header', header: 'x-powered-by', confidence: 0.8 },
  { name: 'ASP.NET', category: 'framework', pattern: '([\\d.]+)', from: 'header', header: 'x-aspnet-version', confidence: 0.85 },
  { name: 'Spring Boot', category: 'framework', pattern: '.+', from: 'header', header: 'x-application-context', confidence: 0.85 },
  { name: 'Servlet', category: 'framework', pattern: 'Servlet/([\\d.]+)', from: 'header', header: 'x-powered-by', confidence: 0.8 },
  { name: 'Next.js', category: 'framework', pattern: 'Next\\.js', from: 'header', header: 'x-powered-by', confidence: 0.85 },
  { name: 'Drupal', category: 'framework', pattern: '.+', from: 'header', header: 'x-generator', confidence: 0.8 },
  { name: 'Java Servlet', category: 'framework', pattern: 'JSESSIONID', from: 'cookie', confidence: 0.7 },
  { name: 'PHP', category: 'framework', pattern: 'PHPSESSID', from: 'cookie', confidence: 0.75 },
  { name: 'ASP.NET', category: 'framework', pattern: 'ASP\\.NET_SessionId', from: 'cookie', confidence: 0.8 },
  { name: 'Laravel', category: 'framework', pattern: 'laravel_session', from: 'cookie', confidence: 0.75 },
  { name: 'CodeIgniter', category: 'framework', pattern: 'ci_session', from: 'cookie', confidence: 0.7 },
  { name: 'Express.js', category: 'framework', pattern: 'connect\\.sid', from: 'cookie', confidence: 0.7 },
  { name: 'Next.js', category: 'framework', pattern: '__NEXT_DATA__|/_next/', from: 'body', confidence: 0.8 },
  { name: 'Nuxt', category: 'framework', pattern: '__NUXT__|/_nuxt/', from: 'body', confidence: 0.75 },
  { name: 'Django', category: 'framework', pattern: 'csrfmiddlewaretoken|__admin__', from: 'body', confidence: 0.6 },
  { name: 'Flask', category: 'framework', pattern: 'Werkzeug', from: 'body', confidence: 0.5 },
  { name: 'Vue SPA', category: 'framework', pattern: 'data-v-app|__vue__', from: 'body', confidence: 0.6 },
  { name: 'React SPA', category: 'framework', pattern: 'data-reactroot|__REACT_DEVTOOLS_GLOBAL_HOOK__', from: 'body', confidence: 0.6 },

  // ---- CMS ----
  { name: 'WordPress', category: 'cms', pattern: 'wp-content|wp-includes', from: 'body', confidence: 0.7 },
  { name: 'Drupal', category: 'cms', pattern: 'Drupal\\.settings|drupal', from: 'body', confidence: 0.6 },
  { name: 'Joomla', category: 'cms', pattern: 'Joomla!', from: 'body', confidence: 0.6 },

  // ---- 前端库 ----
  { name: 'jQuery', category: 'frontend', pattern: 'jquery[.-]([\\d.]+)', from: 'body', confidence: 0.7 },
  { name: 'Vue.js', category: 'frontend', pattern: 'vue[.@-]([\\d.]+)', from: 'body', confidence: 0.6 },
  { name: 'React', category: 'frontend', pattern: 'react[.@-]([\\d.]+)', from: 'body', confidence: 0.6 },
  { name: 'Angular', category: 'frontend', pattern: 'angular[.@-]([\\d.]+)', from: 'body', confidence: 0.6 },
  { name: 'Bootstrap', category: 'frontend', pattern: 'bootstrap[.@-]([\\d.]+)', from: 'body', confidence: 0.6 },
  { name: 'Layui', category: 'frontend', pattern: 'layui[.@-]([\\d.]+)', from: 'body', confidence: 0.6 },

  // ---- 代理 / 网关（Via 头是判断「前面还有一跳」的最直接线索） ----
  { name: 'Squid', category: 'proxy', pattern: 'squid', from: 'header', header: 'via', confidence: 0.7 },
  { name: 'uproxy', category: 'proxy', pattern: 'uproxy', from: 'header', header: 'via', confidence: 0.7 },
  { name: 'Nginx (proxy)', category: 'proxy', pattern: 'nginx', from: 'header', header: 'via', confidence: 0.6 },

  // ---- WAF / 网关 ----
  { name: 'Cloudflare', category: 'waf', pattern: 'cloudflare|cf-ray', from: 'header', confidence: 0.85, waf: true },
  { name: 'AWS WAF/ALB', category: 'waf', pattern: 'awselb|AWSALB|awswaf', from: 'header', confidence: 0.7, waf: true },
  { name: 'Akamai', category: 'waf', pattern: 'AkamaiGHost', from: 'header', confidence: 0.85, waf: true },
  { name: 'FortiWeb', category: 'waf', pattern: 'FortiWeb', from: 'header', confidence: 0.85, waf: true },
  { name: 'Sucuri', category: 'waf', pattern: 'x-sucuri-id|Sucuri', from: 'header', confidence: 0.8, waf: true },
  { name: 'Imperva Incapsula', category: 'waf', pattern: 'x-iinfo|incap_ses|visid_incap', from: 'header', confidence: 0.8, waf: true },
  { name: 'Huawei Cloud WAF', category: 'waf', pattern: 'hwwafsesid|hwwaf_cookie', from: 'header', confidence: 0.75, waf: true },
  { name: '360 WAF', category: 'waf', pattern: 'wzws|qax', from: 'header', confidence: 0.7, waf: true },
  { name: 'SafeDog', category: 'waf', pattern: 'safedog|WAF/', from: 'header', confidence: 0.7, waf: true },
  { name: 'F5 BIG-IP', category: 'waf', pattern: 'BIG-IP|TS0[0-9a-f]{6}', from: 'cookie', confidence: 0.8, waf: true },
  { name: 'ModSecurity', category: 'waf', pattern: 'mod_security|NOYB', from: 'body', confidence: 0.7, waf: true },
]

/** SPA / Spring Boot 默认错误页特征，用于识别错误页形态。 */
const ERROR_PAGE_MARKERS: ReadonlyArray<{ name: string; pattern: RegExp }> = [
  { name: 'Spring Boot Whitelabel', pattern: /Whitelabel Error Page/i },
  { name: 'Tomcat 默认错误页', pattern: /Apache Tomcat\/[\d.]+/i },
  { name: 'Nginx 默认错误页', pattern: /<center>nginx<\/center>/i },
  { name: 'SPA 兜底路由', pattern: /<div id="(app|root)"><\/div>/i },
]

/** 执行指纹识别。任何单点探测失败都不影响整体结论，只记入 probeErrors。 */
export async function fingerprintTarget(
  runtime: CvescoutRuntime,
  targetUrl: string,
  signal?: AbortSignal,
): Promise<FingerprintResult> {
  const startedAt = Date.now()
  // 先归一化：用户可能只给域名或系统别名，必须在安全护栏之前解析成绝对 URL。
  const target = resolveTarget(runtime, targetUrl)
  const result: FingerprintResult = {
    targetUrl: target,
    statusCode: null,
    server: null,
    framework: null,
    title: null,
    techStack: [],
    wafDetected: false,
    wafVendor: null,
    allowedMethods: [],
    errorPageSignature: null,
    robots: null,
    securityTxt: null,
    tls: null,
    protocolHints: null,
    scanDurationMs: 0,
    probeErrors: [],
  }

  // 根请求必须先单独做：它确认可达性、决定最终协议（可能发生 http↔https 回退），
  // 后续所有探测都要落在这个已确认的基址上。
  let root: Awaited<ReturnType<typeof request>> | null = null
  try {
    root = await probe(runtime, target, 'GET', signal)
  } catch (error) {
    // 未授权必须冒泡，不能降级成「不可达」，否则会被当成普通失败放过。
    if (error instanceof SafetyBlockedError && error.isScopeViolation) throw error
    result.error = `目标根路径不可达: ${(error as Error).message}`
    result.scanDurationMs = Date.now() - startedAt
    return result
  }

  const base = pickBaseUrl(target, root.finalUrl, result.probeErrors)

  result.statusCode = root.statusCode
  result.server = root.headers.server ?? null
  result.protocolHints = extractProtocolHints(root.headers)
  result.techStack = matchRules({
    headerText: flattenHeaders(root.headers),
    bodyText: root.bodyPreview,
    cookieText: root.headers['set-cookie'] ?? '',
    serverHeader: root.headers.server ?? '',
  })
  result.title = extractTitle(root.bodyPreview)
  applyDerived(result)

  // 以下探测彼此独立，全部并发；并发上限走配置，避免把目标打爆。
  const tasks: Array<() => Promise<void>> = []

  if (runtime.cfg.probeAllowedMethods) {
    tasks.push(async () => {
      try {
        const optionsResponse = await probe(runtime, base, 'OPTIONS', signal)
        const allow = optionsResponse.headers.allow
        if (allow) {
          result.allowedMethods = allow
            .split(',')
            .map((item) => item.trim().toUpperCase())
            .filter(Boolean)
        }
      } catch (error) {
        result.probeErrors.push(`OPTIONS 探测失败: ${describeError(error)}`)
      }
    })
  }

  if (runtime.cfg.errorPageProbe) {
    tasks.push(async () => {
      try {
        const randomPath = `/__cvescout_${Math.random().toString(36).slice(2, 10)}`
        const notFound = await probe(runtime, joinUrl(base, randomPath), 'GET', signal)
        const marker = ERROR_PAGE_MARKERS.find((item) => item.pattern.test(notFound.bodyPreview))
        const snippet = notFound.bodyPreview.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 160)
        result.errorPageSignature = marker
          ? `${marker.name} (HTTP ${notFound.statusCode})`
          : `HTTP ${notFound.statusCode}: ${snippet}`
      } catch (error) {
        result.probeErrors.push(`错误页探测失败: ${describeError(error)}`)
      }
    })
  }

  // 被动路径去重，避免配置里写了重复项时对同一路径重复发请求。
  const passivePaths = Array.from(new Set(runtime.cfg.passiveProbePaths.map((item) => item.trim()).filter(Boolean)))
  for (const path of passivePaths) {
    tasks.push(async () => {
      try {
        const response = await probe(runtime, joinUrl(base, path), 'GET', signal)
        if (response.statusCode !== 200) return
        const snippet = response.bodyPreview.slice(0, 500)
        if (path.includes('robots.txt')) result.robots = snippet
        else if (path.includes('security.txt')) result.securityTxt = snippet
      } catch (error) {
        result.probeErrors.push(`路径探测失败 ${path}: ${describeError(error)}`)
      }
    })
  }

  // TLS 握手：只做一次裸握手，不发任何 HTTP 载荷。
  // 仅在 https 目标上做——探测一个与目标不同的端口（http 目标去连 443）会产生
  // 与用户意图不符的连接，宁可记为「未知」。
  let baseScheme = ''
  try {
    baseScheme = new URL(base).protocol
  } catch {
    baseScheme = ''
  }
  if (runtime.cfg.tlsProbe && baseScheme === 'https:') {
    tasks.push(async () => {
      try {
        const parsed = new URL(base)
        const port = parsed.port ? Number(parsed.port) : 443
        // TLS 握手同样是「对外触达目标」，必须先过护栏（并计入配额）。
        runtime.safety.assertAllowed('fingerprint', { url: base, action: 'tls-handshake' })
        result.tls = await probeTls({
          host: parsed.hostname,
          port,
          timeoutMs: runtime.cfg.timeoutMs,
          signal,
        })
        if (!result.tls.ok && result.tls.error) {
          result.probeErrors.push(`TLS 探测失败: ${result.tls.error}`)
        }
      } catch (error) {
        result.probeErrors.push(`TLS 探测失败: ${describeError(error)}`)
        result.tls = emptyTlsIntel(describeError(error))
      }
    })
  }

  const failures = await runLimited(tasks, runtime.cfg.probeConcurrency)
  // 并行任务里若出现「目标未授权」，必须整体硬失败——不能因为被 try/catch 包住
  // 就把它降级成一条 probeError。
  const scopeViolation = failures.find(
    (item) => item instanceof SafetyBlockedError && item.isScopeViolation,
  )
  if (scopeViolation) throw scopeViolation

  result.scanDurationMs = Date.now() - startedAt
  return result
}

/**
 * 按并发上限执行任务列表。
 *
 * 返回收集到的异常而不是提前 reject：这样即便某个任务抛错，其余任务也能跑完，
 * 调用方还能在结果里挑出「必须硬失败」的那一类（越权）。
 */
async function runLimited(tasks: Array<() => Promise<void>>, limit: number): Promise<unknown[]> {
  const queue = [...tasks]
  const errors: unknown[] = []
  const width = Math.max(1, Math.min(limit, queue.length))
  const workers = Array.from({ length: width }, async () => {
    for (;;) {
      const task = queue.shift()
      if (!task) return
      try {
        await task()
      } catch (error) {
        errors.push(error)
      }
    }
  })
  await Promise.all(workers)
  return errors
}

/**
 * 选择后续探测的基址。
 *
 * 只在**同主机**重定向时才改用最终 URL：跨主机重定向意味着目标把我们引到了
 * 另一台机器，那里既不在本轮授权的语义内，也会让护栏合理地拒掉后续请求。
 * 这种情况下保留原目标，并如实记录这次重定向。
 */
function pickBaseUrl(original: string, finalUrl: string, probeErrors: string[]): string {
  if (!finalUrl || finalUrl === original) return original
  let originalHost = ''
  let finalHost = ''
  try {
    originalHost = new URL(original).host
    finalHost = new URL(finalUrl).host
  } catch {
    return original
  }
  if (originalHost === finalHost) return finalUrl
  probeErrors.push(
    `根路径重定向到 ${finalUrl}（跨主机，后续探测仍针对原目标 ${original}）`,
  )
  return original
}

/** 抽取 HTTP 层协议线索。 */
export function extractProtocolHints(headers: Record<string, string>): ProtocolHints {
  const altSvc = headers['alt-svc'] ?? null
  return {
    altSvc,
    // Alt-Svc 里出现 h2="..." 或 h2=:port 表示服务器广告了 HTTP/2 服务。
    http2Advertised: altSvc ? /(^|[\s,])h2\s*=/i.test(altSvc) : false,
    viaProxy: headers.via ?? null,
  }
}

/** 通过安全护栏后再发请求。 */
async function probe(
  runtime: CvescoutRuntime,
  url: string,
  method: string,
  signal?: AbortSignal,
): Promise<Awaited<ReturnType<typeof request>>> {
  runtime.safety.assertAllowed('fingerprint', { url, method })
  return request(runtime.cfg, { url, method }, signal)
}

function describeError(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

function matchRules(input: {
  headerText: string
  bodyText: string
  cookieText: string
  serverHeader: string
}): TechComponent[] {
  const found = new Map<string, TechComponent>()

  for (const rule of FINGERPRINT_RULES) {
    let haystack: string
    if (rule.from === 'header') {
      haystack = rule.header ? (extractHeaderValue(input.headerText, rule.header) ?? '') : input.headerText
    } else if (rule.from === 'cookie') {
      haystack = input.cookieText
    } else {
      haystack = input.bodyText
    }
    if (!haystack) continue

    let match: RegExpExecArray | null
    try {
      match = new RegExp(rule.pattern, 'i').exec(haystack)
    } catch {
      continue
    }
    if (!match) continue

    const key = rule.name.toLowerCase()
    const existing = found.get(key)
    if (existing && existing.confidence >= rule.confidence) continue

    found.set(key, {
      name: rule.name,
      version: pickVersion(match, rule.from === 'cookie' ? '' : haystack),
      category: rule.category,
      confidence: rule.confidence,
    })
  }

  return Array.from(found.values())
}

/** 从匹配结果或所在文本里挑一个像版本的串。 */
function pickVersion(match: RegExpExecArray, haystack: string): string | null {
  for (let i = match.length - 1; i >= 1; i -= 1) {
    const group = match[i]
    if (group && /^\d+(\.\d+)+/.test(group)) return group
  }
  const fromHaystack = haystack.match(/\b(\d+(?:\.\d+){1,3})\b/)
  return fromHaystack ? fromHaystack[1] : null
}

function applyDerived(result: FingerprintResult): void {
  for (const component of result.techStack) {
    if (component.category === 'waf' && !result.wafDetected) {
      result.wafDetected = true
      result.wafVendor = component.name
    }
  }
  if (!result.framework) {
    const framework = result.techStack.find((item) =>
      ['framework', 'cms', 'frontend'].includes(item.category),
    )
    if (framework) {
      result.framework = framework.version ? `${framework.name}/${framework.version}` : framework.name
    }
  }
}

function flattenHeaders(headers: Record<string, string>): string {
  return Object.entries(headers)
    .map(([key, value]) => `${key}: ${value}`)
    .join('\n')
}

function extractHeaderValue(flattened: string, headerName: string): string | null {
  const pattern = new RegExp(`^${headerName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}:\\s*(.*)$`, 'im')
  const match = flattened.match(pattern)
  return match ? match[1].trim() : null
}

function extractTitle(html: string): string | null {
  const match = html.match(/<title[^>]*>([\s\S]{0,200}?)<\/title>/i)
  return match ? match[1].replace(/\s+/g, ' ').trim() : null
}

/** 以任意路径与基础 URL 拼接。 */
export function joinUrl(baseUrl: string, path: string): string {
  if (path.startsWith('http://') || path.startsWith('https://')) return path
  return `${baseUrl.replace(/\/+$/, '')}/${path.replace(/^\/+/, '')}`
}
