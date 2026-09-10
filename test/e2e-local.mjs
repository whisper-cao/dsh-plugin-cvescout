/**
 * 端到端冒烟测试：起一个本地 HTTP 服务作为「授权目标」，跑完整复测流水线
 * （目标解析 → 指纹 → 缓存 → CVE 情报 → 判读 → PoC 搜索 → 被动取证 → 判定 → 报告）。
 *
 * 覆盖三条用户实际会走的入口：
 *   1. 直接给完整 URL
 *   2. 只给裸域名/host:port（并验证 https→http 自动换协议）
 *   3. 用配置里的系统别名 + 一次给多个 CVE（走 cve_retest → 批量委托）
 *
 * 目标固定为 127.0.0.1，不触碰任何外部站点。CVE 情报仍会查 NVD（只读公开接口），
 * 若网络不可达则以 error 路径收敛，测试仍会断言结构完整。
 *
 * 运行：node test/e2e-local.mjs（测试对象是构建产物 lib/，先 npm run build）
 */
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { createRuntime } from '../lib/index.js'
import { registerAllTools } from '../lib/tools/index.js'
import { fingerprintTarget } from '../lib/sources/fingerprint.js'
import { retestBatch, retestOne } from '../lib/core/retest.js'
import { parseReproMarkdown, executeRepro } from '../lib/core/pentest.js'

const PAGE = `<!doctype html><html><head><title>CVEScout E2E</title>
<script src="/static/jquery-3.5.1.min.js"></script></head>
<body><div id="app"></div></body></html>`

const server = createServer((req, res) => {
  if (req.url === '/robots.txt') {
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end('User-agent: *\nDisallow: /admin\n')
    return
  }
  if (req.url === '/static/jquery-3.5.1.min.js') {
    res.writeHead(200, { 'content-type': 'application/javascript' })
    res.end('/* jQuery v3.5.1 */')
    return
  }
  if (req.url === '/api/health') {
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end('{"status":"ok","marker":"CVE_TEST_OK"}')
    return
  }
  res.writeHead(200, {
    'content-type': 'text/html; charset=utf-8',
    server: 'nginx/1.18.0',
    'x-powered-by': 'PHP/7.4.3',
    allow: 'GET, HEAD, OPTIONS',
  })
  res.end(PAGE)
})

await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
const port = server.address().port
const base = `http://127.0.0.1:${port}`
const bareHost = `127.0.0.1:${port}`
console.log(`本地授权目标: ${base}`)

const dir = await mkdtemp(join(tmpdir(), 'cvescout-e2e-'))
const runtime = createRuntime({
  allowedDomains: ['127.0.0.1'],
  // 故意用 https 作为默认协议：本地服务只开 http，用来验证自动换协议。
  defaultScheme: 'https',
  allowSchemeFallback: true,
  targetAliases: { 本地靶机: base, 裸域名靶机: bareHost },
  cachePath: join(dir, 'intel.json'),
  reportDir: dir,
  timeoutMs: 8000,
  maxRequestsPerMinute: 120,
  maxTotalRequests: 500,
})

// 工具注册（用假 ctx，只需要 register）。
const registered = new Map()
registerAllTools(
  { tools: { register: (definition) => (registered.set(definition.name, definition), () => {}) } },
  runtime,
)

try {
  // 1) 裸 host:port + https 默认协议 → 首次 TLS 失败后自动换 http
  const viaBareHost = await fingerprintTarget(runtime, bareHost)
  assert.equal(viaBareHost.statusCode, 200, '裸 host:port 应通过自动换协议拿到 200')
  assert.equal(viaBareHost.server, 'nginx/1.18.0')
  const names = viaBareHost.techStack.map((item) => item.name)
  assert.ok(names.includes('Nginx'), `应识别出 Nginx，实际: ${names.join(',')}`)
  assert.ok(names.includes('PHP'), `应识别出 PHP，实际: ${names.join(',')}`)
  assert.ok(names.includes('jQuery'), `应识别出 jQuery，实际: ${names.join(',')}`)
  assert.ok(viaBareHost.allowedMethods.includes('OPTIONS'), 'OPTIONS 的 Allow 头应被解析')
  assert.ok(viaBareHost.robots && viaBareHost.robots.includes('Disallow'), 'robots.txt 应被采集')
  console.log(`裸 host:port + 自动换协议：${names.join(', ')}；Allow=${viaBareHost.allowedMethods.join('/')}`)

  // 2) 未授权目标仍被拦（护栏要先于网络访问生效）
  await assert.rejects(
    () => fingerprintTarget(runtime, 'https://not-authorized.example/'),
    /不在授权范围内/,
  )
  console.log('未授权域名被护栏拦截')

  // 3) 系统别名 → 目标
  const viaAlias = await retestOne(runtime, '本地靶机', 'CVE-2021-44228', { forceRecon: true })
  assert.equal(viaAlias.targetUrl, base + '/')
  assert.ok(['VULNERABLE', 'NOT_VULNERABLE', 'UNCERTAIN'].includes(viaAlias.verdict))
  assert.ok(viaAlias.limitations.length > 0, '必须给出限制说明')
  console.log(`系统别名解析通过：${viaAlias.verdict}（置信度 ${viaAlias.confidence}）`)

  // 4) 第二次应命中情报缓存
  const cached = await retestOne(runtime, '本地靶机', 'CVE-2021-44228')
  assert.equal(cached.intel.cacheHit, true, '第二次复测应命中情报缓存')
  console.log('情报缓存命中生效')

  // 5) 非破坏性复现：破坏性步骤被跳过，正向指标被识别
  const doc = parseReproMarkdown(
    `# 本地验证

## 复现步骤
1. 访问健康检查接口
   curl '${base}/api/health'
   成功指标: 200, CVE_TEST_OK

2. 破坏性清理步骤
   curl -X DELETE '${base}/api/health?force=1'
`,
    'CVE-2021-44228',
  )
  assert.equal(doc.steps.length, 2)
  const report = await executeRepro(runtime, base, doc)
  assert.equal(report.stepsTotal, 2)
  assert.equal(report.stepsSkipped, 1, 'DELETE 步骤必须被跳过')
  assert.equal(report.overallSuccess, true, '健康检查步骤应命中成功指标')
  console.log(`非破坏性复现通过：${report.stepsSuccess}/${report.stepsTotal} 成功，跳过 ${report.stepsSkipped} 个破坏性步骤`)

  // 6) cve_retest 收到多个 CVE 时自动委托给批量路径（模拟用户一句「这几个 CVE 都排查一下」）
  const multi = await registered.get('cve_retest').execute(
    { url: bareHost, cve_id: 'CVE-2021-44228, CVE-2020-36518' },
    { signal: undefined },
  )
  assert.equal(multi.total, 2, '多 CVE 应自动转批量')
  assert.equal(multi.results.length, 2)
  assert.ok(multi.report.includes('# CVE 批量复测汇总报告'))
  assert.equal(multi.reportPath, null, '未开启 save_report 时不应落盘')
  console.log(`cve_retest 多 CVE 自动委托通过：共 ${multi.total} 个，报告 ${multi.report.length} 字`)

  // 7) 批量复测 + 报告落盘
  const batch = await retestBatch(runtime, base, ['CVE-2021-44228', 'CVE-2020-36518', 'not-a-cve'], {
    saveReport: true,
  })
  assert.equal(batch.total, 3)
  assert.equal(batch.stats.vulnerable + batch.stats.notVulnerable + batch.stats.uncertain, 3)
  assert.ok(batch.reportPath && batch.reportJsonPath, 'saveReport=true 时应落盘')
  console.log(`批量复测通过：共 ${batch.total} 个；报告落盘 ${batch.reportPath}`)

  // 8) target_scope 能读出授权范围与别名
  const scope = await registered.get('target_scope').execute({ alias: '本地靶机' }, { signal: undefined })
  assert.equal(scope.authorizationMode, 'whitelist')
  assert.deepEqual(scope.authorizedDomains, ['127.0.0.1'])
  assert.equal(scope.resolvedAuthorized, true)
  console.log(`target_scope 通过：模式 ${scope.authorizationMode}，别名解析 ${scope.resolvedTarget}`)

  // 9) 审计报告可用
  const audit = runtime.safety.report()
  assert.ok(audit.totalCalls > 0)
  assert.ok(audit.log.length > 0)
  console.log(`审计通过：共 ${audit.totalCalls} 次调用、拦截 ${audit.blockedCalls} 次`)

  console.log('\n端到端冒烟测试通过')
} finally {
  server.close()
  await rm(dir, { recursive: true, force: true })
}
