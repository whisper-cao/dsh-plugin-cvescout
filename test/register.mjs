/**
 * 入口冒烟测试（不联网、不启动 Harness）。
 *
 * 直接调用构建产物的 `apply(ctx, config)` —— 也就是 `dsh plugin add` 安装后被
 * 加载器调用的那个函数 —— 用假 ctx 验证：工具全部注册、参数 schema 编译正确、
 * 系统提示词指引段注册成功、工具能真正执行。
 *
 * 因为测的是 `lib/`，这条测试同时充当「忘记重新构建」的哨兵。
 * 先构建再跑：`npm run build && node test/register.mjs`。
 */
import assert from 'node:assert/strict'

import { apply, createRuntime } from '../lib/index.js'
import { PROMPT_SECTION_NAME, PROMPT_SECTION_ORDER } from '../lib/prompt.js'
import { TOOL_NAMES } from '../lib/tools/index.js'

const registered = new Map()
const promptSections = []
const injectedDeps = []

/** 假的 Cordis ctx：只需覆盖 register / inject / systemPrompt 三个面。 */
const fakeCtx = {
  tools: {
    register(definition) {
      registered.set(definition.name, definition)
      return () => registered.delete(definition.name)
    },
  },
  systemPrompt: {
    section(section) {
      promptSections.push(section)
      return () => {}
    },
  },
  inject(deps, callback) {
    injectedDeps.push(deps)
    callback(fakeCtx)
    return { dispose: () => {} }
  },
}

const config = {
  allowedDomains: ['portal.example.com', 'erp.example.com'],
  targetAliases: { 内部管理系统: 'erp.example.com' },
  cachePath: './.smoke-cache.json',
}

// 走真实入口。
apply(fakeCtx, config)
const runtime = createRuntime(config)

assert.deepEqual([...registered.keys()].sort(), [...TOOL_NAMES].sort(), '注册的工具名与声明不一致')
assert.equal(registered.size, 11)
console.log(`已通过 apply() 注册 ${registered.size} 个工具`)

for (const name of TOOL_NAMES) {
  const definition = registered.get(name)
  assert.ok(definition, `缺少工具 ${name}`)
  assert.equal(typeof definition.description, 'string')
  assert.ok(definition.description.length > 10, `${name} 的 description 过短，模型难以判断何时调用`)
  assert.equal(typeof definition.execute, 'function', `${name} 缺少 execute`)
  assert.ok(definition.output && definition.output.schema, `${name} 缺少 output.schema`)
  assert.equal(typeof definition.output.render, 'function', `${name} 缺少 output.render`)
}
console.log('每个工具都有 description / execute / output.schema / output.render')

// 自然语言自动路由依赖两件事：描述里有触发话术，且注册了系统提示词指引段。
const retest = registered.get('cve_retest')
assert.match(retest.description, /排查/, 'cve_retest 的描述必须包含用户实际会说的触发词')
assert.match(retest.description, /优先用本工具/)
assert.match(registered.get('target_scope').description, /系统名|别名/)
assert.match(registered.get('http_probe').description, /cve_retest/)

assert.equal(promptSections.length, 1, '必须注册一段系统提示词指引')
assert.equal(promptSections[0].name, PROMPT_SECTION_NAME)
assert.equal(promptSections[0].order, PROMPT_SECTION_ORDER)
assert.equal(typeof promptSections[0].text, 'function', '指引文本应当是每次组装时求值的 provider')
assert.deepEqual(injectedDeps, [['systemPrompt']])
const guidance = promptSections[0].text({})
assert.match(guidance, /erp\.example\.com/)
assert.match(guidance, /内部管理系统/)
console.log(`系统提示词指引已注册（${PROMPT_SECTION_NAME} @ ${PROMPT_SECTION_ORDER}），文本 ${guidance.length} 字`)

// defineTool 在注册时就把 parameters 编译成 JSON Schema，这里核对关键结构。
const httpProbe = registered.get('http_probe').parameters
assert.equal(httpProbe.type, 'object')
assert.deepEqual(httpProbe.required, ['url'], 'url 必须是唯一必填参数')
assert.deepEqual(httpProbe.properties.method.enum, ['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'])
assert.equal(httpProbe.properties.headers.type, 'object')
assert.equal(httpProbe.properties.headers.additionalProperties, true, '显式 object 节点必须声明 additionalProperties')
console.log('http_probe 参数 schema 编译正确：必填 url、method 枚举、headers 开放对象')

const batchParams = registered.get('cve_batch_retest').parameters
assert.deepEqual(batchParams.required.slice().sort(), ['cve_ids', 'url'])
const reproParams = registered.get('cve_repro_parse').parameters
assert.deepEqual(reproParams.properties.format.enum, ['json', 'markdown'])
const scopeParams = registered.get('target_scope').parameters
assert.deepEqual(Object.keys(scopeParams.properties), ['alias'], 'target_scope 应只接受可选 alias')
assert.equal(scopeParams.required, undefined)
console.log('批量复测 / 复现解析 / target_scope 的参数约束正确')

for (const [name, definition] of registered) {
  for (const [key, property] of Object.entries(definition.parameters.properties ?? {})) {
    assert.equal(typeof property.type, 'string', `${name}.${key} 缺少 type`)
  }
}
console.log('全部工具的参数节点均已声明 type')

// target_scope 的实际行为：把系统名解析成域名并确认授权状态。
const scopeResult = await registered.get('target_scope').execute(
  { alias: '内部管理系统' },
  { signal: undefined },
)
assert.equal(scopeResult.authorizationMode, 'whitelist')
assert.equal(scopeResult.requestedAlias, '内部管理系统')
assert.equal(scopeResult.resolvedTarget, 'https://erp.example.com/')
assert.equal(scopeResult.resolvedAuthorized, true)
assert.equal(scopeResult.warning, null)
assert.deepEqual(scopeResult.authorizedDomains, ['portal.example.com', 'erp.example.com'])
console.log('target_scope 能把系统名解析成域名并判定授权状态')

const unknownScope = await registered.get('target_scope').execute({ alias: '别的系统' }, { signal: undefined })
assert.equal(unknownScope.resolvedAuthorized, false)
console.log('未授权的目标会被标记为 resolvedAuthorized=false')

// http_probe 的护栏：未授权目标必须被拒，且错误信息可执行。
await assert.rejects(
  () => registered.get('http_probe').execute({ url: 'https://outside.example.net' }, { signal: undefined }),
  /不在授权范围内/,
)
console.log('http_probe 对未授权目标抛错（含可执行提示）')

assert.equal(runtime.cfg.allowedDomains.length, 2)
assert.equal(runtime.cfg.allowNonIdempotentProbe, false, '非幂等探测必须默认关闭')
assert.equal(runtime.cfg.defaultScheme, 'https')
assert.equal(runtime.safety.isDomainAllowed('https://portal.example.com/x'), true)
assert.equal(runtime.safety.isDomainAllowed('erp.example.com'), true, '裸域名也必须能通过授权校验')
assert.equal(runtime.safety.isDomainAllowed('https://outside.example.net/x'), false)
console.log('运行期配置与安全护栏装配正确')

console.log('\n入口冒烟测试通过')
