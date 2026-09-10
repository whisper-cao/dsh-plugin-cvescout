/**
 * 编排级工具。
 *
 *   - cve_retest        单 CVE 复测（情报 → 判读 → 被动取证 → 判定，可选非破坏性复现）
 *   - cve_batch_retest  同目标多 CVE 批量复测 + 汇总报告
 *   - cve_repro_parse   复现文档解析（标出破坏性步骤，不做任何请求）
 *   - pentest_repro     非破坏性复现执行（支持 dry_run 只做载荷安全化预览）
 */
import { readFile } from 'node:fs/promises'
import type { Context } from '@deepseek-ai/cordis'
import { defineTool } from '@deepseek-ai/dsh-tools'
import type { CvescoutRuntime } from '../core/runtime.ts'
import { resolveTarget } from '../core/runtime.ts'
import { normalizeCveId } from '../sources/nvd.ts'
import { retestBatch, retestOne } from '../core/retest.ts'
import { executeRepro, parseReproDoc, sanitizePayload } from '../core/pentest.ts'
import type { ReproDoc } from '../types.ts'
import { asJsonValue, fromJsonValue } from './json.ts'

function assertSafety(runtime: CvescoutRuntime, toolName: string, params: unknown): void {
  const decision = runtime.safety.check(toolName, params)
  if (!decision.allowed) {
    throw new Error(`安全护栏拦截 [${toolName}]: ${decision.reason}`)
  }
}

/** 目标参数的统一说明，保证模型知道可以只给域名。 */
const TARGET_PARAM_DESCRIPTION =
  '目标地址：完整 URL、裸域名（portal.example.com）、host:port 均可；未写协议时按 defaultScheme 补齐，连接失败自动换协议重试一次；也接受 cordis.yml 中 targetAliases 配置的系统别名'

/** 从参数里拆分 CVE 编号列表（支持逗号、顿号、分号、空白）。 */
function splitCveIds(raw: string): string[] {
  return Array.from(
    new Set(
      String(raw ?? '')
        .split(/[\s,;、，]+/)
        .map((item) => normalizeCveId(item))
        .filter(Boolean),
    ),
  )
}

/** 渲染：一句人读结论 + 完整规范化 JSON，保证 Native 模式下信息不丢失。 */
function renderWithHeadline(headline: string, value: unknown): { type: 'text'; text: string }[] {
  return [{ type: 'text', text: `${headline}\n\n${JSON.stringify(value, null, 2)}` }]
}

/** 从参数里拿到复现文档内容（内联内容优先，其次读文件）。 */
async function resolveDocument(document?: string, documentPath?: string): Promise<string | null> {
  if (document && document.trim()) return document
  if (documentPath && documentPath.trim()) {
    return await readFile(documentPath.trim(), 'utf8')
  }
  return null
}

/** 注册编排级工具。 */
export function registerPipelineTools(ctx: Context, runtime: CvescoutRuntime): void {
  // ------------------------------------------------------- 单 CVE 复测
  ctx.tools.register(
    defineTool({
      name: 'cve_retest',
      description:
        '【CVE 复测主入口】当用户说「某网站/系统涉及某个 CVE，帮我排查/验证/确认是否受影响/复测一下」时，优先用本工具。它会自动完成：取或复用目标指纹情报 → 拉取 CVE 受影响组件与版本区间 → 静态判读 → 必要时被动探测取证 → 输出 VULNERABLE / NOT_VULNERABLE / UNCERTAIN、置信度、依据与限制说明。' +
        '若用户在 CVE 编号里给了多个（逗号分隔），会自动转成批量复测。可选传入复现文档以执行其中的非破坏性步骤；只有取得正向证据才会给出 VULNERABLE。' +
        '判读会在版本区间之上叠加**协议前置条件**：对 HTTP/2 Rapid Reset 一类「必须启用 HTTP/2 才能触发」的 CVE，会先做一次裸 TLS 握手确认 HTTP/2 是否可用，实测不可用即直接排除（这类排除依据记为 protocol）。' +
        '本工具不投递攻击载荷、不写入目标数据；目标不在授权范围时会直接被拦截并说明如何补充配置。',
      parameters: {
        url: { type: 'string', required: true, description: TARGET_PARAM_DESCRIPTION },
        cve_id: {
          type: 'string',
          required: true,
          description: 'CVE 编号；多个可用逗号/空格/顿号分隔，例如 "CVE-2021-44228 CVE-2020-36518"',
        },
        force_recon: { type: 'boolean', description: '忽略情报缓存强制重新侦察，默认 false' },
        run_pentest: {
          type: 'boolean',
          description: '是否执行复现文档中的非破坏性步骤，默认 true（仅在提供 repro_document 时生效）',
        },
        repro_document: { type: 'string', description: '复现文档内容（Markdown 或 JSON）' },
        repro_document_path: { type: 'string', description: '复现文档文件路径（与 repro_document 二选一）' },
      },
      output: {
        schema: { type: 'json' },
        render: (_args, value) => {
          const result = fromJsonValue<{
            cveId?: string
            verdict?: string
            confidence?: number
            reason?: string
            total?: number
          }>(value)
          if (result.total !== undefined) {
            return renderWithHeadline(`批量复测完成：共 ${result.total} 个 CVE`, value)
          }
          return renderWithHeadline(
            `[${result.cveId}] ${result.verdict}（置信度 ${result.confidence}）— ${result.reason}`,
            value,
          )
        },
      },
      async execute(args, exec) {
        const target = resolveTarget(runtime, args.url)
        const cveIds = splitCveIds(args.cve_id)
        if (cveIds.length === 0) throw new Error('请提供至少一个合法 CVE 编号')

        assertSafety(runtime, 'cve_retest', { url: target, cve_ids: cveIds })

        let reproDoc: ReproDoc | null = null
        if (args.run_pentest !== false) {
          const content = await resolveDocument(args.repro_document, args.repro_document_path)
          if (content) {
            reproDoc = parseReproDoc(content, cveIds[0])
          }
        }

        // 多个 CVE 直接走批量路径，省一次侦察且报告更完整。
        if (cveIds.length > 1) {
          return asJsonValue(
            await retestBatch(runtime, target, cveIds, { forceRecon: args.force_recon === true, reproDoc }, exec.signal),
          )
        }

        return asJsonValue(
          await retestOne(
            runtime,
            target,
            cveIds[0],
            { forceRecon: args.force_recon === true, reproDoc },
            exec.signal,
          ),
        )
      },
    }),
  )

  // ------------------------------------------------------- 批量复测
  ctx.tools.register(
    defineTool({
      name: 'cve_batch_retest',
      description:
        '对同一目标的多个 CVE 做批量复测，复用一次指纹侦察，最后给出统计与 Markdown 汇总报告。当用户一次列出多个「站点 + CVE」组合且目标是同一个时用本工具；报告需要归档时把 save_report 置 true。',
      parameters: {
        url: { type: 'string', required: true, description: TARGET_PARAM_DESCRIPTION },
        cve_ids: {
          type: 'string',
          required: true,
          description: 'CVE 编号列表，逗号或空白分隔，例如 "CVE-2021-44228, CVE-2020-36518"',
        },
        force_recon: { type: 'boolean', description: '忽略情报缓存强制重新侦察，默认 false' },
        save_report: { type: 'boolean', description: '是否把报告写入磁盘，默认 false' },
        report_dir: { type: 'string', description: '报告输出目录，默认取插件配置' },
        repro_document: { type: 'string', description: '复现文档内容，只会作用于文档中标注的同名 CVE' },
      },
      output: {
        schema: { type: 'json' },
        render: (_args, value) => {
          const batch = fromJsonValue<{ total: number; stats: { vulnerable: number; notVulnerable: number; uncertain: number } }>(
            value,
          )
          return renderWithHeadline(
            `批量复测完成：共 ${batch.total} 个 CVE，存在漏洞 ${batch.stats.vulnerable}、不受影响 ${batch.stats.notVulnerable}、需人工确认 ${batch.stats.uncertain}`,
            value,
          )
        },
      },
      async execute(args, exec) {
        const cveIds = args.cve_ids
          .split(/[\s,;、]+/)
          .map((item) => item.trim())
          .filter(Boolean)
        if (cveIds.length === 0) throw new Error('cve_ids 为空，至少需要一个 CVE 编号')

        const target = resolveTarget(runtime, args.url)
        assertSafety(runtime, 'cve_batch_retest', { url: target, count: cveIds.length })

        const reproDoc = args.repro_document ? parseReproDoc(args.repro_document, cveIds[0]) : null

        return asJsonValue(
          await retestBatch(
            runtime,
            target,
            cveIds,
            {
              forceRecon: args.force_recon === true,
              saveReport: args.save_report === true,
              reportDir: args.report_dir,
              reproDoc,
            },
            exec.signal,
          ),
        )
      },
    }),
  )

  // ------------------------------------------------------- 复现文档解析
  ctx.tools.register(
    defineTool({
      name: 'cve_repro_parse',
      description:
        '解析复现文档（Markdown 或 JSON），输出结构化步骤、每步的 HTTP 方法与指标，并标出哪些步骤属破坏性（执行时会被跳过）。本工具不发任何网络请求。',
      parameters: {
        document: { type: 'string', required: true, description: '复现文档内容' },
        cve_id: { type: 'string', required: true, description: '该文档对应的 CVE 编号' },
        format: { type: 'string', enum: ['json', 'markdown'], description: '强制指定格式，默认按内容自动判断' },
      },
      output: {
        schema: { type: 'json' },
        render: (_args, value) => {
          const doc = fromJsonValue<{ steps: unknown[]; title: string }>(value)
          return renderWithHeadline(`复现文档《${doc.title || '未命名'}》共解析出 ${doc.steps.length} 个步骤`, value)
        },
      },
      async execute(args) {
        const doc = parseReproDoc(args.document, normalizeCveId(args.cve_id), args.format)
        return asJsonValue({
          ...doc,
          destructiveSteps: doc.steps.filter((step) => step.isDestructive).map((step) => step.stepId),
          executableSteps: doc.steps.filter((step) => !step.isDestructive).length,
        })
      },
    }),
  )

  // ------------------------------------------------------- 非破坏性复现
  ctx.tools.register(
    defineTool({
      name: 'pentest_repro',
      description:
        '对目标执行复现文档中的非破坏性步骤（破坏性步骤自动跳过，载荷先做无害化替换）。dry_run=true 时只做解析与载荷安全化预览，不发请求。全部请求受安全护栏与时序限制约束。' +
        '当用户提供了 PoC/复现步骤，希望「实际验证一下」时用本工具；cve_retest 的结论为 UNCERTAIN 且存在公开 PoC 时也适合接着调用。',
      parameters: {
        url: { type: 'string', required: true, description: TARGET_PARAM_DESCRIPTION },
        cve_id: { type: 'string', required: true, description: 'CVE 编号' },
        document: { type: 'string', description: '复现文档内容（Markdown 或 JSON）' },
        document_path: { type: 'string', description: '复现文档文件路径（与 document 二选一）' },
        dry_run: { type: 'boolean', description: '仅预览不执行，默认 false' },
      },
      output: {
        schema: { type: 'json' },
        render: (_args, value) => {
          const report = fromJsonValue<{ cveId: string; overallSuccess: boolean; stepsSuccess: number; stepsTotal: number }>(
            value,
          )
          return renderWithHeadline(
            `[${report.cveId}] 非破坏性复现${report.overallSuccess ? '取得正向证据' : '未取得正向证据'}（${report.stepsSuccess}/${report.stepsTotal} 步成功）`,
            value,
          )
        },
      },
      async execute(args, exec) {
        const target = resolveTarget(runtime, args.url)
        assertSafety(runtime, 'pentest_repro', { url: target, cve_id: args.cve_id })
        const content = await resolveDocument(args.document, args.document_path)
        if (!content) throw new Error('需要提供 document 或 document_path 之一')

        const cveId = normalizeCveId(args.cve_id)
        const doc = parseReproDoc(content, cveId)

        if (args.dry_run === true) {
          return asJsonValue({
            dryRun: true,
            cveId,
            targetUrl: target,
            steps: doc.steps.map((step) => {
              const sanitized = step.body ? sanitizePayload(step.body, 'repro') : null
              return {
                stepId: step.stepId,
                description: step.description,
                httpMethod: step.httpMethod,
                endpoint: step.endpoint,
                isDestructive: step.isDestructive,
                willSkip: step.isDestructive,
                payloadOriginal: sanitized?.original ?? null,
                payloadSanitized: sanitized?.safeVersion ?? null,
                payloadSafe: sanitized?.isSafe ?? true,
                payloadReason: sanitized?.reason ?? '',
                expectedIndicators: step.expectedIndicators,
              }
            }),
          })
        }

        return asJsonValue(await executeRepro(runtime, target, doc, exec.signal))
      },
    }),
  )
}
