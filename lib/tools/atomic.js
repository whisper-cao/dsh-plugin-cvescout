import { defineTool } from '@deepseek-ai/dsh-tools';
import { resolveTarget } from "../core/runtime.js";
import { HttpRequestError, request } from "../core/http.js";
import { intelFromFingerprint } from "../core/retest.js";
import { fingerprintTarget } from "../sources/fingerprint.js";
import { lookupCve } from "../sources/nvd.js";
import { searchPoc } from "../sources/poc.js";
import { asJsonValue } from "./json.js";
/** 统一护栏入口：拦截即抛错，让模型看到明确的失败而不是“看似正常”的结果。 */
function assertSafety(runtime, toolName, params) {
    const decision = runtime.safety.check(toolName, params);
    if (!decision.allowed) {
        throw new Error(`安全护栏拦截 [${toolName}]: ${decision.reason}`);
    }
}
/** 目标参数的统一说明，保证模型知道可以只给域名。 */
const TARGET_PARAM_DESCRIPTION = '目标地址：完整 URL、裸域名（portal.example.com）、host:port 均可；未写协议时按配置的 defaultScheme 补齐，连接失败会自动换协议重试一次；也接受 cordis.yml 中 targetAliases 配置的系统别名';
/** 安全护栏用的目标集合：已解析 URL + 原始输入（别名也要能被提示出来）。 */
function scopeParams(runtime, raw) {
    const params = {};
    try {
        params.url = resolveTarget(runtime, raw);
    }
    catch {
        params.url = String(raw);
    }
    if (typeof raw === 'string' && raw.trim() && raw.trim() !== params.url) {
        params.target_alias = raw.trim();
    }
    return params;
}
function toStringRecord(value) {
    if (!value || typeof value !== 'object')
        return undefined;
    const result = {};
    for (const [key, item] of Object.entries(value)) {
        result[key] = String(item);
    }
    return result;
}
/** 以文本形式渲染结构化结果，保持可读且不掺入 UI 格式。 */
function jsonText(value) {
    return [{ type: 'text', text: JSON.stringify(value, null, 2) }];
}
/** 注册全部原子工具。 */
export function registerAtomicTools(ctx, runtime) {
    // ---------------------------------------------------------------- CVE 查询
    ctx.tools.register(defineTool({
        name: 'cve_lookup',
        description: '查询 CVE 详情。优先查 NVD API 2.0，失败回退 GitHub Advisory。返回描述、CVSS 评分与等级、受影响组件及其版本区间、参考链接。用于复测前获取该 CVE 的适用条件。',
        parameters: {
            cve_id: { type: 'string', required: true, description: 'CVE 编号，例如 CVE-2021-44228' },
        },
        output: {
            schema: { type: 'json' },
            render: (_args, value) => jsonText(value),
        },
        async execute(args, exec) {
            assertSafety(runtime, 'cve_lookup', { cve_id: args.cve_id });
            return asJsonValue(await lookupCve(runtime.cfg, args.cve_id, exec.signal));
        },
    }));
    // ------------------------------------------------------------ PoC 搜索
    ctx.tools.register(defineTool({
        name: 'cve_poc_search',
        description: '搜索 CVE 相关的公开 PoC / 利用代码。来源为 GitHub 仓库搜索与 ExploitDB 检索页。ExploitDB 无公开 API，其结果是弱信号，需人工确认。',
        parameters: {
            cve_id: { type: 'string', required: true, description: 'CVE 编号' },
            max_results: { type: 'number', description: '返回条数上限，默认 5' },
        },
        output: {
            schema: { type: 'json' },
            render: (_args, value) => jsonText(value),
        },
        async execute(args, exec) {
            assertSafety(runtime, 'cve_poc_search', { cve_id: args.cve_id });
            return asJsonValue(await searchPoc(runtime.cfg, args.cve_id, exec.signal, args.max_results ?? 5));
        },
    }));
    // ------------------------------------------------------------ HTTP 探测
    ctx.tools.register(defineTool({
        name: 'http_probe',
        description: '向目标发送无害的 HTTP 探测请求，用于确认存活、响应头、错误页与 Allow 方法。受安全护栏约束：默认只允许 GET/HEAD/OPTIONS，禁止 TRACE/CONNECT，且目标必须命中授权域名白名单（拦截信息里会说明如何配置）。当用户给出具体 URL 并问「这个地址能不能访问 / 返回什么头 / 是否可达」时用本工具；问「某站点是否有某 CVE」请用 cve_retest。',
        parameters: {
            url: { type: 'string', required: true, description: TARGET_PARAM_DESCRIPTION },
            method: {
                type: 'string',
                enum: ['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'],
                description: 'HTTP 方法，默认 GET。非幂等方法需在插件配置里开启 allowNonIdempotentProbe。',
            },
            headers: {
                type: 'object',
                additionalProperties: true,
                description: '额外请求头（键值均为字符串）',
            },
            body: { type: 'string', description: '请求体，仅 POST/PUT/PATCH 有意义' },
            timeout_ms: { type: 'number', description: '超时毫秒数，默认取插件配置' },
        },
        output: {
            schema: { type: 'json' },
            render: (_args, value) => jsonText(value),
        },
        async execute(args, exec) {
            const target = resolveTarget(runtime, args.url);
            const payload = {
                url: target,
                method: args.method ?? 'GET',
                headers: args.headers,
                body: args.body,
            };
            assertSafety(runtime, 'http_probe', payload);
            try {
                const response = await request(runtime.cfg, {
                    url: target,
                    method: args.method ?? 'GET',
                    headers: toStringRecord(args.headers),
                    body: args.body ?? null,
                    timeoutMs: args.timeout_ms,
                }, exec.signal);
                // 只把 preview 回给模型：bodyText 是内部解析用的完整响应，不回传以免撑爆上下文。
                const { bodyText: _bodyText, ...modelFacing } = response;
                return asJsonValue(modelFacing);
            }
            catch (error) {
                if (error instanceof HttpRequestError)
                    throw new Error(`HTTP 探测失败（${error.kind}）: ${error.message}`);
                throw error;
            }
        },
    }));
    // ------------------------------------------------------------ 指纹识别
    ctx.tools.register(defineTool({
        name: 'fingerprint',
        description: '识别目标技术栈：服务器、框架、CMS、前端库、WAF，并采集 Allow 方法与错误页特征。全部为被动探测（GET/HEAD/OPTIONS 与固定被动路径），不做任何写入。当需要「先摸清某个站点用什么组件」而不针对特定 CVE 时用本工具。',
        parameters: {
            url: { type: 'string', required: true, description: TARGET_PARAM_DESCRIPTION },
            write_cache: { type: 'boolean', description: '是否把结果写入情报缓存，默认 true' },
        },
        output: {
            schema: { type: 'json' },
            render: (_args, value) => jsonText(value),
        },
        async execute(args, exec) {
            const target = resolveTarget(runtime, args.url);
            assertSafety(runtime, 'fingerprint', { url: target });
            const result = await fingerprintTarget(runtime, target, exec.signal);
            if (args.write_cache !== false && !result.error) {
                await runtime.cache.set(intelFromFingerprint(target, result));
            }
            return asJsonValue(result);
        },
    }));
    // ------------------------------------------------------------ 情报缓存
    ctx.tools.register(defineTool({
        name: 'intel_cache',
        description: '管理目标情报缓存（JSON 文件 + TTL）。action=get 读单个目标已缓存的情报；list 列出全部条目；invalidate 删除单个目标；clear 清空。用户问「上次扫描结果是什么 / 缓存了哪些目标 / 清一下缓存」时用本工具。',
        parameters: {
            action: {
                type: 'string',
                enum: ['get', 'list', 'invalidate', 'clear'],
                required: true,
                description: '要执行的操作',
            },
            url: { type: 'string', description: `action=get/invalidate 时必填。${TARGET_PARAM_DESCRIPTION}` },
            limit: { type: 'number', description: 'action=list 时返回条数上限，默认 100' },
        },
        output: {
            schema: { type: 'json' },
            render: (_args, value) => jsonText(value),
        },
        async execute(args, exec) {
            assertSafety(runtime, 'intel_cache', scopeParams(runtime, args.url ?? ''));
            const cachePath = runtime.cache.path;
            const resolvedUrl = args.url ? resolveTarget(runtime, args.url) : null;
            switch (args.action) {
                case 'get': {
                    if (!resolvedUrl)
                        throw new Error('action=get 需要提供 url');
                    const intel = await runtime.cache.get(resolvedUrl);
                    return asJsonValue({ action: 'get', cachePath, hit: intel !== null, url: resolvedUrl, intel });
                }
                case 'list': {
                    const entries = await runtime.cache.list();
                    return asJsonValue({
                        action: 'list',
                        cachePath,
                        total: entries.length,
                        entries: entries.slice(0, args.limit ?? 100),
                    });
                }
                case 'invalidate': {
                    if (!resolvedUrl)
                        throw new Error('action=invalidate 需要提供 url');
                    const removed = await runtime.cache.invalidate(resolvedUrl);
                    return asJsonValue({ action: 'invalidate', cachePath, removed, url: resolvedUrl });
                }
                case 'clear': {
                    const cleared = await runtime.cache.clear();
                    return asJsonValue({ action: 'clear', cachePath, cleared });
                }
                default:
                    throw new Error(`未知 action: ${String(args.action)}`);
            }
        },
    }));
    // ------------------------------------------------------ 授权范围与别名
    ctx.tools.register(defineTool({
        name: 'target_scope',
        description: '查看本插件的授权目标范围与配置状态：授权域名白名单、系统别名映射（例如「内部管理系统」→ 具体域名）、默认协议、非幂等探测是否开启、速率与总量配额、情报缓存与报告路径。' +
            '当用户提到的站点是系统名/简称而不是域名，或不确定某目标是否已获授权时，先调用本工具把名字解析成域名，再调 cve_retest。若某目标被判定为不在授权范围，也要用它读出白名单并如实告知用户需要补充配置。',
        parameters: {
            alias: { type: 'string', description: '可选：要解析的系统名/别名，返回其映射到的目标地址' },
        },
        output: {
            schema: { type: 'json' },
            render: (_args, value) => jsonText(value),
        },
        async execute(args) {
            const aliases = runtime.cfg.targetAliases;
            const requested = args.alias?.trim();
            let resolved = null;
            if (requested) {
                try {
                    resolved = resolveTarget(runtime, requested);
                }
                catch {
                    resolved = null;
                }
            }
            return asJsonValue({
                authorizationMode: runtime.cfg.allowedDomains.length > 0 ? 'whitelist' : 'unrestricted',
                authorizedDomains: runtime.cfg.allowedDomains,
                scopeDescription: runtime.safety.describeScope(),
                targetAliases: aliases,
                requestedAlias: requested ?? null,
                resolvedTarget: resolved,
                resolvedAuthorized: resolved ? runtime.safety.isDomainAllowed(resolved) : null,
                defaultScheme: runtime.cfg.defaultScheme,
                allowSchemeFallback: runtime.cfg.allowSchemeFallback,
                allowNonIdempotentProbe: runtime.cfg.allowNonIdempotentProbe,
                limits: {
                    maxRequestsPerMinute: runtime.cfg.maxRequestsPerMinute,
                    maxTotalRequests: runtime.cfg.maxTotalRequests,
                    usedRequests: runtime.safety.usedRequests,
                },
                cachePath: runtime.cache.path,
                cacheTtlHours: runtime.cfg.cacheTtlHours,
                reportDir: runtime.cfg.reportDir || '(默认 ~/.cvescout/reports)',
                warning: runtime.cfg.allowedDomains.length === 0
                    ? '未配置 allowedDomains：当前不限制目标。建议在 cordis.yml 里填入你已获授权测试的域名，避免误扫未授权站点。'
                    : null,
            });
        },
    }));
    // ------------------------------------------------------------ 审计报告
    ctx.tools.register(defineTool({
        name: 'safety_audit',
        description: '读取本插件运行期的安全审计：工具调用总数、拦截次数与原因、当前速率与总量配额用量、授权域名白名单。参数已做敏感字段脱敏。',
        parameters: {
            limit: { type: 'number', description: '返回最近多少条审计记录，默认 50' },
        },
        output: {
            schema: { type: 'json' },
            render: (_args, value) => jsonText(value),
        },
        async execute(args) {
            return asJsonValue(runtime.safety.report(args.limit ?? 50));
        },
    }));
}
