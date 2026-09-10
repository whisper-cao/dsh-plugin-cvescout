import { hostOf } from "./url.js";
/** 破坏性工具名单：这些名字在我们的工具集里本就不存在，作为纵深防御保留。 */
export const BLOCKED_TOOL_NAMES = [
    'write_file',
    'delete_file',
    'exec_command',
    'shell_exec',
];
const SENSITIVE_KEY_PATTERN = /password|passwd|token|api[_-]?key|secret|cookie|authorization|credential/i;
const MAX_AUDIT_ENTRIES = 500;
/** 安全护栏拒绝调用时抛出的专用错误，便于调用方与网络错误区分开。 */
export class SafetyBlockedError extends Error {
    toolName;
    kind;
    constructor(toolName, reason, kind = 'scope') {
        super(`安全护栏拦截 [${toolName}]: ${reason}`);
        this.name = 'SafetyBlockedError';
        this.toolName = toolName;
        this.kind = kind;
    }
    /** 是否为「目标未授权」——这类拒绝必须硬失败，不允许被静默降级。 */
    get isScopeViolation() {
        return this.kind === 'scope';
    }
}
export class SafetyGuard {
    cfg;
    auditLog = [];
    timestamps = [];
    totalRequests = 0;
    counter = 0;
    constructor(cfg) {
        this.cfg = cfg;
    }
    /** 同步校验一次工具调用；通过后才计入速率与总量配额。 */
    check(toolName, params) {
        const decision = this.evaluate(toolName, params);
        if (!decision.allowed) {
            this.record(toolName, params, false, decision.reason);
            return decision;
        }
        this.totalRequests += 1;
        this.timestamps.push(Date.now());
        this.record(toolName, params, true, '');
        return decision;
    }
    /**
     * 校验失败时抛 SafetyBlockedError，便于在非工具上下文中使用
     * （例如批量流水线内部）。调用方若在 try/catch 里吞异常，必须显式
     * 放行这个错误类型，否则会把「未授权」误报成「不可达」。
     */
    assertAllowed(toolName, params) {
        const decision = this.check(toolName, params);
        if (!decision.allowed) {
            throw new SafetyBlockedError(toolName, decision.reason, decision.kind);
        }
    }
    evaluate(toolName, params) {
        if (BLOCKED_TOOL_NAMES.includes(toolName)) {
            return {
                allowed: false,
                kind: 'blocked-tool',
                reason: `工具 ${toolName} 属破坏性操作，已被拦截`,
            };
        }
        const payloadHit = this.matchBlockedPattern(params);
        if (payloadHit) {
            return { allowed: false, kind: 'blocked-pattern', reason: `参数包含禁止模式: ${payloadHit}` };
        }
        const scopeHit = this.matchScopeViolation(params);
        if (scopeHit) {
            return { allowed: false, kind: 'scope', reason: this.scopeHint(scopeHit) };
        }
        const now = Date.now();
        while (this.timestamps.length > 0 && now - this.timestamps[0] >= 60_000) {
            this.timestamps.shift();
        }
        if (this.timestamps.length >= this.cfg.maxRequestsPerMinute) {
            return {
                allowed: false,
                kind: 'rate-limit',
                reason: `超过速率限制 (${this.cfg.maxRequestsPerMinute}/min)`,
            };
        }
        if (this.totalRequests >= this.cfg.maxTotalRequests) {
            return {
                allowed: false,
                kind: 'total-limit',
                reason: `超过总请求数限制 (${this.cfg.maxTotalRequests})`,
            };
        }
        return { allowed: true, kind: 'ok', reason: 'ok' };
    }
    matchBlockedPattern(params) {
        const serialized = safeStringify(params).toLowerCase();
        for (const pattern of this.cfg.blockedPayloadPatterns) {
            try {
                if (new RegExp(pattern, 'i').test(serialized))
                    return pattern;
            }
            catch {
                // 配置里的非法正则不应让整条链路崩掉，忽略即可（配置加载时已有拼写校验空间）。
            }
        }
        return null;
    }
    matchScopeViolation(params) {
        if (this.cfg.allowedDomains.length === 0)
            return null;
        for (const candidate of collectUrlLikeValues(params)) {
            if (!this.isDomainAllowed(candidate))
                return candidate;
        }
        return null;
    }
    /**
     * 目标主机是否落在授权白名单内（精确匹配或子域后缀匹配）。
     *
     * 接受裸域名输入（`portal.example.com`、`127.0.0.1:5000`）：调用方可能还没做地址
     * 归一化就来校验，这里不能因为解析失败就把合法目标判成越权。
     */
    isDomainAllowed(rawUrl) {
        if (this.cfg.allowedDomains.length === 0)
            return true;
        const host = hostOf(rawUrl, this.cfg.defaultScheme);
        if (!host)
            return false;
        return this.cfg.allowedDomains.some((domain) => {
            const normalized = String(domain)
                .trim()
                .toLowerCase()
                .replace(/^https?:\/\//, '')
                .replace(/^\./, '')
                .split('/')[0]
                .split(':')[0];
            if (!normalized)
                return false;
            return host === normalized || host.endsWith(`.${normalized}`);
        });
    }
    /** 授权范围的人类可读描述，供拦截信息与 target_scope 工具共用。 */
    describeScope() {
        if (this.cfg.allowedDomains.length === 0) {
            return '未配置授权域名白名单（当前不限制目标，仅建议离线/隔离环境这样用）';
        }
        return `当前授权域名：${this.cfg.allowedDomains.join('、')}`;
    }
    /** 目标不在授权范围时的可执行提示。 */
    scopeHint(target) {
        return (`目标 ${target} 不在授权范围内。${this.describeScope()}。` +
            '请把该域名加入 cordis.yml 的 allowedDomains（或用 targetAliases 给系统名配别名）后重试；' +
            '在获得授权前不要尝试绕过校验。');
    }
    record(toolName, params, allowed, reason) {
        this.counter += 1;
        this.auditLog.push({
            index: this.counter,
            timestamp: new Date().toISOString(),
            tool: toolName,
            params: sanitize(params),
            allowed,
            reason,
        });
        if (this.auditLog.length > MAX_AUDIT_ENTRIES) {
            this.auditLog.splice(0, this.auditLog.length - MAX_AUDIT_ENTRIES);
        }
    }
    /** 生成审计报告。 */
    report(limit = 50) {
        const blocked = this.auditLog.filter((entry) => !entry.allowed).length;
        const total = this.auditLog.length;
        const now = Date.now();
        const lastMinute = this.timestamps.filter((ts) => now - ts < 60_000).length;
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
        };
    }
    /** 清空审计与计数（用于批量任务之间复位）。 */
    reset() {
        this.auditLog.length = 0;
        this.timestamps.length = 0;
        this.totalRequests = 0;
        this.counter = 0;
    }
    get usedRequests() {
        return this.totalRequests;
    }
}
function safeStringify(value) {
    try {
        return JSON.stringify(value) ?? String(value);
    }
    catch {
        return String(value);
    }
}
function sanitize(params) {
    if (params === null || typeof params !== 'object')
        return params;
    if (Array.isArray(params))
        return params.map((item) => sanitize(item));
    const out = {};
    for (const [key, value] of Object.entries(params)) {
        out[key] = SENSITIVE_KEY_PATTERN.test(key) ? '***REDACTED***' : sanitize(value);
    }
    return out;
}
/** 递归收集参数里所有像 URL 的字符串，用于授权范围检查。 */
function collectUrlLikeValues(value, depth = 0) {
    if (depth > 6 || value === null || value === undefined)
        return [];
    if (typeof value === 'string') {
        return /^https?:\/\//i.test(value.trim()) ? [value.trim()] : [];
    }
    if (Array.isArray(value)) {
        return value.flatMap((item) => collectUrlLikeValues(item, depth + 1));
    }
    if (typeof value === 'object') {
        return Object.values(value).flatMap((item) => collectUrlLikeValues(item, depth + 1));
    }
    return [];
}
