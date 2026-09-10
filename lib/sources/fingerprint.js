import { request } from "../core/http.js";
import { SafetyBlockedError } from "../core/safety.js";
import { resolveTarget } from "../core/runtime.js";
/** 指纹规则表。 */
export const FINGERPRINT_RULES = [
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
    // ---- 语言 / 框架 ----
    { name: 'PHP', category: 'framework', pattern: 'PHP/([\\d.]+)', from: 'header', header: 'x-powered-by', confidence: 0.9 },
    { name: 'Express.js', category: 'framework', pattern: 'Express', from: 'header', header: 'x-powered-by', confidence: 0.85 },
    { name: 'ASP.NET', category: 'framework', pattern: 'ASP\\.NET', from: 'header', header: 'x-powered-by', confidence: 0.8 },
    { name: 'ASP.NET', category: 'framework', pattern: '([\\d.]+)', from: 'header', header: 'x-aspnet-version', confidence: 0.85 },
    { name: 'Spring Boot', category: 'framework', pattern: '.+', from: 'header', header: 'x-application-context', confidence: 0.85 },
    { name: 'Java Servlet', category: 'framework', pattern: 'JSESSIONID', from: 'cookie', confidence: 0.7 },
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
    // ---- WAF / 网关 ----
    { name: 'Cloudflare', category: 'waf', pattern: 'cloudflare|cf-ray', from: 'header', confidence: 0.85, waf: true },
    { name: 'AWS WAF/ALB', category: 'waf', pattern: 'awselb|AWSALB|awswaf', from: 'header', confidence: 0.7, waf: true },
    { name: 'Akamai', category: 'waf', pattern: 'AkamaiGHost', from: 'header', confidence: 0.85, waf: true },
    { name: 'FortiWeb', category: 'waf', pattern: 'FortiWeb', from: 'header', confidence: 0.85, waf: true },
    { name: 'F5 BIG-IP', category: 'waf', pattern: 'BIG-IP|TS0[0-9a-f]{6}', from: 'cookie', confidence: 0.8, waf: true },
    { name: 'ModSecurity', category: 'waf', pattern: 'mod_security|NOYB', from: 'body', confidence: 0.7, waf: true },
];
/** SPA / Spring Boot 默认错误页特征，用于识别错误页形态。 */
const ERROR_PAGE_MARKERS = [
    { name: 'Spring Boot Whitelabel', pattern: /Whitelabel Error Page/i },
    { name: 'Tomcat 默认错误页', pattern: /Apache Tomcat\/[\d.]+/i },
    { name: 'Nginx 默认错误页', pattern: /<center>nginx<\/center>/i },
    { name: 'SPA 兜底路由', pattern: /<div id="(app|root)"><\/div>/i },
];
/** 执行指纹识别。任何单点探测失败都不影响整体结论，只记入 probeErrors。 */
export async function fingerprintTarget(runtime, targetUrl, signal) {
    const startedAt = Date.now();
    // 先归一化：用户可能只给域名或系统别名，必须在安全护栏之前解析成绝对 URL。
    const target = resolveTarget(runtime, targetUrl);
    const result = {
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
        scanDurationMs: 0,
        probeErrors: [],
    };
    let root = null;
    try {
        root = await probe(runtime, target, 'GET', signal);
    }
    catch (error) {
        // 未授权/被护栏拦截必须冒泡，不能降级成「不可达」，否则会被当成普通失败放过。
        if (error instanceof SafetyBlockedError)
            throw error;
        result.error = `目标根路径不可达: ${error.message}`;
        result.scanDurationMs = Date.now() - startedAt;
        return result;
    }
    result.statusCode = root.statusCode;
    result.server = root.headers.server ?? null;
    result.techStack = matchRules({
        headerText: flattenHeaders(root.headers),
        bodyText: root.bodyPreview,
        cookieText: root.headers['set-cookie'] ?? '',
        serverHeader: root.headers.server ?? '',
    });
    result.title = extractTitle(root.bodyPreview);
    applyDerived(result);
    // OPTIONS：读 Allow 头，属被动探测。
    if (runtime.cfg.probeAllowedMethods) {
        try {
            const optionsResponse = await probe(runtime, target, 'OPTIONS', signal);
            const allow = optionsResponse.headers.allow;
            if (allow) {
                result.allowedMethods = allow
                    .split(',')
                    .map((item) => item.trim().toUpperCase())
                    .filter(Boolean);
            }
        }
        catch (error) {
            result.probeErrors.push(`OPTIONS 探测失败: ${error.message}`);
        }
    }
    // 错误页签名：随机不存在路径，用于判断 404 是框架错误页还是 SPA 兜底。
    if (runtime.cfg.errorPageProbe) {
        try {
            const randomPath = `/__cvescout_${Math.random().toString(36).slice(2, 10)}`;
            const notFound = await probe(runtime, joinUrl(target, randomPath), 'GET', signal);
            const marker = ERROR_PAGE_MARKERS.find((item) => item.pattern.test(notFound.bodyPreview));
            const snippet = notFound.bodyPreview.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 160);
            result.errorPageSignature = marker
                ? `${marker.name} (HTTP ${notFound.statusCode})`
                : `HTTP ${notFound.statusCode}: ${snippet}`;
        }
        catch (error) {
            result.probeErrors.push(`错误页探测失败: ${error.message}`);
        }
    }
    // 额外被动路径。
    for (const path of runtime.cfg.passiveProbePaths) {
        try {
            const response = await probe(runtime, joinUrl(target, path), 'GET', signal);
            if (response.statusCode !== 200)
                continue;
            const snippet = response.bodyPreview.slice(0, 500);
            if (path.includes('robots.txt'))
                result.robots = snippet;
            else if (path.includes('security.txt'))
                result.securityTxt = snippet;
        }
        catch (error) {
            result.probeErrors.push(`路径探测失败 ${path}: ${error.message}`);
        }
    }
    result.scanDurationMs = Date.now() - startedAt;
    return result;
}
/** 通过安全护栏后再发请求。 */
async function probe(runtime, url, method, signal) {
    runtime.safety.assertAllowed('fingerprint', { url, method });
    return request(runtime.cfg, { url, method }, signal);
}
function matchRules(input) {
    const found = new Map();
    for (const rule of FINGERPRINT_RULES) {
        let haystack;
        if (rule.from === 'header') {
            haystack = rule.header ? (extractHeaderValue(input.headerText, rule.header) ?? '') : input.headerText;
        }
        else if (rule.from === 'cookie') {
            haystack = input.cookieText;
        }
        else {
            haystack = input.bodyText;
        }
        if (!haystack)
            continue;
        let match;
        try {
            match = new RegExp(rule.pattern, 'i').exec(haystack);
        }
        catch {
            continue;
        }
        if (!match)
            continue;
        const key = rule.name.toLowerCase();
        const existing = found.get(key);
        if (existing && existing.confidence >= rule.confidence)
            continue;
        found.set(key, {
            name: rule.name,
            version: pickVersion(match, rule.from === 'cookie' ? '' : haystack),
            category: rule.category,
            confidence: rule.confidence,
        });
    }
    return Array.from(found.values());
}
/** 从匹配结果或所在文本里挑一个像版本的串。 */
function pickVersion(match, haystack) {
    for (let i = match.length - 1; i >= 1; i -= 1) {
        const group = match[i];
        if (group && /^\d+(\.\d+)+/.test(group))
            return group;
    }
    const fromHaystack = haystack.match(/\b(\d+(?:\.\d+){1,3})\b/);
    return fromHaystack ? fromHaystack[1] : null;
}
function applyDerived(result) {
    for (const component of result.techStack) {
        if (component.category === 'waf' && !result.wafDetected) {
            result.wafDetected = true;
            result.wafVendor = component.name;
        }
    }
    if (!result.framework) {
        const framework = result.techStack.find((item) => ['framework', 'cms', 'frontend'].includes(item.category));
        if (framework) {
            result.framework = framework.version ? `${framework.name}/${framework.version}` : framework.name;
        }
    }
}
function flattenHeaders(headers) {
    return Object.entries(headers)
        .map(([key, value]) => `${key}: ${value}`)
        .join('\n');
}
function extractHeaderValue(flattened, headerName) {
    const pattern = new RegExp(`^${headerName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}:\\s*(.*)$`, 'im');
    const match = flattened.match(pattern);
    return match ? match[1].trim() : null;
}
function extractTitle(html) {
    const match = html.match(/<title[^>]*>([\s\S]{0,200}?)<\/title>/i);
    return match ? match[1].replace(/\s+/g, ' ').trim() : null;
}
/** 以任意路径与基础 URL 拼接。 */
export function joinUrl(baseUrl, path) {
    if (path.startsWith('http://') || path.startsWith('https://'))
        return path;
    return `${baseUrl.replace(/\/+$/, '')}/${path.replace(/^\/+/, '')}`;
}
