import { fetchJson, request } from "../core/http.js";
import { githubHeaders, isValidCveId, normalizeCveId } from "./nvd.js";
/** 搜索 CVE 相关公开 PoC。 */
export async function searchPoc(cfg, cveIdRaw, signal, maxResults = 10) {
    const cveId = normalizeCveId(cveIdRaw);
    if (!isValidCveId(cveId)) {
        return { cveId, pocCount: 0, pocs: [], error: `CVE 编号格式非法: ${cveIdRaw}` };
    }
    const [githubResult, exploitdbResult] = await Promise.all([
        searchGithub(cfg, cveId, signal),
        searchExploitDb(cfg, cveId, signal),
    ]);
    const pocs = [...githubResult.pocs, ...exploitdbResult.pocs].slice(0, maxResults);
    const errors = [githubResult.error, exploitdbResult.error].filter((item) => Boolean(item));
    if (pocs.length === 0) {
        return {
            cveId,
            pocCount: 0,
            pocs: [],
            message: errors.length > 0 ? `未找到公开 PoC（${errors.join('；')}）` : '未找到公开 PoC',
        };
    }
    return { cveId, pocCount: pocs.length, pocs };
}
async function searchGithub(cfg, cveId, signal) {
    const params = new URLSearchParams({
        q: `${cveId} poc exploit`,
        sort: 'stars',
        order: 'desc',
        per_page: '5',
    });
    const url = `https://api.github.com/search/repositories?${params.toString()}`;
    const data = await fetchJson(cfg, url, githubHeaders(cfg), signal);
    if (!data.data)
        return { pocs: [], error: `GitHub 搜索失败（${data.error ?? '未知原因'}）` };
    const pocs = (data.data.items ?? []).map((item) => ({
        source: 'GitHub',
        name: item.full_name ?? item.name ?? '(unnamed)',
        url: item.html_url ?? '',
        description: item.description ?? '',
        stars: item.stargazers_count ?? 0,
        language: item.language ?? null,
        updated: item.updated_at ?? '',
    }));
    return { pocs };
}
async function searchExploitDb(cfg, cveId, signal) {
    const url = `https://www.exploit-db.com/search?cve=${encodeURIComponent(cveId)}`;
    try {
        const response = await request(cfg, { url, method: 'GET', headers: { accept: 'text/html' }, maxBytes: 1024 * 1024 }, signal);
        if (response.statusCode !== 200) {
            return { pocs: [], error: `ExploitDB 返回 ${response.statusCode}` };
        }
        // 弱信号：仅当检索页命中 CVE 编号时才认为可能存在条目。
        if (!response.bodyText.toLowerCase().includes(cveId.toLowerCase())) {
            return { pocs: [] };
        }
        return {
            pocs: [
                {
                    source: 'ExploitDB',
                    name: `${cveId} - ExploitDB entry`,
                    url,
                    description: 'ExploitDB 检索页命中该 CVE（弱信号，需人工确认条目有效性）',
                },
            ],
        };
    }
    catch (error) {
        return { pocs: [], error: `ExploitDB 查询失败: ${error.message}` };
    }
}
