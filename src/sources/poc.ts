/**
 * 公开 PoC / 利用代码搜索。
 *
 * GitHub Search API + ExploitDB 检索页。ExploitDB 没有公开 API，这里只做
 * 「检索页是否包含该 CVE」的弱信号判断，并在结果里标注该来源置信度较低。
 */
import type { CvescoutConfig } from '../config.ts'
import type { PocEntry, PocResult } from '../types.ts'
import { fetchJson, request } from '../core/http.ts'
import { githubHeaders, isValidCveId, normalizeCveId } from './nvd.ts'

interface GithubSearchResponse {
  items?: Array<{
    name?: string
    full_name?: string
    html_url?: string
    description?: string | null
    stargazers_count?: number
    language?: string | null
    updated_at?: string
  }>
}

/** 搜索 CVE 相关公开 PoC。 */
export async function searchPoc(
  cfg: CvescoutConfig,
  cveIdRaw: string,
  signal?: AbortSignal,
  maxResults = 10,
): Promise<PocResult> {
  const cveId = normalizeCveId(cveIdRaw)
  if (!isValidCveId(cveId)) {
    return { cveId, pocCount: 0, pocs: [], error: `CVE 编号格式非法: ${cveIdRaw}` }
  }

  const [githubResult, exploitdbResult] = await Promise.all([
    searchGithub(cfg, cveId, signal),
    searchExploitDb(cfg, cveId, signal),
  ])

  const pocs = [...githubResult.pocs, ...exploitdbResult.pocs].slice(0, maxResults)
  const errors = [githubResult.error, exploitdbResult.error].filter((item): item is string => Boolean(item))

  if (pocs.length === 0) {
    return {
      cveId,
      pocCount: 0,
      pocs: [],
      message: errors.length > 0 ? `未找到公开 PoC（${errors.join('；')}）` : '未找到公开 PoC',
    }
  }

  return { cveId, pocCount: pocs.length, pocs }
}

async function searchGithub(
  cfg: CvescoutConfig,
  cveId: string,
  signal?: AbortSignal,
): Promise<{ pocs: PocEntry[]; error?: string }> {
  const params = new URLSearchParams({
    q: `${cveId} poc exploit`,
    sort: 'stars',
    order: 'desc',
    per_page: '5',
  })
  const url = `https://api.github.com/search/repositories?${params.toString()}`

  const data = await fetchJson<GithubSearchResponse>(cfg, url, githubHeaders(cfg), signal)
  if (!data.data) return { pocs: [], error: `GitHub 搜索失败（${data.error ?? '未知原因'}）` }

  const pocs: PocEntry[] = (data.data.items ?? []).map((item) => ({
    source: 'GitHub',
    name: item.full_name ?? item.name ?? '(unnamed)',
    url: item.html_url ?? '',
    description: item.description ?? '',
    stars: item.stargazers_count ?? 0,
    language: item.language ?? null,
    updated: item.updated_at ?? '',
  }))

  return { pocs }
}

async function searchExploitDb(
  cfg: CvescoutConfig,
  cveId: string,
  signal?: AbortSignal,
): Promise<{ pocs: PocEntry[]; error?: string }> {
  const url = `https://www.exploit-db.com/search?cve=${encodeURIComponent(cveId)}`
  try {
    const response = await request(
      cfg,
      { url, method: 'GET', headers: { accept: 'text/html' }, maxBytes: 1024 * 1024 },
      signal,
    )
    if (response.statusCode !== 200) {
      return { pocs: [], error: `ExploitDB 返回 ${response.statusCode}` }
    }
    // 弱信号：仅当检索页命中 CVE 编号时才认为可能存在条目。
    if (!response.bodyText.toLowerCase().includes(cveId.toLowerCase())) {
      return { pocs: [] }
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
    }
  } catch (error) {
    return { pocs: [], error: `ExploitDB 查询失败: ${(error as Error).message}` }
  }
}
