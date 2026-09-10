/**
 * 目标地址解析。
 *
 * 用户在对话里不会总给标准 URL：可能只说域名（`portal.example.com`）、带中文标点
 * （`https://portal.example.com。`）、或者用系统别名（`内部管理系统`）。
 * 这一层负责把这类输入收敛成绝对 URL，并且**必须在安全护栏校验之前完成**——
 * 否则 `portal.example.com` 会因为 `new URL()` 解析失败而被判成「不在授权范围」。
 */
import { HttpRequestError } from './http.ts'

export interface TargetResolveOptions {
  /** 未写 scheme 时补的协议，默认 https。 */
  defaultScheme?: string
  /** 别名表：系统名 / 简称 → 域名或 URL。 */
  aliases?: Record<string, string>
}

const SCHEME_PATTERN = /^([a-z][a-z0-9+.-]*):\/\//i
const HTTP_URL_PATTERN = /https?:\/\/[^\s"'<>，。；、）】]+/i
/** 需要从首尾剥掉的噪声字符（中文标点、引号、括号、markdown 反引号等）。 */
const TRIM_CHARS = /^[\s`'"<>()（）[\]【】]+|[\s`'"<>()（）[\]【】，。；、,;:：]+$/g

function cleanup(raw: string): string {
  const text = String(raw ?? '')
  // 若整串里嵌着标准 URL（模型偶尔会带一句说明），优先把它抠出来。
  const embedded = HTTP_URL_PATTERN.exec(text)
  if (embedded) return embedded[0].replace(TRIM_CHARS, '')
  return text.replace(TRIM_CHARS, '')
}

function lookupAlias(input: string, aliases?: Record<string, string>): string | null {
  if (!aliases) return null
  const needle = input.trim().toLowerCase()
  if (!needle) return null
  for (const [key, value] of Object.entries(aliases)) {
    if (key.trim().toLowerCase() === needle) return String(value)
  }
  return null
}

/** 输入里是否已经写明协议。 */
export function hasExplicitScheme(raw: string): boolean {
  return SCHEME_PATTERN.test(cleanup(raw))
}

/**
 * 把用户输入解析成绝对 URL。
 *
 * 接受：`portal.example.com`、`portal.example.com/api/x`、`127.0.0.1:5000`、
 * `https://x.cn/a?b=c`、以及别名表里的键。
 */
export function resolveTargetInput(raw: string, options: TargetResolveOptions = {}): string {
  const cleaned = cleanup(raw)
  if (!cleaned) throw new HttpRequestError('invalid-url', '目标为空，请给出域名或 URL')

  const aliased = lookupAlias(cleaned, options.aliases)
  const candidate = aliased ?? cleaned

  const schemeMatch = SCHEME_PATTERN.exec(candidate)
  if (schemeMatch && !/^https?$/i.test(schemeMatch[1])) {
    throw new HttpRequestError('invalid-url', `仅支持 http/https，收到 ${schemeMatch[1]}:`)
  }

  const absolute = schemeMatch
    ? candidate
    : `${options.defaultScheme ?? 'https'}://${candidate.replace(/^\/+/, '')}`

  let parsed: URL
  try {
    parsed = new URL(absolute)
  } catch {
    throw new HttpRequestError('invalid-url', `无法解析为目标地址: ${cleaned}`)
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new HttpRequestError('invalid-url', `仅支持 http/https，收到 ${parsed.protocol}`)
  }
  if (!parsed.hostname) {
    throw new HttpRequestError('invalid-url', `缺少主机名: ${cleaned}`)
  }
  return parsed.toString()
}

/** 取反协议后的 URL；已是 http 则给 https，反之亦然。 */
export function swapScheme(url: string): string | null {
  try {
    const parsed = new URL(url)
    if (parsed.protocol === 'https:') parsed.protocol = 'http:'
    else if (parsed.protocol === 'http:') parsed.protocol = 'https:'
    else return null
    return parsed.toString()
  } catch {
    return null
  }
}

/** 从 URL 取主机名；解析不了返回 null（不做任何猜测）。 */
export function hostOf(raw: string, defaultScheme?: string): string | null {
  const candidates = [raw]
  if (!hasExplicitScheme(raw)) candidates.push(`${defaultScheme ?? 'https'}://${cleanup(raw)}`)
  for (const candidate of candidates) {
    try {
      const host = new URL(candidate).hostname
      if (host) return host.toLowerCase()
    } catch {
      // 试下一个候选
    }
  }
  return null
}
