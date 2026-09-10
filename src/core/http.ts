/**
 * 受控 HTTP 客户端。
 *
 * 把「响应体截断」「方法白名单」「超时与取消」「协议回退」收敛到一处，
 * 供 http_probe 工具、指纹识别与非破坏性复现引擎共用。
 */
import type { CvescoutConfig } from '../config.ts'
import { HttpRequestError, type HttpErrorKind } from './errors.ts'
import { resolveTargetInput, swapScheme } from './url.ts'

export { HttpRequestError }
export type { HttpErrorKind }

/** 永远不允许的 HTTP 方法（既不改状态也不属于被动探测）。 */
const FORBIDDEN_METHODS = new Set(['TRACE', 'CONNECT'])

/** 无副作用的方法，默认放行。 */
const PASSIVE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])

export interface HttpRequestInput {
  url: string
  method?: string
  headers?: Record<string, string>
  body?: string | null
  /** 覆盖配置中的超时。 */
  timeoutMs?: number
  /** 是否跟随重定向，默认 true。 */
  followRedirects?: boolean
  /**
   * 完整响应体的读取上限（字节）。默认等于配置的 maxResponseBytes；
   * 解析结构化 API 响应（NVD / GitHub）时必须调高，否则截断后的 JSON 无法解析。
   */
  maxBytes?: number
}

export interface HttpResponseData {
  /** 原始请求 URL。 */
  url: string
  /** 跟随重定向后的最终 URL。 */
  finalUrl: string
  statusCode: number
  headers: Record<string, string>
  /** 截断到配置上限的预览，用于回给模型。 */
  bodyPreview: string
  /** 在 maxBytes 上限内的完整响应体文本，供插件内部解析。 */
  bodyText: string
  bodyBytes: number
  truncated: boolean
  elapsedMs: number
  /** true 表示首次请求连不上（TLS/连接层失败），已自动换协议重试成功。 */
  schemeFallback: boolean
}

/** 构造基础请求头：默认 UA + 可选调用方追加。 */
export function baseHeaders(cfg: CvescoutConfig, extra?: Record<string, string>): Record<string, string> {
  const headers: Record<string, string> = {
    'user-agent': cfg.userAgent,
    accept: '*/*',
  }
  if (extra) {
    for (const [key, value] of Object.entries(extra)) {
      headers[key.toLowerCase()] = value
    }
  }
  return headers
}

/**
 * 校验并归一化 URL（不带方案时按 https 补齐）。
 * 需要别名解析时请直接用 {@link resolveTargetInput}。
 */
export function normalizeUrl(raw: string): string {
  return resolveTargetInput(raw, { defaultScheme: 'https' })
}

/**
 * 发送一次 HTTP 请求。
 *
 * `allowNonIdempotentProbe` 由配置注入：为 false 时仅放行 GET/HEAD/OPTIONS，
 * 与「不做真实内容写入」的验证策略一致。
 *
 * URL 会先经 {@link resolveTargetInput} 归一化（裸域名补默认协议、别名解析、
 * 剥掉中文标点），因此调用方可以直接传用户原话里的域名。若首次请求在连接/TLS
 * 层失败且配置允许，会自动换一次协议重试（仅限被动方法）——内网站点常只开 http
 * 或只开 https，这一步能显著减少「目标不可达」的假失败。
 */
export async function request(
  cfg: CvescoutConfig,
  input: HttpRequestInput,
  signal?: AbortSignal,
): Promise<HttpResponseData> {
  const method = (input.method ?? 'GET').toUpperCase()

  if (FORBIDDEN_METHODS.has(method)) {
    throw new HttpRequestError('blocked-method', `禁止使用 ${method} 方法`)
  }
  if (!PASSIVE_METHODS.has(method) && !cfg.allowNonIdempotentProbe) {
    throw new HttpRequestError(
      'blocked-method',
      `${method} 属非幂等探测，需在配置中显式开启 allowNonIdempotentProbe`,
    )
  }

  const primaryUrl = resolveTargetInput(input.url, {
    defaultScheme: cfg.defaultScheme,
    aliases: cfg.targetAliases,
  })

  try {
    return await attemptRequest(cfg, primaryUrl, method, input, signal, false)
  } catch (error) {
    const retryable = error instanceof HttpRequestError && error.kind === 'network'
    if (!retryable || !cfg.allowSchemeFallback || !PASSIVE_METHODS.has(method)) throw error
    const alternate = swapScheme(primaryUrl)
    if (!alternate) throw error
    return await attemptRequest(cfg, alternate, method, input, signal, true)
  }
}

async function attemptRequest(
  cfg: CvescoutConfig,
  url: string,
  method: string,
  input: HttpRequestInput,
  signal: AbortSignal | undefined,
  schemeFallback: boolean,
): Promise<HttpResponseData> {
  const timeoutMs = input.timeoutMs ?? cfg.timeoutMs
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(new Error('timeout')), timeoutMs)

  const onAbort = () => controller.abort(signal?.reason)
  if (signal) {
    if (signal.aborted) onAbort()
    else signal.addEventListener('abort', onAbort, { once: true })
  }

  const startedAt = Date.now()
  try {
    const response = await fetch(url, {
      method,
      headers: baseHeaders(cfg, input.headers),
      body: input.body ?? undefined,
      redirect: input.followRedirects === false ? 'manual' : 'follow',
      signal: controller.signal,
    })

    const buffer = Buffer.from(await response.arrayBuffer())
    const previewLimit = Math.max(256, cfg.maxResponseBytes)
    const readLimit = Math.max(previewLimit, input.maxBytes ?? previewLimit)
    const truncated = buffer.byteLength > readLimit
    const slice = truncated ? buffer.subarray(0, readLimit) : buffer
    const bodyText = new TextDecoder('utf-8', { fatal: false }).decode(slice)
    const headers: Record<string, string> = {}
    response.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value
    })

    return {
      url,
      finalUrl: response.url || url,
      statusCode: response.status,
      headers,
      bodyPreview: bodyText.slice(0, previewLimit),
      bodyText,
      bodyBytes: buffer.byteLength,
      truncated,
      elapsedMs: Date.now() - startedAt,
      schemeFallback,
    }
  } catch (error) {
    if (signal?.aborted) {
      throw new HttpRequestError('aborted', '调用方已取消请求', error)
    }
    if (controller.signal.aborted || (error instanceof Error && error.name === 'TimeoutError')) {
      throw new HttpRequestError('timeout', `请求超时（${timeoutMs}ms）`, error)
    }
    if (error instanceof TypeError && /redirect/i.test(error.message)) {
      throw new HttpRequestError('too-many-redirects', '重定向次数过多', error)
    }
    throw new HttpRequestError('network', `请求失败: ${(error as Error)?.message ?? String(error)}`, error)
  } finally {
    clearTimeout(timer)
    if (signal) signal.removeEventListener('abort', onAbort)
  }
}

/** 结构化 API 响应体的默认读取上限（8 MiB）。 */
export const API_BODY_LIMIT = 8 * 1024 * 1024

export interface JsonFetchResult<T> {
  data: T | null
  statusCode: number
  /** 失败原因，带上分类（HTTP 状态码 / TLS / 超时 / JSON 解析），便于原样写进报告取证。 */
  error?: string
}

/**
 * GET 一个 JSON 接口，并保留失败原因。
 *
 * 之所以不直接抛异常：情报源（NVD / GitHub）不可用时，复测仍应给出结论，
 * 只是结论里要如实写明「情报不可用」及原因，而不是静默当成「无漏洞」。
 */
export async function fetchJson<T>(
  cfg: CvescoutConfig,
  url: string,
  headers?: Record<string, string>,
  signal?: AbortSignal,
): Promise<JsonFetchResult<T>> {
  try {
    const response = await request(cfg, { url, method: 'GET', headers, maxBytes: API_BODY_LIMIT }, signal)
    if (response.statusCode < 200 || response.statusCode >= 300) {
      return { data: null, statusCode: response.statusCode, error: `HTTP ${response.statusCode}` }
    }
    try {
      return { data: JSON.parse(response.bodyText) as T, statusCode: response.statusCode }
    } catch (error) {
      return {
        data: null,
        statusCode: response.statusCode,
        error: `响应不是合法 JSON: ${(error as Error).message}`,
      }
    }
  } catch (error) {
    return {
      data: null,
      statusCode: 0,
      error: error instanceof HttpRequestError ? `${error.kind}: ${error.message}` : String(error),
    }
  }
}
