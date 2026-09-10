/**
 * 传输层错误类型。
 *
 * 单独成文件是为了打断 `http.ts ↔ url.ts` 的循环依赖：`url.ts` 需要在解析失败时
 * 抛出分类错误，而 `http.ts` 需要用 `url.ts` 归一化地址。
 */

export type HttpErrorKind =
  | 'invalid-url'
  | 'blocked-method'
  | 'timeout'
  | 'aborted'
  | 'network'
  | 'too-many-redirects'

export class HttpRequestError extends Error {
  readonly kind: HttpErrorKind

  constructor(kind: HttpErrorKind, message: string, cause?: unknown) {
    super(message)
    this.name = 'HttpRequestError'
    this.kind = kind
    if (cause !== undefined) {
      ;(this as { cause?: unknown }).cause = cause
    }
  }
}
