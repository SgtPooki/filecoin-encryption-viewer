import type { RandomAccessSource } from 'filecoin-encryption-envelope'
import { NotAvailableError, RangeUnsupportedError } from './errors.js'

// Covers the envelope header plus the first metadata window, so opening costs one request when the metadata is small
const HEAD_BYTES = 320 * 1024
const COSE_ENCRYPT0_TAG_BYTE = 0xd0
const CONTENT_RANGE = /^bytes (\d+)-(\d+)\/(\d+)$/

// ponytail: never request byte 0: the gateway's service worker sniffs ranges that start at 0 by walking the whole file
// in the background (js-ipfs-unixfs#501, verified-fetch detectContentType). Every v0/v1 envelope starts with 0xd0
// (COSE_Encrypt0 tag). Remove when fixed upstream.
// ponytail: requests are sequential; add bounded read-ahead if previews feel slow
/**
 * A random-access view of the envelope behind `url`, read with Range requests. `size` comes from the first
 * response's Content-Range, and the head bytes it carried are reused, so the header parse costs no extra request.
 */
/** What the injected fetch is asked for; it decides where the envelope lives (dev harness, tests). */
const ENVELOPE = 'envelope'

export async function openRangeSource(fetchFn: typeof fetch): Promise<RandomAccessSource> {
  const url = ENVELOPE
  const first = await requestHead(url, fetchFn)
  const body = await readAll(first.body).catch((error) => {
    throw new NotAvailableError('The download was interrupted', { cause: error })
  })
  if (first.start !== 1 || first.end >= HEAD_BYTES || body.length !== first.end) {
    throw new NotAvailableError('The server answered with a different range than requested')
  }
  // If the guessed byte 0 is wrong, fee.parse fails and the share is reported as not a share
  const head = new Uint8Array(body.length + 1)
  head[0] = COSE_ENCRYPT0_TAG_BYTE
  head.set(body, 1)
  const size = first.total

  return {
    size,
    async openRange(offset, length) {
      const end = offset + length
      if (end <= head.length) return streamOf(head.subarray(offset, end))
      // Past the head: fetch only from the end of the head on (never from 0) and prepend what the head already holds
      const start = Math.max(offset, head.length)
      const response = await requestRange(url, fetchFn, start, end - start)
      if (response.start !== start || response.end !== end - 1 || response.total !== size) {
        await response.body.cancel().catch(() => undefined)
        throw new NotAvailableError('The server answered with a different range than requested')
      }
      return offset < head.length ? prepend(head.subarray(offset), response.body) : response.body
    },
  }
}

const UNSATISFIED_RANGE = /^bytes \*\/(\d+)$/

// Servers differ on a Range whose end is past the last byte: some clamp, dweb.link answers 416 with the size.
// Probe with the full head window; on 416, read the size from Content-Range and ask again for exactly what exists.
async function requestHead(url: string, fetchFn: typeof fetch) {
  try {
    return await requestRange(url, fetchFn, 1, HEAD_BYTES - 1)
  } catch (error) {
    if (!(error instanceof UnsatisfiableRangeError) || error.total <= 1) throw error
    return requestRange(url, fetchFn, 1, Math.min(error.total, HEAD_BYTES) - 1)
  }
}

class UnsatisfiableRangeError extends Error {
  total: number
  constructor(total: number) {
    super('The server answered 416 to the head request')
    this.total = total
  }
}

async function requestRange(url: string, fetchFn: typeof fetch, offset: number, length: number) {
  let response: Response
  try {
    // no-store: inbrowser.link's service worker otherwise answers later Range requests with a cached full 200
    response = await fetchFn(url, {
      headers: { Range: `bytes=${offset}-${offset + length - 1}` },
      cache: 'no-store',
      redirect: 'error',
    })
  } catch (error) {
    throw new NotAvailableError('Share is not available yet', { cause: error })
  }
  // The content exists but can't be read in parts; the caller keeps the response so its body can still be saved
  if (response.status === 200) throw new RangeUnsupportedError(response)
  // Responses that are thrown away get their body cancelled, so the gateway stops sending it
  if ([404, 502, 504].includes(response.status)) {
    await discard(response)
    throw new NotAvailableError('Share is not available yet')
  }
  if (response.status === 416) {
    const total = UNSATISFIED_RANGE.exec(response.headers.get('content-range') ?? '')
    await discard(response)
    if (total) throw new UnsatisfiableRangeError(Number(total[1]))
    throw new Error('Unexpected response: 416')
  }
  if (response.status !== 206) {
    await discard(response)
    throw new Error(`Unexpected response: ${response.status}`)
  }

  const range = CONTENT_RANGE.exec(response.headers.get('content-range') ?? '')
  if (!range || !response.body) {
    await discard(response)
    throw new NotAvailableError('The server sent an invalid range response')
  }
  return { start: Number(range[1]), end: Number(range[2]), total: Number(range[3]), body: response.body }
}

const discard = (response: Response) => response.body?.cancel().catch(() => undefined)

function prepend(first: Uint8Array, rest: ReadableStream<Uint8Array>): ReadableStream<Uint8Array> {
  const reader = rest.getReader()
  return new ReadableStream({
    start(controller) {
      controller.enqueue(first)
    },
    async pull(controller) {
      const { done, value } = await reader.read()
      if (done) controller.close()
      else controller.enqueue(value)
    },
    cancel: (reason) => reader.cancel(reason),
  })
}

function streamOf(bytes: Uint8Array): ReadableStream<Uint8Array> {
  return new ReadableStream({
    start(controller) {
      controller.enqueue(bytes)
      controller.close()
    },
  })
}

async function readAll(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  const reader = stream.getReader()
  const parts: Uint8Array[] = []
  let length = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    parts.push(value)
    length += value.length
  }
  const out = new Uint8Array(length)
  let at = 0
  for (const part of parts) {
    out.set(part, at)
    at += part.length
  }
  return out
}
