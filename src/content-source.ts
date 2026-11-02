import { withHTTP } from '@helia/http'
import { unixfs } from '@helia/unixfs'
import type { RandomAccessSource } from 'filecoin-encryption-envelope'
import { createHeliaLight } from 'helia'
import type { CID } from 'multiformats/cid'
import * as raw from 'multiformats/codecs/raw'
import { NotAvailableError } from './errors.js'

/** Delegated routers (routing v1) asked who provides the share. The first with an answer wins; none hardcodes content. */
export const DEFAULT_ROUTERS = ['https://delegated-ipfs.dev', 'https://cid.contact']
const BLOCK_TIMEOUT_MS = 30_000

export interface ContentSourceOptions {
  routers?: string[]
  /** Tests only: let the router name http:// and loopback providers. */
  allowInsecure?: boolean
  allowLocal?: boolean
}

const nodes = new Map<string, Promise<ReturnType<typeof createHeliaLight>>>()

// One node per router set (one per page in production): providers found for the root serve every block of it
function helia(options: ContentSourceOptions): Promise<ReturnType<typeof createHeliaLight>> {
  const key = (options.routers ?? DEFAULT_ROUTERS).join(' ')
  let node = nodes.get(key)
  if (node) return node
  node = (async () => {
    const light = withHTTP(createHeliaLight(), {
      delegatedRouters: options.routers ?? DEFAULT_ROUTERS,
      // No recursive gateway: content comes only from providers the routers name, every block hash-checked
      recursiveGateways: [],
      allowInsecure: options.allowInsecure,
      allowLocal: options.allowLocal,
    })
    await light.start()
    return light
  })()
  nodes.set(key, node)
  return node
}

/**
 * The share's envelope as a random-access source, read from providers the routers name for `cid`. Every block is
 * verified against its CID before any byte is returned. A raw root is one block, held in memory; a UnixFS root is read
 * by range so only the leaves a window touches are fetched.
 */
export async function openContentSource(cid: CID, options: ContentSourceOptions = {}): Promise<RandomAccessSource> {
  const light = await helia(options)
  try {
    if (cid.code === raw.code) {
      // helia 7 streams the block; a raw root is one block, so gather it (it is verified before the first chunk)
      const parts: Uint8Array[] = []
      for await (const part of light.blockstore.get(cid, { signal: AbortSignal.timeout(BLOCK_TIMEOUT_MS) })) {
        parts.push(part)
      }
      const block = new Uint8Array(await new Blob(parts as BlobPart[]).arrayBuffer())
      return {
        size: block.length,
        async openRange(offset, length) {
          return streamOf(block.subarray(offset, offset + length))
        },
      }
    }
    const fs = unixfs(light)
    const stat = await fs.stat(cid, { signal: AbortSignal.timeout(BLOCK_TIMEOUT_MS) })
    if (stat.type !== 'file') throw new Error(`The share root is a ${stat.type}, not a file`)
    const size = Number(stat.size)
    return {
      size,
      async openRange(offset, length) {
        const iterator = fs
          .cat(cid, { offset, length, signal: AbortSignal.timeout(BLOCK_TIMEOUT_MS) })
          [Symbol.asyncIterator]()
        return new ReadableStream<Uint8Array>({
          async pull(controller) {
            const { value, done } = await iterator.next()
            if (done) controller.close()
            else controller.enqueue(value)
          },
          async cancel() {
            await iterator.return?.()
          },
        })
      },
    }
  } catch (error) {
    // A block that is missing, unreachable, or fails its hash check all end here; the share is not readable right now
    throw new NotAvailableError('Share is not available yet', { cause: error })
  }
}

function streamOf(bytes: Uint8Array): ReadableStream<Uint8Array> {
  return new ReadableStream({
    start(controller) {
      controller.enqueue(bytes)
      controller.close()
    },
  })
}
