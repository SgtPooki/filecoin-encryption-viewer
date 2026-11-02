// @vitest-environment node
import { type Server, createServer } from 'node:http'
import { CID } from 'multiformats/cid'
import * as raw from 'multiformats/codecs/raw'
import { sha256 } from 'multiformats/hashes/sha2'
import { afterEach, describe, expect, it } from 'vitest'
import { openContentSource } from '../src/content-source.js'
import { NotAvailableError } from '../src/errors.js'

const bytes = new Uint8Array(750).map((_, index) => (index * 7) % 251)
let servers: Server[] = []
afterEach(async () => {
  await Promise.all(servers.map((server) => new Promise((resolve) => server.close(resolve))))
  servers = []
})

async function listen(handler: Parameters<typeof createServer>[1]): Promise<string> {
  const server = createServer(handler).listen(0, '127.0.0.1')
  servers.push(server)
  await new Promise((resolve) => server.once('listening', resolve))
  const address = server.address()
  if (address === null || typeof address === 'string') throw new Error('no port')
  return `http://127.0.0.1:${address.port}`
}

// A delegated router (routing v1) naming `gateway` as the only provider, and a gateway serving `body` for every block
async function harness(body: Uint8Array | null) {
  const gateway = await listen((_request, response) => {
    if (body === null) {
      response.writeHead(404)
      return response.end()
    }
    response.writeHead(200, { 'content-type': 'application/vnd.ipld.raw' })
    response.end(body)
  })
  const port = new URL(gateway).port
  const router = await listen((request, response) => {
    if (!request.url?.startsWith('/routing/v1/providers/')) {
      response.writeHead(404)
      return response.end()
    }
    response.writeHead(200, { 'content-type': 'application/json' })
    response.end(
      JSON.stringify({
        Providers: [
          {
            Schema: 'peer',
            ID: '12D3KooWBxDK8Bq8wXxxx5x2mzcs1pUP9W6exq5sbgC3f4uwYj2e',
            Addrs: [`/ip4/127.0.0.1/tcp/${port}/http`],
            Protocols: ['transport-ipfs-gateway-http'],
          },
        ],
      })
    )
  })
  return { routers: [router], allowInsecure: true, allowLocal: true }
}

async function readAll(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  const reader = stream.getReader()
  const parts: Uint8Array[] = []
  for (;;) {
    const { done, value } = await reader.read()
    if (done) return new Uint8Array(await new Blob(parts as BlobPart[]).arrayBuffer())
    parts.push(value)
  }
}

describe('content source over delegated routing', () => {
  const cid = async () => CID.createV1(raw.code, await sha256.digest(bytes))

  it('finds the provider through the router and serves a verified range', async () => {
    const source = await openContentSource(await cid(), await harness(bytes))
    expect(source.size).toBe(750)
    expect(await readAll(await source.openRange(1, 100))).toEqual(bytes.subarray(1, 101))
  })

  it('rejects a block whose bytes do not hash to the CID', async () => {
    const tampered = new Uint8Array(bytes)
    tampered[100] ^= 0xff
    await expect(openContentSource(await cid(), await harness(tampered))).rejects.toBeInstanceOf(NotAvailableError)
  })

  it('reports a share with no reachable block as not available', async () => {
    await expect(openContentSource(await cid(), await harness(null))).rejects.toBeInstanceOf(NotAvailableError)
  })
})
