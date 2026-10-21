// Browser console WebSocket client. Speaks the panel's frame protocol (JSON; binary terminal data
// and file chunks are base64). The session cookie rides the same-origin upgrade automatically; the
// one-time step-up grant is passed as a query param.

function b64encode(bytes) {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin)
}
function b64decodeToBytes(s) {
  const bin = atob(s)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

const enc = new TextEncoder()

export class ConsoleSocket {
  constructor(opts) {
    this.opts = opts // {machine, grant, session, cols, rows, onData, onExit, onError, onFileChunk, onFileList, onOpen, onClose}
    this.ws = null
    this.closedByUs = false
    this._fileBufs = new Map() // path -> array of Uint8Array (downloads)
  }

  connect() {
    const { machine, grant, session, cols, rows } = this.opts
    const proto = location.protocol === 'https:' ? 'wss' : 'ws'
    const qs = new URLSearchParams({ machine, grant, session, cols: String(cols || 80), rows: String(rows || 24) })
    const ws = new WebSocket(`${proto}://${location.host}/api/fleet/console/ws?${qs}`)
    this.ws = ws
    ws.onopen = () => this.opts.onOpen?.()
    ws.onclose = () => { if (!this.closedByUs) this.opts.onClose?.() }
    ws.onerror = () => this.opts.onError?.('connection error')
    ws.onmessage = (ev) => this._onFrame(JSON.parse(ev.data))
  }

  _onFrame(f) {
    switch (f.t) {
      case 'data':
        if (f.data) this.opts.onData?.(b64decodeToBytes(f.data))
        break
      case 'session-exit':
        this.opts.onExit?.(f.msg || '')
        break
      case 'error':
        this.opts.onError?.(f.msg || 'error')
        break
      case 'file-chunk':
        this._onFileChunk(f)
        break
      case 'file-list-result':
        this.opts.onFileList?.(f.path, f.items || [])
        break
      case 'pong': {
        const latency = f.ts ? Math.max(0, Date.now() - f.ts) : null
        this.opts.onPong?.(latency, f.cwd || '')
        break
      }
    }
  }

  // ping measures round-trip latency and fetches the session's cwd (reply via onPong).
  ping() {
    this._send({ t: 'ping', session: this.opts.session, ts: Date.now() })
  }

  _onFileChunk(f) {
    if (f.data) {
      const arr = this._fileBufs.get(f.path) || []
      arr.push(b64decodeToBytes(f.data))
      this._fileBufs.set(f.path, arr)
    }
    if (f.eof) {
      const arr = this._fileBufs.get(f.path) || []
      this._fileBufs.delete(f.path)
      this.opts.onFileChunk?.(f.path, arr, f.msg)
    }
  }

  _send(frame) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) this.ws.send(JSON.stringify(frame))
  }

  sendInput(str) {
    this._send({ t: 'data', session: this.opts.session, data: b64encode(enc.encode(str)) })
  }

  resize(cols, rows) {
    this._send({ t: 'resize', session: this.opts.session, cols, rows })
  }

  // putFile uploads a File/Blob's bytes to an absolute path on the host, chunked.
  async putFile(path, file) {
    const buf = new Uint8Array(await file.arrayBuffer())
    const chunk = 48 * 1024
    for (let off = 0; off < buf.length; off += chunk) {
      const slice = buf.subarray(off, Math.min(off + chunk, buf.length))
      this._send({ t: 'file-put', session: this.opts.session, path, data: b64encode(slice), eof: off + chunk >= buf.length })
    }
    if (buf.length === 0) this._send({ t: 'file-put', session: this.opts.session, path, eof: true })
  }

  getFile(path) {
    this._send({ t: 'file-get', session: this.opts.session, path })
  }

  // listDir asks the agent for a directory's entries; the reply arrives via onFileList.
  listDir(path) {
    this._send({ t: 'file-list', session: this.opts.session, path })
  }

  close() {
    this.closedByUs = true
    this._send({ t: 'close', session: this.opts.session })
    this.ws?.close()
  }
}

export { b64decodeToBytes }
