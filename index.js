const { Pull, Push, HEADERBYTES, KEYBYTES, ABYTES } = require('sodium-secretstream')
const sodium = require('sodium-universal')
const { Duplex } = require('streamx')
const b4a = require('b4a')
const Bridge = require('./lib/bridge')
const Handshake = require('./lib/handshake')

const IDHEADERBYTES = HEADERBYTES + 32

const slab = b4a.alloc(92)

const NS = slab.subarray(0, 32)
const NS_INITIATOR = slab.subarray(32, 64)
const NS_RESPONDER = slab.subarray(64, 96)

sodium.crypto_generichash(NS, b4a.from('hyperswarm/secret-stream'))
sodium.crypto_generichash(NS_INITIATOR, b4a.from([0]), NS)
sodium.crypto_generichash(NS_RESPONDER, b4a.from([1]), NS)

module.exports = class NoiseSecretStream extends Duplex {
  constructor (isInitiator, rawStream, opts = {}) {
    super()

    this.noiseStream = this
    this.isInitiator = isInitiator
    this.rawStream = null

    this.publicKey = opts.publicKey || null
    this.remotePublicKey = opts.remotePublicKey || null
    this.handshakeHash = null

    // pointer for upstream to set data here if they want
    this.userData = null

    let openedDone = null
    this.opened = new Promise((resolve) => { openedDone = resolve })

    // unwrapped raw stream
    this._rawStream = null

    // handshake state
    this._handshake = null
    this._handshakePattern = opts.pattern || null
    this._handshakeDone = null

    // message parsing state
    this._state = 0
    this._len = 0
    this._tmp = 1
    this._message = null

    this._openedDone = openedDone
    this._startDone = null
    this._drainDone = null
    this._outgoingPlain = null
    this._outgoingWrapped = null
    this._utp = null
    this._setup = true
    this._encrypt = null
    this._decrypt = null

    if (opts.autoStart !== false) this.start(rawStream, opts)

    // wiggle it to trigger open immediately (TODO add streamx option for this)
    this.resume()
    this.pause()
  }

  static keyPair (seed) {
    return Handshake.keyPair(seed)
  }

  static id (handshakeHash, isInitiator, id) {
    return streamId(handshakeHash, isInitiator, id)
  }

  start (rawStream, opts = {}) {
    if (rawStream) {
      this.rawStream = rawStream
      this._rawStream = rawStream
      if (typeof this.rawStream.setContentSize === 'function') {
        this._utp = rawStream
      }
    } else {
      this.rawStream = new Bridge(this)
      this._rawStream = this.rawStream.reverse
    }

    this.rawStream.on('error', this.destroy.bind(this))
    this.rawStream.on('close', this.destroy.bind(this, null))

    this._startHandshake(opts.handshake, opts.keyPair || null)

    if (this._startDone !== null) {
      const done = this._startDone
      this._startDone = null
      this._open(done)
    }

    if (opts.data) this._onrawdata(opts.data)
    if (opts.ended) this._onrawend()
  }

  _startHandshake (handshake, keyPair) {
    if (handshake) {
      const { tx, rx, hash, publicKey, remotePublicKey } = handshake
      this._setupSecretStream(tx, rx, hash, publicKey, remotePublicKey)
      return
    }

    if (!keyPair) keyPair = Handshake.keyPair()
    const pattern = this._handshakePattern || 'XX'
    const remotePublicKey = this.remotePublicKey

    this._handshake = new Handshake(this.isInitiator, keyPair, remotePublicKey, pattern)
    this.publicKey = this._handshake.keyPair.publicKey
  }

  _onrawdata (data) {
    let offset = 0

    do {
      switch (this._state) {
        case 0: {
          while (this._tmp !== 0x1000000 && offset < data.length) {
            const v = data[offset++]
            this._len += this._tmp * v
            this._tmp *= 256
          }

          if (this._tmp === 0x1000000) {
            this._tmp = 0
            this._state = 1
            const unprocessed = data.length - offset
            if (unprocessed < this._len && this._utp !== null) this._utp.setContentSize(this._len - unprocessed)
          }

          break
        }

        case 1: {
          const missing = this._len - this._tmp
          const end = missing + offset

          if (this._message === null && end <= data.length) {
            this._message = data.subarray(offset, end)
            offset += missing
            this._incoming()
            break
          }

          const unprocessed = data.length - offset

          if (this._message === null) {
            this._message = b4a.allocUnsafe(this._len)
          }

          data.copy(this._message, this._tmp, offset)
          this._tmp += unprocessed

          if (end <= data.length) {
            offset += missing
            this._incoming()
          } else {
            offset += unprocessed
          }

          break
        }
      }
    } while (offset < data.length && !this.destroying)
  }

  _onrawend () {
    this.push(null)
  }

  _onrawdrain () {
    const drain = this._drainDone
    if (drain === null) return
    this._drainDone = null
    drain()
  }

  _read (cb) {
    this.rawStream.resume()
    cb(null)
  }

  _incoming () {
    const message = this._message

    this._state = 0
    this._len = 0
    this._tmp = 1
    this._message = null

    if (this._setup === true) {
      if (this._handshake) {
        this._onhandshakert(this._handshake.recv(message))
      } else {
        if (message.byteLength !== IDHEADERBYTES) {
          this.destroy(new Error('Invalid header message received'))
          return
        }

        const remoteId = message.subarray(0, 32)
        const expectedId = streamId(this.handshakeHash, !this.isInitiator)
        const header = message.subarray(32)

        if (!expectedId.equals(remoteId)) {
          this.destroy(new Error('Invalid header received'))
          return
        }

        this._decrypt.init(header)
        this._setup = false // setup is now done
      }
      return
    }

    if (message.length < ABYTES) {
      this.destroy(new Error('Invalid message received'))
      return
    }

    const plain = message.subarray(1, message.byteLength - ABYTES + 1)

    try {
      this._decrypt.next(message, plain)
    } catch (err) {
      this.destroy(err)
      return
    }

    if (this.push(plain) === false) {
      this.rawStream.pause()
    }
  }

  _onhandshakert (h) {
    if (this._handshakeDone === null) return

    if (h !== null) {
      if (h.data) this._rawStream.write(h.data)
      if (!h.tx) return
    }

    const done = this._handshakeDone
    const publicKey = this._handshake.keyPair.publicKey

    this._handshakeDone = null
    this._handshake = null

    if (h === null) return done(new Error('Noise handshake failed'))

    this._setupSecretStream(h.tx, h.rx, h.hash, publicKey, h.remotePublicKey)
    this._resolveOpened(true)
    done(null)
  }

  _setupSecretStream (tx, rx, handshakeHash, publicKey, remotePublicKey) {
    const buf = b4a.allocUnsafe(3 + IDHEADERBYTES)
    writeUint24le(IDHEADERBYTES, buf)

    this._encrypt = new Push(tx.subarray(0, KEYBYTES), undefined, buf.subarray(3 + 32))
    this._decrypt = new Pull(rx.subarray(0, KEYBYTES))

    this.publicKey = publicKey
    this.remotePublicKey = remotePublicKey
    this.handshakeHash = handshakeHash

    const id = buf.subarray(3, 3 + 32)
    streamId(handshakeHash, this.isInitiator, id)

    this.emit('handshake')
    // if rawStream is a bridge, also emit it there
    if (this.rawStream !== this._rawStream) this.rawStream.emit('handshake')

    if (this.destroying) return

    this._rawStream.write(buf)
  }

  _open (cb) {
    if (this._rawStream === null) { // no autostart
      this._startDone = cb
      return
    }

    this._rawStream.on('data', this._onrawdata.bind(this))
    this._rawStream.on('end', this._onrawend.bind(this))
    this._rawStream.on('drain', this._onrawdrain.bind(this))

    if (this._encrypt !== null) {
      this._resolveOpened(true)
      return cb(null)
    }

    this._handshakeDone = cb

    if (this.isInitiator) this._onhandshakert(this._handshake.send())
  }

  _predestroy () {
    if (this._startDone !== null) {
      const done = this._startDone
      this._startDone = null
      done(new Error('Stream destroyed'))
    }

    if (this._handshakeDone !== null) {
      const done = this._handshakeDone
      this._handshakeDone = null
      if (this.rawStream) this.rawStream.destroy()
      done(new Error('Stream destroyed'))
    }

    if (this._drainDone !== null) {
      const done = this._drainDone
      this._drainDone = null
      if (this.rawStream) this.rawStream.destroy()
      done(new Error('Stream destroyed'))
    }
  }

  _write (data, cb) {
    let wrapped = this._outgoingWrapped

    if (data !== this._outgoingPlain) {
      if (typeof data === 'string') data = b4a.from(data)
      wrapped = b4a.allocUnsafe(data.byteLength + 3 + ABYTES)
      wrapped.set(data, 4)
    } else {
      this._outgoingWrapped = this._outgoingPlain = null
    }

    writeUint24le(wrapped.byteLength - 3, wrapped)
    // offset 4 so we can do it in-place
    this._encrypt.next(wrapped.subarray(4, 4 + data.byteLength), wrapped.subarray(3))

    if (this._rawStream.write(wrapped) === false) {
      this._drainDone = cb
    } else {
      cb(null)
    }
  }

  _final (cb) {
    this._rawStream.end()
    cb(null)
  }

  _resolveOpened (val) {
    if (this._openedDone !== null) {
      const opened = this._openedDone
      this._openedDone = null
      opened(val)
      if (val) this.emit('connect')
    }
  }

  _destroy (cb) {
    this._resolveOpened(false)
    const error = this._readableState.error || this._writableState.error
    if (this.rawStream) this.rawStream.destroy(error)
    cb(null)
  }

  alloc (len) {
    const buf = b4a.allocUnsafe(len + 3 + ABYTES)
    this._outgoingWrapped = buf
    this._outgoingPlain = buf.subarray(4, buf.byteLength - ABYTES + 1)
    return this._outgoingPlain
  }
}

function writeUint24le (n, buf) {
  buf[0] = (n & 255)
  buf[1] = (n >>> 8) & 255
  buf[2] = (n >>> 16) & 255
}

function streamId (handshakeHash, isInitiator, out = b4a.allocUnsafe(32)) {
  sodium.crypto_generichash(out, handshakeHash, isInitiator ? NS_INITIATOR : NS_RESPONDER)
  return out
}
