const b4a = require('b4a')
const { randomBytes } = require('crypto')
const pq = require('noise-handshake/pq')

const EMPTY = b4a.alloc(0)
const DEFAULT_PATTERN = 'pqXX'
const PqNoise = pq.default || pq.PqNoise

module.exports = class Handshake {
  constructor(isInitiator, keyPair, remotePublicKey, pattern, pqOpts) {
    this.isInitiator = isInitiator
    this.keyPair = keyPair
    this.noise = new PqNoise(pattern || DEFAULT_PATTERN, isInitiator, keyPair, pqOpts)
    this.noise.initialise(EMPTY, remotePublicKey)
    this.destroyed = false
  }

  static create(isInitiator, keyPair, remotePublicKey, pattern, opts = {}) {
    const pqOpts = toPqOpts(opts)

    if (!keyPair) {
      keyPair = this._generateKeyPair(pqOpts.skem || pqOpts.kem)
    } else {
      validateKeyPair(keyPair, pqOpts.skem || pqOpts.kem)
      keyPair = {
        publicKey: b4a.from(keyPair.publicKey),
        secretKey: b4a.from(keyPair.secretKey)
      }
    }

    if (remotePublicKey) validateRemotePublicKey(remotePublicKey, pqOpts.skem || pqOpts.kem)
    return new Handshake(isInitiator, keyPair, remotePublicKey, pattern, pqOpts)
  }

  static keyPair(seed, opts = {}) {
    const pqOpts = toPqOpts(opts)
    const kemSpec = pqOpts.skem || pqOpts.kem
    const kem = getKem(kemSpec)
    const lengths = kem.lengths || {}

    if (seed) {
      if (!b4a.isBuffer(seed)) seed = b4a.from(seed)
      if (typeof lengths.seed === 'number' && seed.byteLength !== lengths.seed) {
        throw new Error(
          'Invalid seed byte length for selected KEM. Expected ' +
            lengths.seed +
            ' bytes, got ' +
            seed.byteLength
        )
      }
      return this._generateKeyPair(kemSpec, seed)
    }

    return this._generateKeyPair(kemSpec)
  }

  static _generateKeyPair(kemSpec, seed) {
    const kem = getKem(kemSpec)
    const lengths = kem.lengths || {}
    const randomSeed = seed || randomBytes(lengths.seed || 64)
    const keyPair = kem.keygen(randomSeed)
    return {
      publicKey: b4a.from(keyPair.publicKey),
      secretKey: b4a.from(keyPair.secretKey)
    }
  }

  recv(data) {
    try {
      this.noise.recv(data)
      if (this.noise.complete) return this._return(null)
      return this.send()
    } catch {
      this.destroy()
      return null
    }
  }

  // note that the data returned here is framed so we don't have to do an extra copy
  // when sending it...
  send() {
    try {
      const data = this.noise.send()
      const wrap = b4a.allocUnsafe(data.byteLength + 3)

      writeUint24le(data.byteLength, wrap)
      wrap.set(data, 3)

      return this._return(wrap)
    } catch {
      this.destroy()
      return null
    }
  }

  destroy() {
    if (this.destroyed) return
    this.destroyed = true
  }

  _return(data) {
    const tx = this.noise.complete ? b4a.toBuffer(this.noise.tx) : null
    const rx = this.noise.complete ? b4a.toBuffer(this.noise.rx) : null
    const hash = this.noise.complete ? b4a.toBuffer(this.noise.hash) : null
    const remotePublicKey = this.noise.complete ? b4a.toBuffer(this.noise.rs) : null

    return {
      data,
      remotePublicKey,
      hash,
      tx,
      rx
    }
  }
}

function writeUint24le(n, buf) {
  buf[0] = n & 255
  buf[1] = (n >>> 8) & 255
  buf[2] = (n >>> 16) & 255
}

function toPqOpts(opts) {
  const pqOpts = {
    kem: opts.kem || pq.MLKEM512
  }

  if (opts.ekem) pqOpts.ekem = opts.ekem
  if (opts.skem) pqOpts.skem = opts.skem
  if (opts.cipher) pqOpts.cipher = opts.cipher
  if (opts.hash) pqOpts.hash = opts.hash
  if (opts.psk) pqOpts.psk = opts.psk
  if (opts.psks) pqOpts.psks = opts.psks
  if (opts.rng) pqOpts.rng = opts.rng

  return pqOpts
}

function getKem(kemSpec) {
  if (
    !kemSpec ||
    typeof kemSpec !== 'object' ||
    !kemSpec.kem ||
    typeof kemSpec.kem.keygen !== 'function'
  ) {
    throw new Error('Invalid KEM configuration. Expected an object with a .kem.keygen function.')
  }
  return kemSpec.kem
}

function validateRemotePublicKey(remotePublicKey, kemSpec) {
  const kem = getKem(kemSpec)
  const expected = kem.lengths?.publicKey
  if (!b4a.isBuffer(remotePublicKey)) remotePublicKey = b4a.from(remotePublicKey)
  if (typeof expected === 'number' && remotePublicKey.byteLength !== expected) {
    throw new Error(
      'Invalid remotePublicKey byte length for selected KEM. Expected ' +
        expected +
        ' bytes, got ' +
        remotePublicKey.byteLength
    )
  }
}

function validateKeyPair(keyPair, kemSpec) {
  const kem = getKem(kemSpec)
  const lengths = kem.lengths || {}

  if (!keyPair || keyPair.publicKey === undefined || keyPair.secretKey === undefined) {
    throw new Error('Invalid keyPair. Expected { publicKey, secretKey }.')
  }

  const publicKey = b4a.isBuffer(keyPair.publicKey)
    ? keyPair.publicKey
    : b4a.from(keyPair.publicKey)
  const secretKey = b4a.isBuffer(keyPair.secretKey)
    ? keyPair.secretKey
    : b4a.from(keyPair.secretKey)

  if (typeof lengths.publicKey === 'number' && publicKey.byteLength !== lengths.publicKey) {
    throw new Error(
      'Invalid keyPair.publicKey byte length for selected KEM. Expected ' +
        lengths.publicKey +
        ' bytes, got ' +
        publicKey.byteLength
    )
  }

  if (typeof lengths.secretKey === 'number' && secretKey.byteLength !== lengths.secretKey) {
    throw new Error(
      'Invalid keyPair.secretKey byte length for selected KEM. Expected ' +
        lengths.secretKey +
        ' bytes, got ' +
        secretKey.byteLength
    )
  }
}
