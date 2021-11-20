const crypto = require('hypercore-crypto')
const curve = require('noise-curve-ristretto')
const Noise = require('noise-handshake')

const EMPTY = Buffer.alloc(0)

module.exports = class Handshake {
  constructor (isInitiator, keyPair, remotePublicKey, pattern) {
    this.isInitiator = isInitiator
    this.keyPair = keyPair
    this.noise = new Noise(pattern, isInitiator, keyPair, { curve })
    this.noise.initialise(EMPTY, remotePublicKey)
    this.destroyed = false
  }

  static keyPair (seed) {
    return crypto.keyPair(seed)
  }

  recv (data) {
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
  send () {
    try {
      const data = this.noise.send()
      const wrap = Buffer.allocUnsafe(data.byteLength + 3)

      writeUint24le(data.byteLength, wrap)
      wrap.set(data, 3)

      return this._return(wrap)
    } catch {
      this.destroy()
      return null
    }
  }

  destroy () {
    if (this.destroyed) return
    this.destroyed = true
  }

  _return (data) {
    const tx = this.noise.complete ? toBuffer(this.noise.tx) : null
    const rx = this.noise.complete ? toBuffer(this.noise.rx) : null
    const hash = this.noise.complete ? toBuffer(this.noise.hash) : null
    const remotePublicKey = this.noise.complete ? toBuffer(this.noise.rs) : null

    return {
      data,
      remotePublicKey,
      hash,
      tx,
      rx
    }
  }
}

function writeUint24le (n, buf) {
  buf[0] = (n & 255)
  buf[1] = (n >>> 8) & 255
  buf[2] = (n >>> 16) & 255
}

function toBuffer (uint) {
  return Buffer.from(uint.buffer, uint.byteOffset, uint.byteLength)
}
