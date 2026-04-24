# @hyperswarm/secret-stream

### [See the full API docs at docs.pears.com](https://docs.pears.com/helpers/secretstream)

Secret stream backed by PQ Noise and libsodium's secretstream.

```
npm install @hyperswarm/secret-stream
```

## Usage

You can either make a secret stream from an existing transport stream.

```js
const SecretStream = require('@hyperswarm/secret-stream')

const a = new SecretStream(true, tcpClientStream)
const b = new SecretStream(false, tcpServerStream)

// pipe the underlying rawstreams together

a.write(Buffer.from('hello encrypted!'))

b.on('data', function (data) {
  console.log(data) // <Buffer hello encrypted!>
})
```

Or by making your own pipeline

```js
const a = new SecretStream(true)
const b = new SecretStream(false)

// pipe the underlying rawstreams together
a.rawStream.pipe(b.rawStream).pipe(a.rawStream)

a.write(Buffer.from('hello encrypted!'))

b.on('data', function (data) {
  console.log(data) // <Buffer hello encrypted!>
})
```

## API

#### `const s = new SecretStream(isInitiator, [rawStream], [options])`

Make a new stream. `isInitiator` is a boolean indication whether you are the client or the server.
`rawStream` can be set to an underlying transport stream you want to run the noise stream over.

Options include:

```js
{
  pattern: 'pqXX', // which PQ noise pattern to use (must start with pq)
  remotePublicKey, // static KEM public key if your handshake requires it
  keyPair: { publicKey, secretKey },
  kem, // defaults to MLKEM512 (@lukeburns/noise-handshake/pq preset)
  ekem, // optional KEM override for ephemeral keys
  skem, // optional KEM override for static keys
  cipher, // optional @lukeburns/noise-handshake/pq cipher override
  hash, // optional @lukeburns/noise-handshake/pq hash override
  psk, // optional 32-byte PSK
  psks, // optional array of 32-byte PSKs
  handshake: { // if you want to use an handshake performed elsewhere pass it here
    tx,
    rx,
    hash,
    publicKey,
    remotePublicKey
  },
  enableSend: true // (advanced) set false to disable the send API
}
```

The SecretStream returned is a Duplex stream that you use as as normal stream, to write/read data from,
except it's payloads are encrypted using the libsodium secretstream.

The built-in handshake is PQ-only and uses ML-KEM key material. Classical Noise (curve-ed) peers are not wire-compatible.

If you need to load the key pair asynchronously, then secret-stream also supports passing in a promise
instead of the keypair that later resolves to `{ publicKey, secretKey }`. The stream lifecycle will wait
for the resolution and auto destroy the stream if the promise errors.

When `pattern` requires a pre-shared static key (for example `pqIK`), `remotePublicKey` must be a static KEM public key for the selected `skem`/`kem`.

## Migrating from classical to PQ

If you are migrating an existing setup, the simplest mental model is:

- `XX` becomes `pqXX`
- `keyPair` is still `{ publicKey, secretKey }`, but now it is ML-KEM key material
- everything else (stream wiring, read/write flow) stays the same

Before (classical):

```js
const SecretStream = require('@hyperswarm/secret-stream')

const aKeyPair = SecretStream.keyPair()
const bKeyPair = SecretStream.keyPair()

const a = new SecretStream(true, aRaw, {
  pattern: 'XX',
  keyPair: aKeyPair
})

const b = new SecretStream(false, bRaw, {
  pattern: 'XX',
  keyPair: bKeyPair
})
```

After (post-quantum):

```js
const SecretStream = require('@hyperswarm/secret-stream')

const aKeyPair = await SecretStream.keyPair()
const bKeyPair = await SecretStream.keyPair()

const a = new SecretStream(true, aRaw, {
  pattern: 'pqXX',
  keyPair: aKeyPair
})

const b = new SecretStream(false, bRaw, {
  pattern: 'pqXX',
  keyPair: bKeyPair
})
```

If you persist long-term identity keys, persist and reuse the new PQ keypairs just like you did before.

#### `s.start(rawStream, [options])`

Start a SecretStream from a rawStream asynchrously.

```js
const s = new SecretStream({
  autoStart: false // call start manually
})

// ... do async stuff or destroy the stream

s.start(rawStream, {
  ... options from above
})
```

#### `s.setTimeout(ms)`

Set the stream timeout. If no data is received within a `ms` window,
the stream is auto destroyed.

#### `s.setKeepAlive(ms)`

Send a heartbeat (empty message) every time the socket is idle for `ms` milliseconds. **Note:** If one side calls `s.setKeepAlive()` and the other does not, then the empty messages will be passed through to the piped stream.

#### `s.publicKey`

Get the local public key.

#### `s.remotePublicKey`

Get the remote's public key.
Populated after `open` is emitted.

#### `s.handshakeHash`

Get the unique hash of this handshake.
Populated after `open` is emitted.

#### `s.keepAlive`

Get the interval (in milliseconds) at which keep-alive messages are sent (0 means none are sent).

#### `s.sendKeepAlive()`

A convenience method that sends an empty message.

#### `s.rawBytesWritten`

The number of bytes (measured after encryption) written.

#### `s.rawBytesRead`

The number of bytes (measured before decryption) received.

#### `s.on('connect', onconnect)`

Emitted when the handshake is fully done.
It is safe to write to the stream immediately though, as data is buffered
internally before the handshake has been completed.

#### `await s.send(buffer)`

Sends an encrypted unordered message, see [udx-native](https://github.com/holepunchto/udx-native/tree/main?tab=readme-ov-file#await-streamsendbuffer) for details.  
This method with silently fail if called before handshake is complete or if the underlying rawStream is not an UDX-stream (not capable of UDP).

#### `s.trySend(buffer)`

Same as `send(buffer)` but does not return a promise.

#### `s.on('message', onmessage)`

Emmitted when an unordered message is received

#### `keyPair = await SecretStream.keyPair([seed], [options])`

Generate a static KEM key pair for PQ handshakes.

`options` can include `{ kem, skem }` so key generation matches the selected handshake KEM.

## License

Apache-2.0
