# aes-cbc-partial-decrypt
In CBC mode, the only thing needed to decrypt a specific block, is the ciphertext, key and previous ciphertext (to use as IV).

![CBC mode](https://upload.wikimedia.org/wikipedia/commons/thumb/2/2a/CBC_decryption.svg/601px-CBC_decryption.svg.png)

This library takes advantage of that, and implements partial decryption for AES-CBC with 128, 192 or 256 key length. Although other algorithms should be possible to implement as well.

It creates a stream that can be read, and will emit the resource decrypted from byte `start` to byte `end` (inclusive) specified.

# How to use
```javascript
var PartialDecryptStream = require('cbc-partial-decrypt')

var opts = {
  mode: 'aes-cbc-256', // which encryption algorithm and mode to use, passed directly to internal decipher
  keyLength: 256, // They keylength to use, to generate the Buffer version if password as a string is used
  password: 'password', // The password to use, either text or Buffer
  iv: 'd', // optional: initial IV with which the file was encrypted. If blank, the default one will be used
  start: 0, // optional: first byte to receive. Default 0
  end: 250, // optional: last byte to receive, included. Default until end of file
  // Function that should have the same signature as fs.createReadStream, and should
  // return a stream that reads the resource to decrypt. opts will have `start` and `end`.
  // They will be different to the ones above, as this function will require the resource needed
  // to also get the IV, and handles the blocksize of AES, so every part can be properly decrypted
  encrypted: function (opts) {
    return fs.createReadStream('path', opts)
  }
}

var partialDecrypt = new PartialDecryptStream(opts)
partialDecrypt.pipe(process.stdout)
```

# Notes
## Specify end byte
This library uses `setAutoPadding(false)` on the internal `crypto.createDecipheriv()`, so it is recommended to know the **original** size of the
resource, and use it as `end` when reading until the end of the file, as the default `padding` will be emitted as data as well, unless cut out.

## Non-stream mode
The library only offers to return back a stream, but the method should work aswell done synchronously with a part of the resource. Happy to accept PR with this functionality.

## Other algorithms
As CBC is the block mode, but not the algoritmh itself, it should also be possible to implement this method with different cryptographic algorithms. Happy to accept PR with this functionality.
