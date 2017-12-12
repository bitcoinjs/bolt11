# bolt11
A library for encoding and decoding lightning network payment requests as defined in [BOLT #11](https://github.com/lightningnetwork/lightning-rfc/blob/master/11-payment-encoding.md).


## Installation
``` bash
npm install bolt11
```

## Setup
### Node.js
``` javascript
var lightningPayReq = require('bolt11')
```


## Examples
### Decoding
``` javascript
var decoded = lightningPayReq.decode('lnbc20m1pvjluezhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfppqw508d6qejxtdg4y5r3zarvary0c5xw7kepvrhrm9s57hejg0p662ur5j5cr03890fa7k2pypgttmh4897d3raaq85a293e9jpuqwl0rnfuwzam7yr8e690nd2ypcq9hlkdwdvycqa0qza8')
/* decoded == below
{
  "coinType": "bitcoin",
  "payeeNodeKey": "03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad",
  "paymentRequest": "lnbc20m1pvjluezhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfppqw508d6qejxtdg4y5r3zarvary0c5xw7kepvrhrm9s57hejg0p662ur5j5cr03890fa7k2pypgttmh4897d3raaq85a293e9jpuqwl0rnfuwzam7yr8e690nd2ypcq9hlkdwdvycqa0qza8",
  "recoveryFlag": 0,
  "satoshis": 2000000,
  "signature": "c8583b8f65853d7cc90f0eb4ae0e92a606f89caf4f7d65048142d7bbd4e5f3623ef407a75458e4b20f00efbc734f1c2eefc419f3a2be6d51038016ffb35cd613",
  "tags": [
    {
      "tagName": "purpose_commit_hash",
      "data": "3925b6f67e2c340036ed12093dd44e0368df1b6ea26c53dbe4811f58fd5db8c1"
    },
    {
      "tagName": "payment_hash",
      "data": "0001020304050607080900010203040506070809000102030405060708090102"
    },
    {
      "tagName": "fallback_address",
      "data": {
        "code": 0,
        "address": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        "addressHash": "751e76e8199196d454941c45d1b3a323f1433bd6"
      }
    }
  ],
  "timestamp": 1496314658,
  "timestampString": "2017-06-01T10:57:38.000Z"
}
*/
```

### Encoding
* MINIMUM NEED: `privateKey` and one `payment_hash` tag as well as one `description`
  * (`timestamp` defaults to current time, `description` defaults to empty string,
    and `coinType` defaults to bitcoin testnet)
  * coinType should be the name of a network object from bitcoinjs-lib
* Alternatively: You can pass the result of decode into encode and it will use the
signature and recoveryFlag attributes to reconstruct the payment request. In this
case you will require also `coinType` and `timestamp` as well as all tags in the
exact order of the original signed request.
  * It is also required to pass the `payeeNodeKey` attribute when encoding an
  already signed request, as decoders will recover the pubkey, any incorrect data
  would cause an incorrect pubkey to be generated and will cause an error on the
  decoding end when trying to send.
* Note: `satoshis` can be defined up to 3 decimal points (ie. `0.001` is the smallest valid
  value for satoshis, as lightning network can deal with millisatoshis)
* Note: tag order matters. The message is signed, so to maintain tag order it is
  an array type.

``` javascript
var encoded = lightningPayReq.encode({
  "coinType": "bitcoin",
  "satoshis": 2000000,
  "timestamp": 1496314658,
  "tags": [
    {
      "tagName": "purpose_commit_hash",
      "data": "3925b6f67e2c340036ed12093dd44e0368df1b6ea26c53dbe4811f58fd5db8c1"
    },
    {
      "tagName": "payment_hash",
      "data": "0001020304050607080900010203040506070809000102030405060708090102"
    },
    {
      "tagName": "fallback_address",
      "data": {
        "address": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
      }
    }
  ]
})
// sign takes the encoded object and the private key buffer as arguments
var signed = lightningPayReq.sign(encoded, Buffer.from('e126f68f7eafcc8b74f54d269fe206be715000f94dac067d1c04a8ca3b2db734','hex'))
/* signed.paymentRequest == below
lnbc20m1pvjluezhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfppqw508d6qejxtdg4y5r3zarvary0c5xw7kxqrrsscqpflsxzqz6h26hyg6dr482sn8nzxc8d455a38hvg38rmam09t0n65nxe58g6x82dygjgvty7dr72rl3h3zwjlc0zzw4a5r29lxsqn9t4rgqzuv4vu
*/
```

## Contributing
We are always accepting of pull requests, but we do adhere to specific standards in regards to coding style, test driven development and commit messages.

Please make your best effort to adhere to these when contributing to save on trivial corrections.


### Running the test suite

``` bash
npm test
npm run-script coverage
```


## LICENSE [MIT](LICENSE)
