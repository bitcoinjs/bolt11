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
// The tags array output can be parsed into an object using the getTagsObject function (see below)
var decoded = lightningPayReq.decode('lnbc20u1pvjluezhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfppqw508d6qejxtdg4y5r3zarvary0c5xw7kxqrrsssp5m6kmam774klwlh4dhmhaatd7al02m0h0m6kmam774klwlh4dhmhs9qypqqqcqpf3cwux5979a8j28d4ydwahx00saa68wq3az7v9jdgzkghtxnkf3z5t7q5suyq2dl9tqwsap8j0wptc82cpyvey9gf6zyylzrm60qtcqsq7egtsq')
/* decoded == below
{
  "complete": true,
  "millisatoshis": "2000000",
  "network": {
    "bech32": "bc",
    "pubKeyHash": 0,
    "scriptHash": 5,
    "validWitnessVersions": [0, 1]
  },
  "payeeNodeKey": "03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad",
  "paymentRequest": "lnbc20u1pvjluezhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfppqw508d6qejxtdg4y5r3zarvary0c5xw7kxqrrsssp5m6kmam774klwlh4dhmhaatd7al02m0h0m6kmam774klwlh4dhmhs9qypqqqcqpf3cwux5979a8j28d4ydwahx00saa68wq3az7v9jdgzkghtxnkf3z5t7q5suyq2dl9tqwsap8j0wptc82cpyvey9gf6zyylzrm60qtcqsq7egtsq",
  "prefix": "lnbc20u",
  "recoveryFlag": 0,
  "satoshis": 2000,
  "signature": "8e1dc350be2f4f251db5235ddb99ef877ba3b811e8bcc2c9a81591759a764c4545f81487080537e5581d0e84f27b82bc1d580919921509d0884f887bd3c0bc02",
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
    },
    {
      "tagName": "expire_time",
      "data": 3600
    },
    {
      "tagName": "payment_secret",
      "data": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    },
    {
      "tagName": "feature_bits",
      "data": {
        "word_length": 4,
        "option_data_loss_protect": {
          "required": false,
          "supported": false
        },
        "initial_routing_sync": {
          "required": false,
          "supported": false
        },
        "option_upfront_shutdown_script": {
          "required": false,
          "supported": false
        },
        "gossip_queries": {
          "required": false,
          "supported": false
        },
        "var_onion_optin": {
          "required": false,
          "supported": false
        },
        "gossip_queries_ex": {
          "required": false,
          "supported": false
        },
        "option_static_remotekey": {
          "required": false,
          "supported": false
        },
        "payment_secret": {
          "required": false,
          "supported": true
        },
        "basic_mpp": {
          "required": false,
          "supported": false
        },
        "option_support_large_channel": {
          "required": false,
          "supported": false
        },
        "extra_bits": {
          "start_bit": 20,
          "bits": [],
          "has_required": false
        }
      }
    },
    {
      "tagName": "min_final_cltv_expiry",
      "data": 9
    }
  ],
  "timeExpireDate": 1496318258,
  "timeExpireDateString": "2017-06-01T11:57:38.000Z",
  "timestamp": 1496314658,
  "timestampString": "2017-06-01T10:57:38.000Z",
  "wordsTemp": "temp1pvjluezhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfppqw508d6qejxtdg4y5r3zarvary0c5xw7kxqrrsssp5m6kmam774klwlh4dhmhaatd7al02m0h0m6kmam774klwlh4dhmhs9qypqqqcqpf3cwux5979a8j28d4ydwahx00saa68wq3az7v9jdgzkghtxnkf3z5t7q5suyq2dl9tqwsap8j0wptc82cpyvey9gf6zyylzrm60qtcqsq5xx76e"
}
*/
```

### Get tags as an object
```javascript
// decoded is from above
var tagsObject = lightningPayReq.getTagsObject(decoded.tags)
/*
{
  "purpose_commit_hash": "3925b6f67e2c340036ed12093dd44e0368df1b6ea26c53dbe4811f58fd5db8c1",
  "payment_hash": "0001020304050607080900010203040506070809000102030405060708090102",
  "fallback_address": {
    "code": 0,
    "address": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
    "addressHash": "751e76e8199196d454941c45d1b3a323f1433bd6"
  },
  "expire_time": 3600,
  "payment_secret": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "feature_bits": {
    "word_length": 4,
    "option_data_loss_protect": {
      "required": false,
      "supported": false
    },
    "initial_routing_sync": {
      "required": false,
      "supported": false
    },
    "option_upfront_shutdown_script": {
      "required": false,
      "supported": false
    },
    "gossip_queries": {
      "required": false,
      "supported": false
    },
    "var_onion_optin": {
      "required": false,
      "supported": false
    },
    "gossip_queries_ex": {
      "required": false,
      "supported": false
    },
    "option_static_remotekey": {
      "required": false,
      "supported": false
    },
    "payment_secret": {
      "required": false,
      "supported": true
    },
    "basic_mpp": {
      "required": false,
      "supported": false
    },
    "option_support_large_channel": {
      "required": false,
      "supported": false
    },
    "extra_bits": {
      "start_bit": 20,
      "bits": [],
      "has_required": false
    }
  },
  "min_final_cltv_expiry": 9
}
*/
```

### Warning
The `"satoshis"` field will only be set if the invoice is for a whole number of satoshis. If it is in a fractional number of satoshis, the `"millisatoshis"` field must be used. 1000 millisatoshis is 1 satoshi.

### Encoding
* MINIMUM NEED: `privateKey` and one `payment_hash` tag as well as one `description`
  * (`timestamp` defaults to current time, `description` defaults to empty string,
    and `network` defaults to bitcoin mainnet)
* Alternatively: You can pass the result of decode into encode and it will use the
signature and recoveryFlag attributes to reconstruct the payment request. In this
case you will require also `network` and `timestamp` as well as all tags in the
exact order of the original signed request.
  * It is also required to pass the `payeeNodeKey` attribute when encoding an
  already signed request, as decoders will recover the pubkey, any incorrect data
  would cause an incorrect pubkey to be generated and will cause an error on the
  decoding end when trying to send.
* Note: tag order matters. The message is signed, so to maintain tag order it is
  an array type.

``` javascript
var encoded = lightningPayReq.encode({
  "network": {
    "bech32": "bc",
    "pubKeyHash": 0,
    "scriptHash": 5,
    "validWitnessVersions": [0, 1]
  },
  "satoshis": 2000,
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
    },
    {
      "tagName": "expire_time",
      "data": 3600
    },
    {
      "tagName": "payment_secret",
      "data": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    },
    {
        "tagName": "feature_bits",
        "data": {
          "payment_secret": {
            "required": false,
            "supported": true
          }
        }
    }
  ]
})
// sign takes the encoded object and the private key as arguments
var privateKeyHex = 'e126f68f7eafcc8b74f54d269fe206be715000f94dac067d1c04a8ca3b2db734'
var signed = lightningPayReq.sign(encoded, privateKeyHex)
/* signed.paymentRequest == below
lnbc20u1pvjluezhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfppqw508d6qejxtdg4y5r3zarvary0c5xw7kxqrrsssp5m6kmam774klwlh4dhmhaatd7al02m0h0m6kmam774klwlh4dhmhs9qypqqqcqpf3cwux5979a8j28d4ydwahx00saa68wq3az7v9jdgzkghtxnkf3z5t7q5suyq2dl9tqwsap8j0wptc82cpyvey9gf6zyylzrm60qtcqsq7egtsq
*/
```

## Browser Use
You can use this in the browser. First install browserify and uglify-es (uglifyjs for ES6+) globally.

``` bash
npm install -g browserify uglify-es
```

Then run the command.

``` bash
browserify -r bolt11 --standalone lightningPayReq | uglifyjs -c -m -o bolt11.min.js
```

Now load bolt11.min.js into an HTML page like so:

``` HTML
<script src="./js/bolt11.min.js"></script>
```

And now you can do all the examples above in a browser using the global
`lightningPayReq` object.

## Contributing
We are always accepting of pull requests, but we do adhere to specific standards in regards to coding style, test driven development and commit messages.

Please make your best effort to adhere to these when contributing to save on trivial corrections.


### Running the test suite

``` bash
npm test
npm run-script coverage
```


## LICENSE [MIT](LICENSE)
