'use strict'
let tape = require('tape')
let fixtures = require('./fixtures')
let lnpayreq = require('../')
let BN = require('bn.js')

fixtures.satToHrp.valid.forEach((f) => {
  tape(`test valid satoshi to hrp string`, (t) => {
    t.plan(1)
    t.same(f.output, lnpayreq.satToHrp(new BN(f.input, 10)))
  })
})

fixtures.millisatToHrp.valid.forEach((f) => {
  tape(`test valid millisatoshi to hrp string`, (t) => {
    t.plan(1)
    t.same(f.output, lnpayreq.millisatToHrp(new BN(f.input, 10)))
  })
})

fixtures.satToHrp.invalid.forEach((f) => {
  tape(`test invalid satoshi to hrp string`, (t) => {
    t.plan(1)
    t.throws(() => {
      lnpayreq.satToHrp(f.input)
    }, new RegExp(f.error))
  })
})

fixtures.millisatToHrp.invalid.forEach((f) => {
  tape(`test invalid millisatoshi to hrp string`, (t) => {
    t.plan(1)
    t.throws(() => {
      lnpayreq.millisatToHrp(f.input)
    }, new RegExp(f.error))
  })
})

fixtures.hrpToSat.valid.forEach((f) => {
  tape(`test valid hrp string to satoshi`, (t) => {
    t.plan(1)
    t.same(f.output, lnpayreq.hrpToSat(f.input).toString())
  })
})

fixtures.hrpToMillisat.valid.forEach((f) => {
  tape(`test valid hrp string to millisatoshi`, (t) => {
    t.plan(1)
    t.same(f.output, lnpayreq.hrpToMillisat(f.input).toString())
  })
})

fixtures.hrpToSat.invalid.forEach((f) => {
  tape(`test invalid hrp string to satoshi`, (t) => {
    t.plan(1)
    t.throws(() => {
      lnpayreq.hrpToSat(f.input)
    }, new RegExp(f.error))
  })
})

fixtures.hrpToMillisat.invalid.forEach((f) => {
  tape(`test invalid hrp string to millisatoshi`, (t) => {
    t.plan(1)
    t.throws(() => {
      lnpayreq.hrpToMillisat(f.input)
    }, new RegExp(f.error))
  })
})

fixtures.sign.invalid.forEach((f) => {
  tape(`test invalid vectors for sign`, (t) => {
    t.plan(1)

    let privateKey = f.privateKey
      ? Buffer.from(f.privateKey, 'hex')
      : Buffer.from(fixtures.privateKey, 'hex')

    t.throws(() => {
      lnpayreq.sign(f.data, privateKey)
    }, new RegExp(f.error))
  })
})

fixtures.encode.valid.forEach((f) => {
  tape(`test valid vectors for encode`, (t) => {
    let encoded = lnpayreq.encode(f.data)

    let signedData = lnpayreq.sign(encoded, fixtures.privateKey)

    t.same(signedData.complete, true)

    let tagPayeeNodeKey = signedData.tags.filter(item => item.tagName === 'payee_node_key')
    if (tagPayeeNodeKey.length > 0) {
      tagPayeeNodeKey = tagPayeeNodeKey[0]
      t.same(tagPayeeNodeKey, signedData.payeeNodeKey)
    }

    t.end()
  })
})

fixtures.encode.invalid.forEach((f) => {
  tape(`test invalid vectors for encode`, (t) => {
    t.plan(1)

    t.throws(() => {
      lnpayreq.encode(f.data, f.addDefaults)
    }, new RegExp(f.error))
  })
})

fixtures.decode.valid.forEach((f) => {
  tape(`test valid vectors for decode`, (t) => {
    let decoded = lnpayreq.decode(f.paymentRequest)

    t.same(f, decoded)

    let tagPayeeNodeKey = decoded.tags.filter(item => item.tagName === 'payee_node_key')
    if (tagPayeeNodeKey.length > 0) {
      tagPayeeNodeKey = tagPayeeNodeKey[0]
      t.same(tagPayeeNodeKey, decoded.payeeNodeKey)
    }

    t.end()
  })

  tape(`test valid decode reverse encode without privateKey then with privateKey`, (t) => {
    let decoded = lnpayreq.decode(f.paymentRequest)
    let encodedNoPriv = lnpayreq.encode(decoded)

    delete decoded['signature']
    delete decoded['recoveryFlag']

    let encodedWithPrivObj = lnpayreq.encode(decoded, false)

    delete encodedWithPrivObj['payeeNodeKey']

    let signedData = lnpayreq.sign(encodedWithPrivObj, fixtures.privateKey)

    let encodedSignedData = lnpayreq.encode(signedData, false)

    encodedWithPrivObj.payeeNodeKey = signedData.payeeNodeKey

    let signedData2 = lnpayreq.sign(encodedWithPrivObj, fixtures.privateKey)

    let signedData3 = lnpayreq.sign(signedData2, fixtures.privateKey)

    t.same(f, encodedNoPriv)
    t.same(f, signedData)
    t.same(f, encodedSignedData)
    t.same(f, signedData2)
    t.same(f, signedData3)

    t.end()
  })
})

fixtures.decode.invalid.forEach((f) => {
  tape(`test invalid vectors for decode`, (t) => {
    t.plan(1)

    t.throws(() => {
      lnpayreq.decode(f.paymentRequest)
    }, new RegExp(f.error))
  })
})

// edge cases

function tagsItems (tags, tagName) {
  let tag = tags.filter(item => item.tagName === tagName)
  let data = tag.length > 0 ? tag[0].data : null
  return data
}

function tagsContainItem (tags, tagName) {
  return tagsItems(tags, tagName) !== null
}

tape(`encode adds defaults by default`, (t) => {
  let encoded = lnpayreq.encode({
    tags: [
      {
        tagName: 'payment_hash',
        data: '100102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f'
      }
    ]
  })

  t.ok(encoded.timestamp !== undefined)
  t.ok(encoded.coinType !== undefined)
  t.ok(tagsContainItem(encoded.tags, 'description'))
  t.ok(tagsContainItem(encoded.tags, 'expire_time'))
  t.ok(tagsContainItem(encoded.tags, 'min_final_cltv_expiry'))

  t.end()
})
