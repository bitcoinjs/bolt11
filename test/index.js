'use strict'
let tape = require('tape')
let fixtures = require('./fixtures')
let lnpayreq = require('../')

fixtures.encode.invalid.forEach((f) => {
  tape(`test vectors`, (t) => {
    t.plan(1)

    t.throws(() => {
      lnpayreq.encode(f.data, f.addDefaults)
    }, new RegExp(f.error))
  })
})


fixtures.decode.valid.forEach((f) => {
  tape(`test vectors`, (t) => {
    let decoded = lnpayreq.decode(f.paymentRequest)

    t.same(decoded.coinType, f.coinType)
    t.same(decoded.satoshis, f.satoshis)
    t.same(decoded.timestamp, f.timestamp)
    t.same(decoded.timestampString, f.timestampString)
    t.same(decoded.payeeNodeKey, f.payeeNodeKey)
    t.same(decoded.signature, f.signature)
    t.same(decoded.recoveryFlag, f.recoveryFlag)
    t.same(decoded.tags, f.tags)

    let tagPayeeNodeKey = decoded.tags.filter(item => item.tagName === 'payee_node_key')
    if (tagPayeeNodeKey.length > 0) {
      tagPayeeNodeKey = tagPayeeNodeKey[0]
      t.same(tagPayeeNodeKey, decoded.payeeNodeKey)
    }

    t.end()
  })

  tape(`test reverse without privateKey then with privateKey`, (t) => {
    let decoded = lnpayreq.decode(f.paymentRequest)
    let encodedNoPriv = lnpayreq.encode(decoded)

    delete decoded['signature']
    delete decoded['recoveryFlag']

    let encodedWithPrivObj = lnpayreq.encode(decoded, false)
    let signedData = lnpayreq.sign(encodedWithPrivObj, Buffer.from(f.privateKey, 'hex'))

    t.same(f.paymentRequest, encodedNoPriv.paymentRequest)
    t.same(f.paymentRequest, signedData.paymentRequest)

    t.end()
  })
})

fixtures.decode.invalid.forEach((f) => {
  tape(`test vectors`, (t) => {
    t.plan(1)

    t.throws(() => {
      lnpayreq.decode(f.paymentRequest)
    }, new RegExp(f.error))
  })
})
