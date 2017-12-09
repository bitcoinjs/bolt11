'use strict'
let tape = require('tape')
let fixtures = require('./fixtures')
let lnpayreq = require('../')

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

    decoded['privateKey'] = f.privateKey
    let encodedWithPriv = lnpayreq.encode(decoded)

    t.same(f.paymentRequest, encodedNoPriv)
    t.same(f.paymentRequest, encodedWithPriv)

    t.end()
  })
})

fixtures.decode.invalid.forEach((f) => {
  tape(`test vectors`, (t) => {
    t.plan(1)

    t.throws(() => {
      lnpayreq.decode(f.paymentRequest)
    }, new Error(f.error))
  })
})
