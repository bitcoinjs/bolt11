'use strict'
let tape = require('tape')
let fixtures = require('./fixtures')
let lnpayreq = require('../')

fixtures.decode.valid.forEach((f) => {

  tape(`test vectors`, (t) => {
    t.plan(6)

    let decoded = lnpayreq.decode(f.paymentRequest)

    t.same(decoded.coinType, f.coinType)
    t.same(decoded.satoshis, f.satoshis)
    t.same(decoded.timestamp, f.timestamp)
    t.same(decoded.timestampString, f.timestampString)
    t.same(decoded.payeeNodeKey, f.payeeNodeKey)
    t.same(decoded.tags, f.tags)
  })

})

fixtures.decode.invalid.forEach((f) => {

  tape(`test vectors`, (t) => {
    t.plan(1)

    t.throws(() =>{
      let decoded = lnpayreq.decode(f.paymentRequest)
    }, new Error(f.error))
  })

})
