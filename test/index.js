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
    let decoded = lnpayreq.decode(f.paymentRequest, f.network)

    if (f.network === undefined) f.network = decoded.network

    t.same(f, decoded)

    let tagPayeeNodeKey = decoded.tags.filter(item => item.tagName === 'payee_node_key')
    if (tagPayeeNodeKey.length > 0) {
      tagPayeeNodeKey = tagPayeeNodeKey[0]
      t.same(tagPayeeNodeKey, decoded.payeeNodeKey)
    }

    t.end()
  })

  tape(`test valid decode reverse encode without privateKey then with privateKey`, (t) => {
    let decoded = lnpayreq.decode(f.paymentRequest, f.network)
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
      lnpayreq.decode(f.paymentRequest, f.network)
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

tape(`decode detects invalid network`, (t) => {
  const f = fixtures.decode.valid[3]
  t.throws(() => {
    lnpayreq.decode(f.paymentRequest, { bech32: 'bc' })
  }, new RegExp('Invalid network'))
  t.end()
})

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
  t.ok(encoded.network !== undefined)
  t.ok(tagsContainItem(encoded.tags, 'description'))
  t.ok(tagsContainItem(encoded.tags, 'expire_time'))
  t.ok(tagsContainItem(encoded.tags, 'min_final_cltv_expiry'))

  t.end()
})

tape(`can decode upper case payment request`, (t) => {
  let decoded = lnpayreq.decode('LNBC2500U1PVJLUEZPP5QQQSYQCYQ5RQWZQFQQQSYQC' +
                                'YQ5RQWZQFQQQSYQCYQ5RQWZQFQYPQDQ5XYSXXATSYP3' +
                                'K7ENXV4JSXQZPUAZTRNWNGZN3KDZW5HYDLZF03QDGM2' +
                                'HDQ27CQV3AGM2AWHZ5SE903VRUATFHQ77W3LS4EVS3C' +
                                'H9ZW97J25EMUDUPQ63NYW24CG27H2RSPFJ9SRP')
  t.ok(decoded.complete === true)
  t.end()
})

tape(`can decode and encode payment request containing unknown tags`, (t) => {
  const paymentRequest = 'lntb30m1pw2f2yspp5s59w4a0kjecw3zyexm7zur8l8' +
                         'n4scw674w8sftjhwec33km882gsdpa2pshjmt9de6zq' +
                         'un9w96k2um5ypmkjargypkh2mr5d9cxzun5ypeh2urs' +
                         'dae8gxqruyqvzddp68gup69uhnzwfj9cejuvf3xshrw' +
                         'de68qcrswf0d46kcarfwpshyaplw3skw0tdw4k8g6ts' +
                         'v9e8gu2etcvsym36pdjpz04wm9nn96f9ntc3t3h5r08' +
                         'pe9d62p3js5wt5rkurqnrl7zkj2fjpvl3rmn7wwazt8' +
                         '0letwxlm22hngu8n88g7hsp542qpl'

  const decoded = lnpayreq.decode(paymentRequest, {
    bech32: 'tb',
    pubKeyHash: 0x6f,
    scriptHash: 0xc4,
    validWitnessVersions: [0]
  })
  t.ok(decoded.complete === true)

  const encoded = lnpayreq.encode(decoded)
  t.same(encoded.paymentRequest, paymentRequest)

  // make canReconstruct false
  // encoding unknown tags should fail if making a new request
  // if signature and recoveryFlag are present there are checks
  // to make sure that the data is what is signed
  // As long as it is impossible to create
  decoded.signature = undefined
  decoded.recoveryFlag = undefined

  t.throws(() => {
    lnpayreq.encode(decoded)
  }, new RegExp('Unknown tag key: unknownTag'))

  t.end()
})

tape(`can decode unknown network payment request`, (t) => {
  const network = {
    bech32: 'sb',
    pubKeyHash: 0x6f,
    scriptHash: 0xc4,
    validWitnessVersions: [0]
  }
  let decoded = lnpayreq.decode(
    'lnsb1u1pwslkj8pp52u27w39645j24a0zfxnwytshxserjchdqt8nz8uwv9fp8wasxrhsdq' +
    'l2pkxz7tfdenjqum0w4hxggrgv4kxj7qcqzpgnvqq8t63nxmgha5945s633fdd3p5x9k889' +
    'g6p02qsghx4vrgqgr3xzz3hgld8r84ellwgz3teexvqzwlxj7lgkhl8xh2p7dstq0fgsspa' +
    '5ldq6',
    network
  )
  t.ok(decoded.complete === true)
  t.end()
})
