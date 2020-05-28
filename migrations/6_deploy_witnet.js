var CBOR = artifacts.require("CBOR")
var Witnet = artifacts.require("Witnet")
const addresses = require("./addresses.json")

module.exports = function (deployer, network) {
  if (network in addresses && addresses[network].Witnet) {
    Witnet.address = addresses[network].Witnet
  }
  else {
    console.log(`> Migrating CBOR and Witnet into ${network} network`)
    deployer.deploy(CBOR).then(function () {
      deployer.link(CBOR, Witnet)
      return deployer.deploy(Witnet)
    })
  }
}
