var BlockRelayProxy = artifacts.require("BlockRelayProxy")
var BlockRelay = artifacts.require("CentralizedBlockRelay")
const addresses = require("./addresses.json")

module.exports = function (deployer, network) {
  network = network.split("-")[0]
  if (network in addresses && addresses[network].BlockRelayProxy) {
    BlockRelayProxy.address = addresses[network].BlockRelayProxy
  }
  else {
    console.log(`> Migrating BlockRelayProxy into ${network} network`)
    deployer.deploy(BlockRelayProxy, BlockRelay.address)
  } 
}
