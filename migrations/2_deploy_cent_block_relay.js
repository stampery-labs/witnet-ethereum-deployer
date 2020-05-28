var CentralizedBlockRelay = artifacts.require("CentralizedBlockRelay")
const addresses = require("./addresses.json")

module.exports = function (deployer, network) {
  if (network in addresses && addresses[network].CentralizedBlockRelay) {
    CentralizedBlockRelay.address = addresses[network].CentralizedBlockRelay
  }
  else{
    console.log(`> Migrating CentralizedBlockRelay into ${network} network`)
    deployer.deploy(CentralizedBlockRelay)
  }
}
