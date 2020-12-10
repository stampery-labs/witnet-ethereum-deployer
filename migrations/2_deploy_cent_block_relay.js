var CentralizedBlockRelay = artifacts.require("CentralizedBlockRelay")
const addresses = require("./addresses.json")

module.exports = function (deployer, network, accounts) {
  network = network.split("-")[0]
  if (network in addresses && addresses[network].CentralizedBlockRelay) {
    CentralizedBlockRelay.address = addresses[network].CentralizedBlockRelay
  }
  else{
    console.log(`> Migrating CentralizedBlockRelay into ${network} network`)
    deployer.deploy(CentralizedBlockRelay, [accounts[0]])
  }
}

