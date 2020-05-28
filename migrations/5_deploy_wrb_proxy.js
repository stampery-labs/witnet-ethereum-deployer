
const WitnetRequestsBoard = artifacts.require("WitnetRequestsBoard")
const WitnetRequestsBoardProxy = artifacts.require("WitnetRequestsBoardProxy")
const addresses = require("./addresses.json")

module.exports = function (deployer, network) {
  network = network.split("-")[0]
  console.log(network)
  if (network in addresses && addresses[network].WitnetRequestsBoardProxy) {
    WitnetRequestsBoardProxy.address = addresses[network].WitnetRequestsBoardProxy
  } else {
    console.log(`> Migrating WitnetRequestsBoardProxy into ${network} network`)
    return deployer.deploy(WitnetRequestsBoardProxy, WitnetRequestsBoard.address)
  }
}
