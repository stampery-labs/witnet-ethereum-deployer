
const BlockRelayProxy = artifacts.require("BlockRelayProxy")
const WitnetRequestsBoard = artifacts.require("WitnetRequestsBoard")
const addresses = require("./addresses.json")

module.exports = function (deployer, network) {
  network = network.split("-")[0]
  console.log(network)
  if (network in addresses && addresses[network].WitnetRequestsBoard) {
    WitnetRequestsBoard.address = addresses[network].WitnetRequestsBoard
  } else {
    console.log(`> Migrating WitnetRequestsBoard into ${network} network`)
    return deployer.deploy(WitnetRequestsBoard, BlockRelayProxy.address, 2)
  }
}
