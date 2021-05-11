
const WitnetRequestBoard = artifacts.require("WitnetRequestBoard")
const WitnetRequestBoardProxy = artifacts.require("WitnetRequestBoardProxy")
const addresses = require("./addresses.json")

module.exports = function (deployer, network) {
  network = network.split("-")[0]
  console.log(network)
  if (network in addresses && addresses[network].WitnetRequestBoardProxy) {
    WitnetRequestBoardProxy.address = addresses[network].WitnetRequestBoardProxy
  } else {
    console.log(`> Migrating WitnetRequestBoardProxy into ${network} network`)
    return deployer.deploy(WitnetRequestBoardProxy, WitnetRequestBoard.address)
  }
}
