
const WitnetRequestBoard = artifacts.require("WitnetRequestBoard")
const addresses = require("./addresses.json")

module.exports = function (deployer, network, accounts) {
  network = network.split("-")[0]
  console.log(network)
  if (network in addresses && addresses[network].WitnetRequestBoard) {
    WitnetRequestBoard.address = addresses[network].WitnetRequestBoard
  } else {
    console.log(`> Migrating WitnetRequestBoard into ${network} network`)
    return deployer.deploy(WitnetRequestBoard, [accounts[0]])
  }
}
