
const Witnet = artifacts.require("Witnet")
const WitnetRequestBoardProxy = artifacts.require("WitnetRequestBoardProxy")
const GoldEurPriceFeed = artifacts.require("GoldEurPriceFeed")
const addresses = require("./addresses.json")

module.exports = function (deployer, network) {
  network = network.split("-")[0]
  if (network in addresses && addresses[network].GoldEurPriceFeed) {
    GoldEurPriceFeed.address = addresses[network].GoldEurPriceFeed
  } else{
      deployer.link(Witnet, [GoldEurPriceFeed])
      deployer.deploy(GoldEurPriceFeed, WitnetRequestBoardProxy.address)
  }
}
