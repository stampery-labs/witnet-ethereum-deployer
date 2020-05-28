
const Witnet = artifacts.require("Witnet")
const WitnetRequestsBoardProxy = artifacts.require("WitnetRequestsBoardProxy")
const GoldEurPriceFeed = artifacts.require("GoldEurPriceFeed")
const addresses = require("./addresses.json")

module.exports = function (deployer, network) {
  if (network in addresses && addresses[network].GoldEurPriceFeed) {
    GoldEurPriceFeed.address = addresses[network].GoldEurPriceFeed
  } else{
      deployer.link(Witnet, [GoldEurPriceFeed])
      deployer.deploy(GoldEurPriceFeed, WitnetRequestsBoardProxy.address)
  }
}
