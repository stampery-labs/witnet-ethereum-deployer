const Witnet = artifacts.require("Witnet")
const WitnetRequestsBoardProxy = artifacts.require("WitnetRequestsBoardProxy")
const EthUsdPriceFeed = artifacts.require("EthUsdPriceFeed")
const addresses = require("./addresses.json")

module.exports = function (deployer, network) {
  network = network.split("-")[0]
  if (network in addresses && addresses[network].EthUsdPriceFeed) {
    EthUsdPriceFeed.address = addresses[network].EthUsdPriceFeed
  } else{
      deployer.link(Witnet, [EthUsdPriceFeed])
      deployer.deploy(EthUsdPriceFeed, WitnetRequestsBoardProxy.address)
  }
}

