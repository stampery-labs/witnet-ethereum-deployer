const Witnet = artifacts.require("Witnet")
const WitnetRequestBoardProxy = artifacts.require("WitnetRequestBoardProxy")
const BtcUsdPriceFeed = artifacts.require("BtcUsdPriceFeed")
const addresses = require("./addresses.json")

module.exports = function (deployer, network) {
  network = network.split("-")[0]
  if (network in addresses && addresses[network].BtcUsdPriceFeed) {
    BtcUsdPriceFeed.address = addresses[network].BtcUsdPriceFeed
  } else{
      deployer.link(Witnet, [BtcUsdPriceFeed])
      deployer.deploy(BtcUsdPriceFeed, WitnetRequestBoardProxy.address)
  }
}
