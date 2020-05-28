const Witnet = artifacts.require("Witnet")
const WitnetRequestsBoardProxy = artifacts.require("WitnetRequestsBoardProxy")
const BtcUsdPriceFeed = artifacts.require("BtcUsdPriceFeed")
const addresses = require("./addresses.json")

module.exports = function (deployer, network) {
  if (network in addresses && addresses[network].BtcUsdPriceFeed) {
    BtcUsdPriceFeed.address = addresses[network].BtcUsdPriceFeed
  } else{
      deployer.link(Witnet, [BtcUsdPriceFeed])
      deployer.deploy(BtcUsdPriceFeed, WitnetRequestsBoardProxy.address)
  }
}
