pragma solidity ^0.6.6;
pragma experimental ABIEncoderV2;

// Import the UsingWitnet library that enables interacting with Witnet
import "witnet-ethereum-bridge/contracts/UsingWitnet.sol";
import "witnet-ethereum-bridge/contracts/WitnetRequestBoard.sol";
import "witnet-ethereum-bridge/contracts/WitnetRequestBoardProxy.sol";
import "witnet-ethereum-bridge/contracts/Witnet.sol";
import "witnet-ethereum-bridge/contracts/CBOR.sol";
// Import price feeds
import "witnet-price-feeds-examples/contracts/bitcoin_price_feed/BtcUsdPriceFeed.sol";
import "witnet-price-feeds-examples/contracts/eth_price_feed/EthUsdPriceFeed.sol";
import "witnet-price-feeds-examples/contracts/gold_price_feed/GoldEurPriceFeed.sol";

contract WitnetDeployer  {
}
