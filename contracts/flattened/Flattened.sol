// SPDX-License-Identifier: MIT

pragma solidity >=0.6.0 <0.7.0;
pragma experimental ABIEncoderV2;

// File: witnet-ethereum-block-relay/contracts/BlockRelayInterface.sol
/**
 * @title Block Relay Interface
 * @notice Interface of a Block Relay to a Witnet network
 * It defines how to interact with the Block Relay in order to support:
 *  - Retrieve last beacon information
 *  - Verify proof of inclusions (PoIs) of data request and tally transactions
 * @author Witnet Foundation
 */
interface BlockRelayInterface {

  /// @notice Returns the beacon from the last inserted block.
  /// The last beacon (in bytes) will be used by Witnet Bridge nodes to compute their eligibility.
  /// @return last beacon in bytes
  function getLastBeacon() external view returns(bytes memory);

  /// @notice Returns the lastest epoch reported to the block relay.
  /// @return epoch
  function getLastEpoch() external view returns(uint256);

  /// @notice Returns the latest hash reported to the block relay
  /// @return blockhash
  function getLastHash() external view returns(uint256);

  /// @notice Verifies the validity of a data request PoI against the DR merkle root
  /// @param _poi the proof of inclusion as [sibling1, sibling2,..]
  /// @param _blockHash the blockHash
  /// @param _index the index in the merkle tree of the element to verify
  /// @param _element the leaf to be verified
  /// @return true if valid data request PoI
  function verifyDrPoi(
    uint256[] calldata _poi,
    uint256 _blockHash,
    uint256 _index,
    uint256 _element) external view returns(bool);

  /// @notice Verifies the validity of a tally PoI against the Tally merkle root
  /// @param _poi the proof of inclusion as [sibling1, sibling2,..]
  /// @param _blockHash the blockHash
  /// @param _index the index in the merkle tree of the element to verify
  /// @param _element the leaf to be verified
  /// @return true if valid tally PoI
  function verifyTallyPoi(
    uint256[] calldata _poi,
    uint256 _blockHash,
    uint256 _index,
    uint256 _element) external view returns(bool);

  /// @notice Verifies if the block relay can be upgraded
  /// @return true if contract is upgradable
  function isUpgradable(address _address) external view returns(bool);

}
// File: witnet-ethereum-block-relay/contracts/CentralizedBlockRelay.sol
/**
 * @title Block relay contract
 * @notice Contract to store/read block headers from the Witnet network
 * @author Witnet Foundation
 */
contract CentralizedBlockRelay is BlockRelayInterface {

  struct MerkleRoots {
    // hash of the merkle root of the DRs in Witnet
    uint256 drHashMerkleRoot;
    // hash of the merkle root of the tallies in Witnet
    uint256 tallyHashMerkleRoot;
  }

  struct Beacon {
    // hash of the last block
    uint256 blockHash;
    // epoch of the last block
    uint256 epoch;
  }

  // Address of the block pusher
  address public witnet;

  // Last block reported
  Beacon public lastBlock;

  mapping (uint256 => MerkleRoots) public blocks;

  // Event emitted when a new block is posted to the contract
  event NewBlock(address indexed _from, uint256 _id);

  // Only the owner should be able to push blocks
  modifier isOwner() {
    require(msg.sender == witnet, "Sender not authorized"); // If it is incorrect here, it reverts.
    _; // Otherwise, it continues.
  }

  // Ensures block exists
  modifier blockExists(uint256 _id){
    require(blocks[_id].drHashMerkleRoot!=0, "Non-existing block");
    _;
  }

  // Ensures block does not exist
  modifier blockDoesNotExist(uint256 _id){
    require(blocks[_id].drHashMerkleRoot==0, "The block already existed");
    _;
  }

  constructor() public{
    // Only the contract deployer is able to push blocks
    witnet = msg.sender;
  }

  /// @dev Read the beacon of the last block inserted
  /// @return bytes to be signed by bridge nodes
  function getLastBeacon()
    external
    view
    override
  returns(bytes memory)
  {
    return abi.encodePacked(lastBlock.blockHash, lastBlock.epoch);
  }

  /// @notice Returns the lastest epoch reported to the block relay.
  /// @return epoch
  function getLastEpoch() external view override returns(uint256) {
    return lastBlock.epoch;
  }

  /// @notice Returns the latest hash reported to the block relay
  /// @return blockhash
  function getLastHash() external view override returns(uint256) {
    return lastBlock.blockHash;
  }

  /// @dev Verifies the validity of a PoI against the DR merkle root
  /// @param _poi the proof of inclusion as [sibling1, sibling2,..]
  /// @param _blockHash the blockHash
  /// @param _index the index in the merkle tree of the element to verify
  /// @param _element the leaf to be verified
  /// @return true or false depending the validity
  function verifyDrPoi(
    uint256[] calldata _poi,
    uint256 _blockHash,
    uint256 _index,
    uint256 _element)
  external
  view
  override
  blockExists(_blockHash)
  returns(bool)
  {
    uint256 drMerkleRoot = blocks[_blockHash].drHashMerkleRoot;
    return(verifyPoi(
      _poi,
      drMerkleRoot,
      _index,
      _element));
  }

  /// @dev Verifies the validity of a PoI against the tally merkle root
  /// @param _poi the proof of inclusion as [sibling1, sibling2,..]
  /// @param _blockHash the blockHash
  /// @param _index the index in the merkle tree of the element to verify
  /// @param _element the element
  /// @return true or false depending the validity
  function verifyTallyPoi(
    uint256[] calldata _poi,
    uint256 _blockHash,
    uint256 _index,
    uint256 _element)
  external
  view
  override
  blockExists(_blockHash)
  returns(bool)
  {
    uint256 tallyMerkleRoot = blocks[_blockHash].tallyHashMerkleRoot;
    return(verifyPoi(
      _poi,
      tallyMerkleRoot,
      _index,
      _element));
  }

  /// @dev Verifies if the contract is upgradable
  /// @return true if the contract upgradable
  function isUpgradable(address _address) external view override returns(bool) {
    if (_address == witnet) {
      return true;
    }
    return false;
  }

  /// @dev Post new block into the block relay
  /// @param _blockHash Hash of the block header
  /// @param _epoch Witnet epoch to which the block belongs to
  /// @param _drMerkleRoot Merkle root belonging to the data requests
  /// @param _tallyMerkleRoot Merkle root belonging to the tallies
  function postNewBlock(
    uint256 _blockHash,
    uint256 _epoch,
    uint256 _drMerkleRoot,
    uint256 _tallyMerkleRoot)
    external
    isOwner
    blockDoesNotExist(_blockHash)
  {
    lastBlock.blockHash = _blockHash;
    lastBlock.epoch = _epoch;
    blocks[_blockHash].drHashMerkleRoot = _drMerkleRoot;
    blocks[_blockHash].tallyHashMerkleRoot = _tallyMerkleRoot;
    emit NewBlock(witnet, _blockHash);
  }

  /// @dev Retrieve the requests-only merkle root hash that was reported for a specific block header.
  /// @param _blockHash Hash of the block header
  /// @return Requests-only merkle root hash in the block header.
  function readDrMerkleRoot(uint256 _blockHash)
    external
    view
    blockExists(_blockHash)
  returns(uint256)
    {
    return blocks[_blockHash].drHashMerkleRoot;
  }

  /// @dev Retrieve the tallies-only merkle root hash that was reported for a specific block header.
  /// @param _blockHash Hash of the block header.
  /// @return tallies-only merkle root hash in the block header.
  function readTallyMerkleRoot(uint256 _blockHash)
    external
    view
    blockExists(_blockHash)
  returns(uint256)
  {
    return blocks[_blockHash].tallyHashMerkleRoot;
  }

  /// @dev Verifies the validity of a PoI
  /// @param _poi the proof of inclusion as [sibling1, sibling2,..]
  /// @param _root the merkle root
  /// @param _index the index in the merkle tree of the element to verify
  /// @param _element the leaf to be verified
  /// @return true or false depending the validity
  function verifyPoi(
    uint256[] memory _poi,
    uint256 _root,
    uint256 _index,
    uint256 _element)
  private pure returns(bool)
  {
    uint256 tree = _element;
    uint256 index = _index;
    // We want to prove that the hash of the _poi and the _element is equal to _root
    // For knowing if concatenate to the left or the right we check the parity of the the index
    for (uint i = 0; i < _poi.length; i++) {
      if (index%2 == 0) {
        tree = uint256(sha256(abi.encodePacked(tree, _poi[i])));
      } else {
        tree = uint256(sha256(abi.encodePacked(_poi[i], tree)));
      }
      index = index >> 1;
    }
    return _root == tree;
  }

}
// File: witnet-ethereum-block-relay/contracts/BlockRelayProxy.sol
/**
 * @title Block Relay Proxy
 * @notice Contract to act as a proxy between the Witnet Bridge Interface and the block relay
 * @dev More information can be found here
 * DISCLAIMER: this is a work in progress, meaning the contract could be voulnerable to attacks
 * @author Witnet Foundation
 */
contract BlockRelayProxy {

  // Address of the current controller
  address internal blockRelayAddress;
  // Current interface to the controller
  BlockRelayInterface internal blockRelayInstance;

  struct ControllerInfo {
    // last epoch seen by a controller
    uint256 lastEpoch;
    // address of the controller
    address blockRelayController;
  }

  // array containing the information about controllers
  ControllerInfo[] internal controllers;

  modifier notIdentical(address _newAddress) {
    require(_newAddress != blockRelayAddress, "The provided Block Relay instance address is already in use");
    _;
  }

  constructor(address _blockRelayAddress) public {
    // Initialize the first epoch pointing to the first controller
    controllers.push(ControllerInfo({lastEpoch: 0, blockRelayController: _blockRelayAddress}));
    blockRelayAddress = _blockRelayAddress;
    blockRelayInstance = BlockRelayInterface(_blockRelayAddress);
  }

  /// @notice Returns the beacon from the last inserted block.
  /// The last beacon (in bytes) will be used by Witnet Bridge nodes to compute their eligibility.
  /// @return last beacon in bytes
  function getLastBeacon() external view returns(bytes memory) {
    return blockRelayInstance.getLastBeacon();
  }

  /// @notice Returns the last Wtinet epoch known to the block relay instance.
  /// @return The last epoch is used in the WRB to avoid reusage of PoI in a data request.
  function getLastEpoch() external view returns(uint256) {
    return blockRelayInstance.getLastEpoch();
  }

  /// @notice Verifies the validity of a data request PoI against the DR merkle root
  /// @param _poi the proof of inclusion as [sibling1, sibling2,..]
  /// @param _blockHash the blockHash
  /// @param _epoch the epoch of the blockchash
  /// @param _index the index in the merkle tree of the element to verify
  /// @param _element the leaf to be verified
  /// @return true if valid data request PoI
  function verifyDrPoi(
    uint256[] calldata _poi,
    uint256 _blockHash,
    uint256 _epoch,
    uint256 _index,
    uint256 _element) external view returns(bool)
    {
    address controller = getController(_epoch);
    return BlockRelayInterface(controller).verifyDrPoi(
      _poi,
      _blockHash,
      _index,
      _element);
  }

  /// @notice Verifies the validity of a tally PoI against the DR merkle root
  /// @param _poi the proof of inclusion as [sibling1, sibling2,..]
  /// @param _blockHash the blockHash
  /// @param _epoch the epoch of the blockchash
  /// @param _index the index in the merkle tree of the element to verify
  /// @param _element the leaf to be verified
  /// @return true if valid data request PoI
  function verifyTallyPoi(
    uint256[] calldata _poi,
    uint256 _blockHash,
    uint256 _epoch,
    uint256 _index,
    uint256 _element) external view returns(bool)
    {
    address controller = getController(_epoch);

    return BlockRelayInterface(controller).verifyTallyPoi(
      _poi,
      _blockHash,
      _index,
      _element);
  }

  /// @notice Upgrades the block relay if the current one is upgradeable
  /// @param _newAddress address of the new block relay to upgrade
  function upgradeBlockRelay(address _newAddress) external notIdentical(_newAddress) {
    // Check if the controller is upgradeable
    require(blockRelayInstance.isUpgradable(msg.sender), "The upgrade has been rejected by the current implementation");
    // Get last epoch seen by the replaced controller
    uint256 epoch = blockRelayInstance.getLastEpoch();
    // Get the length of last epochs seen by the different controllers
    uint256 n = controllers.length;
    // If the the last epoch seen by the replaced controller is lower than the one already anotated e.g. 0
    // just update the already anotated epoch with the new address, ignoring the previously inserted controller
    // Else, anotate the epoch from which the new controller should start receiving blocks
    if (epoch < controllers[n-1].lastEpoch) {
      controllers[n-1].blockRelayController = _newAddress;
    } else {
      controllers.push(ControllerInfo({lastEpoch: epoch+1, blockRelayController: _newAddress}));
    }

    // Update instance
    blockRelayAddress = _newAddress;
    blockRelayInstance = BlockRelayInterface(_newAddress);
  }

  /// @notice Gets the controller associated with the BR controller corresponding to the epoch provided
  /// @param _epoch the epoch to work with
  function getController(uint256 _epoch) public view returns(address _controller) {
    // Get length of all last epochs seen by controllers
    uint256 n = controllers.length;
    // Go backwards until we find the controller having that blockhash
    for (uint i = n; i > 0; i--) {
      if (_epoch >= controllers[i-1].lastEpoch) {
        return (controllers[i-1].blockRelayController);
      }
    }
  }
}
// File: @openzeppelin/contracts/math/SafeMath.sol
/**
 * @dev Wrappers over Solidity's arithmetic operations with added overflow
 * checks.
 *
 * Arithmetic operations in Solidity wrap on overflow. This can easily result
 * in bugs, because programmers usually assume that an overflow raises an
 * error, which is the standard behavior in high level programming languages.
 * `SafeMath` restores this intuition by reverting the transaction when an
 * operation overflows.
 *
 * Using this library instead of the unchecked operations eliminates an entire
 * class of bugs, so it's recommended to use it always.
 */
library SafeMath {
    /**
     * @dev Returns the addition of two unsigned integers, reverting on
     * overflow.
     *
     * Counterpart to Solidity's `+` operator.
     *
     * Requirements:
     * - Addition cannot overflow.
     */
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a, "SafeMath: addition overflow");

        return c;
    }

    /**
     * @dev Returns the subtraction of two unsigned integers, reverting on
     * overflow (when the result is negative).
     *
     * Counterpart to Solidity's `-` operator.
     *
     * Requirements:
     * - Subtraction cannot overflow.
     */
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        return sub(a, b, "SafeMath: subtraction overflow");
    }

    /**
     * @dev Returns the subtraction of two unsigned integers, reverting with custom message on
     * overflow (when the result is negative).
     *
     * Counterpart to Solidity's `-` operator.
     *
     * Requirements:
     * - Subtraction cannot overflow.
     */
    function sub(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        require(b <= a, errorMessage);
        uint256 c = a - b;

        return c;
    }

    /**
     * @dev Returns the multiplication of two unsigned integers, reverting on
     * overflow.
     *
     * Counterpart to Solidity's `*` operator.
     *
     * Requirements:
     * - Multiplication cannot overflow.
     */
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        // Gas optimization: this is cheaper than requiring 'a' not being zero, but the
        // benefit is lost if 'b' is also tested.
        // See: https://github.com/OpenZeppelin/openzeppelin-contracts/pull/522
        if (a == 0) {
            return 0;
        }

        uint256 c = a * b;
        require(c / a == b, "SafeMath: multiplication overflow");

        return c;
    }

    /**
     * @dev Returns the integer division of two unsigned integers. Reverts on
     * division by zero. The result is rounded towards zero.
     *
     * Counterpart to Solidity's `/` operator. Note: this function uses a
     * `revert` opcode (which leaves remaining gas untouched) while Solidity
     * uses an invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     * - The divisor cannot be zero.
     */
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        return div(a, b, "SafeMath: division by zero");
    }

    /**
     * @dev Returns the integer division of two unsigned integers. Reverts with custom message on
     * division by zero. The result is rounded towards zero.
     *
     * Counterpart to Solidity's `/` operator. Note: this function uses a
     * `revert` opcode (which leaves remaining gas untouched) while Solidity
     * uses an invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     * - The divisor cannot be zero.
     */
    function div(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        // Solidity only automatically asserts when dividing by 0
        require(b > 0, errorMessage);
        uint256 c = a / b;
        // assert(a == b * c + a % b); // There is no case in which this doesn't hold

        return c;
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),
     * Reverts when dividing by zero.
     *
     * Counterpart to Solidity's `%` operator. This function uses a `revert`
     * opcode (which leaves remaining gas untouched) while Solidity uses an
     * invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     * - The divisor cannot be zero.
     */
    function mod(uint256 a, uint256 b) internal pure returns (uint256) {
        return mod(a, b, "SafeMath: modulo by zero");
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),
     * Reverts with custom message when dividing by zero.
     *
     * Counterpart to Solidity's `%` operator. This function uses a `revert`
     * opcode (which leaves remaining gas untouched) while Solidity uses an
     * invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     * - The divisor cannot be zero.
     */
    function mod(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        require(b != 0, errorMessage);
        return a % b;
    }
}
// File: elliptic-curve-solidity/contracts/EllipticCurve.sol
/**
 * @title Elliptic Curve Library
 * @dev Library providing arithmetic operations over elliptic curves.
 * @author Witnet Foundation
 */
library EllipticCurve {

  /// @dev Modular euclidean inverse of a number (mod p).
  /// @param _x The number
  /// @param _pp The modulus
  /// @return q such that x*q = 1 (mod _pp)
  function invMod(uint256 _x, uint256 _pp) internal pure returns (uint256) {
    require(_x != 0 && _x != _pp && _pp != 0, "Invalid number");
    uint256 q = 0;
    uint256 newT = 1;
    uint256 r = _pp;
    uint256 newR = _x;
    uint256 t;
    while (newR != 0) {
      t = r / newR;
      (q, newT) = (newT, addmod(q, (_pp - mulmod(t, newT, _pp)), _pp));
      (r, newR) = (newR, r - t * newR );
    }

    return q;
  }

  /// @dev Modular exponentiation, b^e % _pp.
  /// Source: https://github.com/androlo/standard-contracts/blob/master/contracts/src/crypto/ECCMath.sol
  /// @param _base base
  /// @param _exp exponent
  /// @param _pp modulus
  /// @return r such that r = b**e (mod _pp)
  function expMod(uint256 _base, uint256 _exp, uint256 _pp) internal pure returns (uint256) {
    require(_pp!=0, "Modulus is zero");

    if (_base == 0)
      return 0;
    if (_exp == 0)
      return 1;

    uint256 r = 1;
    uint256 bit = 2 ** 255;
    assembly {
      for { } gt(bit, 0) { }{
        r := mulmod(mulmod(r, r, _pp), exp(_base, iszero(iszero(and(_exp, bit)))), _pp)
        r := mulmod(mulmod(r, r, _pp), exp(_base, iszero(iszero(and(_exp, div(bit, 2))))), _pp)
        r := mulmod(mulmod(r, r, _pp), exp(_base, iszero(iszero(and(_exp, div(bit, 4))))), _pp)
        r := mulmod(mulmod(r, r, _pp), exp(_base, iszero(iszero(and(_exp, div(bit, 8))))), _pp)
        bit := div(bit, 16)
      }
    }

    return r;
  }

  /// @dev Converts a point (x, y, z) expressed in Jacobian coordinates to affine coordinates (x', y', 1).
  /// @param _x coordinate x
  /// @param _y coordinate y
  /// @param _z coordinate z
  /// @param _pp the modulus
  /// @return (x', y') affine coordinates
  function toAffine(
    uint256 _x,
    uint256 _y,
    uint256 _z,
    uint256 _pp)
  internal pure returns (uint256, uint256)
  {
    uint256 zInv = invMod(_z, _pp);
    uint256 zInv2 = mulmod(zInv, zInv, _pp);
    uint256 x2 = mulmod(_x, zInv2, _pp);
    uint256 y2 = mulmod(_y, mulmod(zInv, zInv2, _pp), _pp);

    return (x2, y2);
  }

  /// @dev Derives the y coordinate from a compressed-format point x [[SEC-1]](https://www.secg.org/SEC1-Ver-1.0.pdf).
  /// @param _prefix parity byte (0x02 even, 0x03 odd)
  /// @param _x coordinate x
  /// @param _aa constant of curve
  /// @param _bb constant of curve
  /// @param _pp the modulus
  /// @return y coordinate y
  function deriveY(
    uint8 _prefix,
    uint256 _x,
    uint256 _aa,
    uint256 _bb,
    uint256 _pp)
  internal pure returns (uint256)
  {
    require(_prefix == 0x02 || _prefix == 0x03, "Invalid compressed EC point prefix");

    // x^3 + ax + b
    uint256 y2 = addmod(mulmod(_x, mulmod(_x, _x, _pp), _pp), addmod(mulmod(_x, _aa, _pp), _bb, _pp), _pp);
    y2 = expMod(y2, (_pp + 1) / 4, _pp);
    // uint256 cmp = yBit ^ y_ & 1;
    uint256 y = (y2 + _prefix) % 2 == 0 ? y2 : _pp - y2;

    return y;
  }

  /// @dev Check whether point (x,y) is on curve defined by a, b, and _pp.
  /// @param _x coordinate x of P1
  /// @param _y coordinate y of P1
  /// @param _aa constant of curve
  /// @param _bb constant of curve
  /// @param _pp the modulus
  /// @return true if x,y in the curve, false else
  function isOnCurve(
    uint _x,
    uint _y,
    uint _aa,
    uint _bb,
    uint _pp)
  internal pure returns (bool)
  {
    if (0 == _x || _x == _pp || 0 == _y || _y == _pp) {
      return false;
    }
    // y^2
    uint lhs = mulmod(_y, _y, _pp);
    // x^3
    uint rhs = mulmod(mulmod(_x, _x, _pp), _x, _pp);
    if (_aa != 0) {
      // x^3 + a*x
      rhs = addmod(rhs, mulmod(_x, _aa, _pp), _pp);
    }
    if (_bb != 0) {
      // x^3 + a*x + b
      rhs = addmod(rhs, _bb, _pp);
    }

    return lhs == rhs;
  }

  /// @dev Calculate inverse (x, -y) of point (x, y).
  /// @param _x coordinate x of P1
  /// @param _y coordinate y of P1
  /// @param _pp the modulus
  /// @return (x, -y)
  function ecInv(
    uint256 _x,
    uint256 _y,
    uint256 _pp)
  internal pure returns (uint256, uint256)
  {
    return (_x, (_pp - _y) % _pp);
  }

  /// @dev Add two points (x1, y1) and (x2, y2) in affine coordinates.
  /// @param _x1 coordinate x of P1
  /// @param _y1 coordinate y of P1
  /// @param _x2 coordinate x of P2
  /// @param _y2 coordinate y of P2
  /// @param _aa constant of the curve
  /// @param _pp the modulus
  /// @return (qx, qy) = P1+P2 in affine coordinates
  function ecAdd(
    uint256 _x1,
    uint256 _y1,
    uint256 _x2,
    uint256 _y2,
    uint256 _aa,
    uint256 _pp)
    internal pure returns(uint256, uint256)
  {
    uint x = 0;
    uint y = 0;
    uint z = 0;
    // Double if x1==x2 else add
    if (_x1==_x2) {
      (x, y, z) = jacDouble(
        _x1,
        _y1,
        1,
        _aa,
        _pp);
    } else {
      (x, y, z) = jacAdd(
        _x1,
        _y1,
        1,
        _x2,
        _y2,
        1,
        _pp);
    }
    // Get back to affine
    return toAffine(
      x,
      y,
      z,
      _pp);
  }

  /// @dev Substract two points (x1, y1) and (x2, y2) in affine coordinates.
  /// @param _x1 coordinate x of P1
  /// @param _y1 coordinate y of P1
  /// @param _x2 coordinate x of P2
  /// @param _y2 coordinate y of P2
  /// @param _aa constant of the curve
  /// @param _pp the modulus
  /// @return (qx, qy) = P1-P2 in affine coordinates
  function ecSub(
    uint256 _x1,
    uint256 _y1,
    uint256 _x2,
    uint256 _y2,
    uint256 _aa,
    uint256 _pp)
  internal pure returns(uint256, uint256)
  {
    // invert square
    (uint256 x, uint256 y) = ecInv(_x2, _y2, _pp);
    // P1-square
    return ecAdd(
      _x1,
      _y1,
      x,
      y,
      _aa,
      _pp);
  }

  /// @dev Multiply point (x1, y1, z1) times d in affine coordinates.
  /// @param _k scalar to multiply
  /// @param _x coordinate x of P1
  /// @param _y coordinate y of P1
  /// @param _aa constant of the curve
  /// @param _pp the modulus
  /// @return (qx, qy) = d*P in affine coordinates
  function ecMul(
    uint256 _k,
    uint256 _x,
    uint256 _y,
    uint256 _aa,
    uint256 _pp)
  internal pure returns(uint256, uint256)
  {
    // Jacobian multiplication
    (uint256 x1, uint256 y1, uint256 z1) = jacMul(
      _k,
      _x,
      _y,
      1,
      _aa,
      _pp);
    // Get back to affine
    return toAffine(
      x1,
      y1,
      z1,
      _pp);
  }

  /// @dev Adds two points (x1, y1, z1) and (x2 y2, z2).
  /// @param _x1 coordinate x of P1
  /// @param _y1 coordinate y of P1
  /// @param _z1 coordinate z of P1
  /// @param _x2 coordinate x of square
  /// @param _y2 coordinate y of square
  /// @param _z2 coordinate z of square
  /// @param _pp the modulus
  /// @return (qx, qy, qz) P1+square in Jacobian
  function jacAdd(
    uint256 _x1,
    uint256 _y1,
    uint256 _z1,
    uint256 _x2,
    uint256 _y2,
    uint256 _z2,
    uint256 _pp)
  internal pure returns (uint256, uint256, uint256)
  {
    if ((_x1==0)&&(_y1==0))
      return (_x2, _y2, _z2);
    if ((_x2==0)&&(_y2==0))
      return (_x1, _y1, _z1);
    // We follow the equations described in https://pdfs.semanticscholar.org/5c64/29952e08025a9649c2b0ba32518e9a7fb5c2.pdf Section 5

    uint[4] memory zs; // z1^2, z1^3, z2^2, z2^3
    zs[0] = mulmod(_z1, _z1, _pp);
    zs[1] = mulmod(_z1, zs[0], _pp);
    zs[2] = mulmod(_z2, _z2, _pp);
    zs[3] = mulmod(_z2, zs[2], _pp);

    // u1, s1, u2, s2
    zs = [
      mulmod(_x1, zs[2], _pp),
      mulmod(_y1, zs[3], _pp),
      mulmod(_x2, zs[0], _pp),
      mulmod(_y2, zs[1], _pp)
    ];

    // In case of zs[0] == zs[2] && zs[1] == zs[3], double function should be used
    require(zs[0] != zs[2], "Invalid data");

    uint[4] memory hr;
    //h
    hr[0] = addmod(zs[2], _pp - zs[0], _pp);
    //r
    hr[1] = addmod(zs[3], _pp - zs[1], _pp);
    //h^2
    hr[2] = mulmod(hr[0], hr[0], _pp);
    // h^3
    hr[3] = mulmod(hr[2], hr[0], _pp);
    // qx = -h^3  -2u1h^2+r^2
    uint256 qx = addmod(mulmod(hr[1], hr[1], _pp), _pp - hr[3], _pp);
    qx = addmod(qx, _pp - mulmod(2, mulmod(zs[0], hr[2], _pp), _pp), _pp);
    // qy = -s1*z1*h^3+r(u1*h^2 -x^3)
    uint256 qy = mulmod(hr[1], addmod(mulmod(zs[0], hr[2], _pp), _pp - qx, _pp), _pp);
    qy = addmod(qy, _pp - mulmod(zs[1], hr[3], _pp), _pp);
    // qz = h*z1*z2
    uint256 qz = mulmod(hr[0], mulmod(_z1, _z2, _pp), _pp);
    return(qx, qy, qz);
  }

  /// @dev Doubles a points (x, y, z).
  /// @param _x coordinate x of P1
  /// @param _y coordinate y of P1
  /// @param _z coordinate z of P1
  /// @param _pp the modulus
  /// @param _aa the a scalar in the curve equation
  /// @return (qx, qy, qz) 2P in Jacobian
  function jacDouble(
    uint256 _x,
    uint256 _y,
    uint256 _z,
    uint256 _aa,
    uint256 _pp)
  internal pure returns (uint256, uint256, uint256)
  {
    if (_z == 0)
      return (_x, _y, _z);
    uint256[3] memory square;
    // We follow the equations described in https://pdfs.semanticscholar.org/5c64/29952e08025a9649c2b0ba32518e9a7fb5c2.pdf Section 5
    // Note: there is a bug in the paper regarding the m parameter, M=3*(x1^2)+a*(z1^4)
    square[0] = mulmod(_x, _x, _pp); //x1^2
    square[1] = mulmod(_y, _y, _pp); //y1^2
    square[2] = mulmod(_z, _z, _pp); //z1^2

    // s
    uint s = mulmod(4, mulmod(_x, square[1], _pp), _pp);
    // m
    uint m = addmod(mulmod(3, square[0], _pp), mulmod(_aa, mulmod(square[2], square[2], _pp), _pp), _pp);
    // qx
    uint256 qx = addmod(mulmod(m, m, _pp), _pp - addmod(s, s, _pp), _pp);
    // qy = -8*y1^4 + M(S-T)
    uint256 qy = addmod(mulmod(m, addmod(s, _pp - qx, _pp), _pp), _pp - mulmod(8, mulmod(square[1], square[1], _pp), _pp), _pp);
    // qz = 2*y1*z1
    uint256 qz = mulmod(2, mulmod(_y, _z, _pp), _pp);

    return (qx, qy, qz);
  }

  /// @dev Multiply point (x, y, z) times d.
  /// @param _d scalar to multiply
  /// @param _x coordinate x of P1
  /// @param _y coordinate y of P1
  /// @param _z coordinate z of P1
  /// @param _aa constant of curve
  /// @param _pp the modulus
  /// @return (qx, qy, qz) d*P1 in Jacobian
  function jacMul(
    uint256 _d,
    uint256 _x,
    uint256 _y,
    uint256 _z,
    uint256 _aa,
    uint256 _pp)
  internal pure returns (uint256, uint256, uint256)
  {
    uint256 remaining = _d;
    uint256[3] memory point;
    point[0] = _x;
    point[1] = _y;
    point[2] = _z;
    uint256 qx = 0;
    uint256 qy = 0;
    uint256 qz = 1;

    if (_d == 0) {
      return (qx, qy, qz);
    }
    // Double and add algorithm
    while (remaining != 0) {
      if ((remaining & 1) != 0) {
        (qx, qy, qz) = jacAdd(
          qx,
          qy,
          qz,
          point[0],
          point[1],
          point[2],
          _pp);
      }
      remaining = remaining / 2;
      (point[0], point[1], point[2]) = jacDouble(
        point[0],
        point[1],
        point[2],
        _aa,
        _pp);
    }
    return (qx, qy, qz);
  }
}
// File: vrf-solidity/contracts/VRF.sol
/**
 * @title Verifiable Random Functions (VRF)
 * @notice Library verifying VRF proofs using the `Secp256k1` curve and the `SHA256` hash function.
 * @dev This library follows the algorithms described in [VRF-draft-04](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-04) and [RFC6979](https://tools.ietf.org/html/rfc6979).
 * It supports the _SECP256K1_SHA256_TAI_ cipher suite, i.e. the aforementioned algorithms using `SHA256` and the `Secp256k1` curve.
 * @author Witnet Foundation
 */
library VRF {

  /**
   * Secp256k1 parameters
   */

  // Generator coordinate `x` of the EC curve
  uint256 public constant GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
  // Generator coordinate `y` of the EC curve
  uint256 public constant GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
  // Constant `a` of EC equation
  uint256 public constant AA = 0;
  // Constant `b` of EC equation
  uint256 public constant BB = 7;
  // Prime number of the curve
  uint256 public constant PP = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
  // Order of the curve
  uint256 public constant NN = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

  /// @dev Public key derivation from private key.
  /// @param _d The scalar
  /// @param _x The coordinate x
  /// @param _y The coordinate y
  /// @return (qx, qy) The derived point
  function derivePoint(uint256 _d, uint256 _x, uint256 _y) internal pure returns (uint256, uint256) {
    return EllipticCurve.ecMul(
      _d,
      _x,
      _y,
      AA,
      PP
    );
  }

  /// @dev Function to derive the `y` coordinate given the `x` coordinate and the parity byte (`0x03` for odd `y` and `0x04` for even `y`).
  /// @param _yByte The parity byte following the ec point compressed format
  /// @param _x The coordinate `x` of the point
  /// @return The coordinate `y` of the point
  function deriveY(uint8 _yByte, uint256 _x) internal pure returns (uint256) {
    return EllipticCurve.deriveY(
      _yByte,
      _x,
      AA,
      BB,
      PP);
  }

  /// @dev Computes the VRF hash output as result of the digest of a ciphersuite-dependent prefix
  /// concatenated with the gamma point
  /// @param _gammaX The x-coordinate of the gamma EC point
  /// @param _gammaY The y-coordinate of the gamma EC point
  /// @return The VRF hash ouput as shas256 digest
  function gammaToHash(uint256 _gammaX, uint256 _gammaY) internal pure returns (bytes32) {
    bytes memory c = abi.encodePacked(
      // Cipher suite code (SECP256K1-SHA256-TAI is 0xFE)
      uint8(0xFE),
      // 0x01
      uint8(0x03),
      // Compressed Gamma Point
      encodePoint(_gammaX, _gammaY));

    return sha256(c);
  }

  /// @dev VRF verification by providing the public key, the message and the VRF proof.
  /// This function computes several elliptic curve operations which may lead to extensive gas consumption.
  /// @param _publicKey The public key as an array composed of `[pubKey-x, pubKey-y]`
  /// @param _proof The VRF proof as an array composed of `[gamma-x, gamma-y, c, s]`
  /// @param _message The message (in bytes) used for computing the VRF
  /// @return true, if VRF proof is valid
  function verify(uint256[2] memory _publicKey, uint256[4] memory _proof, bytes memory _message) internal pure returns (bool) {
    // Step 2: Hash to try and increment (outputs a hashed value, a finite EC point in G)
    uint256[2] memory hPoint;
    (hPoint[0], hPoint[1]) = hashToTryAndIncrement(_publicKey, _message);

    // Step 3: U = s*B - c*Y (where B is the generator)
    (uint256 uPointX, uint256 uPointY) = ecMulSubMul(
      _proof[3],
      GX,
      GY,
      _proof[2],
      _publicKey[0],
      _publicKey[1]);

    // Step 4: V = s*H - c*Gamma
    (uint256 vPointX, uint256 vPointY) = ecMulSubMul(
      _proof[3],
      hPoint[0],
      hPoint[1],
      _proof[2],
      _proof[0],_proof[1]);

    // Step 5: derived c from hash points(...)
    bytes16 derivedC = hashPoints(
      hPoint[0],
      hPoint[1],
      _proof[0],
      _proof[1],
      uPointX,
      uPointY,
      vPointX,
      vPointY);

    // Step 6: Check validity c == c'
    return uint128(derivedC) == _proof[2];
  }

  /// @dev VRF fast verification by providing the public key, the message, the VRF proof and several intermediate elliptic curve points that enable the verification shortcut.
  /// This function leverages the EVM's `ecrecover` precompile to verify elliptic curve multiplications by decreasing the security from 32 to 20 bytes.
  /// Based on the original idea of Vitalik Buterin: https://ethresear.ch/t/you-can-kinda-abuse-ecrecover-to-do-ecmul-in-secp256k1-today/2384/9
  /// @param _publicKey The public key as an array composed of `[pubKey-x, pubKey-y]`
  /// @param _proof The VRF proof as an array composed of `[gamma-x, gamma-y, c, s]`
  /// @param _message The message (in bytes) used for computing the VRF
  /// @param _uPoint The `u` EC point defined as `U = s*B - c*Y`
  /// @param _vComponents The components required to compute `v` as `V = s*H - c*Gamma`
  /// @return true, if VRF proof is valid
  function fastVerify(
    uint256[2] memory _publicKey,
    uint256[4] memory _proof,
    bytes memory _message,
    uint256[2] memory _uPoint,
    uint256[4] memory _vComponents)
  internal pure returns (bool)
  {
    // Step 2: Hash to try and increment -> hashed value, a finite EC point in G
    uint256[2] memory hPoint;
    (hPoint[0], hPoint[1]) = hashToTryAndIncrement(_publicKey, _message);

    // Step 3 & Step 4:
    // U = s*B - c*Y (where B is the generator)
    // V = s*H - c*Gamma
    if (!ecMulSubMulVerify(
      _proof[3],
      _proof[2],
      _publicKey[0],
      _publicKey[1],
      _uPoint[0],
      _uPoint[1]) ||
      !ecMulVerify(
        _proof[3],
        hPoint[0],
        hPoint[1],
        _vComponents[0],
        _vComponents[1]) ||
      !ecMulVerify(
        _proof[2],
        _proof[0],
        _proof[1],
        _vComponents[2],
        _vComponents[3])
      )
    {
      return false;
    }
    (uint256 vPointX, uint256 vPointY) = EllipticCurve.ecSub(
      _vComponents[0],
      _vComponents[1],
      _vComponents[2],
      _vComponents[3],
      AA,
      PP);

    // Step 5: derived c from hash points(...)
    bytes16 derivedC = hashPoints(
      hPoint[0],
      hPoint[1],
      _proof[0],
      _proof[1],
      _uPoint[0],
      _uPoint[1],
      vPointX,
      vPointY);

    // Step 6: Check validity c == c'
    return uint128(derivedC) == _proof[2];
  }

  /// @dev Decode VRF proof from bytes
  /// @param _proof The VRF proof as an array composed of `[gamma-x, gamma-y, c, s]`
  /// @return The VRF proof as an array composed of `[gamma-x, gamma-y, c, s]`
  function decodeProof(bytes memory _proof) internal pure returns (uint[4] memory) {
    require(_proof.length == 81, "Malformed VRF proof");
    uint8 gammaSign;
    uint256 gammaX;
    uint128 c;
    uint256 s;
    assembly {
      gammaSign := mload(add(_proof, 1))
	    gammaX := mload(add(_proof, 33))
      c := mload(add(_proof, 49))
      s := mload(add(_proof, 81))
    }
    uint256 gammaY = deriveY(gammaSign, gammaX);

    return [
      gammaX,
      gammaY,
      c,
      s];
  }

  /// @dev Decode EC point from bytes
  /// @param _point The EC point as bytes
  /// @return The point as `[point-x, point-y]`
  function decodePoint(bytes memory _point) internal pure returns (uint[2] memory) {
    require(_point.length == 33, "Malformed compressed EC point");
    uint8 sign;
    uint256 x;
    assembly {
      sign := mload(add(_point, 1))
	    x := mload(add(_point, 33))
    }
    uint256 y = deriveY(sign, x);

    return [x, y];
  }

  /// @dev Compute the parameters (EC points) required for the VRF fast verification function.
  /// @param _publicKey The public key as an array composed of `[pubKey-x, pubKey-y]`
  /// @param _proof The VRF proof as an array composed of `[gamma-x, gamma-y, c, s]`
  /// @param _message The message (in bytes) used for computing the VRF
  /// @return The fast verify required parameters as the tuple `([uPointX, uPointY], [sHX, sHY, cGammaX, cGammaY])`
  function computeFastVerifyParams(uint256[2] memory _publicKey, uint256[4] memory _proof, bytes memory _message)
    internal pure returns (uint256[2] memory, uint256[4] memory)
  {
    // Requirements for Step 3: U = s*B - c*Y (where B is the generator)
    uint256[2] memory hPoint;
    (hPoint[0], hPoint[1]) = hashToTryAndIncrement(_publicKey, _message);
    (uint256 uPointX, uint256 uPointY) = ecMulSubMul(
      _proof[3],
      GX,
      GY,
      _proof[2],
      _publicKey[0],
      _publicKey[1]);
    // Requirements for Step 4: V = s*H - c*Gamma
    (uint256 sHX, uint256 sHY) = derivePoint(_proof[3], hPoint[0], hPoint[1]);
    (uint256 cGammaX, uint256 cGammaY) = derivePoint(_proof[2], _proof[0], _proof[1]);

    return (
      [uPointX, uPointY],
      [
        sHX,
        sHY,
        cGammaX,
        cGammaY
      ]);
  }

  /// @dev Function to convert a `Hash(PK|DATA)` to a point in the curve as defined in [VRF-draft-04](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-04).
  /// Used in Step 2 of VRF verification function.
  /// @param _publicKey The public key as an array composed of `[pubKey-x, pubKey-y]`
  /// @param _message The message used for computing the VRF
  /// @return The hash point in affine cooridnates
  function hashToTryAndIncrement(uint256[2] memory _publicKey, bytes memory _message) internal pure returns (uint, uint) {
    // Step 1: public key to bytes
    // Step 2: V = cipher_suite | 0x01 | public_key_bytes | message | ctr
    bytes memory c = abi.encodePacked(
      // Cipher suite code (SECP256K1-SHA256-TAI is 0xFE)
      uint8(254),
      // 0x01
      uint8(1),
      // Public Key
      encodePoint(_publicKey[0], _publicKey[1]),
      // Message
      _message);

    // Step 3: find a valid EC point
    // Loop over counter ctr starting at 0x00 and do hash
    for (uint8 ctr = 0; ctr < 256; ctr++) {
      // Counter update
      // c[cLength-1] = byte(ctr);
      bytes32 sha = sha256(abi.encodePacked(c, ctr));
      // Step 4: arbitraty string to point and check if it is on curve
      uint hPointX = uint256(sha);
      uint hPointY = deriveY(2, hPointX);
      if (EllipticCurve.isOnCurve(
        hPointX,
        hPointY,
        AA,
        BB,
        PP))
      {
        // Step 5 (omitted): calculate H (cofactor is 1 on secp256k1)
        // If H is not "INVALID" and cofactor > 1, set H = cofactor * H
        return (hPointX, hPointY);
      }
    }
    revert("No valid point was found");
  }

  /// @dev Function to hash a certain set of points as specified in [VRF-draft-04](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-04).
  /// Used in Step 5 of VRF verification function.
  /// @param _hPointX The coordinate `x` of point `H`
  /// @param _hPointY The coordinate `y` of point `H`
  /// @param _gammaX The coordinate `x` of the point `Gamma`
  /// @param _gammaX The coordinate `y` of the point `Gamma`
  /// @param _uPointX The coordinate `x` of point `U`
  /// @param _uPointY The coordinate `y` of point `U`
  /// @param _vPointX The coordinate `x` of point `V`
  /// @param _vPointY The coordinate `y` of point `V`
  /// @return The first half of the digest of the points using SHA256
  function hashPoints(
    uint256 _hPointX,
    uint256 _hPointY,
    uint256 _gammaX,
    uint256 _gammaY,
    uint256 _uPointX,
    uint256 _uPointY,
    uint256 _vPointX,
    uint256 _vPointY)
  internal pure returns (bytes16)
  {
    bytes memory c = abi.encodePacked(
      // Ciphersuite 0xFE
      uint8(254),
      // Prefix 0x02
      uint8(2),
      // Points to Bytes
      encodePoint(_hPointX, _hPointY),
      encodePoint(_gammaX, _gammaY),
      encodePoint(_uPointX, _uPointY),
      encodePoint(_vPointX, _vPointY)
    );
    // Hash bytes and truncate
    bytes32 sha = sha256(c);
    bytes16 half1;
    assembly {
      let freemem_pointer := mload(0x40)
      mstore(add(freemem_pointer,0x00), sha)
      half1 := mload(add(freemem_pointer,0x00))
    }

    return half1;
  }

  /// @dev Encode an EC point to bytes
  /// @param _x The coordinate `x` of the point
  /// @param _y The coordinate `y` of the point
  /// @return The point coordinates as bytes
  function encodePoint(uint256 _x, uint256 _y) internal pure returns (bytes memory) {
    uint8 prefix = uint8(2 + (_y % 2));

    return abi.encodePacked(prefix, _x);
  }

  /// @dev Substracts two key derivation functionsas `s1*A - s2*B`.
  /// @param _scalar1 The scalar `s1`
  /// @param _a1 The `x` coordinate of point `A`
  /// @param _a2 The `y` coordinate of point `A`
  /// @param _scalar2 The scalar `s2`
  /// @param _b1 The `x` coordinate of point `B`
  /// @param _b2 The `y` coordinate of point `B`
  /// @return The derived point in affine cooridnates
  function ecMulSubMul(
    uint256 _scalar1,
    uint256 _a1,
    uint256 _a2,
    uint256 _scalar2,
    uint256 _b1,
    uint256 _b2)
  internal pure returns (uint256, uint256)
  {
    (uint256 m1, uint256 m2) = derivePoint(_scalar1, _a1, _a2);
    (uint256 n1, uint256 n2) = derivePoint(_scalar2, _b1, _b2);
    (uint256 r1, uint256 r2) = EllipticCurve.ecSub(
      m1,
      m2,
      n1,
      n2,
      AA,
      PP);

    return (r1, r2);
  }

  /// @dev Verify an Elliptic Curve multiplication of the form `(qx,qy) = scalar*(x,y)` by using the precompiled `ecrecover` function.
  /// The usage of the precompiled `ecrecover` function decreases the security from 32 to 20 bytes.
  /// Based on the original idea of Vitalik Buterin: https://ethresear.ch/t/you-can-kinda-abuse-ecrecover-to-do-ecmul-in-secp256k1-today/2384/9
  /// @param _scalar The scalar of the point multiplication
  /// @param _x The coordinate `x` of the point
  /// @param _y The coordinate `y` of the point
  /// @param _qx The coordinate `x` of the multiplication result
  /// @param _qy The coordinate `y` of the multiplication result
  /// @return true, if first 20 bytes match
  function ecMulVerify(
    uint256 _scalar,
    uint256 _x,
    uint256 _y,
    uint256 _qx,
    uint256 _qy)
  internal pure returns(bool)
  {
    address result = ecrecover(
      0,
      _y % 2 != 0 ? 28 : 27,
      bytes32(_x),
      bytes32(mulmod(_scalar, _x, NN)));

    return pointToAddress(_qx, _qy) == result;
  }

  /// @dev Verify an Elliptic Curve operation of the form `Q = scalar1*(gx,gy) - scalar2*(x,y)` by using the precompiled `ecrecover` function, where `(gx,gy)` is the generator of the EC.
  /// The usage of the precompiled `ecrecover` function decreases the security from 32 to 20 bytes.
  /// Based on SolCrypto library: https://github.com/HarryR/solcrypto
  /// @param _scalar1 The scalar of the multiplication of `(gx,gy)`
  /// @param _scalar2 The scalar of the multiplication of `(x,y)`
  /// @param _x The coordinate `x` of the point to be mutiply by `scalar2`
  /// @param _y The coordinate `y` of the point to be mutiply by `scalar2`
  /// @param _qx The coordinate `x` of the equation result
  /// @param _qy The coordinate `y` of the equation result
  /// @return true, if first 20 bytes match
  function ecMulSubMulVerify(
    uint256 _scalar1,
    uint256 _scalar2,
    uint256 _x,
    uint256 _y,
    uint256 _qx,
    uint256 _qy)
  internal pure returns(bool)
  {
    uint256 scalar1 = (NN - _scalar1) % NN;
    scalar1 = mulmod(scalar1, _x, NN);
    uint256 scalar2 = (NN - _scalar2) % NN;

    address result = ecrecover(
      bytes32(scalar1),
      _y % 2 != 0 ? 28 : 27,
      bytes32(_x),
      bytes32(mulmod(scalar2, _x, NN)));

    return pointToAddress(_qx, _qy) == result;
  }

  /// @dev Gets the address corresponding to the EC point digest (keccak256), i.e. the first 20 bytes of the digest.
  /// This function is used for performing a fast EC multiplication verification.
  /// @param _x The coordinate `x` of the point
  /// @param _y The coordinate `y` of the point
  /// @return The address of the EC point digest (keccak256)
  function pointToAddress(uint256 _x, uint256 _y)
      internal pure returns(address)
  {
    return address(uint256(keccak256(abi.encodePacked(_x, _y))) & 0x00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF);
  }
}
// File: witnet-ethereum-bridge/contracts/ActiveBridgeSetLib.sol
/**
 * @title Active Bridge Set (ABS) library
 * @notice This library counts the number of bridges that were active recently.
 */
library ActiveBridgeSetLib {

  // Number of Ethereum blocks during which identities can be pushed into a single activity slot
  uint8 public constant CLAIM_BLOCK_PERIOD = 8;

  // Number of activity slots in the ABS
  uint8 public constant ACTIVITY_LENGTH = 100;

  struct ActiveBridgeSet {
    // Mapping of activity slots with participating identities
    mapping (uint16 => address[]) epochIdentities;
    // Mapping of identities with their participation count
    mapping (address => uint16) identityCount;
    // Number of identities in the Active Bridge Set (consolidated during `ACTIVITY_LENGTH`)
    uint32 activeIdentities;
    // Number of identities for the next activity slot (to be updated in the next activity slot)
    uint32 nextActiveIdentities;
    // Last used block number during an activity update
    uint256 lastBlockNumber;
  }

  modifier validBlockNumber(uint256 _blockFromArguments, uint256 _blockFromContractState) {
    require (_blockFromArguments >= _blockFromContractState, "The provided block is older than the last updated block");
    _;
  }

  /// @dev Updates activity in Witnet without requiring protocol participation.
  /// @param _abs The Active Bridge Set structure to be updated.
  /// @param _blockNumber The block number up to which the activity should be updated.
  function updateActivity(ActiveBridgeSet storage _abs, uint256 _blockNumber)
    internal
    validBlockNumber(_blockNumber, _abs.lastBlockNumber)
  {
    (uint16 currentSlot, uint16 lastSlot, bool overflow) = getSlots(_abs, _blockNumber);

    // Avoid gas cost if ABS is up to date
    require(
      updateABS(
        _abs,
        currentSlot,
        lastSlot,
        overflow
      ), "The ABS was already up to date");

    _abs.lastBlockNumber = _blockNumber;
  }

  /// @dev Pushes activity updates through protocol activities (implying insertion of identity).
  /// @param _abs The Active Bridge Set structure to be updated.
  /// @param _address The address pushing the activity.
  /// @param _blockNumber The block number up to which the activity should be updated.
  function pushActivity(ActiveBridgeSet storage _abs, address _address, uint256 _blockNumber)
    internal
    validBlockNumber(_blockNumber, _abs.lastBlockNumber)
  returns (bool success)
  {
    (uint16 currentSlot, uint16 lastSlot, bool overflow) = getSlots(_abs, _blockNumber);

    // Update ABS and if it was already up to date, check if identities already counted
    if (
      updateABS(
        _abs,
        currentSlot,
        lastSlot,
        overflow
      ))
    {
      _abs.lastBlockNumber = _blockNumber;
    } else {
      // Check if address was already counted as active identity in this current activity slot
      uint256 epochIdsLength = _abs.epochIdentities[currentSlot].length;
      for (uint256 i; i < epochIdsLength; i++) {
        if (_abs.epochIdentities[currentSlot][i] == _address) {
          return false;
        }
      }
    }

    // Update current activity slot with identity:
    //  1. Add currentSlot to `epochIdentities` with address
    //  2. If count = 0, increment by 1 `nextActiveIdentities`
    //  3. Increment by 1 the count of the identity
    _abs.epochIdentities[currentSlot].push(_address);
    if (_abs.identityCount[_address] == 0) {
      _abs.nextActiveIdentities++;
    }
    _abs.identityCount[_address]++;

    return true;
  }

  /// @dev Checks if an address is a member of the ABS.
  /// @param _abs The Active Bridge Set structure from the Witnet Requests Board.
  /// @param _address The address to check.
  /// @return true if address is member of ABS.
  function absMembership(ActiveBridgeSet storage _abs, address _address) internal view returns (bool) {
    return _abs.identityCount[_address] > 0;
  }

  /// @dev Gets the slots of the last block seen by the ABS provided and the block number provided.
  /// @param _abs The Active Bridge Set structure containing the last block.
  /// @param _blockNumber The block number from which to get the current slot.
  /// @return (currentSlot, lastSlot, overflow), where overflow implies the block difference &gt; CLAIM_BLOCK_PERIOD* ACTIVITY_LENGTH.
  function getSlots(ActiveBridgeSet storage _abs, uint256 _blockNumber) private view returns (uint8, uint8, bool) {
    // Get current activity slot number
    uint8 currentSlot = uint8((_blockNumber / CLAIM_BLOCK_PERIOD) % ACTIVITY_LENGTH);
    // Get last actitivy slot number
    uint8 lastSlot = uint8((_abs.lastBlockNumber / CLAIM_BLOCK_PERIOD) % ACTIVITY_LENGTH);
    // Check if there was an activity slot overflow
    // `ACTIVITY_LENGTH` is changed to `uint16` here to ensure the multiplication doesn't overflow silently
    bool overflow = (_blockNumber - _abs.lastBlockNumber) >= CLAIM_BLOCK_PERIOD * uint16(ACTIVITY_LENGTH);

    return (currentSlot, lastSlot, overflow);
  }

  /// @dev Updates the provided ABS according to the slots provided.
  /// @param _abs The Active Bridge Set to be updated.
  /// @param _currentSlot The current slot.
  /// @param _lastSlot The last slot seen by the ABS.
  /// @param _overflow Whether the current slot has overflown the last slot.
  /// @return True if update occurred.
  function updateABS(
    ActiveBridgeSet storage _abs,
    uint16 _currentSlot,
    uint16 _lastSlot,
    bool _overflow)
    private
  returns (bool)
  {
    // If there are more than `ACTIVITY_LENGTH` slots empty => remove entirely the ABS
    if (_overflow) {
      flushABS(_abs, _lastSlot, _lastSlot);
    // If ABS are not up to date => fill previous activity slots with empty activities
    } else if (_currentSlot != _lastSlot) {
      flushABS(_abs, _currentSlot, _lastSlot);
    } else {
      return false;
    }

    return true;
  }

  /// @dev Flushes the provided ABS record between lastSlot and currentSlot.
  /// @param _abs The Active Bridge Set to be flushed.
  /// @param _currentSlot The current slot.
  function flushABS(ActiveBridgeSet storage _abs, uint16 _currentSlot, uint16 _lastSlot) private {
    // For each slot elapsed, remove identities and update `nextActiveIdentities` count
    for (uint16 slot = (_lastSlot + 1) % ACTIVITY_LENGTH ; slot != _currentSlot ; slot = (slot + 1) % ACTIVITY_LENGTH) {
      flushSlot(_abs, slot);
    }
    // Update current activity slot
    flushSlot(_abs, _currentSlot);
    _abs.activeIdentities = _abs.nextActiveIdentities;
  }

  /// @dev Flushes a slot of the provided ABS.
  /// @param _abs The Active Bridge Set to be flushed.
  /// @param _slot The slot to be flushed.
  function flushSlot(ActiveBridgeSet storage _abs, uint16 _slot) private {
    // For a given slot, go through all identities to flush them
    uint256 epochIdsLength = _abs.epochIdentities[_slot].length;
    for (uint256 id = 0; id < epochIdsLength; id++) {
      flushIdentity(_abs, _abs.epochIdentities[_slot][id]);
    }
    delete _abs.epochIdentities[_slot];
  }

  /// @dev Decrements the appearance counter of an identity from the provided ABS. If the counter reaches 0, the identity is flushed.
  /// @param _abs The Active Bridge Set to be flushed.
  /// @param _address The address to be flushed.
  function flushIdentity(ActiveBridgeSet storage _abs, address _address) private {
    require(absMembership(_abs, _address), "The identity address is already out of the ARS");
    // Decrement the count of an identity, and if it reaches 0, delete it and update `nextActiveIdentities`count
    _abs.identityCount[_address]--;
    if (_abs.identityCount[_address] == 0) {
      delete _abs.identityCount[_address];
      _abs.nextActiveIdentities--;
    }
  }
}
// File: witnet-ethereum-bridge/contracts/WitnetRequestsBoardInterface.sol
/**
 * @title Witnet Requests Board Interface
 * @notice Interface of a Witnet Request Board (WRB)
 * It defines how to interact with the WRB in order to support:
 *  - Post and upgrade a data request
 *  - Read the result of a dr
 * @author Witnet Foundation
 */
interface WitnetRequestsBoardInterface {

  /// @dev Posts a data request into the WRB in expectation that it will be relayed and resolved in Witnet with a total reward that equals to msg.value.
  /// @param _dr The bytes corresponding to the Protocol Buffers serialization of the data request output.
  /// @param _tallyReward The amount of value that will be detracted from the transaction value and reserved for rewarding the reporting of the final result (aka tally) of the data request.
  /// @return The unique identifier of the data request.
  function postDataRequest(bytes calldata _dr, uint256 _tallyReward) external payable returns(uint256);

  /// @dev Increments the rewards of a data request by adding more value to it. The new request reward will be increased by msg.value minus the difference between the former tally reward and the new tally reward.
  /// @param _id The unique identifier of the data request.
  /// @param _tallyReward The new tally reward. Needs to be equal or greater than the former tally reward.
  function upgradeDataRequest(uint256 _id, uint256 _tallyReward) external payable;

  /// @dev Retrieves the DR hash of the id from the WRB.
  /// @param _id The unique identifier of the data request.
  /// @return The hash of the DR
  function readDrHash (uint256 _id) external view returns(uint256);


  /// @dev Retrieves the result (if already available) of one data request from the WRB.
  /// @param _id The unique identifier of the data request.
  /// @return The result of the DR
  function readResult (uint256 _id) external view returns(bytes memory);

  /// @notice Verifies if the block relay can be upgraded.
  /// @return true if contract is upgradable.
  function isUpgradable(address _address) external view returns(bool);

}
// File: witnet-ethereum-bridge/contracts/WitnetRequestsBoard.sol
/**
 * @title Witnet Requests Board
 * @notice Contract to bridge requests to Witnet.
 * @dev This contract enables posting requests that Witnet bridges will insert into the Witnet network.
 * The result of the requests will be posted back to this contract by the bridge nodes too.
 * @author Witnet Foundation
 */
contract WitnetRequestsBoard is WitnetRequestsBoardInterface {

  using ActiveBridgeSetLib for ActiveBridgeSetLib.ActiveBridgeSet;

  // Expiration period after which a Witnet Request can be claimed again
  uint256 public constant CLAIM_EXPIRATION = 13;

  struct DataRequest {
    bytes dr;
    uint256 inclusionReward;
    uint256 tallyReward;
    bytes result;
    // Block number at which the DR was claimed for the last time
    uint256 blockNumber;
    uint256 drHash;
    address payable pkhClaim;
  }

  // Owner of the Witnet Request Board
  address public witnet;

  // Block Relay proxy prividing verification functions
  BlockRelayProxy public blockRelay;

  // Witnet Requests within the board
  DataRequest[] public requests;

  // Set of recently active bridges
  ActiveBridgeSetLib.ActiveBridgeSet public abs;

  // Replication factor for Active Bridge Set identities
  uint8 public repFactor;

  // Event emitted when a new DR is posted
  event PostedRequest(address indexed _from, uint256 _id);

  // Event emitted when a DR inclusion proof is posted
  event IncludedRequest(address indexed _from, uint256 _id);

  // Event emitted when a result proof is posted
  event PostedResult(address indexed _from, uint256 _id);

  // Ensures the reward is not greater than the value
  modifier payingEnough(uint256 _value, uint256 _tally) {
    require(_value >= _tally, "Transaction value needs to be equal or greater than tally reward");
    _;
  }

  // Ensures the poe is valid
  modifier poeValid(
    uint256[4] memory _poe,
    uint256[2] memory _publicKey,
    uint256[2] memory _uPoint,
    uint256[4] memory _vPointHelpers) {
    require(
      verifyPoe(
        _poe,
        _publicKey,
        _uPoint,
        _vPointHelpers),
      "Not a valid PoE");
    _;
  }

  // Ensures signature (sign(msg.sender)) is valid
  modifier validSignature(
    uint256[2] memory _publicKey,
    bytes memory addrSignature) {
    require(verifySig(abi.encodePacked(msg.sender), _publicKey, addrSignature), "Not a valid signature");
    _;
  }

  // Ensures the DR inclusion proof has not been reported yet
  modifier drNotIncluded(uint256 _id) {
    require(requests[_id].drHash == 0, "DR already included");
    _;
  }

  // Ensures the DR inclusion has been already reported
  modifier drIncluded(uint256 _id) {
    require(requests[_id].drHash != 0, "DR not yet included");
    _;
  }

  // Ensures the result has not been reported yet
  modifier resultNotIncluded(uint256 _id) {
    require(requests[_id].result.length == 0, "Result already included");
    _;
  }

// Ensures the VRF is valid
  modifier vrfValid(
    uint256[4] memory _poe,
    uint256[2] memory _publicKey,
    uint256[2] memory _uPoint,
    uint256[4] memory _vPointHelpers) virtual {
    require(
      VRF.fastVerify(
        _publicKey,
        _poe,
        getLastBeacon(),
        _uPoint,
        _vPointHelpers),
      "Not a valid VRF");
    _;
  }
  // Ensures the address belongs to the active bridge set
  modifier absMember(address _address) {
    require(abs.absMembership(_address), "Not a member of the ABS");
    _;
  }

 /**
  * @notice Include an address to specify the Witnet Block Relay and a replication factor.
  * @param _blockRelayAddress BlockRelayProxy address.
  * @param _repFactor replication factor.
  */
  constructor(address _blockRelayAddress, uint8 _repFactor) public {
    blockRelay = BlockRelayProxy(_blockRelayAddress);
    witnet = msg.sender;

    // Insert an empty request so as to initialize the requests array with length > 0
    DataRequest memory request;
    requests.push(request);
    repFactor = _repFactor;
  }

  /// @dev Posts a data request into the WRB in expectation that it will be relayed and resolved in Witnet with a total reward that equals to msg.value.
  /// @param _serialized The bytes corresponding to the Protocol Buffers serialization of the data request output.
  /// @param _tallyReward The amount of value that will be detracted from the transaction value and reserved for rewarding the reporting of the final result (aka tally) of the data request.
  /// @return The unique identifier of the data request.
  function postDataRequest(bytes calldata _serialized, uint256 _tallyReward)
    external
    payable
    payingEnough(msg.value, _tallyReward)
    override
  returns(uint256)
  {
    // The initial length of the `requests` array will become the ID of the request for everything related to the WRB
    uint256 id = requests.length;

    // Create a new `DataRequest` object and initialize all the non-default fields
    DataRequest memory request;
    request.dr = _serialized;
    request.inclusionReward = SafeMath.sub(msg.value, _tallyReward);
    request.tallyReward = _tallyReward;

    // Push the new request into the contract state
    requests.push(request);

    // Let observers know that a new request has been posted
    emit PostedRequest(msg.sender, id);

    return id;
  }

  /// @dev Increments the rewards of a data request by adding more value to it. The new request reward will be increased by msg.value minus the difference between the former tally reward and the new tally reward.
  /// @param _id The unique identifier of the data request.
  /// @param _tallyReward The new tally reward. Needs to be equal or greater than the former tally reward.
  function upgradeDataRequest(uint256 _id, uint256 _tallyReward)
    external
    payable
    payingEnough(msg.value, _tallyReward)
    resultNotIncluded(_id)
    override
  {
    if (requests[_id].drHash != 0) {
      require(
        msg.value == _tallyReward,
        "Txn value should equal result reward argument (request reward already paid)"
      );
      requests[_id].tallyReward = SafeMath.add(requests[_id].tallyReward, _tallyReward);
    } else {
      requests[_id].inclusionReward = SafeMath.add(requests[_id].inclusionReward, msg.value - _tallyReward);
      requests[_id].tallyReward = SafeMath.add(requests[_id].tallyReward, _tallyReward);
    }
  }

  /// @dev Checks if the data requests from a list are claimable or not.
  /// @param _ids The list of data request identifiers to be checked.
  /// @return An array of booleans indicating if data requests are claimable or not.
  function checkDataRequestsClaimability(uint256[] calldata _ids) external view returns (bool[] memory) {
    uint256 idsLength = _ids.length;
    bool[] memory validIds = new bool[](idsLength);
    for (uint i = 0; i < idsLength; i++) {
      uint256 index = _ids[i];
      validIds[i] = (dataRequestCanBeClaimed(requests[index])) &&
        requests[index].drHash == 0 &&
        index < requests.length &&
        requests[index].result.length == 0;
    }

    return validIds;
  }

  /// @dev Presents a proof of inclusion to prove that the request was posted into Witnet so as to unlock the inclusion reward that was put aside for the claiming identity (public key hash).
  /// @param _id The unique identifier of the data request.
  /// @param _poi A proof of inclusion proving that the data request appears listed in one recent block in Witnet.
  /// @param _index The index in the merkle tree.
  /// @param _blockHash The hash of the block in which the data request was inserted.
  /// @param _epoch The epoch in which the blockHash was created.
  function reportDataRequestInclusion(
    uint256 _id,
    uint256[] calldata _poi,
    uint256 _index,
    uint256 _blockHash,
    uint256 _epoch)
    external
    drNotIncluded(_id)
 {
    // Check the data request has been claimed
    require(dataRequestCanBeClaimed(requests[_id]) == false, "Data Request has not yet been claimed");
    uint256 drOutputHash = uint256(sha256(requests[_id].dr));
    uint256 drHash = uint256(sha256(abi.encodePacked(drOutputHash, _poi[0])));

    // Update the state upon which this function depends before the external call
    requests[_id].drHash = drHash;
    require(
      blockRelay.verifyDrPoi(
      _poi,
      _blockHash,
      _epoch,
      _index,
      drOutputHash), "Invalid PoI");
    requests[_id].pkhClaim.transfer(requests[_id].inclusionReward);
    // Push requests[_id].pkhClaim to abs
    abs.pushActivity(requests[_id].pkhClaim, block.number);
    emit IncludedRequest(msg.sender, _id);
  }

  /// @dev Reports the result of a data request in Witnet.
  /// @param _id The unique identifier of the data request.
  /// @param _poi A proof of inclusion proving that the data in _result has been acknowledged by the Witnet network as being the final result for the data request by putting in a tally transaction inside a Witnet block.
  /// @param _index The position of the tally transaction in the tallies-only merkle tree in the Witnet block.
  /// @param _blockHash The hash of the block in which the result (tally) was inserted.
  /// @param _epoch The epoch in which the blockHash was created.
  /// @param _result The result itself as bytes.
  function reportResult(
    uint256 _id,
    uint256[] calldata _poi,
    uint256 _index,
    uint256 _blockHash,
    uint256 _epoch,
    bytes calldata _result)
    external
    drIncluded(_id)
    resultNotIncluded(_id)
    absMember(msg.sender)
 {

    // Ensures the result byes do not have zero length
    // This would not be a valid encoding with CBOR and could trigger a reentrancy attack
    require(_result.length != 0, "Result has zero length");

    // Update the state upon which this function depends before the external call
    requests[_id].result = _result;

    uint256 resHash = uint256(sha256(abi.encodePacked(requests[_id].drHash, _result)));
    require(
      blockRelay.verifyTallyPoi(
      _poi,
      _blockHash,
      _epoch,
      _index,
      resHash), "Invalid PoI");
    msg.sender.transfer(requests[_id].tallyReward);

    emit PostedResult(msg.sender, _id);
  }

  /// @dev Retrieves the bytes of the serialization of one data request from the WRB.
  /// @param _id The unique identifier of the data request.
  /// @return The result of the data request as bytes.
  function readDataRequest(uint256 _id) external view returns(bytes memory) {
    require(requests.length > _id, "Id not found");
    return requests[_id].dr;
  }

  /// @dev Retrieves the result (if already available) of one data request from the WRB.
  /// @param _id The unique identifier of the data request.
  /// @return The result of the DR
  function readResult(uint256 _id) external view override returns(bytes memory) {
    require(requests.length > _id, "Id not found");
    return requests[_id].result;
  }

  /// @dev Retrieves hash of the data request transaction in Witnet.
  /// @param _id The unique identifier of the data request.
  /// @return The hash of the DataRequest transaction in Witnet.
  function readDrHash(uint256 _id) external view override returns(uint256) {
    require(requests.length > _id, "Id not found");
    return requests[_id].drHash;
  }

  /// @dev Returns the number of data requests in the WRB.
  /// @return the number of data requests in the WRB.
  function requestsCount() external view returns(uint256) {
    return requests.length;
  }

  /// @notice Wrapper around the decodeProof from VRF library.
  /// @dev Decode VRF proof from bytes.
  /// @param _proof The VRF proof as an array composed of `[gamma-x, gamma-y, c, s]`.
  /// @return The VRF proof as an array composed of `[gamma-x, gamma-y, c, s]`.
  function decodeProof(bytes calldata _proof) external pure returns (uint[4] memory) {
    return VRF.decodeProof(_proof);
  }

  /// @notice Wrapper around the decodePoint from VRF library.
  /// @dev Decode EC point from bytes.
  /// @param _point The EC point as bytes.
  /// @return The point as `[point-x, point-y]`.
  function decodePoint(bytes calldata _point) external pure returns (uint[2] memory) {
    return VRF.decodePoint(_point);
  }

  /// @dev Wrapper around the computeFastVerifyParams from VRF library.
  /// @dev Compute the parameters (EC points) required for the VRF fast verification function..
  /// @param _publicKey The public key as an array composed of `[pubKey-x, pubKey-y]`.
  /// @param _proof The VRF proof as an array composed of `[gamma-x, gamma-y, c, s]`.
  /// @param _message The message (in bytes) used for computing the VRF.
  /// @return The fast verify required parameters as the tuple `([uPointX, uPointY], [sHX, sHY, cGammaX, cGammaY])`.
  function computeFastVerifyParams(uint256[2] calldata _publicKey, uint256[4] calldata _proof, bytes calldata _message)
    external pure returns (uint256[2] memory, uint256[4] memory)
  {
    return VRF.computeFastVerifyParams(_publicKey, _proof, _message);
  }

  /// @dev Updates the ABS activity with the block number provided.
  /// @param _blockNumber update the ABS until this block number.
  function updateAbsActivity(uint256 _blockNumber) external {
    require (_blockNumber <= block.number, "The provided block number has not been reached");

    abs.updateActivity(_blockNumber);
  }

  /// @dev Verifies if the contract is upgradable.
  /// @return true if the contract upgradable.
  function isUpgradable(address _address) external view override returns(bool) {
    if (_address == witnet) {
      return true;
    }
    return false;
  }

  /// @dev Claim drs to be posted to Witnet by the node.
  /// @param _ids Data request ids to be claimed.
  /// @param _poe PoE claiming eligibility.
  /// @param _uPoint uPoint coordinates as [uPointX, uPointY] corresponding to U = s*B - c*Y.
  /// @param _vPointHelpers helpers for calculating the V point as [(s*H)X, (s*H)Y, cGammaX, cGammaY]. V = s*H + cGamma.
  function claimDataRequests(
    uint256[] memory _ids,
    uint256[4] memory _poe,
    uint256[2] memory _publicKey,
    uint256[2] memory _uPoint,
    uint256[4] memory _vPointHelpers,
    bytes memory addrSignature)
    public
    validSignature(_publicKey, addrSignature)
    poeValid(_poe,_publicKey, _uPoint,_vPointHelpers)
  returns(bool)
  {
    for (uint i = 0; i < _ids.length; i++) {
      require(
        dataRequestCanBeClaimed(requests[_ids[i]]),
        "One of the listed data requests was already claimed"
      );
      requests[_ids[i]].pkhClaim = msg.sender;
      requests[_ids[i]].blockNumber = block.number;
    }
    return true;
  }

  /// @dev Read the beacon of the last block inserted.
  /// @return bytes to be signed by the node as PoE.
  function getLastBeacon() public view virtual returns(bytes memory) {
    return blockRelay.getLastBeacon();
  }

  /// @dev Claim drs to be posted to Witnet by the node.
  /// @param _poe PoE claiming eligibility.
  /// @param _publicKey The public key as an array composed of `[pubKey-x, pubKey-y]`.
  /// @param _uPoint uPoint coordinates as [uPointX, uPointY] corresponding to U = s*B - c*Y.
  /// @param _vPointHelpers helpers for calculating the V point as [(s*H)X, (s*H)Y, cGammaX, cGammaY]. V = s*H + cGamma.
  function verifyPoe(
    uint256[4] memory _poe,
    uint256[2] memory _publicKey,
    uint256[2] memory _uPoint,
    uint256[4] memory _vPointHelpers)
    internal
    view
    vrfValid(_poe,_publicKey, _uPoint,_vPointHelpers)
  returns(bool)
  {
    uint256 vrf = uint256(VRF.gammaToHash(_poe[0], _poe[1]));
    // True if vrf/(2^{256} -1) <= repFactor/abs.activeIdentities
    if (abs.activeIdentities < repFactor) {
      return true;
    }
    // We rewrote it as vrf <= ((2^{256} -1)/abs.activeIdentities)*repFactor to gain efficiency
    if (vrf <= ((~uint256(0)/abs.activeIdentities)*repFactor)) {
      return true;
    }

    return false;
  }

  /// @dev Verifies the validity of a signature.
  /// @param _message message to be verified.
  /// @param _publicKey public key of the signer as `[pubKey-x, pubKey-y]`.
  /// @param _addrSignature the signature to verify asas r||s||v.
  /// @return true or false depending the validity.
  function verifySig(
    bytes memory _message,
    uint256[2] memory _publicKey,
    bytes memory _addrSignature)
    internal
    pure
  returns(bool)
  {
    bytes32 r;
    bytes32 s;
    uint8 v;
    assembly {
            r := mload(add(_addrSignature, 0x20))
            s := mload(add(_addrSignature, 0x40))
            v := byte(0, mload(add(_addrSignature, 0x60)))
    }

    if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
      return false;
    }

    if (v != 0 && v != 1) {
      return false;
    }
    v = 28 - v;

    bytes32 msgHash = sha256(_message);
    address hashedKey = VRF.pointToAddress(_publicKey[0], _publicKey[1]);
    return ecrecover(
      msgHash,
      v,
      r,
      s) == hashedKey;
  }

  function dataRequestCanBeClaimed(DataRequest memory _request) private view returns (bool) {
    return
      (_request.blockNumber == 0 || block.number - _request.blockNumber > CLAIM_EXPIRATION) &&
      _request.drHash == 0 &&
      _request.result.length == 0;
  }

}
// File: witnet-ethereum-bridge/contracts/WitnetRequestsBoardProxy.sol
/**
 * @title Block Relay Proxy
 * @notice Contract to act as a proxy between the Witnet Bridge Interface and the Block Relay.
 * @author Witnet Foundation
 */
contract WitnetRequestsBoardProxy {

  // Address of the Witnet Request Board contract that is currently being used
  address public witnetRequestsBoardAddress;

  // Struct if the information of each controller
  struct ControllerInfo {
    // Address of the Controller
    address controllerAddress;
    // The lastId of the previous Controller
    uint256 lastId;
  }

  // Last id of the WRB controller
  uint256 internal currentLastId;

  // Instance of the current WitnetRequestBoard
  WitnetRequestsBoardInterface internal witnetRequestsBoardInstance;

  // Array with the controllers that have been used in the Proxy
  ControllerInfo[] internal controllers;

  modifier notIdentical(address _newAddress) {
    require(_newAddress != witnetRequestsBoardAddress, "The provided Witnet Requests Board instance address is already in use");
    _;
  }

 /**
  * @notice Include an address to specify the Witnet Request Board.
  * @param _witnetRequestsBoardAddress WitnetRequestBoard address.
  */
  constructor(address _witnetRequestsBoardAddress) public {
    // Initialize the first epoch pointing to the first controller
    controllers.push(ControllerInfo({controllerAddress: _witnetRequestsBoardAddress, lastId: 0}));
    witnetRequestsBoardAddress = _witnetRequestsBoardAddress;
    witnetRequestsBoardInstance = WitnetRequestsBoardInterface(_witnetRequestsBoardAddress);
  }

  /// @dev Posts a data request into the WRB in expectation that it will be relayed and resolved in Witnet with a total reward that equals to msg.value.
  /// @param _dr The bytes corresponding to the Protocol Buffers serialization of the data request output.
  /// @param _tallyReward The amount of value that will be detracted from the transaction value and reserved for rewarding the reporting of the final result (aka tally) of the data request.
  /// @return The unique identifier of the data request.
  function postDataRequest(bytes calldata _dr, uint256 _tallyReward) external payable returns(uint256) {
    uint256 n = controllers.length;
    uint256 offset = controllers[n - 1].lastId;
    // Update the currentLastId with the id in the controller plus the offSet
    currentLastId = witnetRequestsBoardInstance.postDataRequest{value: msg.value}(_dr, _tallyReward) + offset;
    return currentLastId;
  }

  /// @dev Increments the rewards of a data request by adding more value to it. The new request reward will be increased by msg.value minus the difference between the former tally reward and the new tally reward.
  /// @param _id The unique identifier of the data request.
  /// @param _tallyReward The new tally reward. Needs to be equal or greater than the former tally reward.
  function upgradeDataRequest(uint256 _id, uint256 _tallyReward) external payable {
    address wrbAddress;
    uint256 wrbOffset;
    (wrbAddress, wrbOffset) = getController(_id);
    return witnetRequestsBoardInstance.upgradeDataRequest{value: msg.value}(_id - wrbOffset, _tallyReward);
  }

  /// @dev Retrieves the DR hash of the id from the WRB.
  /// @param _id The unique identifier of the data request.
  /// @return The hash of the DR.
  function readDrHash (uint256 _id)
    external
    view
  returns(uint256)
  {
    // Get the address and the offset of the corresponding to id
    address wrbAddress;
    uint256 offsetWrb;
    (wrbAddress, offsetWrb) = getController(_id);
    // Return the result of the DR readed in the corresponding Controller with its own id
    WitnetRequestsBoardInterface wrbWithDrHash;
    wrbWithDrHash = WitnetRequestsBoardInterface(wrbAddress);
    uint256 drHash = wrbWithDrHash.readDrHash(_id - offsetWrb);
    return drHash;
  }

  /// @dev Retrieves the result (if already available) of one data request from the WRB.
  /// @param _id The unique identifier of the data request.
  /// @return The result of the DR.
  function readResult(uint256 _id) external view returns(bytes memory) {
    // Get the address and the offset of the corresponding to id
    address wrbAddress;
    uint256 offSetWrb;
    (wrbAddress, offSetWrb) = getController(_id);
    // Return the result of the DR in the corresponding Controller with its own id
    WitnetRequestsBoardInterface wrbWithResult;
    wrbWithResult = WitnetRequestsBoardInterface(wrbAddress);
    return wrbWithResult.readResult(_id - offSetWrb);
  }

  /// @notice Upgrades the Witnet Requests Board if the current one is upgradeable.
  /// @param _newAddress address of the new block relay to upgrade.
  function upgradeWitnetRequestsBoard(address _newAddress) public notIdentical(_newAddress) {
    // Require the WRB is upgradable
    require(witnetRequestsBoardInstance.isUpgradable(msg.sender), "The upgrade has been rejected by the current implementation");
    // Map the currentLastId to the corresponding witnetRequestsBoardAddress and add it to controllers
    controllers.push(ControllerInfo({controllerAddress: _newAddress, lastId: currentLastId}));
    // Upgrade the WRB
    witnetRequestsBoardAddress = _newAddress;
    witnetRequestsBoardInstance = WitnetRequestsBoardInterface(_newAddress);
  }

  /// @notice Gets the controller from an Id.
  /// @param _id id of a Data Request from which we get the controller.
  function getController(uint256 _id) internal view returns(address _controllerAddress, uint256 _offset) {
    // Check id is bigger than 0
    require(_id > 0, "Non-existent controller for id 0");

    uint256 n = controllers.length;
    // If the id is bigger than the lastId of a Controller, read the result in that Controller
    for (uint i = n; i > 0; i--) {
      if (_id > controllers[i - 1].lastId) {
        return (controllers[i - 1].controllerAddress, controllers[i - 1].lastId);
      }
    }
  }

}
// File: witnet-ethereum-bridge/contracts/BufferLib.sol
/**
 * @title A convenient wrapper around the `bytes memory` type that exposes a buffer-like interface
 * @notice The buffer has an inner cursor that tracks the final offset of every read, i.e. any subsequent read will
 * start with the byte that goes right after the last one in the previous read.
 * @dev `uint32` is used here for `cursor` because `uint16` would only enable seeking up to 8KB, which could in some
 * theoretical use cases be exceeded. Conversely, `uint32` supports up to 512MB, which cannot credibly be exceeded.
 */
library BufferLib {
  struct Buffer {
    bytes data;
    uint32 cursor;
  }

  // Ensures we access an existing index in an array
  modifier notOutOfBounds(uint32 index, uint256 length) {
    require(index < length, "Tried to read from a consumed Buffer (must rewind it first)");
    _;
  }

  /**
  * @notice Read and consume a certain amount of bytes from the buffer.
  * @param _buffer An instance of `BufferLib.Buffer`.
  * @param _length How many bytes to read and consume from the buffer.
  * @return A `bytes memory` containing the first `_length` bytes from the buffer, counting from the cursor position.
  */
  function read(Buffer memory _buffer, uint32 _length) internal pure returns (bytes memory) {
    // Make sure not to read out of the bounds of the original bytes
    require(_buffer.cursor + _length <= _buffer.data.length, "Not enough bytes in buffer when reading");

    // Create a new `bytes memory destination` value
    bytes memory destination = new bytes(_length);
    bytes memory source = _buffer.data;
    uint32 offset = _buffer.cursor;

    // Get raw pointers for source and destination
    uint sourcePointer;
    uint destinationPointer;
    assembly {
      sourcePointer := add(add(source, 32), offset)
      destinationPointer := add(destination, 32)
    }

    // Copy `_length` bytes from source to destination
    memcpy(destinationPointer, sourcePointer, uint(_length));

    // Move the cursor forward by `_length` bytes
    seek(_buffer, _length, true);

    return destination;
  }

  /**
  * @notice Read and consume the next byte from the buffer.
  * @param _buffer An instance of `BufferLib.Buffer`.
  * @return The next byte in the buffer counting from the cursor position.
  */
  function next(Buffer memory _buffer) internal pure notOutOfBounds(_buffer.cursor, _buffer.data.length) returns (byte) {
    // Return the byte at the position marked by the cursor and advance the cursor all at once
    return _buffer.data[_buffer.cursor++];
  }

  /**
  * @notice Move the inner cursor of the buffer to a relative or absolute position.
  * @param _buffer An instance of `BufferLib.Buffer`.
  * @param _offset How many bytes to move the cursor forward.
  * @param _relative Whether to count `_offset` from the last position of the cursor (`true`) or the beginning of the
  * buffer (`true`).
  * @return The final position of the cursor (will equal `_offset` if `_relative` is `false`).
  */
  // solium-disable-next-line security/no-assign-params
  function seek(Buffer memory _buffer, uint32 _offset, bool _relative) internal pure returns (uint32) {
    // Deal with relative offsets
    if (_relative) {
      require(_offset + _buffer.cursor > _offset, "Integer overflow when seeking");
      _offset += _buffer.cursor;
    }
    // Make sure not to read out of the bounds of the original bytes
    require(_offset <= _buffer.data.length, "Not enough bytes in buffer when seeking");
    _buffer.cursor = _offset;
    return _buffer.cursor;
  }

  /**
  * @notice Move the inner cursor a number of bytes forward.
  * @dev This is a simple wrapper around the relative offset case of `seek()`.
  * @param _buffer An instance of `BufferLib.Buffer`.
  * @param _relativeOffset How many bytes to move the cursor forward.
  * @return The final position of the cursor.
  */
  function seek(Buffer memory _buffer, uint32 _relativeOffset) internal pure returns (uint32) {
    return seek(_buffer, _relativeOffset, true);
  }

  /**
  * @notice Move the inner cursor back to the first byte in the buffer.
  * @param _buffer An instance of `BufferLib.Buffer`.
  */
  function rewind(Buffer memory _buffer) internal pure {
    _buffer.cursor = 0;
  }

  /**
  * @notice Read and consume the next byte from the buffer as an `uint8`.
  * @param _buffer An instance of `BufferLib.Buffer`.
  * @return The `uint8` value of the next byte in the buffer counting from the cursor position.
  */
  function readUint8(Buffer memory _buffer) internal pure notOutOfBounds(_buffer.cursor, _buffer.data.length) returns (uint8) {
    bytes memory bytesValue = _buffer.data;
    uint32 offset = _buffer.cursor;
    uint8 value;
    assembly {
      value := mload(add(add(bytesValue, 1), offset))
    }
    _buffer.cursor++;

    return value;
  }

  /**
  * @notice Read and consume the next 2 bytes from the buffer as an `uint16`.
  * @param _buffer An instance of `BufferLib.Buffer`.
  * @return The `uint16` value of the next 2 bytes in the buffer counting from the cursor position.
  */
  function readUint16(Buffer memory _buffer) internal pure notOutOfBounds(_buffer.cursor + 1, _buffer.data.length) returns (uint16) {
    bytes memory bytesValue = _buffer.data;
    uint32 offset = _buffer.cursor;
    uint16 value;
    assembly {
      value := mload(add(add(bytesValue, 2), offset))
    }
    _buffer.cursor += 2;

    return value;
  }

  /**
  * @notice Read and consume the next 4 bytes from the buffer as an `uint32`.
  * @param _buffer An instance of `BufferLib.Buffer`.
  * @return The `uint32` value of the next 4 bytes in the buffer counting from the cursor position.
  */
  function readUint32(Buffer memory _buffer) internal pure notOutOfBounds(_buffer.cursor + 3, _buffer.data.length) returns (uint32) {
    bytes memory bytesValue = _buffer.data;
    uint32 offset = _buffer.cursor;
    uint32 value;
    assembly {
      value := mload(add(add(bytesValue, 4), offset))
    }
    _buffer.cursor += 4;

    return value;
  }

  /**
  * @notice Read and consume the next 8 bytes from the buffer as an `uint64`.
  * @param _buffer An instance of `BufferLib.Buffer`.
  * @return The `uint64` value of the next 8 bytes in the buffer counting from the cursor position.
  */
  function readUint64(Buffer memory _buffer) internal pure notOutOfBounds(_buffer.cursor + 7, _buffer.data.length) returns (uint64) {
    bytes memory bytesValue = _buffer.data;
    uint32 offset = _buffer.cursor;
    uint64 value;
    assembly {
      value := mload(add(add(bytesValue, 8), offset))
    }
    _buffer.cursor += 8;

    return value;
  }

  /**
  * @notice Read and consume the next 16 bytes from the buffer as an `uint128`.
  * @param _buffer An instance of `BufferLib.Buffer`.
  * @return The `uint128` value of the next 16 bytes in the buffer counting from the cursor position.
  */
  function readUint128(Buffer memory _buffer) internal pure notOutOfBounds(_buffer.cursor + 15, _buffer.data.length) returns (uint128) {
    bytes memory bytesValue = _buffer.data;
    uint32 offset = _buffer.cursor;
    uint128 value;
    assembly {
      value := mload(add(add(bytesValue, 16), offset))
    }
    _buffer.cursor += 16;

    return value;
  }

  /**
  * @notice Read and consume the next 32 bytes from the buffer as an `uint256`.
  * @return The `uint256` value of the next 32 bytes in the buffer counting from the cursor position.
  * @param _buffer An instance of `BufferLib.Buffer`.
  */
  function readUint256(Buffer memory _buffer) internal pure notOutOfBounds(_buffer.cursor + 31, _buffer.data.length) returns (uint256) {
    bytes memory bytesValue = _buffer.data;
    uint32 offset = _buffer.cursor;
    uint256 value;
    assembly {
      value := mload(add(add(bytesValue, 32), offset))
    }
    _buffer.cursor += 32;

    return value;
  }

  /**
  * @notice Read and consume the next 2 bytes from the buffer as an IEEE 754-2008 floating point number enclosed in an
  * `int32`.
  * @dev Due to the lack of support for floating or fixed point arithmetic in the EVM, this method offsets all values
  * by 5 decimal orders so as to get a fixed precision of 5 decimal positions, which should be OK for most `float16`
  * use cases. In other words, the integer output of this method is 10,000 times the actual value. The input bytes are
  * expected to follow the 16-bit base-2 format (a.k.a. `binary16`) in the IEEE 754-2008 standard.
  * @param _buffer An instance of `BufferLib.Buffer`.
  * @return The `uint32` value of the next 4 bytes in the buffer counting from the cursor position.
  */
  function readFloat16(Buffer memory _buffer) internal pure returns (int32) {
    uint32 bytesValue = readUint16(_buffer);
    // Get bit at position 0
    uint32 sign = bytesValue & 0x8000;
    // Get bits 1 to 5, then normalize to the [-14, 15] range so as to counterweight the IEEE 754 exponent bias
    int32 exponent = (int32(bytesValue & 0x7c00) >> 10) - 15;
    // Get bits 6 to 15
    int32 significand = int32(bytesValue & 0x03ff);

    // Add 1024 to the fraction if the exponent is 0
    if (exponent == 15) {
      significand |= 0x400;
    }

    // Compute `2 ^ exponent · (1 + fraction / 1024)`
    int32 result = 0;
    if (exponent >= 0) {
      result = int32(((1 << uint256(exponent)) * 10000 * (uint256(significand) | 0x400)) >> 10);
    } else {
      result = int32((((uint256(significand) | 0x400) * 10000) / (1 << uint256(- exponent))) >> 10);
    }

    // Make the result negative if the sign bit is not 0
    if (sign != 0) {
      result *= - 1;
    }
    return result;
  }

  /**
  * @notice Copy bytes from one memory address into another.
  * @dev This function was borrowed from Nick Johnson's `solidity-stringutils` lib, and reproduced here under the terms
  * of [Apache License 2.0](https://github.com/Arachnid/solidity-stringutils/blob/master/LICENSE).
  * @param _dest Address of the destination memory.
  * @param _src Address to the source memory.
  * @param _len How many bytes to copy.
  */
  // solium-disable-next-line security/no-assign-params
  function memcpy(uint _dest, uint _src, uint _len) private pure {
    // Copy word-length chunks while possible
    for (; _len >= 32; _len -= 32) {
      assembly {
        mstore(_dest, mload(_src))
      }
      _dest += 32;
      _src += 32;
    }

    // Copy remaining bytes
    uint mask = 256 ** (32 - _len) - 1;
    assembly {
      let srcpart := and(mload(_src), not(mask))
      let destpart := and(mload(_dest), mask)
      mstore(_dest, or(destpart, srcpart))
    }
  }

}
// File: witnet-ethereum-bridge/contracts/CBOR.sol
/**
 * @title A minimalistic implementation of “RFC 7049 Concise Binary Object Representation”
 * @notice This library leverages a buffer-like structure for step-by-step decoding of bytes so as to minimize
 * the gas cost of decoding them into a useful native type.
 * @dev Most of the logic has been borrowed from Patrick Gansterer’s cbor.js library: https://github.com/paroga/cbor-js
 * TODO: add support for Array (majorType = 4)
 * TODO: add support for Map (majorType = 5)
 * TODO: add support for Float32 (majorType = 7, additionalInformation = 26)
 * TODO: add support for Float64 (majorType = 7, additionalInformation = 27)
 */
library CBOR {
  using BufferLib for BufferLib.Buffer;

  uint64 constant internal UINT64_MAX = ~uint64(0);

  struct Value {
    BufferLib.Buffer buffer;
    uint8 initialByte;
    uint8 majorType;
    uint8 additionalInformation;
    uint64 len;
    uint64 tag;
  }

  /**
   * @notice Decode a `CBOR.Value` structure into a native `bytes` value.
   * @param _cborValue An instance of `CBOR.Value`.
   * @return The value represented by the input, as a `bytes` value.
   */
  function decodeBytes(Value memory _cborValue) public pure returns(bytes memory) {
    _cborValue.len = readLength(_cborValue.buffer, _cborValue.additionalInformation);
    if (_cborValue.len == UINT64_MAX) {
      bytes memory bytesData;

      // These checks look repetitive but the equivalent loop would be more expensive.
      uint32 itemLength = uint32(readIndefiniteStringLength(_cborValue.buffer, _cborValue.majorType));
      if (itemLength < UINT64_MAX) {
        bytesData = abi.encodePacked(bytesData, _cborValue.buffer.read(itemLength));
        itemLength = uint32(readIndefiniteStringLength(_cborValue.buffer, _cborValue.majorType));
        if (itemLength < UINT64_MAX) {
          bytesData = abi.encodePacked(bytesData, _cborValue.buffer.read(itemLength));
        }
      }
      return bytesData;
    } else {
      return _cborValue.buffer.read(uint32(_cborValue.len));
    }
  }

  /**
   * @notice Decode a `CBOR.Value` structure into a `fixed16` value.
   * @dev Due to the lack of support for floating or fixed point arithmetic in the EVM, this method offsets all values
   * by 5 decimal orders so as to get a fixed precision of 5 decimal positions, which should be OK for most `fixed16`
   * use cases. In other words, the output of this method is 10,000 times the actual value, encoded into an `int32`.
   * @param _cborValue An instance of `CBOR.Value`.
   * @return The value represented by the input, as an `int128` value.
   */
  function decodeFixed16(Value memory _cborValue) public pure returns(int32) {
    require(_cborValue.majorType == 7, "Tried to read a `fixed` value from a `CBOR.Value` with majorType != 7");
    require(_cborValue.additionalInformation == 25, "Tried to read `fixed16` from a `CBOR.Value` with additionalInformation != 25");
    return _cborValue.buffer.readFloat16();
  }

  /**
 * @notice Decode a `CBOR.Value` structure into a native `int128[]` value whose inner values follow the same convention.
 * as explained in `decodeFixed16`.
 * @param _cborValue An instance of `CBOR.Value`.
 * @return The value represented by the input, as an `int128[]` value.
 */
  function decodeFixed16Array(Value memory _cborValue) public pure returns(int128[] memory) {
    require(_cborValue.majorType == 4, "Tried to read `int128[]` from a `CBOR.Value` with majorType != 4");

    uint64 length = readLength(_cborValue.buffer, _cborValue.additionalInformation);
    require(length < UINT64_MAX, "Indefinite-length CBOR arrays are not supported");

    int128[] memory array = new int128[](length);
    for (uint64 i = 0; i < length; i++) {
      Value memory item = valueFromBuffer(_cborValue.buffer);
      array[i] = decodeFixed16(item);
    }

    return array;
  }

  /**
   * @notice Decode a `CBOR.Value` structure into a native `int128` value.
   * @param _cborValue An instance of `CBOR.Value`.
   * @return The value represented by the input, as an `int128` value.
   */
  function decodeInt128(Value memory _cborValue) public pure returns(int128) {
    if (_cborValue.majorType == 1) {
      uint64 length = readLength(_cborValue.buffer, _cborValue.additionalInformation);
      return int128(-1) - int128(length);
    } else if (_cborValue.majorType == 0) {
      // Any `uint64` can be safely casted to `int128`, so this method supports majorType 1 as well so as to have offer
      // a uniform API for positive and negative numbers
      return int128(decodeUint64(_cborValue));
    }
    revert("Tried to read `int128` from a `CBOR.Value` with majorType not 0 or 1");
  }

  /**
   * @notice Decode a `CBOR.Value` structure into a native `int128[]` value.
   * @param _cborValue An instance of `CBOR.Value`.
   * @return The value represented by the input, as an `int128[]` value.
   */
  function decodeInt128Array(Value memory _cborValue) public pure returns(int128[] memory) {
    require(_cborValue.majorType == 4, "Tried to read `int128[]` from a `CBOR.Value` with majorType != 4");

    uint64 length = readLength(_cborValue.buffer, _cborValue.additionalInformation);
    require(length < UINT64_MAX, "Indefinite-length CBOR arrays are not supported");

    int128[] memory array = new int128[](length);
    for (uint64 i = 0; i < length; i++) {
      Value memory item = valueFromBuffer(_cborValue.buffer);
      array[i] = decodeInt128(item);
    }

    return array;
  }

  /**
   * @notice Decode a `CBOR.Value` structure into a native `string` value.
   * @param _cborValue An instance of `CBOR.Value`.
   * @return The value represented by the input, as a `string` value.
   */
  function decodeString(Value memory _cborValue) public pure returns(string memory) {
    _cborValue.len = readLength(_cborValue.buffer, _cborValue.additionalInformation);
    if (_cborValue.len == UINT64_MAX) {
      bytes memory textData;
      bool done;
      while (!done) {
        uint64 itemLength = readIndefiniteStringLength(_cborValue.buffer, _cborValue.majorType);
        if (itemLength < UINT64_MAX) {
          textData = abi.encodePacked(textData, readText(_cborValue.buffer, itemLength / 4));
        } else {
          done = true;
        }
      }
      return string(textData);
    } else {
      return string(readText(_cborValue.buffer, _cborValue.len));
    }
  }

  /**
   * @notice Decode a `CBOR.Value` structure into a native `string[]` value.
   * @param _cborValue An instance of `CBOR.Value`.
   * @return The value represented by the input, as an `string[]` value.
   */
  function decodeStringArray(Value memory _cborValue) public pure returns(string[] memory) {
    require(_cborValue.majorType == 4, "Tried to read `string[]` from a `CBOR.Value` with majorType != 4");

    uint64 length = readLength(_cborValue.buffer, _cborValue.additionalInformation);
    require(length < UINT64_MAX, "Indefinite-length CBOR arrays are not supported");

    string[] memory array = new string[](length);
    for (uint64 i = 0; i < length; i++) {
      Value memory item = valueFromBuffer(_cborValue.buffer);
      array[i] = decodeString(item);
    }

    return array;
  }

  /**
   * @notice Decode a `CBOR.Value` structure into a native `uint64` value.
   * @param _cborValue An instance of `CBOR.Value`.
   * @return The value represented by the input, as an `uint64` value.
   */
  function decodeUint64(Value memory _cborValue) public pure returns(uint64) {
    require(_cborValue.majorType == 0, "Tried to read `uint64` from a `CBOR.Value` with majorType != 0");
    return readLength(_cborValue.buffer, _cborValue.additionalInformation);
  }

  /**
   * @notice Decode a `CBOR.Value` structure into a native `uint64[]` value.
   * @param _cborValue An instance of `CBOR.Value`.
   * @return The value represented by the input, as an `uint64[]` value.
   */
  function decodeUint64Array(Value memory _cborValue) public pure returns(uint64[] memory) {
    require(_cborValue.majorType == 4, "Tried to read `uint64[]` from a `CBOR.Value` with majorType != 4");

    uint64 length = readLength(_cborValue.buffer, _cborValue.additionalInformation);
    require(length < UINT64_MAX, "Indefinite-length CBOR arrays are not supported");

    uint64[] memory array = new uint64[](length);
    for (uint64 i = 0; i < length; i++) {
      Value memory item = valueFromBuffer(_cborValue.buffer);
      array[i] = decodeUint64(item);
    }

    return array;
  }

  /**
   * @notice Decode a CBOR.Value structure from raw bytes.
   * @dev This is the main factory for CBOR.Value instances, which can be later decoded into native EVM types.
   * @param _cborBytes Raw bytes representing a CBOR-encoded value.
   * @return A `CBOR.Value` instance containing a partially decoded value.
   */
  function valueFromBytes(bytes memory _cborBytes) public pure returns(Value memory) {
    BufferLib.Buffer memory buffer = BufferLib.Buffer(_cborBytes, 0);

    return valueFromBuffer(buffer);
  }

  /**
   * @notice Decode a CBOR.Value structure from raw bytes.
   * @dev This is an alternate factory for CBOR.Value instances, which can be later decoded into native EVM types.
   * @param _buffer A Buffer structure representing a CBOR-encoded value.
   * @return A `CBOR.Value` instance containing a partially decoded value.
   */
  function valueFromBuffer(BufferLib.Buffer memory _buffer) public pure returns(Value memory) {
    require(_buffer.data.length > 0, "Found empty buffer when parsing CBOR value");

    uint8 initialByte;
    uint8 majorType = 255;
    uint8 additionalInformation;
    uint64 length;
    uint64 tag = UINT64_MAX;

    bool isTagged = true;
    while (isTagged) {
      // Extract basic CBOR properties from input bytes
      initialByte = _buffer.readUint8();
      majorType = initialByte >> 5;
      additionalInformation = initialByte & 0x1f;

      // Early CBOR tag parsing.
      if (majorType == 6) {
        tag = readLength(_buffer, additionalInformation);
      } else {
        isTagged = false;
      }
    }

    require(majorType <= 7, "Invalid CBOR major type");

    return CBOR.Value(
      _buffer,
      initialByte,
      majorType,
      additionalInformation,
      length,
      tag);
  }

  // Reads the length of the next CBOR item from a buffer, consuming a different number of bytes depending on the
  // value of the `additionalInformation` argument.
  function readLength(BufferLib.Buffer memory _buffer, uint8 additionalInformation) private pure returns(uint64) {
    if (additionalInformation < 24) {
      return additionalInformation;
    }
    if (additionalInformation == 24) {
      return _buffer.readUint8();
    }
    if (additionalInformation == 25) {
      return _buffer.readUint16();
    }
    if (additionalInformation == 26) {
      return _buffer.readUint32();
    }
    if (additionalInformation == 27) {
      return _buffer.readUint64();
    }
    if (additionalInformation == 31) {
      return UINT64_MAX;
    }
    revert("Invalid length encoding (non-existent additionalInformation value)");
  }

  // Read the length of a CBOR indifinite-length item (arrays, maps, byte strings and text) from a buffer, consuming
  // as many bytes as specified by the first byte.
  function readIndefiniteStringLength(BufferLib.Buffer memory _buffer, uint8 majorType) private pure returns(uint64) {
    uint8 initialByte = _buffer.readUint8();
    if (initialByte == 0xff) {
      return UINT64_MAX;
    }
    uint64 length = readLength(_buffer, initialByte & 0x1f);
    require(length < UINT64_MAX && (initialByte >> 5) == majorType, "Invalid indefinite length");
    return length;
  }

  // Read a text string of a given length from a buffer. Returns a `bytes memory` value for the sake of genericness,
  // but it can be easily casted into a string with `string(result)`.
  // solium-disable-next-line security/no-assign-params
  function readText(BufferLib.Buffer memory _buffer, uint64 _length) private pure returns(bytes memory) {
    bytes memory result;
    for (uint64 index = 0; index < _length; index++) {
      uint8 value = _buffer.readUint8();
      if (value & 0x80 != 0) {
        if (value < 0xe0) {
          value = (value & 0x1f) << 6 |
            (_buffer.readUint8() & 0x3f);
          _length -= 1;
        } else if (value < 0xf0) {
          value = (value & 0x0f) << 12 |
            (_buffer.readUint8() & 0x3f) << 6 |
            (_buffer.readUint8() & 0x3f);
          _length -= 2;
        } else {
          value = (value & 0x0f) << 18 |
            (_buffer.readUint8() & 0x3f) << 12 |
            (_buffer.readUint8() & 0x3f) << 6  |
            (_buffer.readUint8() & 0x3f);
          _length -= 3;
        }
      }
      result = abi.encodePacked(result, value);
    }
    return result;
  }
}
// File: witnet-ethereum-bridge/contracts/Witnet.sol
/**
 * @title A library for decoding Witnet request results
 * @notice The library exposes functions to check the Witnet request success.
 * and retrieve Witnet results from CBOR values into solidity types.
 */
library Witnet {
  using CBOR for CBOR.Value;

  /*
    STRUCTS
  */
  struct Result {
    bool success;
    CBOR.Value cborValue;
  }

  /*
    ENUMS
  */
  enum ErrorCodes {
    // 0x00: Unknown error. Something went really bad!
    Unknown,
    // Script format errors
    /// 0x01: At least one of the source scripts is not a valid CBOR-encoded value.
    SourceScriptNotCBOR,
    /// 0x02: The CBOR value decoded from a source script is not an Array.
    SourceScriptNotArray,
    /// 0x03: The Array value decoded form a source script is not a valid RADON script.
    SourceScriptNotRADON,
    /// Unallocated
    ScriptFormat0x04,
    ScriptFormat0x05,
    ScriptFormat0x06,
    ScriptFormat0x07,
    ScriptFormat0x08,
    ScriptFormat0x09,
    ScriptFormat0x0A,
    ScriptFormat0x0B,
    ScriptFormat0x0C,
    ScriptFormat0x0D,
    ScriptFormat0x0E,
    ScriptFormat0x0F,
    // Complexity errors
    /// 0x10: The request contains too many sources.
    RequestTooManySources,
    /// 0x11: The script contains too many calls.
    ScriptTooManyCalls,
    /// Unallocated
    Complexity0x12,
    Complexity0x13,
    Complexity0x14,
    Complexity0x15,
    Complexity0x16,
    Complexity0x17,
    Complexity0x18,
    Complexity0x19,
    Complexity0x1A,
    Complexity0x1B,
    Complexity0x1C,
    Complexity0x1D,
    Complexity0x1E,
    Complexity0x1F,
    // Operator errors
    /// 0x20: The operator does not exist.
    UnsupportedOperator,
    /// Unallocated
    Operator0x21,
    Operator0x22,
    Operator0x23,
    Operator0x24,
    Operator0x25,
    Operator0x26,
    Operator0x27,
    Operator0x28,
    Operator0x29,
    Operator0x2A,
    Operator0x2B,
    Operator0x2C,
    Operator0x2D,
    Operator0x2E,
    Operator0x2F,
    // Retrieval-specific errors
    /// 0x30: At least one of the sources could not be retrieved, but returned HTTP error.
    HTTP,
    /// 0x31: Retrieval of at least one of the sources timed out.
    RetrievalTimeout,
    /// Unallocated
    Retrieval0x32,
    Retrieval0x33,
    Retrieval0x34,
    Retrieval0x35,
    Retrieval0x36,
    Retrieval0x37,
    Retrieval0x38,
    Retrieval0x39,
    Retrieval0x3A,
    Retrieval0x3B,
    Retrieval0x3C,
    Retrieval0x3D,
    Retrieval0x3E,
    Retrieval0x3F,
    // Math errors
    /// 0x40: Math operator caused an underflow.
    Underflow,
    /// 0x41: Math operator caused an overflow.
    Overflow,
    /// 0x42: Tried to divide by zero.
    DivisionByZero,
    Size
  }

  /*
  Result impl's
  */

 /**
   * @notice Decode raw CBOR bytes into a Result instance.
   * @param _cborBytes Raw bytes representing a CBOR-encoded value.
   * @return A `Result` instance.
   */
  function resultFromCborBytes(bytes calldata _cborBytes) external pure returns(Result memory) {
    CBOR.Value memory cborValue = CBOR.valueFromBytes(_cborBytes);
    return resultFromCborValue(cborValue);
  }

 /**
   * @notice Decode a CBOR value into a Result instance.
   * @param _cborValue An instance of `CBOR.Value`.
   * @return A `Result` instance.
   */
  function resultFromCborValue(CBOR.Value memory _cborValue) public pure returns(Result memory) {
    // Witnet uses CBOR tag 39 to represent RADON error code identifiers.
    // [CBOR tag 39] Identifiers for CBOR: https://github.com/lucas-clemente/cbor-specs/blob/master/id.md
    bool success = _cborValue.tag != 39;
    return Result(success, _cborValue);
  }

  /**
   * @notice Tell if a Result is successful.
   * @param _result An instance of Result.
   * @return `true` if successful, `false` if errored.
   */
  function isOk(Result memory _result) public pure returns(bool) {
    return _result.success;
  }

  /**
   * @notice Tell if a Result is errored.
   * @param _result An instance of Result.
   * @return `true` if errored, `false` if successful.
   */
  function isError(Result memory _result) public pure returns(bool) {
    return !_result.success;
  }

  /**
   * @notice Decode a bytes value from a Result as a `bytes` value.
   * @param _result An instance of Result.
   * @return The `bytes` decoded from the Result.
   */
  function asBytes(Result memory _result) public pure returns(bytes memory) {
    require(_result.success, "Tried to read bytes value from errored Result");
    return _result.cborValue.decodeBytes();
  }

  /**
   * @notice Decode an error code from a Result as a member of `ErrorCodes`.
   * @param _result An instance of `Result`.
   * @return The `CBORValue.Error memory` decoded from the Result.
   */
  function asErrorCode(Result memory _result) public pure returns(ErrorCodes) {
    uint64[] memory error = asRawError(_result);
    return supportedErrorOrElseUnknown(error[0]);
  }

  /**
   * @notice Generate a suitable error message for a member of `ErrorCodes` and its corresponding arguments.
   * @dev WARN: Note that client contracts should wrap this function into a try-catch foreseing potential errors generated in this function
   * @param _result An instance of `Result`.
   * @return A tuple containing the `CBORValue.Error memory` decoded from the `Result`, plus a loggable error message.
   */
  function asErrorMessage(Result memory _result) public pure returns(ErrorCodes, string memory) {
    uint64[] memory error = asRawError(_result);
    ErrorCodes errorCode = supportedErrorOrElseUnknown(error[0]);
    bytes memory errorMessage;

    if (errorCode == ErrorCodes.SourceScriptNotCBOR) {
      errorMessage = abi.encodePacked("Source script #", utoa(error[1]), " was not a valid CBOR value");
    } else if (errorCode == ErrorCodes.SourceScriptNotArray) {
      errorMessage = abi.encodePacked("The CBOR value in script #", utoa(error[1]), " was not an Array of calls");
    } else if (errorCode == ErrorCodes.SourceScriptNotRADON) {
      errorMessage = abi.encodePacked("The CBOR value in script #", utoa(error[1]), " was not a valid RADON script");
    } else if (errorCode == ErrorCodes.RequestTooManySources) {
      errorMessage = abi.encodePacked("The request contained too many sources (", utoa(error[1]), ")");
    } else if (errorCode == ErrorCodes.ScriptTooManyCalls) {
      errorMessage = abi.encodePacked(
        "Script #",
        utoa(error[2]),
        " from the ",
        stageName(error[1]),
        " stage contained too many calls (",
        utoa(error[3]),
        ")"
      );
    } else if (errorCode == ErrorCodes.UnsupportedOperator) {
      errorMessage = abi.encodePacked(
      "Operator code 0x",
        utohex(error[4]),
        " found at call #",
        utoa(error[3]),
        " in script #",
        utoa(error[2]),
        " from ",
        stageName(error[1]),
        " stage is not supported"
      );
    } else if (errorCode == ErrorCodes.HTTP) {
      errorMessage = abi.encodePacked(
        "Source #",
        utoa(error[1]),
        " could not be retrieved. Failed with HTTP error code: ",
        utoa(error[2] / 100),
        utoa(error[2] % 100 / 10),
        utoa(error[2] % 10)
      );
    } else if (errorCode == ErrorCodes.RetrievalTimeout) {
      errorMessage = abi.encodePacked(
        "Source #",
        utoa(error[1]),
        " could not be retrieved because of a timeout."
      );
    } else if (errorCode == ErrorCodes.Underflow) {
      errorMessage = abi.encodePacked(
        "Underflow at operator code 0x",
        utohex(error[4]),
        " found at call #",
        utoa(error[3]),
        " in script #",
        utoa(error[2]),
        " from ",
        stageName(error[1]),
        " stage"
      );
    } else if (errorCode == ErrorCodes.Overflow) {
      errorMessage = abi.encodePacked(
        "Overflow at operator code 0x",
        utohex(error[4]),
        " found at call #",
        utoa(error[3]),
        " in script #",
        utoa(error[2]),
        " from ",
        stageName(error[1]),
        " stage"
      );
    } else if (errorCode == ErrorCodes.DivisionByZero) {
      errorMessage = abi.encodePacked(
        "Division by zero at operator code 0x",
        utohex(error[4]),
        " found at call #",
        utoa(error[3]),
        " in script #",
        utoa(error[2]),
        " from ",
        stageName(error[1]),
        " stage"
      );
    } else {
      errorMessage = abi.encodePacked("Unknown error (0x", utohex(error[0]), ")");
    }

    return (errorCode, string(errorMessage));
  }

  /**
   * @notice Decode a raw error from a `Result` as a `uint64[]`.
   * @param _result An instance of `Result`.
   * @return The `uint64[]` raw error as decoded from the `Result`.
   */
  function asRawError(Result memory _result) public pure returns(uint64[] memory) {
    require(!_result.success, "Tried to read error code from successful Result");
    return _result.cborValue.decodeUint64Array();
  }

  /**
   * @notice Decode a fixed16 (half-precision) numeric value from a Result as an `int32` value.
   * @dev Due to the lack of support for floating or fixed point arithmetic in the EVM, this method offsets all values.
   * by 5 decimal orders so as to get a fixed precision of 5 decimal positions, which should be OK for most `fixed16`.
   * use cases. In other words, the output of this method is 10,000 times the actual value, encoded into an `int32`.
   * @param _result An instance of Result.
   * @return The `int128` decoded from the Result.
   */
  function asFixed16(Result memory _result) public pure returns(int32) {
    require(_result.success, "Tried to read `fixed16` value from errored Result");
    return _result.cborValue.decodeFixed16();
  }

  /**
   * @notice Decode an array of fixed16 values from a Result as an `int128[]` value.
   * @param _result An instance of Result.
   * @return The `int128[]` decoded from the Result.
   */
  function asFixed16Array(Result memory _result) public pure returns(int128[] memory) {
    require(_result.success, "Tried to read `fixed16[]` value from errored Result");
    return _result.cborValue.decodeFixed16Array();
  }

  /**
   * @notice Decode a integer numeric value from a Result as an `int128` value.
   * @param _result An instance of Result.
   * @return The `int128` decoded from the Result.
   */
  function asInt128(Result memory _result) public pure returns(int128) {
    require(_result.success, "Tried to read `int128` value from errored Result");
    return _result.cborValue.decodeInt128();
  }

  /**
   * @notice Decode an array of integer numeric values from a Result as an `int128[]` value.
   * @param _result An instance of Result.
   * @return The `int128[]` decoded from the Result.
   */
  function asInt128Array(Result memory _result) public pure returns(int128[] memory) {
    require(_result.success, "Tried to read `int128[]` value from errored Result");
    return _result.cborValue.decodeInt128Array();
  }

  /**
   * @notice Decode a string value from a Result as a `string` value.
   * @param _result An instance of Result.
   * @return The `string` decoded from the Result.
   */
  function asString(Result memory _result) public pure returns(string memory) {
    require(_result.success, "Tried to read `string` value from errored Result");
    return _result.cborValue.decodeString();
  }

  /**
   * @notice Decode an array of string values from a Result as a `string[]` value.
   * @param _result An instance of Result.
   * @return The `string[]` decoded from the Result.
   */
  function asStringArray(Result memory _result) public pure returns(string[] memory) {
    require(_result.success, "Tried to read `string[]` value from errored Result");
    return _result.cborValue.decodeStringArray();
  }

  /**
   * @notice Decode a natural numeric value from a Result as a `uint64` value.
   * @param _result An instance of Result.
   * @return The `uint64` decoded from the Result.
   */
  function asUint64(Result memory _result) public pure returns(uint64) {
    require(_result.success, "Tried to read `uint64` value from errored Result");
    return _result.cborValue.decodeUint64();
  }

  /**
   * @notice Decode an array of natural numeric values from a Result as a `uint64[]` value.
   * @param _result An instance of Result.
   * @return The `uint64[]` decoded from the Result.
   */
  function asUint64Array(Result memory _result) public pure returns(uint64[] memory) {
    require(_result.success, "Tried to read `uint64[]` value from errored Result");
    return _result.cborValue.decodeUint64Array();
  }

  /**
   * @notice Convert a stage index number into the name of the matching Witnet request stage.
   * @param _stageIndex A `uint64` identifying the index of one of the Witnet request stages.
   * @return The name of the matching stage.
   */
  function stageName(uint64 _stageIndex) public pure returns(string memory) {
    if (_stageIndex == 0) {
      return "retrieval";
    } else if (_stageIndex == 1) {
      return "aggregation";
    } else if (_stageIndex == 2) {
      return "tally";
    } else {
      return "unknown";
    }
  }

  /**
  * @notice Get an `ErrorCodes` item from its `uint64` discriminant, or default to `ErrorCodes.Unknown` if it doesn't
  * exist.
  * @param _discriminant The numeric identifier of an error.
  * @return A member of `ErrorCodes`.
  */
  function supportedErrorOrElseUnknown(uint64 _discriminant) private pure returns(ErrorCodes) {
    if (_discriminant < uint8(ErrorCodes.Size)) {
      return ErrorCodes(_discriminant);
    } else {
      return ErrorCodes.Unknown;
    }
  }

  /**
   * @notice Convert a `uint64` into a 1, 2 or 3 characters long `string` representing its.
   * three less significant decimal values.
   * @param _u A `uint64` value.
   * @return The `string` representing its decimal value.
   */
  function utoa(uint64 _u) private pure returns(string memory) {
    if (_u < 10) {
      bytes memory b1 = new bytes(1);
      b1[0] = byte(uint8(_u) + 48);
      return string(b1);
    } else if (_u < 100) {
      bytes memory b2 = new bytes(2);
      b2[0] = byte(uint8(_u / 10) + 48);
      b2[1] = byte(uint8(_u % 10) + 48);
      return string(b2);
    } else {
      bytes memory b3 = new bytes(3);
      b3[0] = byte(uint8(_u / 100) + 48);
      b3[1] = byte(uint8(_u % 100 / 10) + 48);
      b3[2] = byte(uint8(_u % 10) + 48);
      return string(b3);
    }
  }

  /**
 * @notice Convert a `uint64` into a 2 characters long `string` representing its two less significant hexadecimal values.
 * @param _u A `uint64` value.
 * @return The `string` representing its hexadecimal value.
 */
  function utohex(uint64 _u) private pure returns(string memory) {
    bytes memory b2 = new bytes(2);
    uint8 d0 = uint8(_u / 16) + 48;
    uint8 d1 = uint8(_u % 16) + 48;
    if (d0 > 57)
      d0 += 7;
    if (d1 > 57)
      d1 += 7;
    b2[0] = byte(d0);
    b2[1] = byte(d1);
    return string(b2);
  }
}
// File: witnet-ethereum-bridge/contracts/Request.sol
/**
 * @title The serialized form of a Witnet data request
 */
contract Request {
  bytes public bytecode;
  uint256 public id;

 /**
  * @dev A `Request` is constructed around a `bytes memory` value containing a well-formed Witnet data request serialized
  * using Protocol Buffers. However, we cannot verify its validity at this point. This implies that contracts using
  * the WRB should not be considered trustless before a valid Proof-of-Inclusion has been posted for the requests.
  * The hash of the request is computed in the constructor to guarantee consistency. Otherwise there could be a
  * mismatch and a data request could be resolved with the result of another.
  * @param _bytecode Witnet request in bytes.
  */
  constructor(bytes memory _bytecode) public {
    bytecode = _bytecode;
    id = uint256(sha256(_bytecode));
  }
}
// File: witnet-ethereum-bridge/contracts/UsingWitnet.sol
/**
 * @title The UsingWitnet contract
 * @notice Contract writers can inherit this contract in order to create requests for the
 * Witnet network.
 */
contract UsingWitnet {
  using Witnet for Witnet.Result;

  WitnetRequestsBoardProxy internal wrb;

 /**
  * @notice Include an address to specify the WitnetRequestsBoard.
  * @param _wrb WitnetRequestsBoard address.
  */
  constructor(address _wrb) public {
    wrb = WitnetRequestsBoardProxy(_wrb);
  }

  // Provides a convenient way for client contracts extending this to block the execution of the main logic of the
  // contract until a particular request has been successfully accepted into Witnet
  modifier witnetRequestAccepted(uint256 _id) {
    require(witnetCheckRequestAccepted(_id), "Witnet request is not yet accepted into the Witnet network");
    _;
  }

  // Ensures that user-specified rewards are equal to the total transaction value to prevent users from burning any excess value
  modifier validRewards(uint256 _requestReward, uint256 _resultReward) {
    require(_requestReward + _resultReward >= _requestReward, "The sum of rewards overflows");
    require(msg.value == _requestReward + _resultReward, "Transaction value should equal the sum of rewards");
    _;
  }

  /**
  * @notice Send a new request to the Witnet network
  * @dev Call to `post_dr` function in the WitnetRequestsBoard contract
  * @param _request An instance of the `Request` contract
  * @param _requestReward Reward specified for the user which posts the request into Witnet
  * @param _resultReward Reward specified for the user which posts back the request result
  * @return Sequencial identifier for the request included in the WitnetRequestsBoard
  */
  function witnetPostRequest(Request _request, uint256 _requestReward, uint256 _resultReward)
    internal
    validRewards(_requestReward, _resultReward)
  returns (uint256)
  {
    return wrb.postDataRequest.value(_requestReward + _resultReward)(_request.bytecode(), _resultReward);
  }

  /**
  * @notice Check if a request has been accepted into Witnet.
  * @dev Contracts depending on Witnet should not start their main business logic (e.g. receiving value from third.
  * parties) before this method returns `true`.
  * @param _id The sequential identifier of a request that has been previously sent to the WitnetRequestsBoard.
  * @return A boolean telling if the request has been already accepted or not. `false` do not mean rejection, though.
  */
  function witnetCheckRequestAccepted(uint256 _id) internal view returns (bool) {
    // Find the request in the
    uint256 drHash = wrb.readDrHash(_id);
    // If the hash of the data request transaction in Witnet is not the default, then it means that inclusion of the
    // request has been proven to the WRB.
    return drHash != 0;
  }

  /**
  * @notice Upgrade the rewards for a Data Request previously included.
  * @dev Call to `upgrade_dr` function in the WitnetRequestsBoard contract.
  * @param _id The sequential identifier of a request that has been previously sent to the WitnetRequestsBoard.
  * @param _requestReward Reward specified for the user which posts the request into Witnet
  * @param _resultReward Reward specified for the user which post the Data Request result.
  */
  function witnetUpgradeRequest(uint256 _id, uint256 _requestReward, uint256 _resultReward)
    internal
    validRewards(_requestReward, _resultReward)
  {
    wrb.upgradeDataRequest.value(msg.value)(_id, _resultReward);
  }

  /**
  * @notice Read the result of a resolved request.
  * @dev Call to `read_result` function in the WitnetRequestsBoard contract.
  * @param _id The sequential identifier of a request that was posted to Witnet.
  * @return The result of the request as an instance of `Result`.
  */
  function witnetReadResult(uint256 _id) internal view returns (Witnet.Result memory) {
    return Witnet.resultFromCborBytes(wrb.readResult(_id));
  }
}
// File: adomedianizer/contracts/IERC2362.sol
/**
    * @dev EIP2362 Interface for pull oracles
    * https://github.com/tellor-io/EIP-2362
*/
interface IERC2362
{
	/**
	 * @dev Exposed function pertaining to EIP standards
	 * @param _id bytes32 ID of the query
	 * @return int,uint,uint returns the value, timestamp, and status code of query
	 */
	function valueFor(bytes32 _id) external view returns(int256,uint256,uint256);
}
// File: witnet-price-feeds-examples/contracts/requests/BitcoinPrice.sol
// The bytecode of the BitcoinPrice request that will be sent to Witnet
contract BitcoinPriceRequest is Request {
  constructor () Request(hex"0abb0108c3aafbf405123b122468747470733a2f2f7777772e6269747374616d702e6e65742f6170692f7469636b65722f1a13841877821864646c6173748218571903e8185b125c123168747470733a2f2f6170692e636f696e6465736b2e636f6d2f76312f6270692f63757272656e7470726963652e6a736f6e1a2786187782186663627069821866635553448218646a726174655f666c6f61748218571903e8185b1a0d0a0908051205fa3fc00000100322090a0508051201011003100a18042001280130013801400248055046") public { }
}
// File: witnet-price-feeds-examples/contracts/bitcoin_price_feed/BtcUsdPriceFeed.sol
// Import the UsingWitnet library that enables interacting with Witnet

// Import the ERC2362 interface

// Import the BitcoinPrice request that you created before


// Your contract needs to inherit from UsingWitnet
contract BtcUsdPriceFeed is UsingWitnet, IERC2362 {
  // The public Bitcoin price point
  uint64 public lastPrice;

  // Stores the ID of the last Witnet request
  uint256 public lastRequestId;

  // Stores the timestamp of the last time the public price point was updated
  uint256 public timestamp;

  // Tells if an update has been requested but not yet completed
  bool public pending;

  // The Witnet request object, is set in the constructor
  Request public request;

  // Emits when the price is updated
  event priceUpdated(uint64);

  // Emits when found an error decoding request result
  event resultError(string);

  // This is `keccak256("Price-BTC/USD-3")`
  bytes32 constant public BTCUSD3ID = bytes32(hex"637b7efb6b620736c247aaa282f3898914c0bef6c12faff0d3fe9d4bea783020");

  // This constructor does a nifty trick to tell the `UsingWitnet` library where
  // to find the Witnet contracts on whatever Ethereum network you use.
  constructor (address _wrb) UsingWitnet(_wrb) public {
    // Instantiate the Witnet request
    request = new BitcoinPriceRequest();
  }

  /**
  * @notice Sends `request` to the WitnetRequestsBoard.
  * @dev This method will only succeed if `pending` is 0.
  **/
  function requestUpdate() public payable {
    require(!pending, "An update is already pending. Complete it first before requesting another update.");

    // Amount to pay to the bridge node relaying this request from Ethereum to Witnet
    uint256 _witnetRequestReward = 100 szabo;
    // Amount of wei to pay to the bridge node relaying the result from Witnet to Ethereum
    uint256 _witnetResultReward = 100 szabo;

    // Send the request to Witnet and store the ID for later retrieval of the result
    // The `witnetPostRequest` method comes with `UsingWitnet`
    lastRequestId = witnetPostRequest(request, _witnetRequestReward, _witnetResultReward);

    // Signal that there is already a pending request
    pending = true;
  }

  /**
  * @notice Reads the result, if ready, from the WitnetRequestsBoard.
  * @dev The `witnetRequestAccepted` modifier comes with `UsingWitnet` and allows to
  * protect your methods from being called before the request has been successfully
  * relayed into Witnet.
  **/
  function completeUpdate() public witnetRequestAccepted(lastRequestId) {
    require(pending, "There is no pending update.");

    // Read the result of the Witnet request
    // The `witnetReadResult` method comes with `UsingWitnet`
    Witnet.Result memory result = witnetReadResult(lastRequestId);

    // If the Witnet request succeeded, decode the result and update the price point
    // If it failed, revert the transaction with a pretty-printed error message
    if (result.isOk()) {
      lastPrice = result.asUint64();
      timestamp = block.timestamp;
      emit priceUpdated(lastPrice);
    } else {
      string memory errorMessage;

      // Try to read the value as an error message, catch error bytes if read fails
      try result.asErrorMessage() returns (Witnet.ErrorCodes errorCode, string memory e) {
        errorMessage = e;
      }
      catch (bytes memory errorBytes){
        errorMessage = string(errorBytes);
      }
      emit resultError(errorMessage);
    }

    // In any case, set `pending` to false so a new update can be requested
    pending = false;
  }

  /**
  * @notice Exposes the public data point in an ERC2362 compliant way.
  * @dev Returns error `400` if queried for an unknown data point, and `404` if `completeUpdate` has never been called
  * successfully before.
  **/
  function valueFor(bytes32 _id) external view override returns(int256, uint256, uint256) {
    // Unsupported data point ID
    if(_id != BTCUSD3ID) return(0, 0, 400);
    // No value is yet available for the queried data point ID
    if (timestamp == 0) return(0, 0, 404);

    int256 value = int256(lastPrice);

    return(value, timestamp, 200);
  }
}
// File: witnet-price-feeds-examples/contracts/requests/EthPrice.sol
// The bytecode of the EthPrice request that will be sent to Witnet
contract EthPriceRequest is Request {
  constructor () Request(hex"0a850208d7affbf4051245122e68747470733a2f2f7777772e6269747374616d702e6e65742f6170692f76322f7469636b65722f6574687573642f1a13841877821864646c6173748218571903e8185b1247122068747470733a2f2f6170692e636f696e6361702e696f2f76322f6173736574731a238618778218616464617461821818018218646870726963655573648218571903e8185b1253122668747470733a2f2f6170692e636f696e70617072696b612e636f6d2f76312f7469636b6572731a29871876821818038218666671756f746573821866635553448218646570726963658218571903e8185b1a0d0a0908051205fa3fc00000100322090a0508051201011003100a18042001280130013801400248055046") public { }
}
// File: witnet-price-feeds-examples/contracts/eth_price_feed/EthUsdPriceFeed.sol
// Import the UsingWitnet library that enables interacting with Witnet

// Import the ERC2362 interface

// Import the ethPrice request that you created before


// Your contract needs to inherit from UsingWitnet
contract EthUsdPriceFeed is UsingWitnet, IERC2362 {

  // The public eth price point
  uint64 public lastPrice;

  // Stores the ID of the last Witnet request
  uint256 public lastRequestId;

  // Stores the timestamp of the last time the public price point was updated
  uint256 public timestamp;

  // Tells if an update has been requested but not yet completed
  bool public pending;

  // The Witnet request object, is set in the constructor
  Request public request;

  // Emits when the price is updated
  event priceUpdated(uint64);

  // Emits when found an error decoding request result
  event resultError(string);

  // This is the ERC2362 identifier for a eth price feed, computed as `keccak256("Price-ETH/USD-3")`
  bytes32 constant public ETHUSD3ID = bytes32(hex"dfaa6f747f0f012e8f2069d6ecacff25f5cdf0258702051747439949737fc0b5");

  // This constructor does a nifty trick to tell the `UsingWitnet` library where
  // to find the Witnet contracts on whatever Ethereum network you use.
  constructor (address _wrb) UsingWitnet(_wrb) public {
    // Instantiate the Witnet request
    request = new EthPriceRequest();
  }

  /**
  * @notice Sends `request` to the WitnetRequestsBoard.
  * @dev This method will only succeed if `pending` is 0.
  **/
  function requestUpdate() public payable {
    require(!pending, "An update is already pending. Complete it first before requesting another update.");

    // Amount to pay to the bridge node relaying this request from Ethereum to Witnet
    uint256 _witnetRequestReward = 100 szabo;
    // Amount of wei to pay to the bridge node relaying the result from Witnet to Ethereum
    uint256 _witnetResultReward = 100 szabo;

    // Send the request to Witnet and store the ID for later retrieval of the result
    // The `witnetPostRequest` method comes with `UsingWitnet`
    lastRequestId = witnetPostRequest(request, _witnetRequestReward, _witnetResultReward);

    // Signal that there is already a pending request
    pending = true;
  }

  /**
  * @notice Reads the result, if ready, from the WitnetRequestsBoard.
  * @dev The `witnetRequestAccepted` modifier comes with `UsingWitnet` and allows to
  * protect your methods from being called before the request has been successfully
  * relayed into Witnet.
  **/
  function completeUpdate() public witnetRequestAccepted(lastRequestId) {
    require(pending, "There is no pending update.");

    // Read the result of the Witnet request
    // The `witnetReadResult` method comes with `UsingWitnet`
    Witnet.Result memory result = witnetReadResult(lastRequestId);

    // If the Witnet request succeeded, decode the result and update the price point
    // If it failed, revert the transaction with a pretty-printed error message
    if (result.isOk()) {
      lastPrice = result.asUint64();
      timestamp = block.timestamp;
      emit priceUpdated(lastPrice);
    } else {
      string memory errorMessage;

      // Try to read the value as an error message, catch error bytes if read fails
      try result.asErrorMessage() returns (Witnet.ErrorCodes errorCode, string memory e) {
        errorMessage = e;
      }
      catch (bytes memory errorBytes){
        errorMessage = string(errorBytes);
      }
      emit resultError(errorMessage);
    }

    // In any case, set `pending` to false so a new update can be requested
    pending = false;
  }

  /**
  * @notice Exposes the public data point in an ERC2362 compliant way.
  * @dev Returns error `400` if queried for an unknown data point, and `404` if `completeUpdate` has never been called
  * successfully before.
  **/
  function valueFor(bytes32 _id) external view override returns(int256, uint256, uint256) {
    // Unsupported data point ID
    if(_id != ETHUSD3ID) return(0, 0, 400);
    // No value is yet available for the queried data point ID
    if (timestamp == 0) return(0, 0, 404);

    int256 value = int256(lastPrice);

    return(value, timestamp, 200);
  }
}
// File: witnet-price-feeds-examples/contracts/requests/GoldPrice.sol
// The bytecode of the GoldPrice request that will be sent to Witnet
contract GoldPriceRequest is Request {
  constructor () Request(hex"0ab90308c3aafbf4051257123f68747470733a2f2f636f696e7965702e636f6d2f6170692f76312f3f66726f6d3d58415526746f3d455552266c616e673d657326666f726d61743d6a736f6e1a148418778218646570726963658218571903e8185b1253122b68747470733a2f2f646174612d6173672e676f6c6470726963652e6f72672f64625852617465732f4555521a24861877821861656974656d73821818008218646878617550726963658218571903e8185b1255123668747470733a2f2f7777772e6d7963757272656e63797472616e736665722e636f6d2f6170692f63757272656e742f5841552f4555521a1b851877821866646461746182186464726174658218571903e8185b129101125d68747470733a2f2f7777772e696e766572736f726f2e65732f6461746f732f3f706572696f643d3379656172267869676e6974655f636f64653d5841552663757272656e63793d455552267765696768745f756e69743d6f756e6365731a308518778218666a7461626c655f64617461821864736d6574616c5f70726963655f63757272656e748218571903e8185b1a0d0a0908051205fa3fc00000100322090a0508051201011003100a18042001280130013801400248055046") public { }
}
// File: witnet-price-feeds-examples/contracts/gold_price_feed/GoldEurPriceFeed.sol
// Import the UsingWitnet library that enables interacting with Witnet

// Import the ERC2362 interface

// Import the goldPrice request that you created before


// Your contract needs to inherit from UsingWitnet
contract GoldEurPriceFeed is UsingWitnet, IERC2362 {

  // The public gold price point
  uint64 public lastPrice;

  // Stores the ID of the last Witnet request
  uint256 public lastRequestId;

  // Stores the timestamp of the last time the public price point was updated
  uint256 public timestamp;

  // Tells if an update has been requested but not yet completed
  bool public pending;

  // The Witnet request object, is set in the constructor
  Request public request;

  // Emits when the price is updated
  event priceUpdated(uint64);

  // Emits when found an error decoding request result
  event resultError(string);

  // This is the ERC2362 identifier for a gold price feed, computed as `keccak256("Price-XAU/EUR-3")`
  bytes32 constant public XAUEUR3ID = bytes32(hex"68cba0705475e40c1ddbf7dc7c1ae4e7320ca094c4e118d1067c4dea5df28590");

  // This constructor does a nifty trick to tell the `UsingWitnet` library where
  // to find the Witnet contracts on whatever Ethereum network you use.
  constructor (address _wrb) UsingWitnet(_wrb) public {
    // Instantiate the Witnet request
    request = new GoldPriceRequest();
  }

  /**
  * @notice Sends `request` to the WitnetRequestsBoard.
  * @dev This method will only succeed if `pending` is 0.
  **/
  function requestUpdate() public payable {
    require(!pending, "An update is already pending. Complete it first before requesting another update.");

    // Amount to pay to the bridge node relaying this request from Ethereum to Witnet
    uint256 _witnetRequestReward = 100 szabo;
    // Amount of wei to pay to the bridge node relaying the result from Witnet to Ethereum
    uint256 _witnetResultReward = 100 szabo;

    // Send the request to Witnet and store the ID for later retrieval of the result
    // The `witnetPostRequest` method comes with `UsingWitnet`
    lastRequestId = witnetPostRequest(request, _witnetRequestReward, _witnetResultReward);

    // Signal that there is already a pending request
    pending = true;
  }

  /**
  * @notice Reads the result, if ready, from the WitnetRequestsBoard.
  * @dev The `witnetRequestAccepted` modifier comes with `UsingWitnet` and allows to
  * protect your methods from being called before the request has been successfully
  * relayed into Witnet.
  **/
  function completeUpdate() public witnetRequestAccepted(lastRequestId) {
    require(pending, "There is no pending update.");

    // Read the result of the Witnet request
    // The `witnetReadResult` method comes with `UsingWitnet`
    Witnet.Result memory result = witnetReadResult(lastRequestId);

    // If the Witnet request succeeded, decode the result and update the price point
    // If it failed, revert the transaction with a pretty-printed error message
    if (result.isOk()) {
      lastPrice = result.asUint64();
      timestamp = block.timestamp;
      emit priceUpdated(lastPrice);
    } else {
      string memory errorMessage;

      // Try to read the value as an error message, catch error bytes if read fails
      try result.asErrorMessage() returns (Witnet.ErrorCodes errorCode, string memory e) {
        errorMessage = e;
      }
      catch (bytes memory errorBytes){
        errorMessage = string(errorBytes);
      }
      emit resultError(errorMessage);
    }

    // In any case, set `pending` to false so a new update can be requested
    pending = false;
  }

  /**
  * @notice Exposes the public data point in an ERC2362 compliant way.
  * @dev Returns error `400` if queried for an unknown data point, and `404` if `completeUpdate` has never been called
  * successfully before.
  **/
  function valueFor(bytes32 _id) external view override returns(int256, uint256, uint256) {
    // Unsupported data point ID
    if(_id != XAUEUR3ID) return(0, 0, 400);
    // No value is yet available for the queried data point ID
    if (timestamp == 0) return(0, 0, 404);

    int256 value = int256(lastPrice);

    return(value, timestamp, 200);
  }
}
// File: contracts/Deployer.sol
// Import witnet-ethereum-block-relay-contracts


// Import the UsingWitnet library that enables interacting with Witnet




// Import price feeds




contract Deployer  {
}
// File: contracts/Migrations.sol
contract Migrations {
  address public owner;
  uint public lastCompletedMigration;

  constructor() public {
    owner = msg.sender;
  }

  modifier restricted() {
    if (msg.sender == owner)
    _;
  }

  function setCompleted(uint _completed) public restricted {
    lastCompletedMigration = _completed;
  }

  function upgrade(address _newAddress) public restricted {
    Migrations upgraded = Migrations(_newAddress);
    upgraded.setCompleted(lastCompletedMigration);
  }
}
