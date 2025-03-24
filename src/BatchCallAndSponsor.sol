// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ReentrancyGuard} from "openzeppelin-contracts/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "openzeppelin-contracts/contracts/utils/Pausable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract BatchCallAndSponsor is Pausable, ReentrancyGuard {
    using ECDSA for bytes32;

    error EInvalidAuthority(address sender);

    /// @notice A nonce used for replay protection.
    uint256 public nonce;
    
    
    /// @notice Represents a single call within a batch.
    struct Call {
        address to;
        uint256 value;
        bytes data;
    }

    /// @notice Emitted for every individual call executed.
    event CallExecuted(address indexed sender, address indexed to, uint256 value, bytes data);
    /// @notice Emitted when a full batch is executed.
    event BatchExecuted(uint256 indexed nonce, Call[] calls);
    
    // @note add function useNonce to get nonce and increment directly 
    function useNonce() internal returns(uint256){
        return nonce++;
    }

    /**
     * @notice Executes a batch of calls using an off–chain signature.
     * @param calls An array of Call structs containing destination, ETH value, and calldata.
     * @param signature The ECDSA signature over the current nonce and the call data.
     *
     * The signature must be produced off–chain by signing:
     * The signing key should be the account’s key (which becomes the smart account’s own identity after upgrade).
     */
  
     // @note this is vulnerable to reply chain attacks 
     // add a endtime for this transsaction to be valid
    function execute(Call[] calldata calls, bytes calldata signature) external payable nonReentrant whenNotPaused {
        bytes memory encodedCalls;
        for (uint256 i = 0; i < calls.length; i++) {
            encodedCalls = abi.encodePacked(encodedCalls, calls[i].to, calls[i].value, calls[i].data);
        }
        bytes32 digest = keccak256(abi.encodePacked(useNonce(), encodedCalls));

        bytes32 ethSignedMessageHash = MessageHashUtils.toEthSignedMessageHash(digest);

        // Recover the signer from the provided signature.
        address recovered = ECDSA.recover(ethSignedMessageHash, signature);
        require(recovered == address(this), "Invalid signature");

        _executeBatch(calls);
    }

    /**
     * @notice Executes a batch of calls directly.
     * @dev This function is intended for use when the smart account itself (i.e. address(this))
     * calls the contract. It checks that msg.sender is the contract itself.
     * @param calls An array of Call structs containing destination, ETH value, and calldata.
     */
    function execute(Call[] calldata calls) external payable {
        require(msg.sender == address(this), EInvalidAuthority(msg.sender));
        _executeBatch(calls);
    }

    /**
     * @dev Internal function that handles batch execution and nonce incrementation.
     * @param calls An array of Call structs.
     */
    // @note  the batchtransfer goes as one transaction so only one nonce is used  
    function _executeBatch(Call[] calldata calls) internal {
        uint256 currentNonce = nonce;
        useNonce(); // Increment nonce to protect against replay attacks

        for (uint256 i = 0; i < calls.length; i++) {
            _executeCall(calls[i]);
        }

        emit BatchExecuted(currentNonce, calls);
    }

    /**
     * @dev Internal function to execute a single call.
     * @param call The Call struct containing destination, value, and calldata.
     */
    function _executeCall(Call calldata call) internal {
        (bool success,) = call.to.call{value: call.value}(call.data);
        require(success, "Call reverted");
        emit CallExecuted(msg.sender, call.to, call.value, call.data);
    }

    /**
     * @notice Pause the contract.
     * @dev This function is only callable by this contract.
     */
    function pause() external {
        require(msg.sender == address(this), EInvalidAuthority(msg.sender));
        _pause();
    }

    /**
     * @notice Unpause the contract.
     * @dev This function is only callable by this contract.
     */
    function unpause() external {
        require(msg.sender == address(this), EInvalidAuthority(msg.sender));
        _unpause();
    }

    // Allow the contract to receive ETH (e.g. from DEX swaps or other transfers).
    fallback() external payable {}
    receive() external payable {}

}
