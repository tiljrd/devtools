// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.18;

import "./EndpointManager.sol";

// Forge
import { Test } from "forge-std/Test.sol";
import "forge-std/console.sol";

// OpenZeppelin
import { DoubleEndedQueue } from "@openzeppelin/contracts/utils/structs/DoubleEndedQueue.sol";

// LayerZero Protocol
import { IMessageLib } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/IMessageLib.sol";
import { ExecutorOptions } from "@layerzerolabs/lz-evm-protocol-v2/contracts/messagelib/libs/ExecutorOptions.sol";
import { PacketV1Codec } from "@layerzerolabs/lz-evm-protocol-v2/contracts/messagelib/libs/PacketV1Codec.sol";
import { Origin, ILayerZeroEndpointV2 } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";

import { EndpointV2Mock as EndpointV2 } from "./mocks/EndpointV2Mock.sol";
import { ReceiveUln302Mock as ReceiveUln302, IReceiveUlnE2 } from "./mocks/ReceiveUln302Mock.sol";
import { DVNMock as DVN, ExecuteParam } from "./mocks/DVNMock.sol";
import { UlnConfig } from "@layerzerolabs/lz-evm-messagelib-v2/contracts/uln/UlnBase.sol";
import { SimpleMessageLibMock } from "./mocks/SimpleMessageLibMock.sol";

// Miscellaneous Mocks
import { OptionsHelper } from "./OptionsHelper.sol";


interface IOAppSetPeer {
    function setPeer(uint32 _eid, bytes32 _peer) external;
    function endpoint() external view returns (ILayerZeroEndpointV2 iEndpoint);
}

/**
 * @title TestHelperOz5
 * @notice Optimized helper contract for setting up and managing LayerZero test environments.
 * @dev Extends Foundry's Test contract and provides utility functions for setting up mock endpoints and OApps.
 */
contract TestHelperOz5 is Test, OptionsHelper {

    using DoubleEndedQueue for DoubleEndedQueue.Bytes32Deque;
    using PacketV1Codec for bytes;

    mapping(uint32 => mapping(bytes32 => DoubleEndedQueue.Bytes32Deque)) public packetsQueue; // dstEid => dstUA => guids queue
    mapping(bytes32 => bytes) public packets; // guid => packet bytes
    mapping(bytes32 => bytes) public optionsLookup; // guid => options

    uint128 public executorValueCap = 0.1 ether;

    EndpointManager public endpointManager;

    /**
     * @dev Initializes the test environment setup, to be overridden by specific tests.
     */
    function setUp() public virtual {
        _setUpUlnOptions();
    }

    /**
     * @dev Sets the executorValueCap if more than 0.1 ether is necessary.
     * This must be called prior to setUpEndpoints() if the value is to be used.
     * @param _valueCap Amount executor can pass as msg.value to lzReceive().
     */
    function setExecutorValueCap(uint128 _valueCap) public {
        executorValueCap = _valueCap;
    }

    /**
     * @notice Schedules a packet for delivery.
     * @dev Adds the packet to the front of the queue and stores its options for later retrieval.
     * @param _packetBytes The packet data to be scheduled.
     * @param _options The options associated with the packet, used during delivery.
     */
    function schedulePacket(bytes calldata _packetBytes, bytes calldata _options) public {
        uint32 dstEid = _packetBytes.dstEid();
        bytes32 dstAddress = _packetBytes.receiver();
        DoubleEndedQueue.Bytes32Deque storage queue = packetsQueue[dstEid][dstAddress];
        bytes32 guid = _packetBytes.guid();
        queue.pushFront(guid);
        packets[guid] = _packetBytes;
        optionsLookup[guid] = _options;
    }

    // Other helper functions unchanged from the original contract

/**
 * @notice Verifies and processes packets destined for a specific chain and user address.
     * @dev Calls an overloaded version of verifyPackets with default values for packet amount and composer address.
     * @param _dstEid The destination chain's endpoint ID.
     * @param _dstAddress The destination address in bytes32 format.
     */
    function verifyPackets(uint32 _dstEid, bytes32 _dstAddress) public {
        verifyPackets(_dstEid, _dstAddress, 0, address(0x0));
    }

    /**
     * @dev verify packets to destination chain's OApp address.
     * @param _dstEid The destination endpoint ID.
     * @param _dstAddress The destination address.
     */
    function verifyPackets(uint32 _dstEid, address _dstAddress) public {
        verifyPackets(_dstEid, bytes32(uint256(uint160(_dstAddress))), 0, address(0x0));
    }

    /**
     * @dev dst UA receive/execute packets
     * @dev will NOT work calling this directly with composer IF the composed payload is different from the lzReceive msg payload
     */
    function verifyPackets(uint32 _dstEid, bytes32 _dstAddress, uint256 _packetAmount, address _composer) public {
        require(endpointManager.getEndpoint(_dstEid) != address(0), "endpoint not yet registered");

        DoubleEndedQueue.Bytes32Deque storage queue = packetsQueue[_dstEid][_dstAddress];
        uint256 pendingPacketsSize = queue.length();
        uint256 numberOfPackets;
        if (_packetAmount == 0) {
            numberOfPackets = queue.length();
        } else {
            numberOfPackets = pendingPacketsSize > _packetAmount ? _packetAmount : pendingPacketsSize;
        }
        while (numberOfPackets > 0) {
            numberOfPackets--;
            // front in, back out
            bytes32 guid = queue.popBack();
            bytes memory packetBytes = packets[guid];
            this.assertGuid(packetBytes, guid);
            this.validatePacket(packetBytes);

            bytes memory options = optionsLookup[guid];
            if (_executorOptionExists(options, ExecutorOptions.OPTION_TYPE_NATIVE_DROP)) {
                (uint256 amount, bytes32 receiver) = _parseExecutorNativeDropOption(options);
                address to = address(uint160(uint256(receiver)));
                (bool sent, ) = to.call{ value: amount }("");
                require(sent, "Failed to send Ether");
            }
            if (_executorOptionExists(options, ExecutorOptions.OPTION_TYPE_LZRECEIVE)) {
                this.lzReceive(packetBytes, options);
            }
            if (_composer != address(0) && _executorOptionExists(options, ExecutorOptions.OPTION_TYPE_LZCOMPOSE)) {
                this.lzCompose(packetBytes, options, guid, _composer);
            }
        }
    }

    function lzReceive(bytes calldata _packetBytes, bytes memory _options) external payable {
        address endpointAddr = endpointManager.getEndpoint(_packetBytes.dstEid());
        EndpointV2 endpoint = EndpointV2(endpointAddr);
        (uint256 gas, uint256 value) = OptionsHelper._parseExecutorLzReceiveOption(_options);

        Origin memory origin = Origin(_packetBytes.srcEid(), _packetBytes.sender(), _packetBytes.nonce());
        endpoint.lzReceive{ value: value, gas: gas }(
            origin,
            _packetBytes.receiverB20(),
            _packetBytes.guid(),
            _packetBytes.message(),
            bytes("")
        );
    }

    function lzCompose(
        bytes calldata _packetBytes,
        bytes memory _options,
        bytes32 _guid,
        address _composer
    ) external payable {
        this.lzCompose(
            _packetBytes.dstEid(),
            _packetBytes.receiverB20(),
            _options,
            _guid,
            _composer,
            _packetBytes.message()
        );
    }

    // @dev the verifyPackets does not know the composeMsg if it is NOT the same as the original lzReceive payload
    // Can call this directly from your test to lzCompose those types of packets
    function lzCompose(
        uint32 _dstEid,
        address _from,
        bytes memory _options,
        bytes32 _guid,
        address _to,
        bytes calldata _composerMsg
    ) external payable {
        address endpointAddr = endpointManager.getEndpoint(_dstEid);
        EndpointV2 endpoint = EndpointV2(endpointAddr);
        (uint16 index, uint256 gas, uint256 value) = _parseExecutorLzComposeOption(_options);
        endpoint.lzCompose{ value: value, gas: gas }(_from, _to, _guid, index, _composerMsg, bytes(""));
    }

    function validatePacket(bytes calldata _packetBytes) external {
        uint32 dstEid = _packetBytes.dstEid();
        address endpointAddr = endpointManager.getEndpoint(dstEid);
        EndpointV2 endpoint = EndpointV2(endpointAddr);
        (address receiveLib, ) = endpoint.getReceiveLibrary(_packetBytes.receiverB20(), _packetBytes.srcEid());
        ReceiveUln302 dstUln = ReceiveUln302(receiveLib);

        (uint64 major, , ) = IMessageLib(receiveLib).version();
        if (major == 3) {
            // it is ultra light node
            bytes memory config = dstUln.getConfig(_packetBytes.srcEid(), _packetBytes.receiverB20(), 2); // CONFIG_TYPE_ULN
            DVN dvn = DVN(abi.decode(config, (UlnConfig)).requiredDVNs[0]);

            bytes memory packetHeader = _packetBytes.header();
            bytes32 payloadHash = keccak256(_packetBytes.payload());

            // sign
            bytes memory signatures;
            bytes memory verifyCalldata = abi.encodeWithSelector(
                IReceiveUlnE2.verify.selector,
                packetHeader,
                payloadHash,
                100
            );
            {
                bytes32 hash = dvn.hashCallData(dstEid, address(dstUln), verifyCalldata, block.timestamp + 1000);
                bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
                (uint8 v, bytes32 r, bytes32 s) = vm.sign(1, ethSignedMessageHash); // matches dvn signer
                signatures = abi.encodePacked(r, s, v);
            }
            ExecuteParam[] memory params = new ExecuteParam[](1);
            params[0] = ExecuteParam(dstEid, address(dstUln), verifyCalldata, block.timestamp + 1000, signatures);
            dvn.execute(params);

            // commit verification
            bytes memory callData = abi.encodeWithSelector(
                IReceiveUlnE2.commitVerification.selector,
                packetHeader,
                payloadHash
            );
            {
                bytes32 hash = dvn.hashCallData(dstEid, address(dstUln), callData, block.timestamp + 1000);
                bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
                (uint8 v, bytes32 r, bytes32 s) = vm.sign(1, ethSignedMessageHash); // matches dvn signer
                signatures = abi.encodePacked(r, s, v);
            }
            params[0] = ExecuteParam(dstEid, address(dstUln), callData, block.timestamp + 1000, signatures);
            dvn.execute(params);
        } else {
            SimpleMessageLibMock(payable(receiveLib)).validatePacket(_packetBytes);
        }
    }

    function assertGuid(bytes calldata packetBytes, bytes32 guid) external pure {
        bytes32 packetGuid = packetBytes.guid();
        require(packetGuid == guid, "guid not match");
    }

    function hasPendingPackets(uint16 _dstEid, bytes32 _dstAddress) public view returns (bool flag) {
        DoubleEndedQueue.Bytes32Deque storage queue = packetsQueue[_dstEid][_dstAddress];
        return queue.length() > 0;
    }

    function getNextInflightPacket(uint16 _dstEid, bytes32 _dstAddress) public view returns (bytes memory packetBytes) {
        DoubleEndedQueue.Bytes32Deque storage queue = packetsQueue[_dstEid][_dstAddress];
        if (queue.length() > 0) {
            bytes32 guid = queue.back();
            packetBytes = packets[guid];
        }
    }

    function addressToBytes32(address _addr) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(_addr)));
    }

    receive() external payable {}
}
