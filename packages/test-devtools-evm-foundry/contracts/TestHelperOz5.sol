// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.18;

// Forge
import { Test } from "forge-std/Test.sol";
import "forge-std/console.sol";

// OpenZeppelin
import { DoubleEndedQueue } from "@openzeppelin/contracts/utils/structs/DoubleEndedQueue.sol";

// LayerZero Message Library
import { UlnConfig, SetDefaultUlnConfigParam } from "@layerzerolabs/lz-evm-messagelib-v2/contracts/uln/UlnBase.sol";
import { SetDefaultExecutorConfigParam, ExecutorConfig } from "@layerzerolabs/lz-evm-messagelib-v2/contracts/SendLibBase.sol";

// LayerZero Protocol
import { IMessageLib } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/IMessageLib.sol";
import { ExecutorOptions } from "@layerzerolabs/lz-evm-protocol-v2/contracts/messagelib/libs/ExecutorOptions.sol";
import { PacketV1Codec } from "@layerzerolabs/lz-evm-protocol-v2/contracts/messagelib/libs/PacketV1Codec.sol";
import { Origin, ILayerZeroEndpointV2 } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";

// Mocks
import { ReceiveUln302Mock as ReceiveUln302, IReceiveUlnE2 } from "./mocks/ReceiveUln302Mock.sol";
import { DVNMock as DVN, ExecuteParam, IDVN } from "./mocks/DVNMock.sol";
import { DVNFeeLibMock as DVNFeeLib } from "./mocks/DVNFeeLibMock.sol";
import { ExecutorMock as Executor, IExecutor } from "./mocks/ExecutorMock.sol";
import { PriceFeedMock as PriceFeed, ILayerZeroPriceFeed } from "./mocks/PriceFeedMock.sol";
import { EndpointV2Mock as EndpointV2 } from "./mocks/EndpointV2Mock.sol";

// Miscellaneous Mocks
import { OptionsHelper } from "./OptionsHelper.sol";
import { SendUln302Mock as SendUln302 } from "./mocks/SendUln302Mock.sol";
import { SimpleMessageLibMock } from "./mocks/SimpleMessageLibMock.sol";
import { ExecutorFeeLibMock as ExecutorFeeLib } from "./mocks/ExecutorFeeLibMock.sol";

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
    enum LibraryType {
        UltraLightNode,
        SimpleMessageLib
    }

    struct EndpointSetup {
        EndpointV2[] endpointList;
        uint32[] eidList;
        address[] sendLibs;
        address[] receiveLibs;
        address[] signers;
        PriceFeed priceFeed;
    }

    struct LibrarySetup {
        SendUln302 sendUln;
        ReceiveUln302 receiveUln;
        Executor executor;
        DVN dvn;
        ExecutorFeeLib executorLib;
        DVNFeeLib dvnLib;
    }

    struct ConfigParams {
        IExecutor.DstConfigParam[] executorConfigParams;
        IDVN.DstConfigParam[] dvnConfigParams;
    }

    using DoubleEndedQueue for DoubleEndedQueue.Bytes32Deque;
    using PacketV1Codec for bytes;

    mapping(uint32 => mapping(bytes32 => DoubleEndedQueue.Bytes32Deque)) public packetsQueue; // dstEid => dstUA => guids queue
    mapping(bytes32 => bytes) public packets; // guid => packet bytes
    mapping(bytes32 => bytes) public optionsLookup; // guid => options
    mapping(uint32 => address) public endpoints; // eid => endpoint

    uint256 public constant TREASURY_GAS_CAP = 1_000_000_000_000; // Reduced size
    uint256 public constant TREASURY_GAS_FOR_FEE_CAP = 100_000;

    uint128 public executorValueCap = 0.1 ether;

    EndpointSetup internal endpointSetup;
    LibrarySetup internal libSetup;

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
     * @notice Sets up endpoints for testing.
     * @param _endpointNum The number of endpoints to create.
     * @param _libraryType The type of message library to use (UltraLightNode or SimpleMessageLib).
     * @param _customDVNs Custom DVNs provided by the user.
     */
    function setUpEndpoints(
        uint8 _endpointNum,
        LibraryType _libraryType,
        address[] memory _customDVNs
    ) public {
        endpointSetup.endpointList = new EndpointV2[](_endpointNum);
        endpointSetup.eidList = new uint32[](_endpointNum);
        endpointSetup.sendLibs = new address[](_endpointNum);
        endpointSetup.receiveLibs = new address[](_endpointNum);
        endpointSetup.signers = new address ;
        endpointSetup.signers[0] = vm.addr(1);

        for (uint8 i = 0; i < _endpointNum; i++) {
            uint32 eid = i + 1;
            endpointSetup.eidList[i] = eid;
            endpointSetup.endpointList[i] = new EndpointV2(eid, address(this));
            registerEndpoint(endpointSetup.endpointList[i]);
        }

        endpointSetup.priceFeed = new PriceFeed(address(this));

        for (uint8 i = 0; i < _endpointNum; i++) {
            if (_libraryType == LibraryType.UltraLightNode) {
                address endpointAddr = address(endpointSetup.endpointList[i]);

                libSetup.sendUln = new SendUln302(
                    payable(address(this)),
                    endpointAddr,
                    TREASURY_GAS_CAP,
                    TREASURY_GAS_FOR_FEE_CAP
                );
                libSetup.receiveUln = new ReceiveUln302(endpointAddr);
                endpointSetup.endpointList[i].registerLibrary(address(libSetup.sendUln));
                endpointSetup.endpointList[i].registerLibrary(address(libSetup.receiveUln));
                endpointSetup.sendLibs[i] = address(libSetup.sendUln);
                endpointSetup.receiveLibs[i] = address(libSetup.receiveUln);

                address[] memory admins = new address[](1);
                admins[0] = address(this);

                address[] memory messageLibs = new address[](2);
                messageLibs[0] = address(libSetup.sendUln);
                messageLibs[1] = address(libSetup.receiveUln);

                libSetup.executor = new Executor(
                    endpointAddr,
                    address(0x0),
                    messageLibs,
                    address(endpointSetup.priceFeed),
                    address(this),
                    admins
                );

                libSetup.executorLib = new ExecutorFeeLib();
                libSetup.executor.setWorkerFeeLib(address(libSetup.executorLib));

                if (_customDVNs.length > i && _customDVNs[i] != address(0)) {
                    libSetup.dvn = DVN(_customDVNs[i]); // Use custom DVN
                } else {
                    libSetup.dvn = new DVN(
                        i + 1,
                        messageLibs,
                        address(endpointSetup.priceFeed),
                        endpointSetup.signers,
                        1,
                        admins
                    );
                }

                libSetup.dvnLib = new DVNFeeLib(1e18);
                libSetup.dvn.setWorkerFeeLib(address(libSetup.dvnLib));

                ConfigParams memory configParams;
                configParams.executorConfigParams = new IExecutor.DstConfigParam[](_endpointNum);
                configParams.dvnConfigParams = new IDVN.DstConfigParam[](_endpointNum);

                for (uint8 j = 0; j < _endpointNum; j++) {
                    if (i == j) continue;
                    uint32 dstEid = j + 1;

                    address[] memory defaultDVNs = new address[](1);
                    defaultDVNs[0] = address(libSetup.dvn);

                    SetDefaultUlnConfigParam[] memory ulnParams = new SetDefaultUlnConfigParam[](1);
                    UlnConfig memory ulnConfig = UlnConfig(
                        100,
                        uint8(defaultDVNs.length),
                        0,
                        0,
                        defaultDVNs,
                        new address
                    );

                    ulnParams[0] = SetDefaultUlnConfigParam(dstEid, ulnConfig);
                    libSetup.sendUln.setDefaultUlnConfigs(ulnParams);
                    libSetup.receiveUln.setDefaultUlnConfigs(ulnParams);

                    SetDefaultExecutorConfigParam[] memory execParams = new SetDefaultExecutorConfigParam[](1);
                    ExecutorConfig memory execConfig = ExecutorConfig(10000, address(libSetup.executor));
                    execParams[0] = SetDefaultExecutorConfigParam(dstEid, execConfig);
                    libSetup.sendUln.setDefaultExecutorConfigs(execParams);

                    configParams.executorConfigParams[j] = IExecutor.DstConfigParam({
                    dstEid: dstEid,
                    lzReceiveBaseGas: 5000,
                    lzComposeBaseGas: 5000,
                    multiplierBps: 10000,
                    floorMarginUSD: 1e10,
                    nativeCap: executorValueCap
                    });

                    configParams.dvnConfigParams[j] = IDVN.DstConfigParam({
                    dstEid: dstEid,
                    gas: 5000,
                    multiplierBps: 10000,
                    floorMarginUSD: 1e10
                    });

                    uint128 denominator = endpointSetup.priceFeed.getPriceRatioDenominator();
                    ILayerZeroPriceFeed.UpdatePrice[] memory prices = new ILayerZeroPriceFeed.UpdatePrice[](1);
                    prices[0] = ILayerZeroPriceFeed.UpdatePrice(dstEid, ILayerZeroPriceFeed.Price(denominator, 1, 1));
                    endpointSetup.priceFeed.setPrice(prices);
                }

                libSetup.executor.setDstConfig(configParams.executorConfigParams);
                libSetup.dvn.setDstConfig(configParams.dvnConfigParams);
            } else if (_libraryType == LibraryType.SimpleMessageLib) {
                SimpleMessageLibMock messageLib = new SimpleMessageLibMock(
                    payable(address(this)),
                    address(endpointSetup.endpointList[i])
                );
                endpointSetup.endpointList[i].registerLibrary(address(messageLib));
                endpointSetup.sendLibs[i] = address(messageLib);
                endpointSetup.receiveLibs[i] = address(messageLib);
            } else {
                revert("Invalid library type");
            }
        }

        // Configuration
        for (uint8 i = 0; i < _endpointNum; i++) {
            EndpointV2 endpoint = endpointSetup.endpointList[i];
            for (uint8 j = 0; j < _endpointNum; j++) {
                if (i == j) continue;
                endpoint.setDefaultSendLibrary(j + 1, endpointSetup.sendLibs[i]);
                endpoint.setDefaultReceiveLibrary(j + 1, endpointSetup.receiveLibs[i], 0);
            }
        }
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
        require(endpoints[_dstEid] != address(0), "endpoint not yet registered");

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
        EndpointV2 endpoint = EndpointV2(endpoints[_packetBytes.dstEid()]);
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
        EndpointV2 endpoint = EndpointV2(endpoints[_dstEid]);
        (uint16 index, uint256 gas, uint256 value) = _parseExecutorLzComposeOption(_options);
        endpoint.lzCompose{ value: value, gas: gas }(_from, _to, _guid, index, _composerMsg, bytes(""));
    }

    function validatePacket(bytes calldata _packetBytes) external {
        uint32 dstEid = _packetBytes.dstEid();
        EndpointV2 endpoint = EndpointV2(endpoints[dstEid]);
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

    function registerEndpoint(EndpointV2 endpoint) public {
        endpoints[endpoint.eid()] = address(endpoint);
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
