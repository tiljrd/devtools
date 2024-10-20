pragma solidity ^0.8.18;

import { Test } from "forge-std/Test.sol";
import { EndpointV2Mock as EndpointV2 } from "./mocks/EndpointV2Mock.sol";
import { SendUln302Mock as SendUln302 } from "./mocks/SendUln302Mock.sol";
import { ReceiveUln302Mock as ReceiveUln302, IReceiveUlnE2 } from "./mocks/ReceiveUln302Mock.sol";
import { ExecutorMock as Executor, IExecutor } from "./mocks/ExecutorMock.sol";
import { DVNMock as DVN, ExecuteParam, IDVN } from "./mocks/DVNMock.sol";
import { ExecutorFeeLibMock as ExecutorFeeLib } from "./mocks/ExecutorFeeLibMock.sol";
import { PriceFeedMock as PriceFeed, ILayerZeroPriceFeed } from "./mocks/PriceFeedMock.sol";
import { DVNFeeLibMock as DVNFeeLib } from "./mocks/DVNFeeLibMock.sol";
import { SimpleMessageLibMock } from "./mocks/SimpleMessageLibMock.sol";

// LayerZero Message Library
import { UlnConfig, SetDefaultUlnConfigParam } from "@layerzerolabs/lz-evm-messagelib-v2/contracts/uln/UlnBase.sol";
import { SetDefaultExecutorConfigParam, ExecutorConfig } from "@layerzerolabs/lz-evm-messagelib-v2/contracts/SendLibBase.sol";

contract EndpointManager is Test {

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

    enum LibraryType {
        UltraLightNode,
        SimpleMessageLib
    }

    struct ConfigParams {
        IExecutor.DstConfigParam[] executorConfigParams;
        IDVN.DstConfigParam[] dvnConfigParams;
    }

    mapping(uint32 => address) private endpoints; // eid => endpoint

    uint128 public executorValueCap = 0.1 ether;

    EndpointSetup internal endpointSetup;
    LibrarySetup internal libSetup;

    uint256 public constant TREASURY_GAS_CAP = 1_000_000_000_000; // Reduced size
    uint256 public constant TREASURY_GAS_FOR_FEE_CAP = 100_000;

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
        endpointSetup.signers = new address[](1);
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

    function registerEndpoint(EndpointV2 endpoint) public {
        endpoints[endpoint.eid()] = address(endpoint);
    }

    function getEndpoint(uint32 eid) public view returns (address) {
        return endpoints[eid];
    }
}