// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script} from "forge-std/Script.sol";
import {Verifier} from "../src/settlement_verifier_8.sol";

contract VerifyScript is Script {
    function setUp() public {}

    function run() public {
        address v = address(0x3a197A1Aea1035b8952CF6e29b0bB342e2199cE0);
        Verifier vc = Verifier(v);

        uint256[8] memory proof = [
            0x2bd8d3ba57f0114a5e306139085f80d32c7e9fd2e16221f70ad8bf8f8d5b1212,
            0x2da7772e8b30da6104286627465f06f4694fe13555d5b375a748945ac3b569a9,
            0x0015d29f0439de2c567699e765dc937e2e6f63451f7f8b544a1dd42be536d7ea,
            0x113710d9add5ad921452cd2e7b1a005b2100ffe90b8a040c306e6cdbd704c666,
            0x23c99fad59b5793279650b97d0111fc9cb7721583afa529c6b2b982d7e987cee,
            0x2057012d57ed467c1351fa158705d57d6ca43a538163793368b361f5142b825d,
            0x1d4ed513d646fb8a9c3e1b9e23455b5c7b7b3b564c24cb664b74142086555a54,
            0x0843d9dc70a69264b1d24d82f023a546dd3de6b6325676d9666d72de7ac44377
        ];
        uint256[7] memory input = [
            0x000000000000000000000000000000000000000000000000000000000000002a,
            0x0000000000000000000000000000000000000000000000000000000000000000,
            0x0000000000000000000000000000000000000000000000000000000000000008,
            0x0000000000000000000000000000000000000000000000000000000000000008,
            0x0000000000000000000000000000000000000000000000000000000000000001,
            0x2317538110e15135efaa9fbc114942e93152ad2380c157ae6a0ac77fa4d42e1f,
            0x01f9aa8ae32ebc84437cb58e6252a8ec88f01af434668086acfa18d03e8bf056
        ];
        uint256[4] memory compressed = vc.compressProof(proof);
        vm.startBroadcast();

        vc.verifyCompressedProof(compressed, input);

        vm.stopBroadcast();
    }
}
