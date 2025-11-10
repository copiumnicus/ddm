import os, json
from pathlib import Path

TEMPLATE = """
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {Verifier} from "../src/settlement_verifier_8.sol";

contract VerifierTest is Test {
    Verifier public ver;

    function setUp() public {
        ver = new Verifier();
    }

    function test_Verify() public {
        // generated with `make_test.py`
        uint256[8] memory proof = <PROOF>;
        uint256[7] memory input = <INPUT>;
        uint256[4] memory compressed = ver.compressProof(proof);
        ver.verifyCompressedProof(compressed, input);
    }
}
"""

BASE = Path("./artifact")
BASE_SOL = Path("./ddn")
PROOF_PATH = BASE / "proof_8.json"
INPUT_PATH = BASE / "public_sol_8.json"
VERIFIER_PATH = BASE / "settlement_verifier_8.sol"
VERIFIER_TGT_PATH = BASE_SOL / "src" / "settlement_verifier_8.sol"
TEST_TGT_PATH = BASE_SOL / "test" / "settlement_verifier_8.sol"

verifier = ""
with open(VERIFIER_PATH) as f:
    verifier = f.read()
with open(VERIFIER_TGT_PATH, "w") as f:
    f.write(verifier)

proof = []
input = []
with open(PROOF_PATH) as f:
    proof = json.load(f)
with open(INPUT_PATH) as f:
    input = json.load(f)

def arr_u256(v):
    return "[\n" + ",\n".join(v) + "\n]"

res = (TEMPLATE
       .replace("<PROOF>", arr_u256(proof))
       .replace("<INPUT>", arr_u256(input))
)

with open(TEST_TGT_PATH, "w") as f:
    f.write(res)