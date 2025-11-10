#!/bin/bash
RPC=https://arb1.arbitrum.io/rpc
ACC=ddn_test_key

# forge create src/settlement_verifier_8.sol:Verifier --rpc-url $RPC --account $ACC --broadcast

# https://arbiscan.io/address/0x3a197a1aea1035b8952cf6e29b0bb342e2199ce0#code
# commit b6996f125cf6a93a44640618454bafb2189dad14

forge script ./script/verify.s.sol --rpc-url $RPC --account $ACC --broadcast
# uncompressed
# $0.009226
# https://arbiscan.io/tx/0x2e9079dd2e400cc62f878fa699071563d9f09e5914ea8dd29fbbde2c0f00da94
# https://arbiscan.io/tx/0x323321b6f3953817b707b4060759203ac5a7c0f44fe3aca6441dd22c1d4667db


# compressed, more expensive sadly
# $0.009528
# https://arbiscan.io/tx/0xd3e51887f97259bfbb3611bced182c1b2d946f6b903387ea48df156d6313f714
# https://arbiscan.io/tx/0x899ccbdd79c65654e38ad9c896d0ecf0e940a019af98fb9fa86485877ae275f6

