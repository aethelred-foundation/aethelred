// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../contracts/vault/P256Verifier.sol";

contract P256VerifierHarness {
    function verify(
        bytes32 hash,
        uint256 r,
        uint256 s,
        uint256 qx,
        uint256 qy
    )
        external
        view
        returns (bool)
    {
        return P256Verifier.verify(hash, r, s, qx, qy);
    }
}

contract P256VerifierTest is Test {
    uint256 private constant PRIVATE_KEY = 0xA11CE;
    uint256 private constant N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
    address private constant MODEXP = address(0x05);
    address private constant RIP7212 = address(0x100);

    P256VerifierHarness private verifier;

    function setUp() public {
        verifier = new P256VerifierHarness();
    }

    function testValidSignature() public view {
        bytes32 digest = sha256("P256Verifier valid signature");
        (uint256 qx, uint256 qy) = vm.publicKeyP256(PRIVATE_KEY);
        (bytes32 r, bytes32 s) = vm.signP256(PRIVATE_KEY, digest);

        assertTrue(verifier.verify(digest, uint256(r), uint256(s), qx, qy));
    }

    function testModexpFailureFailsClosed() public {
        bytes32 digest = sha256("P256Verifier MODEXP failure");
        (uint256 qx, uint256 qy) = vm.publicKeyP256(PRIVATE_KEY);
        (bytes32 r, bytes32 s) = vm.signP256(PRIVATE_KEY, digest);

        bytes memory rip7212Input = abi.encode(digest, uint256(r), uint256(s), qx, qy);
        vm.mockCallRevert(RIP7212, rip7212Input, hex"");

        bytes memory modexpInput =
            abi.encode(uint256(32), uint256(32), uint256(32), uint256(s), N - 2, N);
        vm.mockCallRevert(MODEXP, modexpInput, hex"");
        vm.expectCall(MODEXP, bytes(""), 1);

        assertFalse(verifier.verify(digest, uint256(r), uint256(s), qx, qy));
    }
}
