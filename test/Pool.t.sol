// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import "forge-std/Test.sol";

import "@eas-contracts/SchemaRegistry.sol";
import "@eas-contracts/EAS.sol";
import "@eas-contracts/Common.sol";

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

import "src/Pool.sol";

contract PoolTest is Test {
    ISchemaRegistry public registry;
    IEAS public eas;
    Pool public pool;

    bytes32 easDomainSeparator;

    bytes32 revokeSchema;
    bytes32 inviteSchema;
    bytes32 blockSchema;
    bytes32 depositSchema;
    bytes32 transferSchema;

    address alice;
    address bob;
    address charlie;

    mapping(address => uint) nonces;

    bytes32 private constant ATTEST_TYPEHASH =
        0xdbfdf8dc2b135c26253e00d5b6cbe6f20457e003fd526d97cea183883570de61;
    bytes32 private constant REVOKE_TYPEHASH =
        0xa98d02348410c9c76735e0d0bb1396f4015ac2bb9615f9c2611d19d7a8a99650;

    constructor() {}

    function setUp() public {
        alice = vm.addr(1);
        bob = vm.addr(2);
        charlie = vm.addr(3);
        vm.deal(alice, 10 ether);
        vm.deal(bob, 10 ether);

        registry = new SchemaRegistry();
        eas = new EAS(registry);
        easDomainSeparator = EIP712Verifier(address(eas)).getDomainSeparator();

        revokeSchema = registry.register(
            "string reason",
            ISchemaResolver(address(0)),
            false
        );
        vm.prank(alice);
        pool = new Pool(eas, revokeSchema);
        vm.prank(alice);
        pool.inviteDeployer("Alice");

        inviteSchema = pool.inviteSchema();
        blockSchema = pool.blockSchema();
        depositSchema = pool.depositSchema();
        transferSchema = pool.transferSchema();
    }

    function testOwnerIsInvitedAndNotBlocked() public view {
        require(pool.isInvited(alice));
        require(!pool.isBlocked(alice));
    }

    function testInvite() public {
        AttestationRequest memory request = AttestationRequest({
            schema: inviteSchema,
            data: AttestationRequestData({
                recipient: bob,
                expirationTime: 0,
                revocable: true,
                refUID: bytes32(0),
                data: abi.encode("Bob", "Inviting Bob to test the contracts."),
                value: 0
            })
        });
        vm.startPrank(alice);
        eas.attest(request);
        vm.stopPrank();

        require(pool.isInvited(bob));
    }

    function testInviteAndRevoke() public {
        AttestationRequest memory inviteBob = AttestationRequest({
            schema: inviteSchema,
            data: AttestationRequestData({
                recipient: bob,
                expirationTime: 0,
                revocable: true,
                refUID: bytes32(0),
                data: abi.encode("Bob", "Inviting Bob to test the contracts."),
                value: 0
            })
        });
        vm.startPrank(alice);
        bytes32 uid = eas.attest(inviteBob);
        vm.stopPrank();
        require(pool.isInvited(bob));

        AttestationRequest memory inviteCharlie = AttestationRequest({
            schema: inviteSchema,
            data: AttestationRequestData({
                recipient: charlie,
                expirationTime: 0,
                revocable: true,
                refUID: bytes32(0),
                data: abi.encode(
                    "Charlie",
                    "Inviting Charlie to test the contracts."
                ),
                value: 0
            })
        });
        vm.startPrank(bob);
        eas.attest(inviteCharlie);
        vm.stopPrank();
        require(pool.isInvited(charlie));

        DelegatedRevocationRequest
            memory revokeRequest = DelegatedRevocationRequest({
                schema: inviteSchema,
                data: RevocationRequestData({uid: uid, value: 0}),
                signature: EIP712Signature(0, 0, 0),
                revoker: alice
            });
        revokeRequest = signDelegatedRevocationRequest(revokeRequest, 1);
        vm.startPrank(alice);
        pool.revokeWithReason(
            revokeRequest,
            "Revoking Bobs invitation to test the contract."
        );
        vm.stopPrank();
        require(
            !pool.isInvited(bob),
            "Bob is invited after invitation was revoked."
        );
        require(pool.isInvited(charlie), "Charlie uninvited before update.");

        AttestationRequest memory reInviteBob = AttestationRequest({
            schema: inviteSchema,
            data: AttestationRequestData({
                recipient: bob,
                expirationTime: 0,
                revocable: true,
                refUID: bytes32(0),
                data: abi.encode(
                    "Bob-2.0",
                    "Reinviting Bob to test the contracts."
                ),
                value: 0
            })
        });
        vm.startPrank(alice);
        eas.attest(reInviteBob);
        vm.stopPrank();
        require(pool.isInvited(bob), "Bob could not be invited again.");
    }

    function testBlockAndRevoke() public {
        AttestationRequest memory request = AttestationRequest({
            schema: inviteSchema,
            data: AttestationRequestData({
                recipient: bob,
                expirationTime: 0,
                revocable: true,
                refUID: bytes32(0),
                data: abi.encode("Bob", "Inviting bob to test the contracts."),
                value: 0
            })
        });
        vm.startPrank(alice);
        eas.attest(request);
        vm.stopPrank();

        AttestationRequest memory blockRequest = AttestationRequest({
            schema: blockSchema,
            data: AttestationRequestData({
                recipient: bob,
                expirationTime: 0,
                revocable: true,
                refUID: bytes32(0),
                data: abi.encode("Blocking Bob."),
                value: 0
            })
        });
        vm.startPrank(alice);
        bytes32 uid = eas.attest(blockRequest);
        vm.stopPrank();
        require(pool.isBlocked(bob), "Bob should be blocked.");

        DelegatedRevocationRequest
            memory revokeRequest = DelegatedRevocationRequest({
                schema: blockSchema,
                data: RevocationRequestData({uid: uid, value: 0}),
                signature: EIP712Signature(0, 0, 0),
                revoker: alice
            });
        revokeRequest = signDelegatedRevocationRequest(revokeRequest, 1);
        vm.startPrank(alice);
        pool.revokeWithReason(revokeRequest, "Unblocking Bob.");
        vm.stopPrank();
        require(!pool.isBlocked(bob), "Bob should be unblocked.");
    }

    function testInvitationExpired() public {
        AttestationRequest memory request = AttestationRequest({
            schema: inviteSchema,
            data: AttestationRequestData({
                recipient: bob,
                expirationTime: uint64(block.timestamp) + 1000,
                revocable: true,
                refUID: bytes32(0),
                data: abi.encode(
                    "Bob",
                    "Inviting bob to test expiration of invitations."
                ),
                value: 0
            })
        });
        vm.startPrank(alice);
        eas.attest(request);
        vm.stopPrank();
        require(pool.isInvited(bob), "Bob should be invited");

        pool.updateExpired(bob);
        require(pool.isInvited(bob), "Bob should be invited");

        skip(1001);
        require(pool.isInvited(bob), "Bob should be invited");

        pool.updateExpired(bob);
        require(!pool.isInvited(bob), "Bob should not be invited");
    }

    function testBlockExpired() public {
        AttestationRequest memory request = AttestationRequest({
            schema: inviteSchema,
            data: AttestationRequestData({
                recipient: bob,
                expirationTime: uint64(block.timestamp) + 1000,
                revocable: true,
                refUID: bytes32(0),
                data: abi.encode(
                    "Bob",
                    "Inviting bob to test expiration of block attestation."
                ),
                value: 0
            })
        });
        vm.startPrank(alice);
        eas.attest(request);
        vm.stopPrank();
        require(pool.isInvited(bob), "Bob should be invited");

        pool.updateExpired(bob);
        require(pool.isInvited(bob), "Bob should be invited");

        AttestationRequest memory blockRequest = AttestationRequest({
            schema: blockSchema,
            data: AttestationRequestData({
                recipient: bob,
                expirationTime: uint64(block.timestamp) + 500,
                revocable: true,
                refUID: bytes32(0),
                data: abi.encode("Blocking Bob."),
                value: 0
            })
        });
        vm.startPrank(alice);
        eas.attest(blockRequest);
        vm.stopPrank();
        require(pool.isBlocked(bob), "Bob should be blocked.");

        skip(501);
        require(pool.isBlocked(bob), "Bob should be blocked.");

        pool.updateExpired(bob);
        require(!pool.isBlocked(bob), "Bob should not be blocked.");
        require(pool.isInvited(bob), "Bob should be invited.");

        skip(500);
        require(pool.isInvited(bob), "Bob should be invited");

        pool.updateExpired(bob);
        require(!pool.isInvited(bob), "Bob should not be invited");
    }

    function testFailInviteSelf() public {
        AttestationRequest memory request = AttestationRequest({
            schema: inviteSchema,
            data: AttestationRequestData({
                recipient: alice,
                expirationTime: 0,
                revocable: true,
                refUID: bytes32(0),
                data: abi.encode(
                    "Alice",
                    "Inviting myself to test the contracts."
                ),
                value: 0
            })
        });
        vm.startPrank(alice);
        eas.attest(request);
        vm.stopPrank();
    }

    function testBlockSelf() public {
        AttestationRequest memory request = AttestationRequest({
            schema: blockSchema,
            data: AttestationRequestData({
                recipient: alice,
                expirationTime: 0,
                revocable: true,
                refUID: bytes32(0),
                data: abi.encode("Blocking myself to test the contracts."),
                value: 0
            })
        });
        vm.startPrank(alice);
        bytes32 uid = eas.attest(request);
        vm.stopPrank();
        require(pool.isBlocked(alice), "Alice should be blocked");

        DelegatedRevocationRequest
            memory revokeRequest = DelegatedRevocationRequest({
                schema: inviteSchema,
                data: RevocationRequestData({uid: uid, value: 0}),
                signature: EIP712Signature(0, 0, 0),
                revoker: alice
            });
        revokeRequest = signDelegatedRevocationRequest(revokeRequest, 1);
        vm.startPrank(alice);
        vm.expectRevert();
        pool.revokeWithReason(revokeRequest, "Revoking blocking myself.");
        vm.stopPrank();
    }

    function testDeposit() public {
        AttestationRequest memory request = AttestationRequest({
            schema: depositSchema,
            data: AttestationRequestData({
                recipient: address(0),
                expirationTime: 0,
                revocable: false,
                refUID: bytes32(0),
                data: abi.encode("Testing deposits from invited people."),
                value: 1 ether
            })
        });
        vm.prank(alice);
        eas.attest{value: 1 ether}(request);
        require(address(pool).balance == 1 ether);
        vm.prank(alice);
        eas.attest{value: 1 ether}(request);
        require(address(pool).balance == 2 ether);

        request.data.data = abi.encode(
            "Testing deposits from not invited people."
        );
        vm.prank(bob);
        eas.attest{value: 1 ether}(request);
        require(address(pool).balance == 3 ether);
        vm.prank(bob);
        eas.attest{value: 1 ether}(request);
        require(address(pool).balance == 4 ether);
    }

    function testTransfer() public {
        AttestationRequest memory request = AttestationRequest({
            schema: depositSchema,
            data: AttestationRequestData({
                recipient: address(0),
                expirationTime: 0,
                revocable: false,
                refUID: bytes32(0),
                data: abi.encode("Testing deposits from invited people."),
                value: 1 ether
            })
        });
        vm.prank(alice);
        eas.attest{value: 1 ether}(request);

        request = AttestationRequest({
            schema: transferSchema,
            data: AttestationRequestData({
                recipient: alice,
                expirationTime: 0,
                revocable: false,
                refUID: bytes32(0),
                data: abi.encode(
                    uint256(0.1 ether),
                    "Testing transfer from the contract to alice"
                ),
                value: 0
            })
        });
        vm.prank(alice);
        eas.attest(request);
        require(alice.balance == 9.1 ether);
    }

    function signDelegatedAttestationRequest(
        DelegatedAttestationRequest memory request,
        uint256 privateKey
    ) internal returns (DelegatedAttestationRequest memory) {
        bytes memory encodedData = abi.encode(
            ATTEST_TYPEHASH,
            request.schema,
            request.data.recipient,
            request.data.expirationTime,
            request.data.revocable,
            request.data.refUID,
            keccak256(request.data.data),
            nonces[request.attester]++
        );
        bytes32 digest = ECDSA.toTypedDataHash(
            easDomainSeparator,
            keccak256(encodedData)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);

        request.signature = EIP712Signature({v: v, r: r, s: s});

        return request;
    }

    function signDelegatedRevocationRequest(
        DelegatedRevocationRequest memory request,
        uint256 privateKey
    ) internal returns (DelegatedRevocationRequest memory) {
        bytes memory encodedData = abi.encode(
            REVOKE_TYPEHASH,
            request.schema,
            request.data.uid,
            nonces[request.revoker]++
        );
        bytes32 digest = ECDSA.toTypedDataHash(
            easDomainSeparator,
            keccak256(encodedData)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);

        request.signature = EIP712Signature({v: v, r: r, s: s});

        return request;
    }
}
