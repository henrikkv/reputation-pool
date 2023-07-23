// SPDX-License-Identifier: MIT

pragma solidity 0.8.19;

import "@eas-contracts/IEAS.sol";
import "@eas-contracts/ISchemaRegistry.sol";
import "@eas-contracts/resolver/SchemaResolver.sol";

import "forge-std/Test.sol";

contract Vault is SchemaResolver, Test {
    ISchemaRegistry private immutable _registry;

    bytes32 public poolSchema;

    bytes32 public inviteSchema;
    bytes32 public blockSchema;
    bytes32 public revokeReasonSchema;
    bytes32 public depositSchema;
    bytes32 public transferSchema;

    // Balance for each pool.
    mapping(bytes32 => uint256) public balance;
    // Blocks for each user for each pool.
    mapping(bytes32 => mapping(address => bytes32[])) public blocks;
    // Invites fro each user for each pool.
    mapping(bytes32 => mapping(address => bytes32[])) public invites;

    mapping(bytes32 => bool) public hasRevokeReason;

    function isBlocked(bytes32 pool, address addr) public view returns (bool) {
        return blocks[pool][addr].length != 0;
    }

    function isInvited(bytes32 pool, address addr) public view returns (bool) {
        return invites[pool][addr].length >= 1;
    }

    function isPayable() public pure override returns (bool) {
        return true;
    }

    constructor(IEAS eas) SchemaResolver(eas) {
        _registry = _eas.getSchemaRegistry();

        poolSchema = _registry.register(
            "string name, string description, string creatorName",
            this,
            false
        );
        // Recipient is the invited address.
        inviteSchema = _registry.register(
            "string name, string inviteReason",
            this,
            true
        );
        // Recipient is the blocked address.
        blockSchema = _registry.register("string blockReason", this, true);
        // RefUID is attestation to revoke.
        revokeReasonSchema = _registry.register(
            "string revokeReason",
            this,
            false
        );
        depositSchema = _registry.register("string depositReason", this, false);
        // Recipient is the address to transfer to.
        transferSchema = _registry.register(
            "uint256 amount, string transferReason",
            this,
            false
        );
    }

    function onAttest(
        Attestation calldata attestation,
        uint256 value
    ) internal override returns (bool) {
        if (attestation.schema == poolSchema) {
            (, , string memory creatorName) = abi.decode(
                attestation.data,
                (string, string, string)
            );

            AttestationRequest memory request = AttestationRequest({
                schema: inviteSchema,
                data: AttestationRequestData({
                    recipient: attestation.attester,
                    expirationTime: 0,
                    revocable: true,
                    refUID: attestation.uid,
                    data: abi.encode(creatorName, "Inviting pool creator."),
                    value: 0
                })
            });
            if (_eas.attest(request) != 0) return true;
            return false;
        }

        bytes32 pool = attestation.refUID;
        if (pool == bytes32(0)) return false;

        if (attestation.schema == depositSchema) {
            if (value == 0) return false;
            balance[pool] += value;
            return true;
        }
        // Schemas below are not payable.
        if (value != 0) return false;

        if (attestation.schema == revokeReasonSchema) {
            Attestation memory toRevoke = _eas.getAttestation(
                attestation.refUID
            );
            if (
                attestation.attester != toRevoke.attester || !toRevoke.revocable
            ) return false;
            hasRevokeReason[toRevoke.uid] = true;
            return true;
        }

        // Only allow attestations from this contract or invited and not blocked addresses.
        if (
            (isBlocked(pool, attestation.attester) ||
                !isInvited(pool, attestation.attester))
        ) {
            if (attestation.attester != address(this)) return false;
        }

        if (attestation.schema == inviteSchema) {
            if (attestation.recipient == address(0)) return false;
            if (attestation.recipient == attestation.attester) return false;
            invites[pool][attestation.recipient].push(attestation.uid);
            return true;
        }
        if (attestation.schema == blockSchema) {
            blocks[pool][attestation.recipient].push(attestation.uid);
            return true;
        }
        if (attestation.schema == transferSchema) {
            if (attestation.recipient == address(0)) return false;
            uint256 amount;
            string memory reason;
            (amount, reason) = abi.decode(attestation.data, (uint256, string));

            if (amount > balance[pool] || amount == 0) return false;
            balance[pool] -= amount;
            (bool sent, ) = attestation.recipient.call{value: amount}("");
            if (!sent) return false;
            return true;
        }
        return false;
    }

    function onRevoke(
        Attestation calldata attestation,
        uint256
    ) internal override returns (bool) {
        if (!hasRevokeReason[attestation.uid]) return false;

        bytes32 pool = attestation.refUID;
        if (isBlocked(pool, attestation.attester)) return false;
        if (!isInvited(pool, attestation.attester)) return false;

        if (attestation.schema == inviteSchema) {
            // Remove revoked invitation from the invites list.
            bytes32[] storage array = invites[pool][attestation.recipient];
            for (uint i = 0; i < array.length; i++) {
                if (array[i] == attestation.uid) {
                    array[i] = array[array.length - 1];
                    array.pop();
                    break;
                }
            }
            return true;
        }
        if (attestation.schema == blockSchema) {
            // Remove revoked block from the blocks list.
            bytes32[] storage array = blocks[pool][attestation.recipient];
            for (uint i = 0; i < array.length; i++) {
                if (array[i] == attestation.uid) {
                    array[i] = array[array.length - 1];
                    array.pop();
                    break;
                }
            }
            return true;
        }
        return false;
    }

    // Remove expired attestations from the invites and blocks list of addr.
    function updateExpired(bytes32 pool, address addr) external {
        Attestation memory attestation;
        uint64 time = uint64(block.timestamp);
        bytes32[] storage array = invites[pool][addr];

        for (uint i = 0; i < array.length; i++) {
            attestation = _eas.getAttestation(array[i]);
            if (attestation.expirationTime < time) {
                array[i] = array[array.length - 1];
                array.pop();
            }
        }
        array = blocks[pool][addr];
        for (uint i = 0; i < array.length; i++) {
            attestation = _eas.getAttestation(array[i]);
            if (attestation.expirationTime < time) {
                array[i] = array[array.length - 1];
                array.pop();
            }
        }
    }
}
