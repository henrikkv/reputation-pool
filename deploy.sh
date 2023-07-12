#!/bin/sh

forge create --rpc-url https://rpc.sepolia.org/ --chain 11155111 --private-key $(cat ~/.key) \
	--constructor-args 0xC2679fBD37d54388Ce493F1DB75320D236e1815e 0x9c26326e71005038f39f00d945c1da6077f4d9b77634221654a03a4477340598 \
	--etherscan-api-key $(cat ~/.etherscan-api-key) \
	--verify \
	./src/Pool.sol:Pool
