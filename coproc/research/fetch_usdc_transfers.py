#!/usr/bin/env python3
"""
Fetch the last N USDC transfer events from Ethereum using JSON-RPC.
"""

import json
import re
import requests
import sys
import time
from typing import List, Dict, Any, Optional, Tuple


# USDC contract address on Ethereum mainnet
USDC_ADDRESS = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"

# Transfer event signature: Transfer(address indexed from, address indexed to, uint256 value)
TRANSFER_EVENT_SIGNATURE = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

# Initial block range to query (will be adjusted dynamically)
INITIAL_CHUNK_SIZE = 100
MIN_CHUNK_SIZE = 10


class RPCError(Exception):
    def __init__(self, error_dict: Dict[str, Any]):
        self.code = error_dict.get('code')
        self.message = error_dict.get('message', '')
        super().__init__(f"RPC Error [{self.code}]: {self.message}")
        self.error_dict = error_dict


class RPCClient:
    def __init__(self, endpoint: str):
        self.endpoint = endpoint
        self.request_id = 0

    def call(self, method: str, params: List[Any]) -> Any:
        self.request_id += 1
        payload = {
            "jsonrpc": "2.0",
            "id": self.request_id,
            "method": method,
            "params": params
        }

        response = requests.post(self.endpoint, json=payload)
        response.raise_for_status()

        result = response.json()
        if "error" in result:
            raise RPCError(result['error'])

        return result.get("result")


def parse_log_entry(log: Dict[str, Any]) -> Dict[str, Any]:
    """Parse a single log entry into a transfer record."""
    block_number = int(log["blockNumber"], 16)

    # Extract from and to addresses from topics
    from_address = "0x" + log["topics"][1][-40:]
    to_address = "0x" + log["topics"][2][-40:]

    # Extract value from data (uint256, 32 bytes)
    value_hex = log["data"]
    value_atoms = int(value_hex, 16)

    return {
        "from": from_address,
        "to": to_address,
        "atoms": value_atoms,
        "block_number": block_number,
        "transaction_hash": log["transactionHash"]
    }


def fetch_logs_with_retry(
    client: RPCClient,
    from_block: int,
    to_block: int,
    max_retries: int = 3
) -> Tuple[List[Dict[str, Any]], int]:
    """
    Fetch logs with automatic retry and chunk size reduction on errors.

    Returns:
        Tuple of (logs, next_from_block)
    """
    chunk_size = to_block - from_block

    for attempt in range(max_retries):
        try:
            filter_params = {
                "fromBlock": hex(from_block),
                "toBlock": hex(to_block),
                "address": USDC_ADDRESS,
                "topics": [TRANSFER_EVENT_SIGNATURE]
            }

            logs = client.call("eth_getLogs", [filter_params])
            return logs, from_block - 1

        except RPCError as e:
            # Check if error is about too many results or too large range
            if "range" in e.message.lower() or "max results" in e.message.lower():
                # Try to extract suggested range from error message
                match = re.search(r'(\d+)-(\d+)', e.message)
                if match:
                    suggested_from = int(match.group(1))
                    suggested_to = int(match.group(2))
                    new_chunk = suggested_to - suggested_from
                    print(f"  RPC suggested range: {suggested_from}-{suggested_to} ({new_chunk} blocks)")
                    to_block = suggested_to
                    from_block = suggested_from
                else:
                    # Reduce chunk size by half
                    new_chunk = max(MIN_CHUNK_SIZE, chunk_size // 2)
                    from_block = to_block - new_chunk
                    print(f"  Reducing chunk size to {new_chunk} blocks")

                chunk_size = to_block - from_block

                if chunk_size < MIN_CHUNK_SIZE:
                    print(f"  Chunk size too small, skipping block range")
                    return [], from_block - 1

                time.sleep(0.5)  # Brief delay before retry
            else:
                raise

    # If all retries failed
    print(f"  Failed after {max_retries} attempts, skipping range")
    return [], from_block - 1


def fetch_usdc_transfers(rpc_endpoint: str, num_events: int) -> Dict[str, Any]:
    """
    Fetch the last N USDC transfer events from Ethereum.

    Args:
        rpc_endpoint: Ethereum JSON-RPC endpoint URL
        num_events: Number of transfer events to fetch

    Returns:
        Dictionary containing transfers and block range
    """
    client = RPCClient(rpc_endpoint)

    # Get the latest block number
    latest_block_hex = client.call("eth_blockNumber", [])
    latest_block = int(latest_block_hex, 16)
    print(f"Latest block: {latest_block}\n")

    all_transfers = []
    current_block = latest_block
    chunk_size = INITIAL_CHUNK_SIZE

    # Fetch events in chunks going backwards
    while len(all_transfers) < num_events and current_block > 0:
        to_block = current_block
        from_block = max(0, current_block - chunk_size)

        print(f"[{len(all_transfers)}/{num_events}] Querying blocks {from_block} to {to_block} ({to_block - from_block} blocks)...")

        logs, next_block = fetch_logs_with_retry(client, from_block, to_block)

        if logs:
            print(f"  Found {len(logs)} events")

            # Process logs in reverse order (newest first)
            for log in reversed(logs):
                if len(all_transfers) >= num_events:
                    break
                all_transfers.append(parse_log_entry(log))

            # Adaptive chunk sizing: increase if we got results successfully
            chunk_size = min(1000, int(chunk_size * 1.5))
        else:
            print(f"  No events found")

        current_block = next_block

        if current_block <= 0:
            print("\nReached genesis block")
            break

    # Trim to exactly N events
    all_transfers = all_transfers[:num_events]

    # Calculate actual block range
    if all_transfers:
        actual_min_block = min(t["block_number"] for t in all_transfers)
        actual_max_block = max(t["block_number"] for t in all_transfers)
    else:
        actual_min_block = latest_block
        actual_max_block = latest_block

    return {
        "block_range": {
            "from_block": actual_min_block,
            "to_block": actual_max_block
        },
        "total_events": len(all_transfers),
        "transfers": [
            {
                "from": t["from"],
                "to": t["to"],
                "atoms": t["atoms"]
            }
            for t in all_transfers
        ],
        "transfers_with_metadata": all_transfers  # Including block number and tx hash
    }


def main():
    if len(sys.argv) < 3:
        print("Usage: python fetch_usdc_transfers.py <RPC_ENDPOINT> <NUM_EVENTS> [OUTPUT_FILE]")
        print("\nExample:")
        print("  python fetch_usdc_transfers.py https://eth.llamarpc.com 100 output.json")
        sys.exit(1)

    rpc_endpoint = sys.argv[1]
    num_events = int(sys.argv[2])
    output_file = sys.argv[3] if len(sys.argv) > 3 else "usdc_transfers.json"

    print(f"Fetching last {num_events} USDC transfers from Ethereum...")
    print(f"RPC Endpoint: {rpc_endpoint}")
    print(f"Output file: {output_file}\n")

    try:
        result = fetch_usdc_transfers(rpc_endpoint, num_events)

        # Save to JSON
        with open(output_file, 'w') as f:
            json.dump(result, f, indent=2)

        print(f"\n✓ Successfully fetched {result['total_events']} transfers")
        print(f"✓ Block range: {result['block_range']['from_block']} to {result['block_range']['to_block']}")
        print(f"✓ Saved to {output_file}")

    except Exception as e:
        print(f"\n✗ Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
