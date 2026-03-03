#!/usr/bin/env python3
import json
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

# Auto-incrementing block height for realistic E2E testing.
# Each call to /blocks/latest advances the height, preventing tests
# from silently passing with stale data.
_block_height = 123456
_block_height_lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    def _send(self, status: int, payload: dict):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/health":
            return self._send(200, {"jsonrpc": "2.0", "id": -1, "result": {"status": "ok"}})

        if path == "/cosmos/base/tendermint/v1beta1/node_info":
            return self._send(200, {
                "default_node_info": {
                    "defaultNodeId": "mocknodeid",
                    "listenAddr": "tcp://0.0.0.0:26657",
                    "network": "aethelred-local-devtools-1",
                    "version": "0.0.1-devtools",
                    "moniker": "aethelred-mock-rpc",
                }
            })

        if path == "/cosmos/base/tendermint/v1beta1/blocks/latest":
            global _block_height
            with _block_height_lock:
                _block_height += 1
                height = _block_height
            return self._send(200, {
                "block": {
                    "header": {
                        "height": str(height),
                        "time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "chain_id": "aethelred-local-devtools-1",
                    }
                }
            })

        if path.startswith("/cosmos/bank/v1beta1/balances/"):
            address = path.rsplit("/", 1)[-1]
            return self._send(200, {
                "balances": [
                    {"denom": "uaeth", "amount": "1000000000"},
                    {"denom": "aethel", "amount": "500000000"},
                ],
                "pagination": {"total": "2"},
                "address": address,
            })

        if path.startswith("/aethelred/pouw/v1/validators/") and path.endswith("/stats"):
            address = path.split("/")[-2]
            return self._send(200, {
                "address": address,
                "jobsCompleted": 1024,
                "jobsFailed": 3,
                "averageLatencyMs": 812,
                "uptimePercentage": 99.92,
                "reputationScore": 98.5,
                "totalRewards": "1250000",
                "slashingEvents": 0,
            })

        if path == "/aethelred/pouw/v1/validators":
            return self._send(200, {
                "validators": [
                    {
                        "address": "aethvaloper1alpha",
                        "jobsCompleted": 1024,
                        "jobsFailed": 3,
                        "averageLatencyMs": 812,
                        "uptimePercentage": 99.92,
                        "reputationScore": 98.5,
                        "totalRewards": "1250000",
                        "slashingEvents": 0,
                    },
                    {
                        "address": "aethvaloper1beta",
                        "jobsCompleted": 873,
                        "jobsFailed": 5,
                        "averageLatencyMs": 941,
                        "uptimePercentage": 99.51,
                        "reputationScore": 96.7,
                        "totalRewards": "1032000",
                        "slashingEvents": 0,
                    },
                ]
            })

        if path.startswith("/aethelred/seal/v1/seals/") and path.endswith("/verify"):
            return self._send(200, {
                "valid": True,
                "verificationDetails": {
                    "signature": True,
                    "consensus": True,
                    "teeAttestation": True,
                },
                "errors": [],
            })

        if path.startswith("/aethelred/seal/v1/seals/"):
            seal_id = path.rsplit("/", 1)[-1]
            now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            return self._send(200, {
                "seal": {
                    "id": seal_id,
                    "jobId": "job_local_001",
                    "modelHash": "0xaaaabbbb",
                    "inputCommitment": "0x1111",
                    "outputCommitment": "0x2222",
                    "modelCommitment": "0x3333",
                    "status": "SEAL_STATUS_ACTIVE",
                    "requester": "aeth1developer",
                    "createdAt": now_utc,
                    "expiresAt": "2026-12-31T00:00:00Z",
                    "validators": [
                        {"validatorAddress": "aethvaloper1alpha", "signature": "0xsig1", "votingPower": "34"},
                        {"validatorAddress": "aethvaloper1beta", "signature": "0xsig2", "votingPower": "33"},
                    ],
                    "consensus": {"totalVotingPower": "100", "attestedVotingPower": "67", "thresholdBps": 6700},
                    "teeAttestation": {
                        "platform": "TEE_PLATFORM_AWS_NITRO",
                        "enclaveHash": "0xdevtools",
                        "timestamp": now_utc,
                        "nonce": "0xnonce",
                        "pcrValues": {"0": "0xpcr0"},
                    },
                }
            })

        return self._send(404, {"error": "not_found", "path": path})


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 26657), Handler)
    server.serve_forever()
