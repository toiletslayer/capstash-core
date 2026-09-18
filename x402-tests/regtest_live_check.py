#!/usr/bin/env python3
import argparse, subprocess, json, hashlib, os, time
from decimal import Decimal

REGTEST_GENESIS = "31eaa9512dcf559c436f18870fb26911f6ab58a41d53a9a3ea81f499f1bbd901"
NETWORK = "bip122:31eaa9512dcf559c436f18870fb26911"

def run(cli, *args):
    cmd = [cli, "-regtest", *map(str, args)]
    out = subprocess.check_output(cmd, text=True).strip()
    try: return json.loads(out)
    except json.JSONDecodeError: return out

def atomic_to_cap(n):
    return f"{Decimal(n) / Decimal(100_000_000):.8f}"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cli", default="capstash-cli")
    ap.add_argument("--amount", type=int, default=1_000_000)
    ap.add_argument("--fee", type=int, default=10_000)
    args = ap.parse_args()

    info = run(args.cli, "getblockchaininfo")
    genesis = run(args.cli, "getblockhash", 0)
    if genesis != REGTEST_GENESIS:
        raise SystemExit(f"Wrong chain: genesis={genesis}")

    payer = run(args.cli, "getnewaddress", "x402-payer", "bech32")
    merchant = run(args.cli, "getnewaddress", "x402-merchant", "bech32")
    mine_to = run(args.cli, "getnewaddress", "x402-miner", "bech32")
    run(args.cli, "generatetoaddress", 101, mine_to)
    utxos = run(args.cli, "listunspent", 1, 9999999)
    utxo = next((u for u in utxos if Decimal(str(u["amount"])) > Decimal("0.02")), None)
    if not utxo:
        raise SystemExit("No suitable spendable UTXO")

    invoice = os.urandom(32).hex()
    expires = int(time.time()) + 300
    amount = args.amount
    preimage = (
        "x402-bip122-exact-v1\n"
        f"network={NETWORK}\n"
        "asset=native\n"
        f"amount={amount}\n"
        f"payTo={merchant}\n"
        f"invoiceId={invoice}\n"
        f"expiresAt={expires}\n"
        "minConfirmations=0\n"
    ).encode()
    commit = b"x402" + b"\x01" + hashlib.sha256(preimage).digest()

    prev_atomic = int((Decimal(str(utxo["amount"])) * Decimal(100_000_000)).to_integral_exact())
    change_atomic = prev_atomic - amount - args.fee
    if change_atomic <= 0:
        raise SystemExit("Selected UTXO too small")

    change = run(args.cli, "getrawchangeaddress", "bech32")
    inputs = [{"txid": utxo["txid"], "vout": utxo["vout"], "sequence": 4294967295}]
    outputs = [
        {merchant: atomic_to_cap(amount)},
        {change: atomic_to_cap(change_atomic)},
        {"data": commit.hex()}
    ]
    raw = run(args.cli, "createrawtransaction",
              json.dumps(inputs, separators=(",", ":")),
              json.dumps(outputs, separators=(",", ":")), 0, False)
    signed = run(args.cli, "signrawtransactionwithwallet", raw)
    if not signed.get("complete"):
        raise SystemExit(f"Signing incomplete: {signed}")

    decoded = run(args.cli, "decoderawtransaction", signed["hex"])
    admission = run(args.cli, "testmempoolaccept",
                    json.dumps([signed["hex"]], separators=(",", ":")))
    print("LIVE_POSITIVE_JSON=" + json.dumps({
        "network": NETWORK,
        "chain": info.get("chain"),
        "blocksBeforePayment": info.get("blocks"),
        "payer": payer,
        "merchant": merchant,
        "invoiceId": invoice,
        "commitmentDataHex": commit.hex(),
        "decodedTxid": decoded["txid"],
        "testmempoolaccept": admission
    }, sort_keys=True))

    if not admission[0].get("allowed"):
        raise SystemExit("Transaction did not pass testmempoolaccept")
    txid = run(args.cli, "sendrawtransaction", signed["hex"])
    print("BROADCAST_TXID=" + txid)
    if txid != decoded["txid"]:
        raise SystemExit("Broadcast txid mismatch")
    mempool_entry = run(args.cli, "getmempoolentry", txid)
    print("MEMPOOL_ENTRY_JSON=" + json.dumps(mempool_entry, sort_keys=True))
    mined = run(args.cli, "generatetoaddress", 1, mine_to)
    print("MINED_BLOCK=" + mined[0])
    tx = run(args.cli, "gettransaction", txid)
    print("CONFIRMATION_JSON=" + json.dumps({
        "txid": txid,
        "confirmations": tx.get("confirmations"),
        "blockhash": tx.get("blockhash"),
        "blockheight": tx.get("blockheight")
    }, sort_keys=True))
    if int(tx.get("confirmations", 0)) < 1:
        raise SystemExit("Transaction failed to confirm")
    print("LIVE_REGTEST_PASS")

if __name__ == "__main__":
    main()
