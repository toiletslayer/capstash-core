#!/usr/bin/env python3
import argparse, subprocess, json, hashlib, time
from decimal import Decimal

REGTEST_GENESIS = "31eaa9512dcf559c436f18870fb26911f6ab58a41d53a9a3ea81f499f1bbd901"
NETWORK = "bip122:31eaa9512dcf559c436f18870fb26911"
ATOMIC = Decimal(100_000_000)

def run(cli, *args):
    cmd=[cli,"-regtest",*map(str,args)]
    p=subprocess.run(cmd,text=True,capture_output=True)
    if p.returncode:
        raise RuntimeError(f"RPC failed {cmd}: rc={p.returncode} stdout={p.stdout!r} stderr={p.stderr!r}")
    s=p.stdout.strip()
    try: return json.loads(s)
    except json.JSONDecodeError: return s

def cap(n): return f"{Decimal(n)/ATOMIC:.8f}"

def commitment(network, amount, payto, invoice, expires, minconf=0):
    pre=("x402-bip122-exact-v1\n"+f"network={network}\n"+"asset=native\n"+
         f"amount={amount}\n"+f"payTo={payto}\n"+f"invoiceId={invoice}\n"+
         f"expiresAt={expires}\n"+f"minConfirmations={minconf}\n").encode()
    return b"x402"+b"\x01"+hashlib.sha256(pre).digest()

def vi(buf, off):
    x=buf[off]; off+=1
    if x<0xfd:return x,off
    if x==0xfd:return int.from_bytes(buf[off:off+2],'little'),off+2
    if x==0xfe:return int.from_bytes(buf[off:off+4],'little'),off+4
    return int.from_bytes(buf[off:off+8],'little'),off+8

def mutate_witness_signature(rawhex):
    b=bytearray.fromhex(rawhex); off=4
    if b[off:off+2]!=b"\x00\x01": raise ValueError("not segwit")
    off+=2; nin,off=vi(b,off)
    for _ in range(nin):
        off+=36; n,off=vi(b,off); off+=n+4
    nout,off=vi(b,off)
    for _ in range(nout):
        off+=8; n,off=vi(b,off); off+=n
    nstack,off=vi(b,off)
    if nstack<1: raise ValueError("no witness")
    n,off=vi(b,off)
    b[off+n-2]^=1
    return b.hex()

def make_tx(cli, utxo, merchant, change, amount, fee, invoice, expires,
            recipient=None, include_commit=True, bad_commit=False,
            duplicate_commit=False, sequence=0xffffffff, locktime=0):
    recipient=recipient or merchant
    prev_atomic=int((Decimal(str(utxo['amount']))*ATOMIC).to_integral_exact())
    change_atomic=prev_atomic-amount-fee
    c=bytearray(commitment(NETWORK, amount, merchant, invoice, expires))
    if bad_commit: c[-1]^=1
    inputs=[{"txid":utxo['txid'],"vout":utxo['vout'],"sequence":sequence}]
    outs=[{recipient:cap(amount)}]
    if change_atomic: outs.append({change:cap(change_atomic)})
    if include_commit:
        outs.append({"data":bytes(c).hex()})
        if duplicate_commit: outs.append({"data":bytes(c).hex()})
    raw=run(cli,"createrawtransaction",json.dumps(inputs,separators=(',',':')),
            json.dumps(outs,separators=(',',':')),locktime,False)
    signed=run(cli,"signrawtransactionwithwallet",raw)
    if not signed.get('complete'): raise RuntimeError(f"incomplete sign: {signed}")
    return signed['hex']

def tma(cli, raw):
    return run(cli,"testmempoolaccept",json.dumps([raw],separators=(',',':')))[0]

def protocol_check(cli, raw, req, now):
    if req['network']!=NETWORK: return False,'invalid_network'
    e=req['extra']
    if now>e['expiresAt']: return False,'invalid_exact_bip122_invoice_expired'
    d=run(cli,"decoderawtransaction",raw)
    if d.get('locktime',0)!=0:return False,'invalid_exact_bip122_nonfinal'
    if any(int(v['sequence'])<0xfffffffe for v in d['vin']):return False,'invalid_exact_bip122_rbf'
    merchant_script=run(cli,"getaddressinfo",req['payTo'])['scriptPubKey']
    matches=[v for v in d['vout'] if v['scriptPubKey']['hex']==merchant_script]
    if len(matches)!=1:return False,'invalid_exact_bip122_recipient_mismatch'
    got=int((Decimal(str(matches[0]['value']))*ATOMIC).to_integral_exact())
    if got!=int(req['amount']):return False,'invalid_exact_bip122_amount_mismatch'
    expected=commitment(req['network'],int(req['amount']),req['payTo'],e['invoiceId'],e['expiresAt'],e['minConfirmations'])
    expected_script=(b'\x6a'+bytes([len(expected)])+expected).hex()
    commits=[v for v in d['vout'] if v['scriptPubKey']['hex'].startswith('6a25')]
    if len(commits)!=1 or Decimal(str(commits[0]['value']))!=0 or commits[0]['scriptPubKey']['hex']!=expected_script:
        return False,'invalid_exact_bip122_commitment'
    return True,'ok'

def req(merchant, invoice, expires, amount=1_000_000, network=NETWORK):
    return {"scheme":"exact","network":network,"amount":str(amount),"asset":"native","payTo":merchant,
            "extra":{"assetTransferMethod":"signedTransaction","paymentFlow":"upfront",
                     "invoiceId":invoice,"expiresAt":expires,"minConfirmations":0}}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--cli',required=True); a=ap.parse_args(); cli=a.cli
    genesis=run(cli,'getblockhash',0)
    if genesis!=REGTEST_GENESIS: raise SystemExit(f"wrong genesis {genesis}")
    miner=run(cli,'getnewaddress','neg-miner','bech32')
    merchant=run(cli,'getnewaddress','neg-merchant','bech32')
    wrong=run(cli,'getnewaddress','neg-wrong','bech32')
    change=run(cli,'getrawchangeaddress','bech32')
    run(cli,'generatetoaddress',110,miner)
    utxos=run(cli,'listunspent',1,9999999)
    utxo=next(u for u in utxos if Decimal(str(u['amount']))>Decimal('0.02'))
    now=int(time.time()); expiry=now+600; invoice='22'*32; amount=1_000_000; fee=10_000
    base_req=req(merchant,invoice,expiry); cases=[]
    def add(name, raw, request=base_req):
        node=tma(cli,raw); pok,preason=protocol_check(cli,raw,request,now)
        cases.append({"case":name,"testmempoolaccept":node,"protocol":{"accepted":pok,"result":preason}})

    add('valid_candidate',make_tx(cli,utxo,merchant,change,amount,fee,invoice,expiry))
    add('underpayment_one_atomic',make_tx(cli,utxo,merchant,change,amount-1,fee,invoice,expiry),base_req)
    add('overpayment_one_atomic',make_tx(cli,utxo,merchant,change,amount+1,fee,invoice,expiry),base_req)
    add('wrong_recipient',make_tx(cli,utxo,merchant,change,amount,fee,invoice,expiry,recipient=wrong),base_req)
    add('missing_commitment',make_tx(cli,utxo,merchant,change,amount,fee,invoice,expiry,include_commit=False),base_req)
    add('bad_commitment',make_tx(cli,utxo,merchant,change,amount,fee,invoice,expiry,bad_commit=True),base_req)
    add('duplicate_commitment',make_tx(cli,utxo,merchant,change,amount,fee,invoice,expiry,duplicate_commit=True),base_req)
    add('rbf_signaling',make_tx(cli,utxo,merchant,change,amount,fee,invoice,expiry,sequence=0xfffffffd),base_req)
    add('nonzero_locktime',make_tx(cli,utxo,merchant,change,amount,fee,invoice,expiry,locktime=1),base_req)
    expired=now-1; expired_req=req(merchant,invoice,expired)
    add('expired_invoice',make_tx(cli,utxo,merchant,change,amount,fee,invoice,expired),expired_req)
    add('zero_fee',make_tx(cli,utxo,merchant,change,amount,0,invoice,expiry),base_req)

    good=make_tx(cli,utxo,merchant,change,amount,fee,invoice,expiry)
    badsig=mutate_witness_signature(good)
    cases.append({"case":"invalid_signature","testmempoolaccept":tma(cli,badsig),
                  "protocol":{"accepted":None,"result":"node-script-validation"}})
    wrongnet=req(merchant,invoice,expiry,network='bip122:8ece4004870037c2c279203723123c62')
    node=tma(cli,good); pok,preason=protocol_check(cli,good,wrongnet,now)
    cases.append({"case":"wrong_connected_network","testmempoolaccept":node,
                  "protocol":{"accepted":pok,"result":preason}})

    utxo2=next(u for u in utxos if (u['txid'],u['vout'])!=(utxo['txid'],utxo['vout']) and Decimal(str(u['amount']))>Decimal('0.02'))
    inva='33'*32; invb='44'*32
    txa=make_tx(cli,utxo2,merchant,change,amount,fee,inva,expiry)
    txb=make_tx(cli,utxo2,merchant,change,amount,fee,invb,expiry)
    pre_a=tma(cli,txa); pre_b=tma(cli,txb)
    txid_a=run(cli,'sendrawtransaction',txa)
    post_b=tma(cli,txb)
    mined=run(cli,'generatetoaddress',1,miner)
    conf=run(cli,'gettransaction',txid_a).get('confirmations')
    cases.append({"case":"double_spend_conflict","beforeBroadcast":{"A":pre_a,"B":pre_b},
                  "broadcastA":txid_a,"afterBroadcastB":post_b,
                  "minedBlock":mined[0] if mined else None,"confirmationsA":conf})
    print('LIVE_NEGATIVE_RESULTS='+json.dumps({"genesis":genesis,"network":NETWORK,"merchant":merchant,"cases":cases},sort_keys=True))

if __name__=='__main__': main()
