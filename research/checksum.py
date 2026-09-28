import hashlib
ALPHA="13456789abcdefghijkmnopqrstuwxyz"
def enc8(b): 
    n=int.from_bytes(b,'big'); return "".join(ALPHA[(n>>(5*(7-i)))&31] for i in range(8))

V=[("5b65b0e8173ee0802c2c3e6c9080d1a16b06de1176c938a924f58670904e82c4","9emk8y1d"),
   ("d9f7762e9cd4e7ed632481308cdb8f54abf0241332c0a8641f61e92e2fb03c12","47yu78gz")]

cands={}
for pkhex,exp in V:
    pk=bytes.fromhex(pkhex)
    c={}
    c['d32[0:5]fwd']=enc8(hashlib.blake2b(pk,digest_size=32).digest()[:5])
    c['d32[0:5]rev']=enc8(hashlib.blake2b(pk,digest_size=32).digest()[:5][::-1])
    c['d32[27:32]fwd']=enc8(hashlib.blake2b(pk,digest_size=32).digest()[27:32])
    c['d32[27:32]rev']=enc8(hashlib.blake2b(pk,digest_size=32).digest()[27:32][::-1])
    c['d5fwd']=enc8(hashlib.blake2b(pk,digest_size=5).digest())
    c['d5rev']=enc8(hashlib.blake2b(pk,digest_size=5).digest()[::-1])
    c['d64[0:5]fwd']=enc8(hashlib.blake2b(pk,digest_size=64).digest()[:5])
    c['d64[0:5]rev']=enc8(hashlib.blake2b(pk,digest_size=64).digest()[:5][::-1])
    c['d64[59:64]fwd']=enc8(hashlib.blake2b(pk,digest_size=64).digest()[59:64])
    c['d64[59:64]rev']=enc8(hashlib.blake2b(pk,digest_size=64).digest()[59:64][::-1])
    print(f"--- {pkhex[:16]}... expected checksum = {exp}")
    for k,v in c.items():
        mark = "  <<<< MATCH" if v==exp else ""
        print(f"    {k:18} {v}{mark}")
    if not cands: cands=c
    else:
        inter=[k for k in cands if cands[k]==exp]
        if inter: print("    candidates consistent with BOTH:", inter)
