import hashlib, subprocess, sys
ALPHA="13456789abcdefghijkmnopqrstuwxyz"
p=2**255-19; d=(-121665*pow(121666,p-2,p))%p; I=pow(2,(p-1)//4,p)
def xrec(y):
    xx=(y*y-1)*pow(d*y*y+1,p-2,p)%p; x=pow(xx,(p+3)//8,p)
    if (x*x-xx)%p: x=x*I%p
    return p-x if x%2 else x
By=4*pow(5,p-2,p)%p; B=(xrec(By)%p,By%p,1,xrec(By)*By%p)
def ea(P,Q):
    (x1,y1,z1,t1),(x2,y2,z2,t2)=P,Q
    a=(y1-x1)*(y2-x2)%p;b=(y1+x1)*(y2+x2)%p;c=t1*2*d*t2%p;dd=z1*2*z2%p
    e,f,g,h=b-a,dd-c,dd+c,b+a
    return(e*f%p,g*h%p,f*g%p,e*h%p)
def sm(P,e):
    Q=(0,1,1,0)
    while e>0:
        if e&1:Q=ea(Q,P)
        P=ea(P,P);e>>=1
    return Q
def enc(P):
    x,y,z,t=P;zi=pow(z,p-2,p);x,y=x*zi%p,y*zi%p
    bits=[(y>>i)&1 for i in range(255)]+[x&1]
    return bytes(sum(bits[i*8+k]<<k for k in range(8)) for i in range(32))
def clamp(s):
    s=bytearray(s);s[0]&=248;s[31]&=127;s[31]|=64;return bytes(s)
def addr(pk):
    n=int.from_bytes(pk,'big')
    body=''.join(ALPHA[(n>>(255-5*i))&31] for i in range(52))
    c=hashlib.blake2b(pk,digest_size=5).digest()[::-1]; cn=int.from_bytes(c,'big')
    return 'nano_'+body+''.join(ALPHA[(cn>>(5*(7-i)))&31] for i in range(8))

def independent(seed, index):
    priv = hashlib.blake2b(seed+index.to_bytes(4,'big'),digest_size=32).digest()
    pk = enc(sm(B, int.from_bytes(clamp(hashlib.blake2b(priv,digest_size=64).digest()[:32]),'little')))
    return priv.hex().upper(), addr(pk)

import os
BIN = os.environ.get(
    "NANO_VANITY_BIN",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "target", "release",
                 "nano-vanity"))

fails = 0

def check(name, got, want):
    global fails
    ok = got == want
    fails += not ok
    print(f"  {name}")
    print(f"    got  {got}")
    print(f"    want {want}")
    print(f"    {'OK' if ok else 'MISMATCH'}\n")
    return ok

print("Independent Python re-implementation, cross-checked against the binary.\n")

# 1. A fixed published anchor. This is the vector from docs.nano.org, so it
#    tests the implementation against something outside this repository rather
#    than only against itself.
print("Published vector (docs.nano.org):")
V_SEED = "D56143E7561D71C1AF4D563C6AF79EECE93E82479818AD8ED88BED1AAE8BE4E5"
V_PRIV = "1F6FEB5D1E05C10B904E1112F430C3FA93ACC7067206B63AD155199501794E3E"
V_ADDR = "nano_16odwi933gpzmkgdcy9tt5zef5ka3jcfubc97fwypsokg7sji4mb9n6qtbme"
priv, adr = independent(bytes.fromhex(V_SEED), 0)
check("private key", priv, V_PRIV)
check("address", adr, V_ADDR)

# 2. Live cross-check. The binary prints the seed it used, so Python can redo
#    the whole derivation from that seed and the reported index. Previously this
#    compared against an all-zero seed while the binary used a random one, so it
#    could never pass.
print("Live cross-check against the binary:")
for prefix in ["1111", "16", "3", "111"]:
    out = subprocess.run([BIN, prefix, "-t", "8"], capture_output=True, text=True,
                         timeout=300).stdout
    field = lambda k: next(l.split(":", 1)[1].strip() for l in out.splitlines()
                           if l.strip().startswith(k))
    seed_hex, idx = field("wallet seed"), int(field("account idx"))
    priv, adr = independent(bytes.fromhex(seed_hex), idx)
    check(f"prefix {prefix!r} (index {idx}, seed {seed_hex[:12]}...)",
          (field("private key"), field("address")), (priv, adr))

print("CROSS-CHECK RESULT:", "ALL PASS" if fails == 0 else f"{fails} FAILURES")
sys.exit(1 if fails else 0)
