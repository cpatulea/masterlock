#!/usr/bin/python
import binascii, ctypes, itertools, os, subprocess, re, sys
from pyelliptic.openssl import OpenSSL

OpenSSL.EC_POINT_point2hex = OpenSSL._lib.EC_POINT_point2hex
OpenSSL.EC_POINT_point2hex.restype = ctypes.c_void_p
OpenSSL.EC_POINT_point2hex.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
POINT_CONVERSION_COMPRESSED = 2

OpenSSL.CRYPTO_free = OpenSSL._lib.CRYPTO_free
OpenSSL.CRYPTO_free.restype = None
OpenSSL.CRYPTO_free.argtypes = [ctypes.c_void_p]

def unlink_f(n):
  try:
    os.unlink(n)
  except OSError:
    pass

# parse
bitcoin, wk, ciphertext = None, None, None
for line in open('montrehack.flag.nc'):
  _, sep, rest = line.partition('cp=')
  if sep:
    cp = rest.rstrip()

  _, sep, rest = line.partition('wk=')
  if sep:
    wk = rest.rstrip()

_, sep, ciphertext = open('montrehack.flag.nc').read().partition('\n.\n')
assert sep and cp and wk and ciphertext

print 'cp=%s' % cp
print 'wk=%s' % wk

# factor
unlink_f('msieve.log')
unlink_f('msieve.dat')
subprocess.check_call(['../msieve/msieve', '0x' + wk])
factors = []
for line in open('msieve.log'):
  m = re.search(r'  ([cp])\d+ factor: (\d+)', line)
  if m:
    assert m.group(1) == 'p'
    factors.append(int(m.group(2)))

print '%d factors: %r' % (len(factors), factors)

# check
key, tried = None, 0
k = OpenSSL.EC_KEY_new_by_curve_name(OpenSSL.get_curve('secp256k1'))
group = OpenSSL.EC_KEY_get0_group(k)
for ff in itertools.product(*[[1, f] for f in factors]):
  a = 1
  for f in ff: a *= f

  if a >= 2 ** 128:
    continue

  ahex = '%x' % a
  if len(ahex) % 2: ahex = '0' + ahex
  abin = binascii.unhexlify(ahex)

  priv_key = OpenSSL.BN_bin2bn(abin, len(abin), 0)
  pub_key = OpenSSL.EC_POINT_new(group)
  assert OpenSSL.EC_POINT_mul(group, pub_key, priv_key, None, None, None) == 1

  pubhex = OpenSSL.EC_POINT_point2hex(
      group, pub_key, POINT_CONVERSION_COMPRESSED, 0)
  if ctypes.cast(pubhex, ctypes.c_char_p).value == cp:
    print 'found it!', ahex
    key = ahex
    break

  OpenSSL.CRYPTO_free(pubhex)
  OpenSSL.EC_POINT_free(pub_key)
  OpenSSL.BN_free(priv_key)

  tried += 1
  if tried % 10000 == 0:
    sys.stdout.write('%d.. ' % tried)
    sys.stdout.flush()

OpenSSL.EC_KEY_free(k)
assert key

# decrypt
key = key.rjust(32, '0')
p = subprocess.Popen([
  'mdecrypt', '--keymode', 'hex', '--keysize', '16', '--bare',
  '--key', key, '--mode', 'cbc',
  '--algorithm', 'rijndael-128',
], stdin=subprocess.PIPE)
p.stdin.write(ciphertext)
p.stdin.close()
p.wait()
