#!/usr/bin/python
import itertools, os, subprocess, re, sys

def unlink_f(n):
  try:
    os.unlink(n)
  except OSError:
    pass

# parse
bitcoin, wk, ciphertext = None, None, None
for line in open('montrehack.flag.nc'):
  m = re.search(r'\b(1\w+)\b', line)
  if m:
    bitcoin = m.group(1)

  m = re.search(r'wk=(\w+)', line)
  if m:
    wk = '0x' + m.group(1)

_, sep, ciphertext = open('montrehack.flag.nc').read().partition('\n.\n')
assert sep

assert bitcoin and wk and ciphertext

print 'bitcoin=%s' % bitcoin
print 'wk=%s' % wk

# factor
unlink_f('msieve.log')
unlink_f('msieve.dat')
subprocess.check_call(['../msieve/msieve', wk])
factors = []
for line in open('msieve.log'):
  m = re.search(r'  ([cp])\d+ factor: (\d+)', line)
  if m:
    assert m.group(1) == 'p'
    factors.append(int(m.group(2)))

print '%d factors: %r' % (len(factors), factors)

# check
p = subprocess.Popen(
  ['../sbag/sbag'],
  stdin=subprocess.PIPE, stdout=subprocess.PIPE)
key, tried = None, 0
for ii in itertools.product([1, 0], repeat=len(factors)):
  a = 1
  for i, f in zip(ii, factors):
    if i:
      a *= f
  p.stdin.write('%x\n' % a)
  addr = p.stdout.readline()
  if not addr:
    raise ValueError('sbag error')

  if addr.strip() == bitcoin:
    key = '%032x' % a
    print 'found it!', key
    break

  tried += 1
  if tried % 10000 == 0:
    sys.stdout.write('%d.. ' % tried)
assert key

# decrypt
p = subprocess.Popen([
  'mdecrypt', '--keymode', 'hex', '--keysize', '16', '--bare',
  '--key', key, '--mode', 'cbc',
  '--algorithm', 'rijndael-128',
], stdin=subprocess.PIPE)
p.stdin.write(ciphertext)
p.stdin.close()
p.wait()
