#!/usr/bin/python
import math, random, time, subprocess, re, os, sys

def unlink_f(n):
  try:
    os.unlink(n)
  except OSError:
    pass

random.seed(1)

dt = float('nan')
factors = sys.maxint
while not (20.0 <= dt <= 30.0 and factors < 20):
  # Fewer factors = easier prime factorization but more difficult to brute force
  # factor satisfying bitcoin address. Many small factors tend to produce
  # trailing '0' bits which should hint towards factorization. Large numbers
  # are intimidating but not necessarily more difficult :>

  # 0x31e6b6fc16c3df9337f72f20d56398: 29 factors,  2.2 seconds
  # 0x164378cd7e18088db868185d25b3c4: 18 factors,  0.3 seconds
  n = 1
  while True:
    f = random.randint(1, 2 ** 40 - 1)
    if n * f < 2 ** 128:
      n *= f
    else:
      break

  stdout = subprocess.check_output(
      ['./trysecret', hex(n).lstrip('0x').rstrip('L')])
  for line in stdout.splitlines():
    if line.startswith('Wrapped key: '):
      print line.rstrip()
      _, _, wrapped_key = line.partition(': ')
      break
  else:
    raise Exception('Wrapped key not found: %r' % stdout)

  start = time.time()
  unlink_f('msieve.log')
  unlink_f('msieve.dat')
  subprocess.check_call([
      '../msieve/msieve',
      '-t', '1', '-d', '1',
      wrapped_key,
  ])
  dt = time.time() - start

  factors = 0
  for line in open('msieve.log'):
    m = re.search(r'  ([cp])\d+ factor: (\d+)', line)
    if m:
      if m.group(1) == 'c':
        factors = sys.maxint
        break
      else:
        factors += 1

  if factors == sys.maxint:
    print '0x%x: partial factorization' % n
  else:
    print '0x%x: %d factors, %4.01f seconds' % (n, factors, dt)
