#!/usr/bin/python
import sys, subprocess

ciphertext = open(sys.argv[1], 'rb').read()
sepindex = ciphertext.find('\n.\n')
if 0 <= sepindex < 1024:
  ciphertext = ciphertext[sepindex + 3:]

p = subprocess.Popen([
  'mdecrypt', '--keymode', 'hex', '--keysize', '16', '--bare',
  '--key', '0031e6b6fc16c3df9337f72f20d56398', '--mode', 'cbc',
  '--algorithm', 'rijndael-128',
], stdin=subprocess.PIPE)
p.stdin.write(ciphertext)
p.stdin.close()
p.wait()
